"""Audit every declared shape and variant; a mismatch alone never proves contradiction."""

from dataclasses import dataclass
from pathlib import Path
from typing import cast

from pydantic import JsonValue

from aletheia import __version__
from aletheia.analysis.ghidra_session import GhidraAnalysis
from aletheia.config import Budgets
from aletheia.schema.canonical import content_hash
from aletheia.schema.models import (
    REGISTRY,
    Algorithm,
    Aspect,
    Budget,
    Claim,
    Counterexample,
    Digest,
    Evidence,
    FunctionPurpose,
    Outcome,
    Verdict,
)
from aletheia.verify.emulate.core import (
    Buffer,
    CallResult,
    Emulator,
    InitializationBudgetExhausted,
)
from aletheia.verify.probes.inputs import generate_inputs, inputs_for_call
from aletheia.verify.probes.minimize import minimize_counterexample
from aletheia.verify.probes.oracles import OracleResult, evaluate, string_pair
from aletheia.verify.probes.pack import CallShape, Pack, VariantProbe
from aletheia.verify.probes.purpose import PurposeMapping
from aletheia.verify.static.arity import infer_arity


@dataclass(frozen=True)
class Trial:
    shape: CallShape
    variant: str
    data: bytes
    result: CallResult
    expected: str
    actual: str
    status: str

    def record(self) -> dict[str, JsonValue]:
        return {
            "shape": self.shape.id,
            "variant": self.variant,
            "input_hex": self.data.hex(),
            "status": self.status,
            "expected_hex": self.expected,
            "actual_hex": self.actual,
            "instructions": self.result.instructions,
            "fault": self.result.fault,
            "uninitialized_state_reads": self.result.uninitialized_state_reads,
            "imports_called": cast(JsonValue, self.result.imports_called),
        }


def expected_hex(expected: OracleResult, shape: CallShape) -> str:
    if shape.comparison == "output":
        return (expected.output or b"").hex()
    return (
        (expected.return_value & ((1 << shape.return_width) - 1)).to_bytes(
            shape.return_width // 8, "little"
        )
        + (expected.output or b"")
    ).hex()


def run_input(
    emu: Emulator, entry: int, shape: CallShape, variant: str, probe: VariantProbe, data: bytes
) -> Trial:
    args: list[int | Buffer] = []
    pair = string_pair(data) if "cstr_b" in shape.roles else None
    for role in shape.roles:
        if role == "seed":
            args.append(probe.bind["seed"])
        elif role == "len":
            args.append(1 << 20 if shape.id == "strlen_bound" else len(data))
        elif role == "buf":
            args.append(Buffer(data))
        elif role in {"cstr", "cstr_b"}:
            value = pair[0 if role == "cstr" else 1] if pair else data
            args.append(Buffer(value + b"\0"))
        else:
            size = shape.output_size(len(data))
            args.append(Buffer(b"\xa5" * size if shape.id == "memcpy" else b"", size))
    oracle = evaluate(probe.oracle, data, **probe.bind)
    expected = expected_hex(oracle, shape)
    result = emu.call(entry, args, shape.return_width)
    actual = b"" if result.ret is None else result.ret.to_bytes(shape.return_width // 8, "little")
    if shape.comparison == "output":
        actual = b""
    elif shape.comparison == "sign" and result.ret is not None:
        signed = result.ret if result.ret < 1 << 31 else result.ret - (1 << 32)
        actual = (((signed > 0) - (signed < 0)) & 0xFFFFFFFF).to_bytes(4, "little")
    if result.ret is not None and "out" in shape.roles:
        index = sum(
            role in {"buf", "cstr", "cstr_b", "out"}
            for role in shape.roles[: shape.roles.index("out")]
        )
        length = len(oracle.output or b"") if shape.comparison == "output" else result.ret
        actual += result.out_buffers[index][:length]
    if result.uninitialized_state_reads:
        status = "state_dependent"
    elif result.fault is not None:
        if result.fault.startswith("unsupported_import:"):
            status = "unsupported_import"
        elif result.fault in (
            "emulation_fault",
            "budget_exhausted",
            "unsupported_relocation",
            "fortify_fail",
        ):
            status = result.fault
        else:
            raise ValueError("unexpected emulator fault: " + result.fault)
    else:
        status = "match" if actual.hex() == expected else "mismatch"
    return Trial(shape, variant, data, result, expected, actual.hex(), status)


@dataclass(frozen=True)
class ProbeOutcome:
    verdict: Verdict
    artifacts: dict[str, JsonValue]


def verify_algorithm(
    claim: Claim,
    analysis: GhidraAnalysis,
    pack: Pack | None,
    binary: Path,
    budgets: Budgets,
    env_digest: Digest,
    purpose_mapping: PurposeMapping | None = None,
) -> ProbeOutcome:
    if not isinstance(claim.body, (Algorithm, FunctionPurpose)):
        raise ValueError("probe requires algorithm_identity or function_purpose")
    purpose = isinstance(claim.body, FunctionPurpose)
    aspect = "category_behavior" if purpose else "output_match"
    requested = None
    if isinstance(claim.body, FunctionPurpose):
        if purpose_mapping is None:
            raise ValueError("purpose probe requires its pinned public mapping")
        requested = purpose_mapping.map.get(claim.body.category)
        if requested is not None and requested.composite:
            raise ValueError("composite purposes require a composite job")
        family = requested.pack if requested else "purpose"
        claimed_variant = None
    else:
        family = claim.body.family
        claimed_variant = claim.body.variant
    if claim.binary_sha256 != analysis.binary_sha256 or binary.stem != claim.binary_sha256:
        raise ValueError("probe binary/analysis identity mismatch")
    if pack is not None and pack.family != family:
        raise ValueError("probe pack family mismatch")
    method = f"probe.{family}@{pack.version if pack else 1}"
    variants = sorted(pack.variants) if pack else []
    allowed = requested.variants if requested else REGISTRY.get(family, ())
    unsupported = sorted(set(allowed) - set(variants))
    scope = (
        [claimed_variant] if claimed_variant is not None else sorted(set(allowed) & set(variants))
    )
    observations: list[Trial] = []
    minimization: list[Trial] = []
    skipped: list[dict[str, JsonValue]] = []
    instructions = 0
    arity = None
    initial_state = "none"

    def finish(
        outcome: Outcome,
        reason: str | None = None,
        harness: str | None = None,
        counterexample: Counterexample | None = None,
    ) -> ProbeOutcome:
        payload = cast(
            JsonValue,
            {
                "schema_version": "1.0",
                "binary_sha256": claim.binary_sha256,
                "subject": claim.subject.address,
                "family": family,
                "claimed_variant": claimed_variant,
                **(
                    {"category": claim.body.category}
                    if isinstance(claim.body, FunctionPurpose)
                    else {}
                ),
                "supported_variants": variants,
                "unsupported_variants": unsupported,
                "arity": arity.model_dump(mode="json") if arity is not None else None,
                "initial_state": initial_state,
                "observations": [trial.record() for trial in observations],
                "minimization": [trial.record() for trial in minimization],
                **(
                    {"skipped_inputs": skipped}
                    if purpose or family in {"md5", "sha1", "sha256"}
                    else {}
                ),
            },
        )
        digest = "sha256:" + content_hash(payload)
        decisive = outcome in ("VERIFIED", "CONTRADICTED")
        strength = "E2" if decisive else None
        verdict = Verdict(
            claim_id=claim.claim_id,
            intrinsic_verdict=outcome,
            strength=strength,
            aspects={aspect: Aspect(verdict=outcome, strength=strength, method=method)},
            methods_run=[method],
            reason=reason,
            harness=harness,
            counterexample=counterexample,
            evidence=[
                Evidence(
                    kind="probe_results",
                    artifact=digest,
                    summary=f"{len(observations)} observations; unsupported variants: "
                    + (", ".join(unsupported) or "none"),
                )
            ],
            budget_used=Budget(instructions=instructions),
            verifier_version=__version__,
            env_digest=env_digest,
        )
        return ProbeOutcome(verdict, {digest: payload})

    if (
        pack is None
        or not scope
        or (claimed_variant is not None and claimed_variant not in variants)
    ):
        return finish("UNVERIFIABLE", "no_pack")
    if not any(fn.entry == claim.subject.address for fn in analysis.functions):
        return finish("ERROR", "subject_not_found")
    arity = infer_arity(claim.subject.address, analysis)
    try:
        emu = Emulator(binary, budgets)
    except InitializationBudgetExhausted as exc:
        instructions = exc.instructions
        initial_state = "init_array budget exhausted"
        return finish("INCONCLUSIVE", "budget_exhausted")
    initial_cost = emu.total_instructions
    initial_state = "init_array run" if initial_cost else "none"
    entry = int(claim.subject.address, 16)
    values = generate_inputs(pack.inputs)
    # Evidence order: declared shape, variant name, then generator ordinal.
    for shape in pack.call_shapes:
        for variant in scope:
            probe = pack.variants[variant]
            if probe.call_shapes is not None and shape.id not in probe.call_shapes:
                continue
            inputs = inputs_for_call(values, probe, shape)
            for index, data in enumerate(inputs):
                trial = run_input(emu, entry, shape, variant, probe, data)
                observations.append(trial)
                if shape.comparison == "output" and trial.status not in {"match", "mismatch"}:
                    # A dirty harness can no longer verify or support contradiction.
                    skipped.append(
                        {
                            "shape": shape.id,
                            "variant": variant,
                            "count": len(inputs) - index - 1,
                            "reason": trial.status,
                        }
                    )
                    break
    instructions = emu.total_instructions

    def harness(shape: CallShape, variant: str, ending: str) -> str:
        probe = pack.variants[variant]
        inputs = inputs_for_call(values, probe, shape)
        fixed_values = [value.encode() for value in pack.inputs.fixed]
        fixed_values += [bytes.fromhex(value) for value in pack.inputs.fixed_hex]
        fixed = len(inputs_for_call(fixed_values, probe, shape))
        return (
            f"Function-level emulation of {claim.subject.address}; shape {shape.id} "
            f"({', '.join(shape.roles)}); stubs S1; initial state: {initial_state}; "
            f"{len(inputs)} inputs ({fixed} fixed, {len(inputs) - fixed} generated, "
            f"seed {pack.inputs.random.seed}); oracle {pack.variants[variant].oracle} "
            f"({family}/{variant}) at {shape.return_width}-bit width: {ending}."
        )

    for shape in pack.call_shapes:
        for variant in scope:
            trials = [
                trial
                for trial in observations
                if trial.shape.id == shape.id and trial.variant == variant
            ]
            if trials and all(trial.status == "match" for trial in trials):
                return finish("VERIFIED", harness=harness(shape, variant, "all matched"))
    shapes = [shape for shape in pack.call_shapes if len(shape.roles) == arity.arity]
    eligible = [trial for trial in observations if trial.shape in shapes]
    clean = bool(eligible) and all(trial.status in ("match", "mismatch") for trial in eligible)
    mismatches = [trial for trial in eligible if trial.status == "mismatch"]
    every_pair = all(
        any(
            trial.status == "mismatch"
            for trial in eligible
            if trial.shape == shape and trial.variant == variant
        )
        for shape in shapes
        for variant in scope
        if pack.variants[variant].call_shapes is None
        or shape.id in (pack.variants[variant].call_shapes or [])
    )
    complete_scope = claimed_variant is not None or not unsupported
    if arity.decisive and shapes and clean and every_pair and complete_scope:
        selected = min(
            mismatches,
            key=lambda trial: (
                len(trial.data),
                trial.data.hex(),
                pack.call_shapes.index(trial.shape),
                trial.variant,
            ),
        )
        exhausted = False

        def fresh(data: bytes) -> Trial | None:
            nonlocal instructions, exhausted
            try:
                evaluate(
                    pack.variants[selected.variant].oracle,
                    data,
                    **pack.variants[selected.variant].bind,
                )
            except ValueError:
                return None
            remaining = budgets.instructions_per_claim - instructions
            if remaining <= initial_cost:
                exhausted = True
                return None
            try:
                pristine = Emulator(
                    binary, budgets.model_copy(update={"instructions_per_claim": remaining})
                )
            except InitializationBudgetExhausted as exc:
                instructions += exc.instructions
                exhausted = True
                return None
            trial = run_input(
                pristine,
                entry,
                selected.shape,
                selected.variant,
                pack.variants[selected.variant],
                data,
            )
            instructions += pristine.total_instructions
            minimization.append(trial)
            return trial

        def still_fails(data: bytes) -> bool:
            trial = fresh(data)
            return trial is not None and trial.status == "mismatch"

        try:
            minimized = minimize_counterexample([selected.data], still_fails)
        except ValueError:
            if exhausted or (minimization and minimization[-1].status == "budget_exhausted"):
                return finish("INCONCLUSIVE", "budget_exhausted")
            return finish("ERROR", "internal")
        reproduced = fresh(minimized)
        if reproduced is None:
            return finish("INCONCLUSIVE", "budget_exhausted")
        if reproduced.status != "mismatch":
            if reproduced.status in (
                "state_dependent",
                "emulation_fault",
                "fortify_fail",
                "budget_exhausted",
                "unsupported_relocation",
            ):
                return finish("INCONCLUSIVE", reproduced.status)
            if reproduced.status == "unsupported_import":
                return finish("INCONCLUSIVE", reproduced.result.fault)
            return finish("ERROR", "internal")
        matches_variant = None
        same_shape = [
            trial
            for trial in observations
            if trial.shape == selected.shape and trial.variant == selected.variant
        ]
        for other, probe in sorted(pack.variants.items()):
            if (
                other == selected.variant
                or probe.bind != pack.variants[selected.variant].bind
                or probe.input_encoding != pack.variants[selected.variant].input_encoding
                or (probe.call_shapes is not None and selected.shape.id not in probe.call_shapes)
            ):
                continue
            try:
                matched = same_shape and all(
                    trial.actual
                    == expected_hex(
                        evaluate(probe.oracle, trial.data, **probe.bind), selected.shape
                    )
                    for trial in same_shape
                )
            except ValueError:
                matched = False
            if matched:
                matches_variant = other
                break
        counterexample = Counterexample(
            call_shape=selected.shape.id,
            input_hex=minimized.hex(),
            expected_hex=reproduced.expected,
            actual_hex=reproduced.actual,
            variant=selected.variant,
            matches_variant=matches_variant,
        )
        return finish(
            "CONTRADICTED",
            harness=harness(
                selected.shape, selected.variant, "mismatch on input " + minimized.hex()
            ),
            counterexample=counterexample,
        )
    for reason in (
        "state_dependent",
        "unsupported_relocation",
        "unsupported_import",
        "emulation_fault",
        "fortify_fail",
        "budget_exhausted",
    ):
        first = next((trial for trial in observations if trial.status == reason), None)
        if first is not None:
            return finish(
                "INCONCLUSIVE", first.result.fault if reason == "unsupported_import" else reason
            )
    if not arity.decisive:
        return finish("INCONCLUSIVE", "binding_not_verified")
    if not shapes:
        return finish("INCONCLUSIVE", "no_matching_call_shape")
    return finish("INCONCLUSIVE", "no_pack")

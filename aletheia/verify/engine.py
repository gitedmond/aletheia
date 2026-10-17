"""Phase 1A audit registry, guarded merging and source-independent verdict caching."""

import hashlib
import json
from collections import Counter
from dataclasses import dataclass, field, replace
from pathlib import Path
from typing import Literal, cast

from pydantic import Field, JsonValue, TypeAdapter

from aletheia import __version__
from aletheia.analysis.ghidra_session import (
    ConstantMatch,
    GhidraAnalysis,
    GhidraOptions,
    publish_immutable,
    read_public_binary,
)
from aletheia.config import Budgets
from aletheia.sandbox.runner import JobRunner
from aletheia.schema.canonical import canonical_bytes, content_hash
from aletheia.schema.models import (
    Address,
    Algorithm,
    Aspect,
    AspectName,
    Budget,
    Call,
    Claim,
    Digest,
    Evidence,
    FunctionPurpose,
    FunctionSignature,
    Job,
    JobResult,
    Outcome,
    Record,
    Sha256,
    Strength,
    Strict,
    Verdict,
)
from aletheia.schema.taxonomy import Taxonomy
from aletheia.sources.base import BinaryRef
from aletheia.store.cache import CacheContext, verdict_cache_key
from aletheia.store.database import Store
from aletheia.verify.composite import CompositeMember, CompositeRequest
from aletheia.verify.composite_client import CompositeClient
from aletheia.verify.emulate.core import BASE, CANARY, HEAP, INPUTS, SENTINEL, STACK, STUBS, TLS
from aletheia.verify.groups import (
    GroupEvidence,
    collect_groups,
    group_preconditions,
    public_members,
)
from aletheia.verify.probes.client import ProbeClient
from aletheia.verify.probes.inputs import generate_inputs, inputs_for_call, inputs_for_shape
from aletheia.verify.probes.pack import HexInput, Pack, load_pack
from aletheia.verify.probes.purpose import PurposeMapping, PurposeScope
from aletheia.verify.static.arity import Arity, infer_arity
from aletheia.verify.static.worker import StaticRequest


@dataclass(frozen=True)
class MethodSpec:
    name: str
    claim_type: Literal[
        "algorithm_identity", "call_relation", "function_signature", "function_purpose"
    ]
    aspect: (
        Literal[
            "output_match",
            "edge_exists",
            "arity",
            "return_width",
            "param_widths",
            "param_types",
            "category_behavior",
        ]
        | None
    )
    strength: Strength | None
    decisive_verified: bool
    decisive_contradicted: bool
    cost_class: Literal["static", "emulation"]


@dataclass(frozen=True)
class DynamicProof:
    binding_verified: bool
    state_clean: bool
    widths_valid: bool
    reproduced: bool
    complete_scope: bool
    execution_reason: str | None = None

    def failure(self) -> str | None:
        if not self.state_clean:
            return "state_dependent"
        if self.execution_reason:
            return self.execution_reason
        if not self.binding_verified:
            return "binding_not_verified"
        if not self.widths_valid:
            return "no_matching_call_shape"
        if not self.reproduced:
            return "emulation_fault"
        if not self.complete_scope:
            return "no_pack"
        return None


@dataclass(frozen=True)
class MethodResult:
    spec: MethodSpec
    verdict: Verdict | None
    evidence: tuple[Evidence, ...] = ()
    proof: DynamicProof | None = None
    details: dict[str, JsonValue] = field(default_factory=lambda: dict[str, JsonValue]())


def guarded_result(result: MethodResult) -> MethodResult:
    verdict = result.verdict
    if (
        verdict is None
        or verdict.intrinsic_verdict != "CONTRADICTED"
        or result.spec.cost_class != "emulation"
    ):
        return result
    reason = result.proof.failure() if result.proof else "binding_not_verified"
    if reason is None:
        return result
    aspects = {
        key: Aspect(verdict="INCONCLUSIVE", method=result.spec.name) for key in verdict.aspects
    }
    value = verdict.model_copy(
        update={
            "intrinsic_verdict": "INCONCLUSIVE",
            "strength": None,
            "reason": reason,
            "harness": None,
            "counterexample": None,
            "aspects": aspects,
        }
    )
    return replace(result, verdict=value, details=result.details | {"precondition_failure": reason})


def _merge_aspect(
    claim: Claim, results: list[MethodResult], env_digest: Digest, aspect: AspectName
) -> Verdict:
    results = sorted(
        (guarded_result(result) for result in results), key=lambda result: result.spec.name
    )
    eligible = [
        result
        for result in results
        if result.spec.claim_type == claim.type
        and result.spec.aspect == aspect
        and (result.spec.decisive_verified or result.spec.decisive_contradicted)
        and result.verdict is not None
    ]
    winner: MethodResult | None = None
    outcome: Outcome = "UNVERIFIABLE"
    reason: str | None = "no_pack"
    invalid = [
        result
        for result in results
        if result.verdict is not None and result.verdict.intrinsic_verdict == "INVALID_CLAIM"
    ]

    def candidates(value: Outcome) -> list[MethodResult]:
        return [
            result
            for result in eligible
            if result.verdict is not None and result.verdict.intrinsic_verdict == value
        ]

    def strongest(values: list[MethodResult]) -> MethodResult:
        return min(
            values,
            key=lambda result: (
                -({"E1": 1, "E2": 2}.get(result.spec.strength or "", 0)),
                result.spec.name,
            ),
        )

    contradicted = [
        result for result in candidates("CONTRADICTED") if result.spec.decisive_contradicted
    ]
    verified = [result for result in candidates("VERIFIED") if result.spec.decisive_verified]
    if invalid:
        winner, outcome = invalid[0], "INVALID_CLAIM"
    elif contradicted:
        winner, outcome = strongest(contradicted), "CONTRADICTED"
    elif verified:
        winner, outcome = strongest(verified), "VERIFIED"
    elif values := candidates("INCONCLUSIVE"):
        priorities = [
            "state_dependent",
            "unsupported_relocation",
            "unsupported_import",
            "emulation_fault",
            "budget_exhausted",
            "binding_not_verified",
            "no_matching_call_shape",
            "no_pack",
        ]

        def order(result: MethodResult) -> tuple[int, str]:
            assert result.verdict is not None
            item = (result.verdict.reason or "").split(":", 1)[0]
            return (
                priorities.index(item) if item in priorities else len(priorities),
                result.spec.name,
            )

        winner, outcome = min(values, key=order), "INCONCLUSIVE"
    elif values := candidates("ERROR"):
        winner, outcome = (
            min(
                values,
                key=lambda result: (
                    result.verdict is None or result.verdict.reason != "wall_timeout",
                    result.spec.name,
                ),
            ),
            "ERROR",
        )
    elif values := candidates("NOT_CHECKED"):
        winner, outcome = values[0], "NOT_CHECKED"
    elif values := candidates("UNVERIFIABLE"):
        winner = values[0]
    value = winner.verdict if winner is not None else None
    decisive = outcome in ("VERIFIED", "CONTRADICTED")
    if value is not None:
        reason = None if decisive else value.reason
    strength = winner.spec.strength if decisive and winner is not None else None
    methods = sorted(
        {
            result.spec.name
            for result in results
            if result.verdict is None
            or result.verdict.intrinsic_verdict not in ("NOT_CHECKED", "INVALID_CLAIM")
        }
    )
    all_evidence = [
        item
        for result in results
        for item in (list(result.evidence) + (result.verdict.evidence if result.verdict else []))
    ]
    evidence = [
        Evidence(kind=kind, artifact=artifact, summary=summary)
        for kind, artifact, summary in sorted(
            {(item.kind, item.artifact, item.summary) for item in all_evidence}
        )
    ]
    aspects: dict[AspectName, Aspect] = {}
    if winner is not None and winner.spec.aspect is not None and outcome != "INVALID_CLAIM":
        aspects[aspect] = Aspect(verdict=outcome, strength=strength, method=winner.spec.name)
    return Verdict(
        claim_id=claim.claim_id,
        intrinsic_verdict=outcome,
        strength=strength,
        reason=reason,
        aspects=aspects,
        methods_run=methods,
        harness=value.harness if decisive and value is not None else None,
        counterexample=value.counterexample
        if outcome == "CONTRADICTED" and value is not None
        else None,
        evidence=evidence,
        budget_used=Budget(
            instructions=sum(
                result.verdict.budget_used.instructions
                for result in results
                if result.verdict is not None
            )
        ),
        verifier_version=__version__,
        env_digest=env_digest,
    )


REQUIRED_ASPECTS: dict[str, tuple[AspectName, ...]] = {
    "algorithm_identity": ("output_match",),
    "call_relation": ("edge_exists",),
    "function_signature": ("arity", "return_width"),
    "function_purpose": ("category_behavior",),
}
OPTIONAL_ASPECTS: dict[str, tuple[AspectName, ...]] = {
    "function_signature": ("param_widths", "param_types"),
}


def merge_results(claim: Claim, results: list[MethodResult], env_digest: Digest) -> Verdict:
    required = REQUIRED_ASPECTS[claim.type]
    if len(required) == 1:
        return _merge_aspect(claim, results, env_digest, required[0])
    results = [guarded_result(result) for result in results]
    decisions: dict[AspectName, Verdict] = {}
    for name in (*required, *OPTIONAL_ASPECTS.get(claim.type, ())):
        projected: list[MethodResult] = []
        for result in results:
            value = result.verdict
            aspect = value.aspects.get(name) if value else None
            if aspect is not None and result.spec.claim_type == claim.type:
                assert value is not None
                if aspect.method != result.spec.name:
                    raise ValueError("method/aspect identity mismatch")
                projected.append(
                    replace(
                        result,
                        spec=replace(result.spec, aspect=name),
                        verdict=value.model_copy(
                            update={
                                "intrinsic_verdict": aspect.verdict,
                                "strength": aspect.strength,
                                "reason": None
                                if aspect.verdict in {"VERIFIED", "CONTRADICTED"}
                                else value.reason or "width_ambiguous",
                                "harness": value.harness
                                or (
                                    f"{result.spec.name}: public register facts "
                                    f"for {claim.subject.address}"
                                ),
                            }
                        ),
                    )
                )
            elif result.spec.aspect == name:
                projected.append(result)
        decisions[name] = _merge_aspect(claim, projected, env_digest, name)
    required_values = [decisions[name] for name in required]
    outcomes = {value.intrinsic_verdict for value in required_values}
    if "INVALID_CLAIM" in outcomes:
        outcome: Outcome = "INVALID_CLAIM"
    elif "CONTRADICTED" in outcomes:
        outcome = "CONTRADICTED"
    elif outcomes == {"VERIFIED"}:
        outcome = "VERIFIED"
    elif outcomes & {"VERIFIED", "INCONCLUSIVE"}:
        outcome = "INCONCLUSIVE"
    elif "ERROR" in outcomes:
        outcome = "ERROR"
    elif "NOT_CHECKED" in outcomes:
        outcome = "NOT_CHECKED"
    else:
        outcome = "UNVERIFIABLE"
    candidates = [value for value in required_values if value.intrinsic_verdict == outcome]
    selected = (candidates or [v for v in required_values if v.intrinsic_verdict != "VERIFIED"])[0]
    decisive = outcome in {"VERIFIED", "CONTRADICTED"}
    strength: Strength | None = (
        min(
            (cast(Strength, v.strength) for v in required_values),
            key=lambda x: {"E1": 1, "E2": 2}[x],
        )
        if outcome == "VERIFIED"
        else selected.strength
        if decisive
        else None
    )
    evidence = {
        (e.kind, e.artifact, e.summary): e for value in decisions.values() for e in value.evidence
    }
    return Verdict(
        claim_id=claim.claim_id,
        intrinsic_verdict=outcome,
        strength=strength,
        reason=None if decisive else selected.reason or "no_pack",
        aspects={
            name: aspect for value in decisions.values() for name, aspect in value.aspects.items()
        },
        methods_run=sorted(
            {method for value in decisions.values() for method in value.methods_run}
        ),
        harness="; ".join(dict.fromkeys(v.harness for v in required_values if v.harness))
        if decisive
        else None,
        counterexample=selected.counterexample if outcome == "CONTRADICTED" else None,
        evidence=[evidence[key] for key in sorted(evidence)],
        budget_used=Budget(
            instructions=sum(r.verdict.budget_used.instructions for r in results if r.verdict)
        ),
        verifier_version=__version__,
        env_digest=env_digest,
    )


class InputObservation(Strict):
    shape: str
    variant: str
    input_hex: HexInput
    status: Literal[
        "match",
        "mismatch",
        "state_dependent",
        "unsupported_import",
        "unsupported_relocation",
        "emulation_fault",
        "fortify_fail",
        "budget_exhausted",
    ]
    expected_hex: HexInput
    actual_hex: HexInput
    instructions: int = Field(ge=0)
    fault: str | None
    uninitialized_state_reads: bool
    imports_called: list[str]


class SkippedInputs(Strict):
    shape: str
    variant: str
    count: int = Field(ge=0)
    reason: str


class ProbeEvidence(Record):
    binary_sha256: Sha256
    subject: Address
    family: str
    claimed_variant: str | None
    category: str | None = None
    supported_variants: list[str]
    unsupported_variants: list[str]
    arity: Arity | None
    initial_state: str
    observations: list[InputObservation]
    minimization: list[InputObservation]
    skipped_inputs: list[SkippedInputs] = Field(default_factory=lambda: list[SkippedInputs]())


def probe_proof(
    claim: Claim,
    analysis: GhidraAnalysis,
    pack: Pack,
    evidence: ProbeEvidence,
    verdict: Verdict,
    purpose_scope: PurposeScope | None = None,
) -> DynamicProof:
    if not isinstance(claim.body, (Algorithm, FunctionPurpose)):
        raise ValueError("dynamic proof requires a behavioral claim")
    if isinstance(claim.body, FunctionPurpose) and purpose_scope is None:
        raise ValueError("purpose proof requires its pinned scope")
    binding = infer_arity(claim.subject.address, analysis)
    if evidence.arity is not None and evidence.arity != binding:
        raise ValueError("probe/analysis binding evidence mismatch")
    shapes = {shape.id: shape for shape in pack.call_shapes}
    eligible = [
        row
        for row in evidence.observations
        if row.shape in shapes and len(shapes[row.shape].roles) == binding.arity
    ]
    state_clean = all(not row.uninitialized_state_reads for row in eligible)
    execution = None
    for status in (
        "unsupported_relocation",
        "unsupported_import",
        "emulation_fault",
        "fortify_fail",
        "budget_exhausted",
    ):
        row = next((row for row in eligible if row.status == status), None)
        if row is not None:
            execution = row.fault if status == "unsupported_import" else status
            break
    widths = bool(eligible) and all(
        (
            len(row.expected_hex) // 2
            == len(row.actual_hex) // 2
            == shapes[row.shape].output_size(len(bytes.fromhex(row.input_hex)))
            - int(shapes[row.shape].out_size == "hex")
            if shapes[row.shape].comparison == "output"
            else len(row.expected_hex) // 2 >= shapes[row.shape].return_width // 8
            and len(row.actual_hex) // 2 >= shapes[row.shape].return_width // 8
            and len(row.actual_hex) // 2
            <= shapes[row.shape].return_width // 8
            + shapes[row.shape].output_size(len(bytes.fromhex(row.input_hex)))
        )
        for row in eligible
    )
    ce = verdict.counterexample
    last = evidence.minimization[-1] if evidence.minimization else None
    reproduced = bool(
        ce is not None
        and last is not None
        and last.status == "mismatch"
        and last.fault is None
        and not last.uninitialized_state_reads
        and (last.shape, last.variant, last.input_hex, last.expected_hex, last.actual_hex)
        == (ce.call_shape, ce.variant, ce.input_hex, ce.expected_hex, ce.actual_hex)
        and last.expected_hex != last.actual_hex
    )
    wanted = (
        purpose_scope.variants
        if purpose_scope is not None
        else [claim.body.variant]
        if isinstance(claim.body, Algorithm) and claim.body.variant
        else list(pack.variants)
    )
    complete = set(wanted) <= set(pack.variants) and (
        purpose_scope is not None
        or isinstance(claim.body, Algorithm)
        and (claim.body.variant is not None or not pack.unsupported_variants)
    )
    values = generate_inputs(pack.inputs)
    for shape in pack.call_shapes:
        if len(shape.roles) != binding.arity:
            continue
        for variant in wanted:
            if variant not in pack.variants:
                complete = False
                continue
            probe = pack.variants[variant]
            if probe.call_shapes is not None and shape.id not in probe.call_shapes:
                continue
            expected = Counter(value.hex() for value in inputs_for_call(values, probe, shape))
            observed = Counter(
                row.input_hex
                for row in eligible
                if row.shape == shape.id and row.variant == variant
            )
            complete = complete and bool(expected) and expected == observed
    return DynamicProof(
        binding.decisive,
        state_clean,
        widths,
        reproduced,
        complete,
        execution,
    )


def verifier_source_hash() -> str:
    root = Path(__file__).resolve().parents[1]
    files = [root / "__init__.py", root / "config.py"]
    for directory in ("verify", "analysis", "worker", "schema", "store", "sandbox"):
        files.extend((root / directory).rglob("*.py"))
    return content_hash(
        {
            path.relative_to(root).as_posix(): hashlib.sha256(path.read_bytes()).hexdigest()
            for path in sorted(set(files))
        }
    )


@dataclass(frozen=True)
class EngineResult:
    verdict: Verdict
    method_results: dict[str, Aspect]
    cache_key: str
    cache_hit: bool


def methods_for(claim: Claim, pack: Pack | None) -> list[MethodSpec]:
    if claim.type == "call_relation":
        return [
            MethodSpec("static.edges@1", "call_relation", "edge_exists", "E1", True, True, "static")
        ]
    if isinstance(claim.body, FunctionSignature):
        return [
            MethodSpec("static.arity@2", "function_signature", "arity", "E1", True, True, "static"),
            MethodSpec(
                "static.widths@1", "function_signature", "return_width", "E1", True, True, "static"
            ),
        ]
    if isinstance(claim.body, FunctionPurpose):
        return [
            MethodSpec(
                f"probe.{pack.family if pack else 'purpose'}@{pack.version if pack else 1}",
                "function_purpose",
                "category_behavior",
                "E2",
                True,
                True,
                "emulation",
            )
        ]
    assert isinstance(claim.body, Algorithm)
    return [
        MethodSpec("static.constants@1", "algorithm_identity", None, "E1", False, False, "static"),
        MethodSpec(
            f"probe.{claim.body.family}@{pack.version if pack else 1}",
            "algorithm_identity",
            "output_match",
            "E2",
            True,
            True,
            "emulation",
        ),
    ]


DEFAULT_PACK_DIRECTORY = Path(__file__).resolve().parents[2] / "packs"


class Engine:
    def __init__(
        self,
        runner: JobRunner,
        store: Store,
        budgets: Budgets,
        options: Path,
        pack_directory: Path = DEFAULT_PACK_DIRECTORY,
        purpose_mapping: Path | None = None,
        mode: Literal["audit", "runtime"] = "audit",
    ):
        if mode not in {"audit", "runtime"}:
            raise ValueError("unknown engine mode")
        self.mode = mode
        self.last_verification_edges: list[tuple[str, str]] = []
        self.runner, self.store = runner, store
        self.budgets = budgets.model_copy(deep=True)
        self.options = GhidraOptions.read(options)
        self.options_hash = hashlib.sha256(options.read_bytes()).hexdigest()
        self.pack_paths: dict[str, Path] = {}
        self.packs: dict[str, Pack] = {}
        self.pack_hashes: dict[str, str] = {}
        for path in sorted(pack_directory.glob("*.yaml")):
            if any(part.is_symlink() for part in (path, *path.parents)):
                raise ValueError("pack cannot be a symlink")
            payload = path.read_bytes()
            digest = hashlib.sha256(payload).hexdigest()
            snapshot = self.runner.input_root / "in" / (digest + ".yaml")
            publish_immutable(snapshot, payload)
            pack = load_pack(snapshot)
            if pack.family in self.packs or pack.family != path.stem:
                raise ValueError("duplicate or mislabeled family pack")
            self.pack_paths[pack.family], self.packs[pack.family] = snapshot, pack
            self.pack_hashes[pack.family] = digest
        mapping_path = (
            purpose_mapping or DEFAULT_PACK_DIRECTORY.parent / "mappings/purpose_packs.yaml"
        )
        if any(part.is_symlink() for part in (mapping_path, *mapping_path.parents)):
            raise ValueError("purpose mapping cannot be a symlink")
        mapping_bytes = mapping_path.read_bytes()
        self.purpose_mapping_hash = hashlib.sha256(mapping_bytes).hexdigest()
        self.purpose_mapping_path = (
            self.runner.input_root / "in" / (self.purpose_mapping_hash + ".yaml")
        )
        publish_immutable(self.purpose_mapping_path, mapping_bytes)
        self.purpose_mapping = PurposeMapping.read(self.purpose_mapping_path)
        self.harness: dict[str, JsonValue] = {
            "mode": mode,
            "taxonomy_version": Taxonomy.bundled().version,
            "purpose_packs_hash": self.purpose_mapping_hash,
            "verifier_version": __version__,
            "verifier_source_hash": verifier_source_hash(),
            "sandbox": cast(JsonValue, runner.config.model_dump(mode="json")),
            "budgets": cast(JsonValue, budgets.model_dump(mode="json")),
            "analysis_options_hash": self.options_hash,
            "stub_set": "S1",
            "initializers": "verified_standard_crt",
            "mutable_state": "initial_zero_bytes_bss_data",
            "layout": {
                "base": BASE,
                "stubs": STUBS,
                "sentinel": SENTINEL,
                "tls": TLS,
                "heap": HEAP,
                "inputs": INPUTS,
                "stack": STACK,
                "canary": f"{CANARY:016x}",
            },
        }
        self.env_digest = "sha256:" + content_hash(self.harness)
        self.probes = ProbeClient(runner)

    def family_for(self, claim: Claim) -> str | None:
        if isinstance(claim.body, Algorithm):
            return claim.body.family
        if isinstance(claim.body, FunctionPurpose):
            scope = self.purpose_mapping.map.get(claim.body.category)
            return scope.pack if scope is not None and not scope.composite else None
        return None

    def _methods(
        self, claim: Claim, pack: Pack | None, group: MethodResult | None
    ) -> list[MethodSpec]:
        if group is None:
            return methods_for(claim, pack)
        return (
            [
                MethodSpec(
                    "static.constants@1", "algorithm_identity", None, "E1", False, False, "static"
                )
            ]
            if isinstance(claim.body, Algorithm)
            else []
        ) + [group.spec]

    def cache_context(
        self, claim: Claim, analysis: GhidraAnalysis, group: MethodResult | None = None
    ) -> CacheContext:
        family = str(group.details["family"]) if group else self.family_for(claim)
        pack = self.packs.get(family) if family is not None else None
        hashes = (
            {family: self.pack_hashes[family]}
            if family is not None and family in self.pack_hashes
            else {}
        )
        return CacheContext(
            verifier_version=__version__,
            method_versions=sorted(spec.name for spec in self._methods(claim, pack, group)),
            pack_hashes=hashes,
            env_digest=self.env_digest,
            analysis_options_hash=self.options_hash,
            taxonomy_version=Taxonomy.bundled().version,
            purpose_packs_hash=self.purpose_mapping_hash,
            harness=self.harness
            | {"analysis_result_hash": content_hash(analysis)}
            | ({"composite_group": group.details["members"]} if group else {}),
        )

    def _stage(self, payload: bytes, suffix: str) -> str:
        digest = hashlib.sha256(payload).hexdigest()
        publish_immutable(self.runner.input_root / "in" / (digest + suffix), payload)
        return "in/" + digest + suffix

    def _error(
        self, spec: MethodSpec, claim: Claim, code: str, detail: str, artifact: str | None = None
    ) -> MethodResult:
        reason = "wall_timeout" if code == "wall_timeout" else "internal"
        if artifact is None:
            artifact = self.runner.artifacts.put(
                canonical_bytes(
                    {
                        "method": spec.name,
                        "error_code": code,
                        "detail": detail,
                        "budget_known": False,
                    }
                )
            )
        evidence = Evidence(
            kind="method_error", artifact=artifact, summary=code + ": " + detail[:160]
        )
        aspects: dict[AspectName, Aspect] = (
            {spec.aspect: Aspect(verdict="ERROR", method=spec.name)} if spec.aspect else {}
        )
        verdict = Verdict(
            claim_id=claim.claim_id,
            intrinsic_verdict="ERROR",
            reason=reason,
            aspects=aspects,
            methods_run=[spec.name],
            evidence=[evidence],
            verifier_version=__version__,
            env_digest=self.env_digest,
        )
        return MethodResult(spec, verdict)

    def _static(self, spec: MethodSpec, claim: Claim, analysis: GhidraAnalysis) -> MethodResult:
        request = StaticRequest(
            claim=claim, env_digest=self.env_digest, analysis_options_sha256=self.options_hash
        )
        job = Job.create(
            "verify_static",
            {
                "request": self._stage(canonical_bytes(request), ".json"),
                "analysis": self._stage(canonical_bytes(analysis), ".json"),
            },
            {"method": spec.name},
        )
        handle = self.runner.submit(job)
        result = self.runner.wait(handle)
        if result.status != "ok":
            return self._error(
                spec,
                claim,
                result.error_code or "internal",
                str(result.output.get("detail", "")),
                handle.result_artifact,
            )
        if spec.name in {"static.edges@1", "static.arity@2", "static.widths@1"}:
            verdict = Verdict.model_validate(result.output["verdict"])
            if verdict.claim_id != claim.claim_id or verdict.env_digest != self.env_digest:
                raise ValueError("static verdict identity mismatch")
            payloads = result.output.get("artifacts", {})
            if not isinstance(payloads, dict) or set(payloads) != {
                item.artifact for item in verdict.evidence
            }:
                raise ValueError("static evidence map mismatch")
            for digest, value in sorted(payloads.items()):
                if self.runner.artifacts.put(canonical_bytes(cast(JsonValue, value))) != digest:
                    raise ValueError("static evidence content/hash mismatch")
            return MethodResult(spec, verdict)
        matches = TypeAdapter(list[ConstantMatch]).validate_python(result.output["matches"])
        payload = cast(
            JsonValue,
            {
                "binary_sha256": claim.binary_sha256,
                "subject": claim.subject.address,
                "matches": [match.model_dump(mode="json") for match in matches],
            },
        )
        digest = self.runner.artifacts.put(canonical_bytes(payload))
        evidence = tuple(
            Evidence(
                kind="constant_match",
                artifact=digest,
                summary=f"{match.name} at {match.address} ({match.location})",
            )
            for match in matches
        )
        if not evidence:
            evidence = (
                Evidence(kind="constant_scan", artifact=digest, summary="No matching constants."),
            )
        return MethodResult(spec, None, evidence=evidence)

    def _probe(
        self,
        spec: MethodSpec,
        claim: Claim,
        binary: BinaryRef,
        analysis: GhidraAnalysis,
        pack: Pack | None,
    ) -> MethodResult:
        assert isinstance(claim.body, (Algorithm, FunctionPurpose))
        family = self.family_for(claim)
        scope = (
            self.purpose_mapping.map.get(claim.body.category)
            if isinstance(claim.body, FunctionPurpose)
            else None
        )
        try:
            verdict = self.probes.probe(
                binary,
                claim,
                analysis,
                self.pack_paths.get(family) if family else None,
                self.budgets,
                self.env_digest,
                self.purpose_mapping_path if isinstance(claim.body, FunctionPurpose) else None,
            )
        except RuntimeError:
            if self.probes.last_artifact is None:
                raise
            result = JobResult.model_validate_json(
                self.runner.artifacts.get(self.probes.last_artifact)
            )
            if result.status != "error":
                raise
            return self._error(
                spec,
                claim,
                result.error_code or "internal",
                str(result.output.get("detail", "")),
                self.probes.last_artifact,
            )
        artifact = next(item.artifact for item in verdict.evidence if item.kind == "probe_results")
        evidence = ProbeEvidence.model_validate_json(self.runner.artifacts.get(artifact))
        if (
            evidence.binary_sha256,
            evidence.subject,
            evidence.family,
            evidence.claimed_variant,
        ) != (
            claim.binary_sha256,
            claim.subject.address,
            family or "purpose",
            claim.body.variant if isinstance(claim.body, Algorithm) else None,
        ):
            raise ValueError("probe evidence identity mismatch")
        if evidence.category != (
            claim.body.category if isinstance(claim.body, FunctionPurpose) else None
        ):
            raise ValueError("probe category identity mismatch")
        proof = (
            probe_proof(claim, analysis, pack, evidence, verdict, scope)
            if (pack is not None and verdict.intrinsic_verdict == "CONTRADICTED")
            else None
        )
        counts: dict[str, JsonValue] = {}
        if pack is not None:
            values = generate_inputs(pack.inputs)
            for shape in pack.call_shapes:
                eligible = len(inputs_for_shape(values, shape.roles))
                counts[shape.id] = {
                    "generated": len(values),
                    "eligible_per_variant": eligible,
                    "skipped_embedded_nul": len(values) - eligible,
                    "executed_by_variant": {
                        variant: sum(
                            row.shape == shape.id and row.variant == variant
                            for row in evidence.observations
                        )
                        for variant in sorted(pack.variants)
                    },
                }
                if isinstance(claim.body, FunctionPurpose):
                    selected_variants = scope.variants if scope else []
                    eligible_by_variant = {
                        variant: len(inputs_for_call(values, pack.variants[variant], shape))
                        for variant in selected_variants
                        if variant in pack.variants
                        and (
                            pack.variants[variant].call_shapes is None
                            or shape.id in (pack.variants[variant].call_shapes or [])
                        )
                    }
                    counts[shape.id] = cast(
                        JsonValue,
                        {
                            "generated": len(values),
                            "eligible_by_variant": eligible_by_variant,
                            "skipped_by_variant": {
                                variant: len(values) - count
                                for variant, count in eligible_by_variant.items()
                            },
                            "executed_by_variant": {
                                variant: sum(
                                    row.shape == shape.id and row.variant == variant
                                    for row in evidence.observations
                                )
                                for variant in eligible_by_variant
                            },
                        },
                    )
        return MethodResult(spec, verdict, proof=proof, details={"input_counts": counts})

    def _composite_results(
        self,
        family: str,
        claims: list[Claim],
        binary: BinaryRef,
        analysis: GhidraAnalysis,
        no_cache: bool,
    ) -> dict[str, MethodResult]:
        try:
            return self._run_composite(family, claims, binary, analysis, no_cache)
        except Exception as exc:
            spec = MethodSpec(
                "composite.hash@1",
                "function_purpose",
                "category_behavior",
                "E2",
                True,
                True,
                "emulation",
            )
            details: dict[str, JsonValue] = {
                "family": family,
                "members": cast(
                    JsonValue, [member.model_dump(mode="json") for member in public_members(claims)]
                ),
            }
            return {
                claim.claim_id: replace(
                    self._error(
                        spec, claim, "internal", type(exc).__name__ + ": " + str(exc)[:240]
                    ),
                    details=details,
                )
                for claim in claims
            }

    def _run_composite(
        self,
        family: str,
        claims: list[Claim],
        binary: BinaryRef,
        analysis: GhidraAnalysis,
        no_cache: bool,
    ) -> dict[str, MethodResult]:
        members = public_members(claims)
        identity = cast(JsonValue, [member.model_dump(mode="json") for member in members])
        details: dict[str, JsonValue] = {"family": family, "members": identity}
        spec = MethodSpec(
            "composite.hash@1",
            "function_purpose",
            "category_behavior",
            "E2",
            True,
            True,
            "emulation",
        )
        pack = self.packs.get(family)
        cache_key = content_hash(
            {
                "kind": "composite_group",
                "taxonomy_version": Taxonomy.bundled().version,
                "purpose_packs_hash": self.purpose_mapping_hash,
                "family": family,
                "members": identity,
                "environment": self.env_digest,
                "analysis": content_hash(analysis),
                "pack": self.pack_hashes.get(family),
            }
        )
        first = None if no_cache else self.store.cached_verdict(cache_key, claims[0].claim_id)
        if first is None:
            if (
                sorted(member.role for member in members) != ["final", "init", "update"]
                or pack is None
            ):
                payload = cast(
                    JsonValue,
                    {"binary_sha256": binary.binary_sha256, "family": family, "members": identity},
                )
                artifact = self.runner.artifacts.put(canonical_bytes(payload))
                first = Verdict(
                    claim_id=claims[0].claim_id,
                    intrinsic_verdict="INCONCLUSIVE" if pack else "UNVERIFIABLE",
                    reason="composite_incomplete" if pack else "no_pack",
                    methods_run=[spec.name],
                    evidence=[
                        Evidence(
                            kind="composite_membership",
                            artifact=artifact,
                            summary="Incomplete or unsupported composite group.",
                        )
                    ],
                    verifier_version=__version__,
                    env_digest=self.env_digest,
                )
            else:
                request = CompositeRequest(
                    binary_sha256=binary.binary_sha256,
                    family=cast(Literal["md5", "sha1", "sha256"], family),
                    members=[
                        CompositeMember.model_validate(
                            {
                                "claim_id": claim.claim_id,
                                "subject": claim.subject.address,
                                "role": claim.body.category.rsplit(".", 1)[1],
                            }
                        )
                        for claim in claims
                        if isinstance(claim.body, FunctionPurpose)
                    ],
                    budgets=self.budgets,
                    env_digest=self.env_digest,
                )
                client = CompositeClient(self.runner)
                try:
                    result = client.verify(binary, analysis, self.pack_paths[family], request)
                except RuntimeError as exc:
                    error = (
                        JobResult.model_validate_json(
                            self.runner.artifacts.get(client.last_artifact)
                        )
                        if client.last_artifact
                        else None
                    )
                    return {
                        claim.claim_id: replace(
                            self._error(
                                spec,
                                claim,
                                error.error_code or "internal" if error else "internal",
                                str(exc),
                                client.last_artifact,
                            ),
                            details=details,
                        )
                        for claim in claims
                    }
                first = result.verdicts[0]
        proof = None
        if first.intrinsic_verdict == "CONTRADICTED":
            if pack is None:
                raise ValueError("composite contradiction has no pack")
            artifact = next(
                item.artifact for item in first.evidence if item.kind == "composite_results"
            )
            evidence = GroupEvidence.model_validate_json(self.runner.artifacts.get(artifact))
            proof = DynamicProof(*group_preconditions(evidence, members, analysis, pack, first))
        first = guarded_result(MethodResult(spec, first, proof=proof)).verdict
        assert first is not None
        if first.intrinsic_verdict != "ERROR":
            self.store.cache_verdict(cache_key, first)
        output: dict[str, MethodResult] = {}
        for claim in claims:
            value = first.model_copy(
                update={
                    "claim_id": claim.claim_id,
                    "aspects": {
                        "category_behavior": Aspect(
                            verdict=first.intrinsic_verdict,
                            strength=first.strength,
                            method=spec.name,
                        )
                    },
                }
            )
            output[claim.claim_id] = MethodResult(spec, value, proof=proof, details=details)
        return output

    def verify_claims(
        self,
        claims: list[Claim],
        binary: BinaryRef,
        analysis: GhidraAnalysis,
        *,
        no_cache: bool = False,
    ) -> list[EngineResult]:
        self.last_verification_edges = []
        if not claims:
            return []
        if len({claim.run_id for claim in claims}) != 1 or any(
            claim.binary_sha256 != binary.binary_sha256 for claim in claims
        ):
            raise ValueError("verification batch requires one run and binary")
        keys = [
            (
                claim.subject.address,
                claim.type,
                claim.body.callee if isinstance(claim.body, Call) else "",
            )
            for claim in claims
        ]
        if len(set(keys)) != len(keys):
            raise ValueError("verification batch contains duplicate active claims")
        if (
            analysis.binary_sha256 != binary.binary_sha256
            or analysis.options_sha256 != self.options_hash
        ):
            raise ValueError("verification batch analysis identity mismatch")
        read_public_binary(binary)
        signatures = {
            claim.subject.address: claim
            for claim in claims
            if isinstance(claim.body, FunctionSignature)
        }
        self.last_verification_edges = sorted(
            (signatures[claim.subject.address].claim_id, claim.claim_id)
            for claim in claims
            if not isinstance(claim.body, FunctionSignature) and claim.subject.address in signatures
        )
        results = [
            self.verify(claim, binary, analysis, no_cache=no_cache)
            for claim in sorted(signatures.values(), key=lambda item: item.claim_id)
        ]
        group_results: dict[str, MethodResult] = {}
        for family, group_claims in collect_groups(claims, self.purpose_mapping).items():
            grouped = self._composite_results(family, group_claims, binary, analysis, no_cache)
            group_results.update(grouped)
            for claim in claims:
                if isinstance(claim.body, Algorithm) and claim.body.family == family:
                    parents = [
                        parent
                        for parent in group_claims
                        if parent.subject.address == claim.subject.address
                    ]
                    if parents:
                        parent = parents[0]
                        source = grouped[parent.claim_id]
                        assert source.verdict is not None
                        value = source.verdict.model_copy(
                            update={
                                "claim_id": claim.claim_id,
                                "aspects": {
                                    "output_match": Aspect(
                                        verdict=source.verdict.intrinsic_verdict,
                                        strength=source.verdict.strength,
                                        method=source.spec.name,
                                    )
                                },
                            }
                        )
                        group_results[claim.claim_id] = replace(
                            source,
                            spec=replace(
                                source.spec, claim_type="algorithm_identity", aspect="output_match"
                            ),
                            verdict=value,
                        )
                        self.last_verification_edges.append((parent.claim_id, claim.claim_id))
        ordered = sorted(
            (claim for claim in claims if not isinstance(claim.body, FunctionSignature)),
            key=lambda claim: (
                isinstance(claim.body, Algorithm) and claim.claim_id in group_results,
                claim.claim_id,
            ),
        )
        results += [
            self.verify(
                claim, binary, analysis, no_cache=no_cache, _group=group_results.get(claim.claim_id)
            )
            for claim in ordered
        ]
        self.last_verification_edges = sorted(set(self.last_verification_edges))
        return results

    def verify(
        self,
        claim: Claim,
        binary: BinaryRef,
        analysis: GhidraAnalysis,
        *,
        no_cache: bool = False,
        _group: MethodResult | None = None,
    ) -> EngineResult:
        read_public_binary(binary)
        if (
            claim.binary_sha256 != binary.binary_sha256
            or analysis.binary_sha256 != binary.binary_sha256
        ):
            raise ValueError("engine public binary/analysis/claim identity mismatch")
        if analysis.options_sha256 != self.options_hash:
            raise ValueError("engine analysis/options identity mismatch")
        if _group is None and isinstance(claim.body, FunctionPurpose):
            scope = self.purpose_mapping.map.get(claim.body.category)
            if scope is not None and scope.composite:
                _group = self._composite_results(scope.pack, [claim], binary, analysis, no_cache)[
                    claim.claim_id
                ]
        context = self.cache_context(claim, analysis, _group)
        key = verdict_cache_key(claim, context)
        if not no_cache:
            cached = self.store.cached_verdict(key, claim.claim_id)
            if cached is not None:
                refs = [item.artifact for item in cached.evidence if item.kind == "method_results"]
                if len(refs) != 1:
                    raise ValueError("cached verdict lacks unique method audit")
                audit = json.loads(self.runner.artifacts.get(refs[0]))
                observations = TypeAdapter(dict[str, Aspect]).validate_python(audit["observations"])
                if set(observations) != set(cached.methods_run):
                    raise ValueError("cached method audit mismatch")
                return EngineResult(cached, observations, key, True)
        family = self.family_for(claim)
        pack = self.packs.get(family) if family else None
        results: list[MethodResult] = []
        for spec in sorted(
            self._methods(claim, pack, _group),
            key=lambda method: (method.cost_class != "static", method.name),
        ):
            try:
                result = (
                    _group
                    if _group is not None and spec.name == _group.spec.name
                    else (
                        self._static(spec, claim, analysis)
                        if spec.cost_class == "static"
                        else (self._probe(spec, claim, binary, analysis, pack))
                    )
                )
            except Exception as exc:
                result = self._error(
                    spec, claim, "internal", type(exc).__name__ + ": " + str(exc)[:240]
                )
            results.append(guarded_result(result))
            if self.mode == "runtime":
                partial = merge_results(claim, results, self.env_digest)
                if all(
                    name in partial.aspects
                    and partial.aspects[name].verdict in {"VERIFIED", "CONTRADICTED"}
                    for name in REQUIRED_ASPECTS[claim.type]
                ):
                    break
        verdict = merge_results(claim, results, self.env_digest)
        observations: dict[str, Aspect] = {}
        records: list[dict[str, JsonValue]] = []
        for result in sorted(results, key=lambda result: result.spec.name):
            value = result.verdict
            if value is None or value.intrinsic_verdict not in ("INVALID_CLAIM", "NOT_CHECKED"):
                # Supporting facts get a non-decision observation, never a claim verdict.
                observations[result.spec.name] = Aspect(
                    verdict=value.intrinsic_verdict if value else "INCONCLUSIVE",
                    strength=value.strength if value else None,
                    method=result.spec.name,
                )
            records.append(
                {
                    "method": result.spec.name,
                    "supporting_only": result.spec.aspect is None,
                    "result": cast(JsonValue, value.model_dump(mode="json", exclude={"claim_id"}))
                    if value
                    else None,
                    "details": cast(JsonValue, result.details),
                }
            )
        decisive = [
            result
            for result in results
            if result.spec.aspect is not None and result.verdict is not None
        ]
        disagreement = any(
            result.verdict is not None
            and result.verdict.intrinsic_verdict == "VERIFIED"
            and result.spec.decisive_verified
            for result in decisive
        ) and any(
            result.verdict is not None
            and result.verdict.intrinsic_verdict == "CONTRADICTED"
            and result.spec.decisive_contradicted
            for result in decisive
        )
        audit = cast(
            JsonValue,
            {
                "schema_version": "1.0",
                "methods": records,
                "observations": {
                    name: value.model_dump(mode="json")
                    for name, value in sorted(observations.items())
                },
                "defects": [{"kind": "method_disagreement"}] if disagreement else [],
            },
        )
        digest = self.runner.artifacts.put(canonical_bytes(audit))
        evidence = sorted(
            [
                *verdict.evidence,
                Evidence(
                    kind="method_results",
                    artifact=digest,
                    summary=f"{len(observations)} methods; {int(disagreement)} disagreements",
                ),
            ],
            key=lambda item: (item.kind, item.artifact, item.summary),
        )
        verdict = verdict.model_copy(update={"evidence": evidence})
        # Wall/resource failures are not deterministic semantic cache entries.
        if all(
            result.verdict is None or result.verdict.intrinsic_verdict != "ERROR"
            for result in results
        ):
            self.store.cache_verdict(key, verdict)
        return EngineResult(verdict, observations, key, False)

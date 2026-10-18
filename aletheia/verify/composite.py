"""Public-input, deterministic init/update/final digest and cipher verification."""

import hashlib
import random
from dataclasses import dataclass
from pathlib import Path
from typing import Literal, Self, cast

from pydantic import Field, JsonValue, model_validator

from aletheia import __version__
from aletheia.analysis.ghidra_session import GhidraAnalysis
from aletheia.config import Budgets
from aletheia.schema.canonical import content_hash
from aletheia.schema.models import (
    Address,
    Budget,
    ClaimId,
    Counterexample,
    Digest,
    Evidence,
    Outcome,
    Record,
    Sha256,
    Strict,
    Verdict,
)
from aletheia.verify.emulate.core import Buffer, Emulator, InitializationBudgetExhausted
from aletheia.verify.probes.inputs import generate_inputs
from aletheia.verify.probes.minimize import minimize_counterexample
from aletheia.verify.probes.oracles import byte_pair, evaluate
from aletheia.verify.probes.pack import Pack
from aletheia.verify.static.arity import infer_arity


class CompositeMember(Strict):
    claim_id: ClaimId
    subject: Address
    role: Literal["init", "update", "final", "crypt"]


class CompositeRequest(Record):
    binary_sha256: Sha256
    family: Literal["md5", "sha1", "sha256", "rc4"]
    members: list[CompositeMember] = Field(min_length=1, max_length=2000)
    budgets: Budgets
    env_digest: Digest

    @model_validator(mode="after")
    def unique_claims(self) -> Self:
        if len({member.claim_id for member in self.members}) != len(self.members):
            raise ValueError("duplicate composite claim ID")
        return self


@dataclass(frozen=True)
class CompositeOutcome:
    verdicts: list[Verdict]
    artifacts: dict[str, JsonValue]


def chunks(data: bytes, count: int, seed: int) -> list[bytes]:
    rng = random.Random(seed ^ int.from_bytes(hashlib.sha256(data).digest()[:8], "big"))
    positions = [
        0,
        *sorted(rng.sample(range(1, len(data)), min(count - 1, max(0, len(data) - 1)))),
        len(data),
    ]
    return [data[start:end] for start, end in zip(positions, positions[1:], strict=False)]


def verify_composite(
    request: CompositeRequest,
    analysis: GhidraAnalysis,
    binary: Path,
    pack: Pack | None,
) -> CompositeOutcome:
    if binary.stem != request.binary_sha256 or analysis.binary_sha256 != request.binary_sha256:
        raise ValueError("composite public input identity mismatch")
    if request.family == "rc4":
        return _verify_cipher(request, analysis, binary, pack)
    observations: list[dict[str, JsonValue]] = []
    minimized: list[dict[str, JsonValue]] = []
    instructions = 0
    planned = 0
    skipped: list[dict[str, JsonValue]] = []
    binding = {member.role: infer_arity(member.subject, analysis) for member in request.members}

    def finish(outcome: Outcome, reason: str | None = None, ce: Counterexample | None = None):
        payload = cast(
            JsonValue,
            {
                "schema_version": "1.0",
                "binary_sha256": request.binary_sha256,
                "family": request.family,
                "members": [
                    {"subject": member.subject, "role": member.role}
                    for member in sorted(
                        request.members, key=lambda item: (item.role, item.subject)
                    )
                ],
                "arity": {
                    role: value.model_dump(mode="json") for role, value in sorted(binding.items())
                },
                "observations": observations,
                "planned_inputs_per_shape": planned,
                "skipped_inputs": skipped,
                "minimization": minimized,
            },
        )
        digest = "sha256:" + content_hash(payload)
        decisive = outcome in {"VERIFIED", "CONTRADICTED"}
        return CompositeOutcome(
            [
                Verdict(
                    claim_id=member.claim_id,
                    intrinsic_verdict=outcome,
                    strength="E2" if decisive else None,
                    reason=reason,
                    methods_run=["composite.hash@1"],
                    harness=(
                        "Fresh init/update/final sequences; 1024-byte context; "
                        "both final argument orders; "
                        "fixed, boundary and 16 seeded random messages; output digest compared."
                    )
                    if decisive
                    else None,
                    counterexample=ce,
                    evidence=[
                        Evidence(
                            kind="composite_results",
                            artifact=digest,
                            summary=f"{len(observations)} composite sequences; {request.family}",
                        )
                    ],
                    budget_used=Budget(instructions=instructions),
                    verifier_version=__version__,
                    env_digest=request.env_digest,
                )
                for member in request.members
            ],
            {digest: payload},
        )

    if sorted(member.role for member in request.members) != ["final", "init", "update"]:
        return finish("INCONCLUSIVE", "composite_incomplete")
    if pack is None or pack.family != request.family or "std" not in pack.variants:
        return finish("UNVERIFIABLE", "no_pack")
    if any(
        not any(fn.entry == member.subject for fn in analysis.functions)
        for member in request.members
    ):
        return finish("ERROR", "subject_not_found")
    entries = {member.role: int(member.subject, 16) for member in request.members}
    seed = pack.inputs.random.seed
    inputs = pack.inputs.model_copy(
        update={"random": pack.inputs.random.model_copy(update={"count": 16})}
    )
    messages = generate_inputs(inputs)
    rng = random.Random(seed)
    plans = [(data, rng.randint(1, 4)) for data in messages]
    planned = len(plans)
    try:
        emu = Emulator(binary, request.budgets)
    except InitializationBudgetExhausted as exc:
        instructions = exc.instructions
        return finish("INCONCLUSIVE", "budget_exhausted")

    def trial(machine: Emulator, data: bytes, count: int, order: str):
        ctx = Buffer(b"", 1024)
        out = Buffer(b"", {"md5": 16, "sha1": 20, "sha256": 32}[request.family])
        pieces = chunks(data, count, seed)
        steps: list[tuple[int, list[int | Buffer], int]] = [(entries["init"], [ctx], 64)]
        steps += [(entries["update"], [ctx, Buffer(piece), len(piece)], 64) for piece in pieces]
        final_args: list[int | Buffer] = [ctx, out] if order == "ctx_out" else [out, ctx]
        steps.append((entries["final"], final_args, 64))
        results = machine.call_sequence(steps)
        expected = evaluate(request.family + "_std", data).output
        assert expected is not None
        fault = next((result.fault for result in results if result.fault), None)
        uninitialized = any(result.uninitialized_state_reads for result in results)
        actual = b""
        if len(results) == len(steps) and not fault:
            actual = results[-1].out_buffers[1 if order == "ctx_out" else 0]
        status = (
            "state_dependent"
            if uninitialized
            else (fault or ("match" if actual == expected else "mismatch"))
        )
        return cast(
            dict[str, JsonValue],
            {
                "final_shape": order,
                "input_hex": data.hex(),
                "chunks": [piece.hex() for piece in pieces],
                "expected_hex": expected.hex(),
                "actual_hex": actual.hex(),
                "status": status,
                "instructions": sum(result.instructions for result in results),
                "imports_called": sorted(
                    {name for result in results for name in result.imports_called}
                ),
            },
        )

    for order in ["ctx_out", "out_ctx"]:
        for ordinal, (data, count) in enumerate(plans):
            row = trial(emu, data, count, order)
            observations.append(row)
            if row["status"] not in {"match", "mismatch"}:
                skipped.append(
                    {
                        "final_shape": order,
                        "count": len(plans) - ordinal - 1,
                        "reason": row["status"],
                    }
                )
                break
    instructions = emu.total_instructions
    for order in ["ctx_out", "out_ctx"]:
        rows = [row for row in observations if row["final_shape"] == order]
        if len(rows) == len(plans) and all(row["status"] == "match" for row in rows):
            return finish("VERIFIED")
    for reason in [
        "state_dependent",
        "fortify_fail",
        "unsupported_relocation",
        "unsupported_import",
        "emulation_fault",
        "budget_exhausted",
    ]:
        for row in observations:
            status = str(row["status"])
            if status == reason or status.startswith(reason + ":"):
                return finish("INCONCLUSIVE", status)
    if not all(
        binding[role].decisive and binding[role].arity == arity
        for role, arity in [("init", 1), ("update", 3), ("final", 2)]
    ):
        return finish("INCONCLUSIVE", "binding_not_verified")
    failures = [
        (data, count)
        for data, count in plans
        if all(
            any(
                row["input_hex"] == data.hex()
                and row["final_shape"] == order
                and row["status"] == "mismatch"
                for row in observations
            )
            for order in ["ctx_out", "out_ctx"]
        )
    ]
    if not failures:
        return finish("INCONCLUSIVE", "emulation_fault")
    selected, count = min(failures, key=lambda pair: (len(pair[0]), pair[0].hex(), pair[1]))
    exhausted = False
    failure_reason: str | None = None

    def reproduce(data: bytes, chunk_count: int):
        nonlocal instructions, exhausted, failure_reason
        remaining = request.budgets.instructions_per_claim - instructions
        if remaining <= 0:
            exhausted = True
            return False
        try:
            fresh = Emulator(
                binary, request.budgets.model_copy(update={"instructions_per_claim": remaining})
            )
        except InitializationBudgetExhausted as exc:
            instructions += exc.instructions
            exhausted = True
            return False
        rows = [trial(fresh, data, chunk_count, order) for order in ["ctx_out", "out_ctx"]]
        instructions += fresh.total_instructions
        minimized.extend(rows)
        failure_reason = next(
            (str(row["status"]) for row in rows if row["status"] not in {"match", "mismatch"}), None
        )
        exhausted = exhausted or any(row["status"] == "budget_exhausted" for row in rows)
        return all(row["status"] == "mismatch" for row in rows)

    try:
        message = minimize_counterexample([selected], lambda data: reproduce(data, count))
    except ValueError:
        return finish(
            "INCONCLUSIVE",
            "budget_exhausted" if exhausted else (failure_reason or "emulation_fault"),
        )
    for candidate in range(1, count + 1):
        if reproduce(message, candidate):
            count = candidate
            break
    if exhausted:
        return finish("INCONCLUSIVE", "budget_exhausted")
    if not reproduce(message, count):
        return finish("INCONCLUSIVE", failure_reason or "emulation_fault")
    ce = Counterexample(
        call_shape="composite_ctx_out+out_ctx",
        input_hex=message.hex(),
        expected_hex=str(minimized[-2]["expected_hex"]) + str(minimized[-1]["expected_hex"]),
        actual_hex=str(minimized[-2]["actual_hex"]) + str(minimized[-1]["actual_hex"]),
        variant="std",
    )
    return finish("CONTRADICTED", ce=ce)


CIPHER_ASSIGNMENTS = ("roles_a", "roles_b")
CIPHER_ARITIES = {"init": 3, "crypt": 3}


def _verify_cipher(
    request: CompositeRequest,
    analysis: GhidraAnalysis,
    binary: Path,
    pack: Pack | None,
) -> CompositeOutcome:
    """In-place stream cipher composite: keyed init then chunked buffer mutation.

    Member roles are canonical ordering labels; both assignments are tried and a
    single consistent assignment must match every input for VERIFIED.
    """
    observations: list[dict[str, JsonValue]] = []
    minimized: list[dict[str, JsonValue]] = []
    instructions = 0
    planned = 0
    skipped: list[dict[str, JsonValue]] = []
    binding = {member.role: infer_arity(member.subject, analysis) for member in request.members}

    def finish(outcome: Outcome, reason: str | None = None, ce: Counterexample | None = None):
        payload = cast(
            JsonValue,
            {
                "schema_version": "1.0",
                "binary_sha256": request.binary_sha256,
                "family": request.family,
                "members": [
                    {"subject": member.subject, "role": member.role}
                    for member in sorted(
                        request.members, key=lambda item: (item.role, item.subject)
                    )
                ],
                "arity": {
                    role: value.model_dump(mode="json") for role, value in sorted(binding.items())
                },
                "observations": observations,
                "planned_inputs_per_shape": planned,
                "skipped_inputs": skipped,
                "minimization": minimized,
            },
        )
        digest = "sha256:" + content_hash(payload)
        decisive = outcome in {"VERIFIED", "CONTRADICTED"}
        return CompositeOutcome(
            [
                Verdict(
                    claim_id=member.claim_id,
                    intrinsic_verdict=outcome,
                    strength="E2" if decisive else None,
                    reason=reason,
                    methods_run=["composite.cipher@1"],
                    harness=(
                        "Fresh init/crypt sequences; 1024-byte context; both member role "
                        "assignments; fixed and 16 seeded random keyed inputs; buffer compared."
                    )
                    if decisive
                    else None,
                    counterexample=ce,
                    evidence=[
                        Evidence(
                            kind="composite_results",
                            artifact=digest,
                            summary=f"{len(observations)} composite sequences; {request.family}",
                        )
                    ],
                    budget_used=Budget(instructions=instructions),
                    verifier_version=__version__,
                    env_digest=request.env_digest,
                )
                for member in request.members
            ],
            {digest: payload},
        )

    if sorted(member.role for member in request.members) != ["crypt", "init"]:
        return finish("INCONCLUSIVE", "composite_incomplete")
    if pack is None or pack.family != request.family or "std" not in pack.variants:
        return finish("UNVERIFIABLE", "no_pack")
    if any(
        not any(fn.entry == member.subject for fn in analysis.functions)
        for member in request.members
    ):
        return finish("ERROR", "subject_not_found")
    entries = {member.role: int(member.subject, 16) for member in request.members}
    assignments = [
        ("roles_a", entries["init"], entries["crypt"]),
        ("roles_b", entries["crypt"], entries["init"]),
    ]
    seed = pack.inputs.random.seed
    inputs = pack.inputs.model_copy(
        update={"random": pack.inputs.random.model_copy(update={"count": 16})}
    )
    pairs = [byte_pair(value) for value in generate_inputs(inputs)]
    rng = random.Random(seed)
    plans = [(payload, key, rng.randint(1, 4)) for payload, key in pairs]
    planned = len(plans)
    try:
        emu = Emulator(binary, request.budgets)
    except InitializationBudgetExhausted as exc:
        instructions = exc.instructions
        return finish("INCONCLUSIVE", "budget_exhausted")

    def trial(
        machine: Emulator,
        payload: bytes,
        key: bytes,
        count: int,
        assignment: tuple[str, int, int],
    ):
        label, init_entry, crypt_entry = assignment
        ctx = Buffer(b"", 1024)
        key_buffer = Buffer(key)
        pieces = chunks(payload, count, seed)
        steps: list[tuple[int, list[int | Buffer], int]] = [
            (init_entry, [ctx, key_buffer, len(key)], 64)
        ]
        steps += [
            (crypt_entry, [ctx, Buffer(piece), len(piece)], 64) for piece in pieces
        ]
        results = machine.call_sequence(steps)
        expected = evaluate(
            "rc4_std", len(payload).to_bytes(2, "little") + payload + key
        ).output
        assert expected is not None
        fault = next((result.fault for result in results if result.fault), None)
        uninitialized = any(result.uninitialized_state_reads for result in results)
        actual = b""
        if len(results) == len(steps) and not fault:
            actual = b"".join(
                results[index].out_buffers[1] for index in range(1, len(results))
            )
        status = (
            "state_dependent"
            if uninitialized
            else (fault or ("match" if actual == expected else "mismatch"))
        )
        return cast(
            dict[str, JsonValue],
            {
                "final_shape": label,
                "input_hex": payload.hex(),
                "key_hex": key.hex(),
                "chunks": [piece.hex() for piece in pieces],
                "expected_hex": expected.hex(),
                "actual_hex": actual.hex(),
                "status": status,
                "instructions": sum(result.instructions for result in results),
                "imports_called": sorted(
                    {name for result in results for name in result.imports_called}
                ),
            },
        )

    for assignment in assignments:
        label = assignment[0]
        for ordinal, (payload, key, count) in enumerate(plans):
            row = trial(emu, payload, key, count, assignment)
            observations.append(row)
            if row["status"] not in {"match", "mismatch"}:
                skipped.append(
                    {
                        "final_shape": label,
                        "count": len(plans) - ordinal - 1,
                        "reason": row["status"],
                    }
                )
                break
    instructions = emu.total_instructions
    for assignment in assignments:
        label = assignment[0]
        rows = [row for row in observations if row["final_shape"] == label]
        if len(rows) == len(plans) and all(row["status"] == "match" for row in rows):
            return finish("VERIFIED")
    for reason in [
        "state_dependent",
        "fortify_fail",
        "unsupported_relocation",
        "unsupported_import",
        "emulation_fault",
        "budget_exhausted",
    ]:
        for row in observations:
            status = str(row["status"])
            if status == reason or status.startswith(reason + ":"):
                return finish("INCONCLUSIVE", status)
    if not all(
        binding[role].decisive and binding[role].arity == arity
        for role, arity in CIPHER_ARITIES.items()
    ):
        return finish("INCONCLUSIVE", "binding_not_verified")
    failures = [
        (payload, key, count)
        for payload, key, count in plans
        if all(
            any(
                row["input_hex"] == payload.hex()
                and row["key_hex"] == key.hex()
                and row["final_shape"] == label
                and row["status"] == "mismatch"
                for row in observations
            )
            for label in CIPHER_ASSIGNMENTS
        )
    ]
    if not failures:
        return finish("INCONCLUSIVE", "emulation_fault")
    selected, selected_key, count = min(
        failures, key=lambda item: (len(item[0]), item[0].hex(), item[1].hex(), item[2])
    )
    exhausted = False
    failure_reason: str | None = None

    def reproduce(payload: bytes, chunk_count: int):
        nonlocal instructions, exhausted, failure_reason
        remaining = request.budgets.instructions_per_claim - instructions
        if remaining <= 0:
            exhausted = True
            return False
        try:
            fresh = Emulator(
                binary, request.budgets.model_copy(update={"instructions_per_claim": remaining})
            )
        except InitializationBudgetExhausted as exc:
            instructions += exc.instructions
            exhausted = True
            return False
        rows = [
            trial(fresh, payload, selected_key, chunk_count, assignment)
            for assignment in assignments
        ]
        instructions += fresh.total_instructions
        minimized.extend(rows)
        failure_reason = next(
            (str(row["status"]) for row in rows if row["status"] not in {"match", "mismatch"}),
            None,
        )
        exhausted = exhausted or any(row["status"] == "budget_exhausted" for row in rows)
        return all(row["status"] == "mismatch" for row in rows)

    try:
        message = minimize_counterexample([selected], lambda data: reproduce(data, count))
    except ValueError:
        return finish(
            "INCONCLUSIVE",
            "budget_exhausted" if exhausted else (failure_reason or "emulation_fault"),
        )
    for candidate in range(1, count + 1):
        if reproduce(message, candidate):
            count = candidate
            break
    if exhausted:
        return finish("INCONCLUSIVE", "budget_exhausted")
    if not reproduce(message, count):
        return finish("INCONCLUSIVE", failure_reason or "emulation_fault")
    ce = Counterexample(
        call_shape="composite_rc4",
        input_hex=message.hex(),
        expected_hex=str(minimized[-2]["expected_hex"]) + str(minimized[-1]["expected_hex"]),
        actual_hex=str(minimized[-2]["actual_hex"]) + str(minimized[-1]["actual_hex"]),
        variant="std",
    )
    return finish("CONTRADICTED", ce=ce)

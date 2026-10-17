"""Signature aspects from independent public Ghidra register observations."""

from dataclasses import dataclass
from typing import Literal, cast

from pydantic import JsonValue

from aletheia import __version__
from aletheia.analysis.ghidra_session import GhidraAnalysis
from aletheia.schema.canonical import content_hash
from aletheia.schema.models import (
    Aspect,
    AspectName,
    Claim,
    Digest,
    Evidence,
    FunctionSignature,
    Outcome,
    Verdict,
)
from aletheia.schema.signature_facts import ARGUMENT_REGISTERS, ParameterRegister, ReturnFact
from aletheia.schema.types import CanonicalType, canonical_type
from aletheia.verify.static.arity import infer_arity

Decision = Literal["VERIFIED", "CONTRADICTED", "INCONCLUSIVE"]


@dataclass(frozen=True)
class SignatureOutcome:
    verdict: Verdict
    artifacts: dict[str, JsonValue]


def decide_return(
    wanted: CanonicalType, paths: list[ReturnFact], callers: list[ReturnFact]
) -> Decision:
    if not paths or not callers or wanted.kind == "unknown":
        return "INCONCLUSIVE"
    if wanted.kind == "void":
        written = all(
            any(value.kind in {"int_or_ptr", "float"} for value in [path.integer, path.floating])
            for path in paths
        )
        determinable = [
            caller
            for caller in callers
            if "unknown" not in {caller.integer.kind, caller.floating.kind}
        ]
        if (
            written
            and determinable
            and all(
                any(
                    value.kind in {"int_or_ptr", "float"}
                    for value in [caller.integer, caller.floating]
                )
                for caller in determinable
            )
        ):
            return "CONTRADICTED"
        return "INCONCLUSIVE"
    callee = [path.floating if wanted.kind == "float" else path.integer for path in paths]
    reads = [caller.floating if wanted.kind == "float" else caller.integer for caller in callers]
    if all(value.kind == "none" for value in [*callee, *reads]):
        return "CONTRADICTED"
    kind = "float" if wanted.kind == "float" else "int_or_ptr"
    if (
        all(value.kind == kind and value.width == wanted.width for value in callee)
        and any(value.kind == kind for value in reads)
        and all(
            value.kind == "none" or (value.kind == kind and value.width == wanted.width)
            for value in reads
        )
    ):
        return "VERIFIED"
    return "INCONCLUSIVE"


def _finish(
    claim: Claim,
    analysis: GhidraAnalysis,
    env_digest: Digest,
    method: str,
    outcome: Outcome,
    reason: str | None,
    aspects: dict[AspectName, Aspect],
    facts: JsonValue,
    pointers: list[str] | None = None,
) -> SignatureOutcome:
    digest = "sha256:" + content_hash(facts)
    evidence = [
        Evidence(
            kind="signature_facts", artifact=digest, summary=f"{method} on {claim.subject.address}"
        )
    ]
    evidence += [
        Evidence(
            kind="pointer_use",
            artifact=digest,
            summary=f"{register} used as a memory base before a write",
        )
        for register in pointers or []
    ]
    decisive = outcome in {"VERIFIED", "CONTRADICTED"}
    verdict = Verdict(
        claim_id=claim.claim_id,
        intrinsic_verdict=outcome,
        strength="E1" if decisive else None,
        reason=None if decisive else reason,
        aspects=aspects,
        methods_run=[method],
        evidence=evidence,
        harness=(
            f"Ghidra {analysis.ghidra_version}, options {analysis.options_sha256}; "
            "callee and direct-caller register observations."
        )
        if decisive
        else None,
        verifier_version=__version__,
        env_digest=env_digest,
    )
    return SignatureOutcome(verdict, {digest: facts})


def verify_arity(claim: Claim, analysis: GhidraAnalysis, env_digest: Digest) -> SignatureOutcome:
    if (
        not isinstance(claim.body, FunctionSignature)
        or claim.binary_sha256 != analysis.binary_sha256
    ):
        raise ValueError("signature arity requires matching public claim and analysis")
    binding = infer_arity(claim.subject.address, analysis)
    outcome: Outcome = (
        ("VERIFIED" if binding.arity == len(claim.body.params) else "CONTRADICTED")
        if binding.decisive
        else "INCONCLUSIVE"
    )
    facts = cast(
        JsonValue,
        {
            "binary_sha256": claim.binary_sha256,
            "subject": claim.subject.address,
            "arity": binding.model_dump(mode="json"),
        },
    )
    return _finish(
        claim,
        analysis,
        env_digest,
        "static.arity@2",
        outcome,
        "arity_not_decisive",
        {
            "arity": Aspect(
                verdict=outcome,
                strength="E1" if binding.decisive else None,
                method="static.arity@2",
            )
        },
        facts,
    )


def verify_widths(claim: Claim, analysis: GhidraAnalysis, env_digest: Digest) -> SignatureOutcome:
    if (
        not isinstance(claim.body, FunctionSignature)
        or claim.binary_sha256 != analysis.binary_sha256
    ):
        raise ValueError("signature widths require matching public claim and analysis")
    function = next((fn for fn in analysis.functions if fn.entry == claim.subject.address), None)
    sites = [
        site
        for fn in analysis.functions
        for site in fn.call_sites
        if site.kind == "direct" and site.target == claim.subject.address
    ]
    calls = [site.signature_use for site in sites if site.signature_use is not None]
    facts = function.signature_facts if function else None
    outcome: Outcome = "ERROR" if function is None else "INCONCLUSIVE"
    params: Decision = "INCONCLUSIVE"
    pointers: list[str] = []
    address_ambiguous = False
    parameter_registers: list[ParameterRegister | None] = []
    integer_index = floating_index = 0
    unknown = False
    for param in claim.body.params:
        kind = canonical_type(param.type).kind
        register: ParameterRegister | None = None
        if kind in {"int", "ptr"} and not unknown and integer_index < 6:
            register = ARGUMENT_REGISTERS[integer_index]
            integer_index += 1
        elif kind == "float" and not unknown and floating_index < 8:
            register = cast(ParameterRegister, "xmm" + str(floating_index))
            floating_index += 1
        else:
            unknown = True
        parameter_registers.append(register)
    if facts is not None and facts.exclusion_reason is None:
        wanted = canonical_type(claim.body.return_type, return_type=True)
        if len(calls) == len(sites):
            outcome = decide_return(
                wanted, facts.return_paths, [call.return_read for call in calls]
            )
        for register, param in zip(parameter_registers, claim.body.params, strict=True):
            kind = canonical_type(param.type)
            if register is not None and register in facts.pointer_params:
                pointers.append(register)
                # A 64-bit integer may legitimately carry an address (uintptr_t).
                if kind.kind == "int" and kind.width == 64:
                    address_ambiguous = True
                elif kind.kind in {"int", "float"} or (kind.width is not None and kind.width < 64):
                    params = "CONTRADICTED"
        if (
            params != "CONTRADICTED"
            and not address_ambiguous
            and len(claim.body.params) <= 14
            and calls
            and len(calls) == len(sites)
        ):
            if all(
                register is not None
                and canonical_type(param.type).width is not None
                and facts.param_reads.get(register) == canonical_type(param.type).width
                and all(
                    call.argument_writes.get(register) == canonical_type(param.type).width
                    for call in calls
                )
                for register, param in zip(parameter_registers, claim.body.params, strict=True)
            ):
                params = "VERIFIED"
    payload = cast(
        JsonValue,
        {
            "binary_sha256": claim.binary_sha256,
            "subject": claim.subject.address,
            "callee": facts.model_dump(mode="json") if facts else None,
            "callers": [
                {
                    "address": site.address,
                    "use": site.signature_use.model_dump(mode="json")
                    if site.signature_use
                    else None,
                }
                for site in sites
            ],
        },
    )
    decisions: list[tuple[AspectName, Outcome]] = [
        ("return_width", outcome),
        ("param_widths", params),
        ("param_types", "INCONCLUSIVE"),
    ]
    aspects: dict[AspectName, Aspect] = {
        key: Aspect(
            verdict=value,
            strength="E1" if value in {"VERIFIED", "CONTRADICTED"} else None,
            method="static.widths@1",
        )
        for key, value in decisions
    }
    return _finish(
        claim,
        analysis,
        env_digest,
        "static.widths@1",
        outcome,
        "subject_not_found" if function is None else "width_ambiguous",
        aspects,
        payload,
        pointers,
    )

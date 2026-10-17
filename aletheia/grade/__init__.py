"""Deterministic benchmark grading; never imported by the verifier."""

import math
from collections.abc import Mapping

from aletheia import __version__
from aletheia.schema.models import (
    AbiType,
    Algorithm,
    AspectName,
    Call,
    Claim,
    FunctionPurpose,
    FunctionSignature,
    Grade,
    GroundFunctionV2,
    GroundTruth,
    Targets,
    Verdict,
)
from aletheia.schema.types import CanonicalType, canonical_type


def claimed_correctness(claim: Claim, item: Grade) -> bool | None:
    if item.correct_claimed is not None:
        return item.correct_claimed
    return (
        item.correct_lenient
        if isinstance(claim.body, Algorithm) and claim.body.variant is None
        else item.correct_strict
    )


def _same_type(left: CanonicalType, right: CanonicalType) -> bool:
    return left.kind != "unknown" and right.kind != "unknown" and left == right


def _abi_type(value: AbiType) -> CanonicalType:
    return (
        CanonicalType("unknown", None)
        if value.kind == "other"
        else CanonicalType(value.kind, value.width)
    )


def grade(
    claims: list[Claim],
    verdicts: list[Verdict],
    gt: GroundTruth,
    targets: Targets,
    *,
    taxonomy_kappa: Mapping[str, float | None] | None = None,
) -> list[Grade]:
    """Null scores are counted exclusions; they never become incorrect labels."""
    if (gt.binary_sha256, gt.variant_id) != (targets.binary_sha256, targets.variant_id):
        raise ValueError("ground truth/targets identity mismatch")
    if any(claim.binary_sha256 != gt.binary_sha256 for claim in claims):
        raise ValueError("claim/ground truth binary identity mismatch")
    if gt.schema_version != "2.0" and any(
        isinstance(c.body, (FunctionPurpose, FunctionSignature)) for c in claims
    ):
        raise ValueError("new claim types require ground truth 2.0")
    if any(isinstance(c.body, FunctionPurpose) for c in claims) and taxonomy_kappa is None:
        raise ValueError("purpose grading requires explicit annotation agreement")
    if taxonomy_kappa is not None and any(
        v is not None and (type(v) not in (int, float) or not math.isfinite(v) or not -1 <= v <= 1)
        for v in taxonomy_kappa.values()
    ):
        raise ValueError("invalid annotation agreement kappa")
    functions = {function.address: function for function in gt.functions}
    if len(functions) != len(gt.functions):
        raise ValueError("duplicate ground-truth function address")
    claim_ids = {claim.claim_id for claim in claims}
    outcomes = {verdict.claim_id: verdict.intrinsic_verdict for verdict in verdicts}
    if len(claim_ids) != len(claims) or len(outcomes) != len(verdicts):
        raise ValueError("duplicate claim or verdict identity")
    if outcomes.keys() - claim_ids:
        raise ValueError("verdict identity has no input claim")
    purposes = {
        (claim.run_id, claim.subject.address)
        for claim in claims
        if isinstance(claim.body, FunctionPurpose)
    }
    on_targets = set(targets.targets)
    grades: list[Grade] = []
    for claim in sorted(claims, key=lambda claim: claim.claim_id):
        function = functions.get(claim.subject.address)
        family_correct = variant_correct = edge_correct = None
        strict: bool | None = False
        lenient: bool | None = False
        partial: float | None = None
        role_correct = None
        suppressed = False
        strict_exclusion = lenient_exclusion = None
        aspects: dict[AspectName, bool | None] = {}
        if isinstance(claim.body, Algorithm):
            family_correct = bool(
                function is not None
                and function.algorithm.family != "none"
                and claim.body.family == function.algorithm.family
            )
            if claim.body.variant is not None:
                variant_correct = bool(
                    family_correct
                    and function is not None
                    and claim.body.variant == function.algorithm.variant
                )
            strict = family_correct and variant_correct is True
            lenient = family_correct
            suppressed = (claim.run_id, claim.subject.address) in purposes
            if suppressed:
                strict = lenient = variant_correct
                if claim.body.variant is None:
                    strict_exclusion = lenient_exclusion = "family_credit_suppressed"
            claimed_correct = lenient if claim.body.variant is None else strict
            aspects["output_match"] = claimed_correct
        elif isinstance(claim.body, Call):
            edges = function.callees if function is not None else []
            edge_correct = any(
                edge.target == claim.body.callee and edge.kind == claim.body.kind for edge in edges
            )
            strict = edge_correct
            lenient = any(edge.target == claim.body.callee for edge in edges)
            claimed_correct = strict
            aspects["edge_exists"] = strict
        elif isinstance(claim.body, FunctionSignature):
            if isinstance(function, GroundFunctionV2):
                abi = function.abi_signature
                wanted = canonical_type(claim.body.return_type, return_type=True)
                params = [canonical_type(param.type) for param in claim.body.params]
                if abi is None or abi.abi_complex:
                    strict = None
                    strict_exclusion = "abi_unavailable" if abi is None else "abi_complex"
                    aspects.update(
                        {
                            name: None
                            for name in ("arity", "return_width", "param_widths", "param_types")
                        }
                    )
                else:
                    arity = len(params) == len(abi.params)
                    returned = _abi_type(abi.return_type)
                    strict = (
                        arity
                        and _same_type(wanted, returned)
                        and all(
                            _same_type(a, _abi_type(b))
                            for a, b in zip(params, abi.params, strict=True)
                        )
                    )

                    def bank(value: CanonicalType):
                        return "int_or_ptr" if value.kind in {"int", "ptr"} else value.kind

                    aspects.update(
                        {
                            "arity": arity,
                            "return_width": wanted.kind != "unknown"
                            and bank(wanted) == bank(returned)
                            and wanted.width == returned.width,
                            "param_widths": arity
                            and all(
                                a.width is not None and a.width == b.width
                                for a, b in zip(params, abi.params, strict=True)
                            ),
                            "param_types": arity
                            and all(
                                _same_type(a, _abi_type(b))
                                for a, b in zip(params, abi.params, strict=True)
                            ),
                        }
                    )
                source = function.source_types
                if source is None:
                    lenient = None
                    lenient_exclusion = "source_signature_unavailable"
                else:
                    lenient = len(params) == len(source.params) and (
                        not params
                        or sum(
                            _same_type(a, canonical_type(b))
                            for a, b in zip(params, source.params, strict=True)
                        )
                        / len(params)
                        >= 0.75
                    )
            claimed_correct = strict
        else:
            assert isinstance(claim.body, FunctionPurpose)
            if isinstance(function, GroundFunctionV2):
                if function.category is None:
                    strict = lenient = None
                    strict_exclusion = lenient_exclusion = "category_unavailable"
                else:
                    kappa = (
                        taxonomy_kappa.get(function.category.split(".")[0])
                        if taxonomy_kappa is not None
                        else None
                    )
                    strict = (
                        claim.body.category in function.acceptable_categories
                        if kappa is not None and kappa >= 0.7
                        else None
                    )
                    if strict is None:
                        strict_exclusion = (
                            "taxonomy_kappa_unavailable"
                            if kappa is None
                            else "taxonomy_kappa_below_threshold"
                        )
                    wanted = claim.body.category.split(".")
                    actual = [category.split(".") for category in function.acceptable_categories]
                    lenient = any(wanted[:-1] == parts[:-1] for parts in actual)
                    depths: list[float] = []
                    for parts in actual:
                        depth = 0
                        for a, b in zip(wanted, parts, strict=False):
                            if a != b:
                                break
                            depth += 1
                        depths.append(depth / len(parts))
                    partial = max(depths, default=0.0)
                    roles = [
                        category.rsplit(".", 1)[1]
                        for category in function.acceptable_categories
                        if category.startswith(("parse.format.", "protocol."))
                    ]
                    if roles:
                        role_correct = (
                            claim.body.category.startswith(("parse.format.", "protocol."))
                            and wanted[-1] in roles
                        )
            claimed_correct = strict
            aspects["category_behavior"] = strict
        outcome = outcomes.get(claim.claim_id)
        verdict_correct = (
            None
            if claimed_correct is None
            else claimed_correct
            if outcome == "VERIFIED"
            else not claimed_correct
            if outcome == "CONTRADICTED"
            else None
        )
        grades.append(
            Grade(
                claim_id=claim.claim_id,
                grader_version=__version__,
                on_target=claim.subject.address in on_targets,
                phantom=function is None,
                family_correct=family_correct,
                variant_correct=variant_correct,
                edge_correct=edge_correct,
                correct_strict=strict,
                correct_lenient=lenient,
                verdict_correct=verdict_correct,
                correct_claimed=claimed_correct if gt.schema_version == "2.0" else None,
                correct_partial=partial,
                role_correct=role_correct,
                family_credit_suppressed=suppressed,
                strict_exclusion_reason=strict_exclusion,
                lenient_exclusion_reason=lenient_exclusion,
                aspect_correct=aspects if gt.schema_version == "2.0" else {},
            )
        )
    return grades

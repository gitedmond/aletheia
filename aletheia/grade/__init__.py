"""Deterministic benchmark grading; never imported by the verifier."""

from aletheia import __version__
from aletheia.schema.models import Algorithm, Claim, Grade, GroundTruth, Targets, Verdict


def grade(
    claims: list[Claim], verdicts: list[Verdict], gt: GroundTruth, targets: Targets
) -> list[Grade]:
    """Grade at the submitted granularity, sorted by claim ID; missing verdicts stay null."""
    if (gt.binary_sha256, gt.variant_id) != (targets.binary_sha256, targets.variant_id):
        raise ValueError("ground truth/targets identity mismatch")
    if any(claim.binary_sha256 != gt.binary_sha256 for claim in claims):
        raise ValueError("claim/ground truth binary identity mismatch")
    functions = {function.address: function for function in gt.functions}
    if len(functions) != len(gt.functions):
        raise ValueError("duplicate ground-truth function address")
    claim_ids = {claim.claim_id for claim in claims}
    outcomes = {verdict.claim_id: verdict.intrinsic_verdict for verdict in verdicts}
    if len(claim_ids) != len(claims) or len(outcomes) != len(verdicts):
        raise ValueError("duplicate claim or verdict identity")
    if outcomes.keys() - claim_ids:
        raise ValueError("verdict identity has no input claim")
    on_targets = set(targets.targets)
    grades: list[Grade] = []
    for claim in sorted(claims, key=lambda claim: claim.claim_id):
        function = functions.get(claim.subject.address)
        family_correct = variant_correct = edge_correct = None
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
            claimed_correct = lenient if claim.body.variant is None else strict
        else:
            edges = function.callees if function is not None else []
            edge_correct = any(
                edge.target == claim.body.callee and edge.kind == claim.body.kind for edge in edges
            )
            strict = edge_correct
            lenient = any(edge.target == claim.body.callee for edge in edges)
            claimed_correct = strict
        outcome = outcomes.get(claim.claim_id)
        verdict_correct = (
            claimed_correct
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
            )
        )
    return grades

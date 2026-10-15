"""Deterministic E1 edge decisions using clean Ghidra facts only."""

from aletheia import __version__
from aletheia.analysis.ghidra_session import GhidraAnalysis
from aletheia.schema.models import Aspect, Call, Claim, Digest, Outcome, Verdict


def verify_edges(claim: Claim, analysis: GhidraAnalysis, env_digest: Digest) -> Verdict:
    """Keep unresolved indirect claims non-decisive and require complete bodies for absence."""
    if claim.binary_sha256 != analysis.binary_sha256:
        raise ValueError("static edge binary identity mismatch")
    if not isinstance(claim.body, Call):
        raise ValueError("static edges requires a call-relation claim")
    function = next((fn for fn in analysis.functions if fn.entry == claim.subject.address), None)
    outcome: Outcome = "INCONCLUSIVE"
    reason = "indirect_unresolved"
    if function is None:
        outcome, reason = "ERROR", "subject_not_found"
    elif claim.body.kind != "indirect":
        if any(
            site.kind == claim.body.kind and site.target == claim.body.callee
            for site in function.call_sites
        ):
            outcome = "VERIFIED"
        elif function.body_complete:
            outcome = "CONTRADICTED"
    decisive = outcome in ("VERIFIED", "CONTRADICTED")
    strength = "E1" if decisive else None
    finding = (
        f"{claim.body.kind} edge to {claim.body.callee} found"
        if outcome == "VERIFIED"
        else f"complete disassembly has no {claim.body.kind} edge to {claim.body.callee}"
    )
    return Verdict(
        claim_id=claim.claim_id,
        intrinsic_verdict=outcome,
        strength=strength,
        reason=None if decisive else reason,
        aspects={
            "edge_exists": Aspect(verdict=outcome, strength=strength, method="static.edges@1")
        },
        methods_run=["static.edges@1"],
        harness=(
            f"Static analysis (Ghidra {analysis.ghidra_version}, options "
            f"{analysis.options_sha256}): {finding}."
        )
        if decisive
        else None,
        verifier_version=__version__,
        env_digest=env_digest,
    )

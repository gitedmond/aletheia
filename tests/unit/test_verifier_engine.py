"""Every intrinsic precedence row and the supporting-only constants boundary."""

import pytest

from aletheia.schema.models import Aspect, Claim, ClaimSubmission, Evidence, Verdict
from aletheia.verify.engine import MethodResult, MethodSpec, merge_results

ENV = "sha256:" + "e" * 64


def claim(algorithm=False):
    return Claim.intake(
        ClaimSubmission.model_validate(
            {
                "run_id": "r_" + "2" * 16,
                "source": {"origin": "human", "source_id": "human:merge-table"},
                "binary_sha256": "a" * 64,
                "subject": {"address": "0x00001000"},
                "type": "algorithm_identity" if algorithm else "call_relation",
                "body": {"family": "fnv", "variant": "fnv1a-64"}
                if algorithm
                else {"callee": "0x00002000", "kind": "direct"},
                "confidence": 1.0,
                "confidence_source": "stated",
            }
        )
    )


def result(outcome, index=0, algorithm=False, reason=None):
    item = claim(algorithm)
    method = MethodSpec(
        "probe.fnv@1" if algorithm else f"static.test{index}@1",
        item.type,
        "output_match" if algorithm else "edge_exists",
        "E2" if algorithm else "E1",
        True,
        True,
        "emulation" if algorithm else "static",
    )
    reasons = {
        "INVALID_CLAIM": "unknown_family",
        "INCONCLUSIVE": "binding_not_verified",
        "ERROR": "wall_timeout",
        "NOT_CHECKED": "budget_exhausted",
        "UNVERIFIABLE": "no_pack",
    }
    decisive = outcome in ("VERIFIED", "CONTRADICTED")
    verdict = Verdict(
        claim_id=item.claim_id,
        intrinsic_verdict=outcome,
        strength=method.strength if decisive else None,
        aspects={
            method.aspect: Aspect(
                verdict=outcome, strength=method.strength if decisive else None, method=method.name
            )
        },
        methods_run=[method.name],
        reason=reason or reasons.get(outcome),
        harness="Controlled static edge evidence." if decisive else None,
        verifier_version="0.1.0",
        env_digest=ENV,
    )
    return MethodResult(method, verdict)


@pytest.mark.parametrize(
    "outcomes,expected",
    [
        (["INVALID_CLAIM", "CONTRADICTED", "VERIFIED"], "INVALID_CLAIM"),
        (["CONTRADICTED", "VERIFIED"], "CONTRADICTED"),
        (["VERIFIED", "ERROR"], "VERIFIED"),
        (["INCONCLUSIVE", "ERROR"], "INCONCLUSIVE"),
        (["ERROR", "UNVERIFIABLE"], "ERROR"),
        (["NOT_CHECKED", "UNVERIFIABLE"], "NOT_CHECKED"),
        (["UNVERIFIABLE"], "UNVERIFIABLE"),
    ],
)
def test_intrinsic_precedence(outcomes, expected):
    actual = merge_results(
        claim(), [result(value, index) for index, value in enumerate(outcomes)], ENV
    )
    assert actual.intrinsic_verdict == expected
    assert actual.claim_id == claim().claim_id
    assert actual.methods_run == sorted(set(actual.methods_run))
    if expected in ("VERIFIED", "CONTRADICTED"):
        assert actual.strength == "E1" and actual.harness


def test_constants_never_promote_no_pack_or_hide_wall_timeout():
    supporting = MethodResult(
        MethodSpec("static.constants@1", "algorithm_identity", None, "E1", False, False, "static"),
        None,
        evidence=(
            Evidence(
                kind="constant_match",
                artifact="sha256:" + "d" * 64,
                summary="A known constant was observed.",
            ),
        ),
    )
    for outcome in ("UNVERIFIABLE", "ERROR"):
        actual = merge_results(claim(True), [supporting, result(outcome, algorithm=True)], ENV)
        assert actual.intrinsic_verdict == outcome
        assert actual.reason == ("no_pack" if outcome == "UNVERIFIABLE" else "wall_timeout")
        assert len(actual.evidence) == 1 and actual.strength is None
    assert merge_results(claim(True), [supporting], ENV).intrinsic_verdict == "UNVERIFIABLE"


def test_dynamic_contradiction_without_production_proof_is_inconclusive():
    actual = merge_results(claim(True), [result("CONTRADICTED", algorithm=True)], ENV)
    assert (actual.intrinsic_verdict, actual.reason) == ("INCONCLUSIVE", "binding_not_verified")
    assert actual.counterexample is None


def test_no_method_applies_is_unverifiable():
    actual = merge_results(claim(), [], ENV)
    assert (actual.intrinsic_verdict, actual.reason) == ("UNVERIFIABLE", "no_pack")
    assert not actual.methods_run

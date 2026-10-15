"""T21 math review: four hand-computed observations in two program clusters."""

import pytest

from aletheia.config import Metrics
from aletheia.grade import grade
from aletheia.metrics import compute_metrics
from aletheia.schema.canonical import canonical_bytes
from aletheia.schema.models import Aspect, Claim, ClaimSubmission, GroundTruth, Targets, Verdict


def dataset(origin="scripted", source_id="scripted:v1", shared=False):
    truths = [
        GroundTruth.model_validate(
            {
                "binary_sha256": digit * 64,
                "program_id": "tierA/" + name,
                "variant_id": "clang23-O2-x64-pie-hardoff",
                "build_flags": "test",
                "functions": [
                    {
                        "address": "0x00001000",
                        "size": 32,
                        "name": "checksum",
                        "scorable": True,
                        "algorithm": {"family": "crc32", "variant": "ieee"},
                    },
                    {
                        "address": "0x00002000",
                        "size": 32,
                        "name": "other",
                        "scorable": True,
                        "algorithm": {"family": family, "variant": variant},
                    },
                ],
            }
        )
        for digit, name, family, variant in [
            ("a", "first", "adler32", "zlib"),
            ("b", "second", "none", None),
        ]
    ]
    specifications = [
        (0, "0x00001000", "crc32", "ieee", 0.9, "VERIFIED", "scripted_correct"),
        (0, "0x00001000", "crc32", "jamcrc", 0.9, "CONTRADICTED", "scripted_mutated"),
        (1, "0x00001000", "crc32", None, 0.9, "VERIFIED", "scripted_correct"),
        (1, "0x00002000", "fnv", None, 0.5, "INCONCLUSIVE", "scripted_mutated"),
    ]
    claims, verdicts, grades, methods = [], [], [], {}
    for index, (program, address, family, variant, confidence, outcome, tag) in enumerate(
        specifications
    ):
        claim = Claim.intake(
            ClaimSubmission.model_validate(
                {
                    "run_id": "r_" + str(index + 1) * 16,
                    "source": {"origin": origin, "source_id": source_id, "shares_backend": shared},
                    "binary_sha256": truths[program].binary_sha256,
                    "subject": {"address": address},
                    "type": "algorithm_identity",
                    "body": {"family": family, "variant": variant},
                    "confidence": confidence,
                    "confidence_source": "scripted" if origin == "scripted" else "tool_default",
                    "derived_from": tag if origin == "scripted" else "constant_xref",
                }
            )
        )
        method = "probe." + family + "@1"
        decisive = outcome in ("VERIFIED", "CONTRADICTED")
        observation = Aspect(verdict=outcome, strength="E2" if decisive else None, method=method)
        observations = [observation]
        if index == 0:
            observations.append(Aspect(verdict="INCONCLUSIVE", method="static.constants@1"))
        verdict = Verdict(
            claim_id=claim.claim_id,
            intrinsic_verdict=outcome,
            strength="E2" if decisive else None,
            harness="fixed math case" if decisive else None,
            reason=None if decisive else "binding_not_verified",
            methods_run=sorted(item.method for item in observations),
            aspects={"output_match": observation},
            verifier_version="0.1.0",
            env_digest="sha256:" + "c" * 64,
        )
        targets = Targets(
            binary_sha256=truths[program].binary_sha256,
            variant_id=truths[program].variant_id,
            targets=["0x00001000", "0x00002000"],
        )
        claims.append(claim)
        verdicts.append(verdict)
        grades.extend(grade([claim], [verdict], truths[program], targets))
        methods[claim.claim_id] = observations
    return claims, verdicts, grades, truths, methods


def report(data):
    claims, verdicts, grades, truths, methods = data
    return compute_metrics(
        grades,
        claims,
        verdicts,
        Metrics(bootstrap_resamples=200, bootstrap_seed=41),
        ground_truths=truths,
        method_results=methods,
    )


def test_hand_computed_metrics_family_granularity_and_cluster_intervals():
    result = report(dataset())
    summary = result.independent.summary
    expected = {
        "strict_accuracy": 0.25,
        "lenient_accuracy": 0.75,
        "granularity": 0.5,
        "algorithm_coverage_strict": 1 / 3,
        "algorithm_coverage_lenient": 2 / 3,
        "false_label_rate": 0.25,
        "brier": 0.47,
        "decisiveness": 0.75,
        "catch_rate": 0.5,
        "false_alarm_rate": 0,
        "verification_precision": 1,
        "cwr_strict@0.8": 2 / 3,
        "cwr_strict@0.9": 2 / 3,
        "cwr_lenient@0.8": 0,
        "cwr_lenient@0.9": 0,
    }
    assert summary.metrics == pytest.approx(expected)
    assert summary.counts["scorable_algorithm_functions"] == 3
    assert summary.confusion["VERIFIED"] == {"correct": 2, "wrong": 0}
    assert summary.confusion["CONTRADICTED"] == {"correct": 0, "wrong": 1}
    interval = result.independent.intervals["strict_accuracy"]
    assert (interval.low, interval.high, interval.defined_resamples) == (0, 0.5, 200)
    coverage = result.independent.intervals["algorithm_coverage_lenient"]
    assert (coverage.low, coverage.high) == (0.5, 1)
    brier = result.independent.intervals["brier"]
    assert (brier.low, brier.high) == pytest.approx((0.41, 0.53))
    assert result.independent_by_scenario["family_only"].summary.metrics["false_alarm_rate"] == 0
    assert result.independent_methods["static.constants@1"].summary.metrics["decisiveness"] == 0


def test_sources_stay_separate_from_controlled_reliability_and_order_is_irrelevant():
    scripted = dataset()
    capa = dataset("tool", "tool:capa@9.4.0+rules@9.4.0")
    findcrypt = dataset("tool", "tool:findcrypt@3.1.10", True)
    combined = tuple(
        scripted[i] + capa[i] + findcrypt[i]
        if i < 3
        else scripted[i]
        if i == 3
        else scripted[i] | capa[i] | findcrypt[i]
        for i in range(5)
    )
    result = report(combined)
    assert result.independent.summary.counts["claims"] == 4
    assert len(result.sources) == 3
    assert [source.source.source_id for source in result.included_sources] == ["scripted:v1"]
    assert len(result.excluded_sources) == 2
    assert (
        next(source for source in result.sources if source.source.shares_backend).label
        == "shared Ghidra backend"
    )
    reversed_data = tuple(list(reversed(combined[i])) if i < 4 else combined[i] for i in range(5))
    assert canonical_bytes(result) == canonical_bytes(report(reversed_data))


def test_undefined_denominators_error_exclusions_and_incomplete_observations():
    data = dataset()
    claims, verdicts, grades, truths, methods = data
    empty = compute_metrics(
        [],
        [],
        [],
        Metrics(bootstrap_resamples=10, bootstrap_seed=1),
        ground_truths=truths,
        method_results={},
    )
    assert empty.independent.summary.metrics["strict_accuracy"] is None
    assert empty.independent.summary.metrics["algorithm_coverage_strict"] == 0
    assert empty.independent.intervals["strict_accuracy"].defined_resamples == 0
    verdicts[-1] = verdicts[-1].model_copy(
        update={"intrinsic_verdict": "ERROR", "reason": "internal"}
    )
    methods[claims[-1].claim_id] = [Aspect(verdict="ERROR", method="probe.fnv@1")]
    changed = report(data)
    assert changed.independent.summary.exclusions == {"ERROR": 1}
    assert changed.independent.summary.metrics["catch_rate"] == 1
    with pytest.raises(ValueError, match="method"):
        compute_metrics(
            grades,
            claims,
            verdicts,
            Metrics(bootstrap_resamples=10),
            ground_truths=truths,
            method_results={},
        )

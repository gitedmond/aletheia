"""Hand-computed PAV, smoothed likelihood, fixed-ratio and dependency examples."""

import pytest

from aletheia.confidence import (
    CalibrationFit,
    LikelihoodFit,
    Sample,
    adjust,
    adjust_graph,
    effective_ratio,
    fit_calibration,
    fit_likelihoods,
)
from aletheia.schema.canonical import canonical_bytes
from aletheia.schema.models import Source


def row(index, confidence=0.5, correct=True, outcome="VERIFIED", origin="agent", **updates):
    data = {
        "claim_id": "c_" + f"{index:024x}",
        "run_id": "r_" + "1" * 16,
        "program": "p1",
        "split": "dev",
        "source": Source(origin=origin, source_id=origin + ":example"),
        "claim_type": "algorithm_identity",
        "confidence": confidence,
        "correct_claimed": correct,
        "on_target": True,
        "verdict": outcome,
        "strength": "E2" if outcome in {"VERIFIED", "CONTRADICTED"} else None,
        "method": "probe.example@1",
    }
    return Sample.model_validate(data | updates)


def test_pav_pools_violations_and_duplicate_confidences_with_a_step_map():
    records = [
        row(i, confidence=c, correct=(i % 10 < k))
        for i, (c, k) in enumerate([(0.2, 9)] * 10 + [(0.5, 1)] * 10 + [(0.8, 8)] * 10)
    ]
    fit = fit_calibration(records)
    assert not fit.unfitted
    mapping = fit.maps[0]
    assert [(b.low, b.high, b.count, b.correct, b.value) for b in mapping.blocks] == [
        (0.2, 0.5, 20, 10, 0.5),
        (0.8, 0.8, 10, 8, 0.8),
    ]
    assert [mapping.predict(c) for c in [0.0, 0.2, 0.6, 0.8, 1.0]] == [0.5, 0.5, 0.5, 0.8, 0.8]
    assert fit == fit_calibration(list(reversed(records)))
    assert fit == CalibrationFit.model_validate_json(canonical_bytes(fit))
    excluded = fit_calibration(
        [
            records[0].model_copy(update={"on_target": False}),
            records[1].model_copy(update={"correct_claimed": None}),
            *records[2:],
        ]
    )
    assert not excluded.maps and excluded.unfitted[0].eligible == 28
    small = fit_calibration(records[:29])
    assert not small.maps and small.unfitted[0].eligible == 29
    with pytest.raises(ValueError, match="dev runs only"):
        fit_calibration([records[0].model_copy(update={"split": "heldout"})])


def test_beta_smoothing_and_scripted_pool_threshold():
    # Non-scripted: n_correct=4, n_wrong=2; VERIFIED counts 3 correct, 1 wrong.
    records = [
        row(i, correct=i < 4, outcome="VERIFIED" if i in [0, 1, 2, 4] else "INCONCLUSIVE")
        for i in range(6)
    ]
    records += [row(i, correct=False, outcome="CONTRADICTED", origin="scripted") for i in [6, 7]]
    table = fit_likelihoods(records)
    value = next(v for v in table.rows if v.key.verdict == "VERIFIED")
    assert (value.n_correct, value.n_wrong, value.k_correct, value.k_wrong) == (4, 4, 3, 1)
    assert value.p_correct == pytest.approx(2 / 3) and value.p_wrong == pytest.approx(1 / 3)
    assert value.likelihood_ratio == pytest.approx(2.0) and value.pooled_scripted
    independent = records[:6] + [
        row(i, correct=False, outcome="CONTRADICTED") for i in range(8, 26)
    ]
    table = fit_likelihoods(independent + records[6:])
    assert all(v.n_wrong == 20 and not v.pooled_scripted for v in table.rows)
    assert table == LikelihoodFit.model_validate_json(canonical_bytes(table))
    with pytest.raises(ValueError, match="dev runs only"):
        fit_likelihoods([row(100, split="heldout")])


@pytest.mark.parametrize(
    "outcome,raw,expected",
    [
        ("ERROR", 5.0, 1.0),
        ("NOT_CHECKED", 0.1, 1.0),
        ("UNVERIFIABLE", 5.0, 1.0),
        ("INVALID_CLAIM", 5.0, 1.0),
        ("INCONCLUSIVE", 5.0, 1.0),
        ("INCONCLUSIVE", 0.2, 0.2),
        ("VERIFIED", 5.0, 5.0),
    ],
)
def test_fixed_ratio_rules(outcome, raw, expected):
    assert effective_ratio(outcome, raw) == expected


def test_adjustment_clamps_unseen_status_and_reasoning_caps():
    maps = CalibrationFit(maps=[], unfitted=[])
    # The hand-counted table above gives VERIFIED LR=2.
    table = fit_likelihoods(
        [
            row(i, correct=i < 4, outcome="VERIFIED" if i in [0, 1, 2, 4] else "INCONCLUSIVE")
            for i in range(6)
        ]
        + [row(i, correct=False, outcome="CONTRADICTED", origin="scripted") for i in [6, 7]]
    )
    assert adjust(row(30), maps, table).adjusted == pytest.approx(2 / 3)
    assert adjust(row(31, strength="E1"), maps, table, [0.3]).adjusted == 0.3
    assert adjust(row(32), maps, table, [0.3]).adjusted == pytest.approx(2 / 3)
    empty = LikelihoodFit(run_ids=[], rows=[])
    assert adjust(row(33, confidence=0.0), maps, empty).adjusted == 0.02
    value = adjust(row(34, confidence=1.0), maps, empty)
    assert (
        value.adjusted == 0.98
        and value.calibration == "uncalibrated"
        and value.likelihood == "neutral_unseen"
    )
    parent = row(35, confidence=0.2, strength="E1")
    child = row(36, confidence=0.9, strength="E1", depends_on=[parent.claim_id])
    output = adjust_graph([child, parent], maps, empty)
    assert output[child.claim_id].adjusted == pytest.approx(0.2)
    with pytest.raises(ValueError, match="missing"):
        adjust_graph([child], maps, empty)
    with pytest.raises(ValueError, match="cyclic"):
        adjust_graph(
            [child, parent.model_copy(update={"depends_on": [child.claim_id]})], maps, empty
        )


def test_three_arms_false_alarms_and_paired_program_bootstrap():
    from aletheia.confidence.headline import Scored, headline

    dev = [
        row(i, correct=i < 8, outcome="VERIFIED" if i < 8 else "CONTRADICTED") for i in range(16)
    ]
    maps, table = fit_calibration(dev), fit_likelihoods(dev)
    heldout = [
        row(
            100,
            confidence=0.9,
            correct=False,
            outcome="CONTRADICTED",
            split="heldout",
            program="p1",
        ),
        row(101, confidence=0.85, correct=True, split="heldout", program="p2"),
        row(
            102,
            confidence=0.4,
            correct=False,
            outcome="CONTRADICTED",
            split="heldout",
            program="p3",
        ),
    ]
    scored = [Scored(sample=record, confidence=adjust(record, maps, table)) for record in heldout]
    result = headline(scored, ["p1", "p2", "p3"], bootstrap_resamples=50)
    assert result.metrics == {
        "arm1_cwr": 0.5,
        "arm2_cwr": 0.5,
        "arm3_cwr": 0.0,
        "relative_reduction": 1.0,
        "false_alarm_all": 0.0,
        "false_alarm_decisive": 0.0,
    }
    assert result == headline(list(reversed(scored)), ["p3", "p2", "p1"], bootstrap_resamples=50)
    assert result.counts["uncalibrated"] == 3
    empty = headline([], ["p1"], bootstrap_resamples=10)
    assert all(value is None for value in empty.metrics.values())
    with pytest.raises(ValueError, match="held-out"):
        headline([Scored(sample=dev[0], confidence=adjust(dev[0], maps, table))], ["p1"])


def test_fractional_fits_survive_canonical_storage_without_rounding_decisions():
    records = [row(i, confidence=0.123456789, correct=i < 10) for i in range(30)]
    fit = fit_calibration(records)
    restored = CalibrationFit.model_validate_json(canonical_bytes(fit))
    assert restored.maps[0].predict(0.123456789) == 1 / 3
    assert restored.maps[0].blocks[0].low == 0.123457
    table = fit_likelihoods(records + [row(30, correct=False, outcome="INCONCLUSIVE")])
    restored_table = LikelihoodFit.model_validate_json(canonical_bytes(table))
    assert [r.likelihood_ratio for r in restored_table.rows] == [
        r.likelihood_ratio for r in table.rows
    ]


def test_saved_confidence_preserves_threshold_and_dependency_decisions():
    from aletheia.confidence import Adjustment
    from aletheia.confidence.headline import Scored, headline

    record = row(500, confidence=0.8, correct=False, split="heldout")
    value = Adjustment(
        raw=0.8,
        prior=0.79999999,
        adjusted=0.79999999,
        calibration="calibrated",
        likelihood="fixed",
        likelihood_ratio=1.0,
        dependency_cap=0.79999999,
    )
    scored = Scored(sample=record, confidence=value)
    restored = Scored.model_validate_json(canonical_bytes(scored))
    assert restored == scored
    assert headline([restored], ["p1"], bootstrap_resamples=2).counts["adjusted_confident"] == 0

"""Held-out three-arm CWR and paired program-cluster percentile intervals."""

import random
from collections import Counter
from typing import Self

from pydantic import model_validator

from aletheia.confidence import Adjustment, ClaimType, Sample
from aletheia.metrics import Interval, percentile
from aletheia.schema.models import Record, Strict


class Scored(Strict):
    sample: Sample
    confidence: Adjustment

    @model_validator(mode="after")
    def same_raw(self) -> Self:
        if self.sample.confidence != self.confidence.raw:
            raise ValueError("headline confidence identity mismatch")
        return self


class Headline(Record):
    source_id: str | None
    claim_type: ClaimType | None
    metrics: dict[str, float | None]
    intervals: dict[str, Interval]
    counts: dict[str, int]
    program_clusters: list[str]
    bootstrap_seed: int
    bootstrap_resamples: int
    notes: list[str]


def _summary(
    rows: list[Scored], weights: Counter[str]
) -> tuple[dict[str, float | None], dict[str, int]]:
    def count(selected: list[Scored]) -> int:
        return sum(weights[row.sample.program] for row in selected)

    def ratio(numerator: int, denominator: int) -> float | None:
        return numerator / denominator if denominator else None

    graded = [row for row in rows if row.sample.correct_claimed is not None]
    arms: list[float | None] = []
    counts = {
        "claims": count(rows),
        "graded": count(graded),
        "ungraded": count(rows) - count(graded),
        "on_target": count([row for row in rows if row.sample.on_target]),
        "uncalibrated": count(
            [row for row in graded if row.confidence.calibration == "uncalibrated"]
        ),
    }
    for name in ["raw", "prior", "adjusted"]:
        confident = [row for row in graded if getattr(row.confidence, name) >= 0.8]
        wrong = [row for row in confident if row.sample.correct_claimed is False]
        arms.append(ratio(count(wrong), count(confident)))
        counts[name + "_confident"] = count(confident)
    correct = [row for row in graded if row.sample.correct_claimed is True]
    decisive = [row for row in correct if row.sample.verdict in {"VERIFIED", "CONTRADICTED"}]
    contradicted = [row for row in correct if row.sample.verdict == "CONTRADICTED"]
    return {
        "arm1_cwr": arms[0],
        "arm2_cwr": arms[1],
        "arm3_cwr": arms[2],
        "relative_reduction": (arms[1] - arms[2]) / arms[1]
        if arms[1] not in (None, 0) and arms[2] is not None
        else None,
        "false_alarm_all": ratio(count(contradicted), count(correct)),
        "false_alarm_decisive": ratio(count(contradicted), count(decisive)),
    }, counts


def headline(
    rows: list[Scored],
    programs: list[str],
    *,
    bootstrap_resamples: int = 1000,
    bootstrap_seed: int = 20261013,
) -> Headline:
    if any(row.sample.split != "heldout" for row in rows):
        raise ValueError("headline requires held-out observations")
    if len({row.sample.claim_id for row in rows}) != len(rows):
        raise ValueError("duplicate headline claim identity")
    identities: set[tuple[str, ClaimType]] = {
        (row.sample.source.source_id, row.sample.claim_type) for row in rows
    }
    if len(identities) > 1:
        raise ValueError("headline must be grouped by source and claim type")
    if (
        not programs
        or len(programs) != len(set(programs))
        or any(row.sample.program not in programs for row in rows)
    ):
        raise ValueError("headline requires the complete program-cluster population")
    if bootstrap_resamples < 1:
        raise ValueError("positive bootstrap resample count required")
    programs = sorted(programs)
    metrics, counts = _summary(rows, Counter({program: 1 for program in programs}))
    samples: dict[str, list[float]] = {key: [] for key in metrics}
    rng = random.Random(bootstrap_seed)
    for _ in range(bootstrap_resamples):
        values, _ = _summary(rows, Counter(rng.choices(programs, k=len(programs))))
        for key, value in values.items():
            if value is not None:
                samples[key].append(value)
    intervals = {
        key: Interval(
            low=percentile(sorted(values), 0.025) if values else None,
            high=percentile(sorted(values), 0.975) if values else None,
            defined_resamples=len(values),
        )
        for key, values in samples.items()
    }
    identity = next(iter(identities)) if identities else (None, None)
    return Headline(
        source_id=identity[0],
        claim_type=identity[1],
        metrics=metrics,
        intervals=intervals,
        counts=counts,
        program_clusters=programs,
        bootstrap_seed=bootstrap_seed,
        bootstrap_resamples=bootstrap_resamples,
        notes=[
            f"Paired bootstrap over {len(programs)} program clusters; intervals may be wide.",
            "Undefined arms or zero Arm 2 leave relative reduction undefined.",
        ],
    )

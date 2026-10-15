"""Deterministic metrics and paired program-cluster percentile intervals."""

import math
import random
from collections import Counter
from dataclasses import dataclass

from pydantic import Field

from aletheia.config import Metrics
from aletheia.schema.models import (
    Algorithm,
    Aspect,
    Claim,
    Grade,
    GroundTruth,
    Outcome,
    Record,
    Source,
    Strict,
    Verdict,
)


class Summary(Strict):
    metrics: dict[str, float | None]
    counts: dict[str, int]
    confusion: dict[str, dict[str, int]]
    exclusions: dict[str, int]


class Interval(Strict):
    low: float | None
    high: float | None
    defined_resamples: int


class Population(Strict):
    summary: Summary
    intervals: dict[str, Interval]


class SourceLabel(Strict):
    source: Source
    label: str


class SourceReport(SourceLabel):
    aggregate: Population
    programs: dict[str, Population]
    methods: dict[str, Population]
    unmapped_counts: dict[str, int]


class MetricsReport(Record):
    sources: list[SourceReport]
    independent: Population
    independent_by_scenario: dict[str, Population]
    independent_by_type: dict[str, Population]
    independent_methods: dict[str, Population]
    included_sources: list[SourceLabel]
    excluded_sources: list[SourceLabel]
    program_clusters: list[str]
    bootstrap_seed: int
    bootstrap_resamples: int
    notes: list[str] = Field(default_factory=list)


@dataclass(frozen=True)
class Observation:
    claim: Claim
    grade: Grade
    program: str
    outcome: Outcome
    false_label: bool

    @property
    def correct(self) -> bool:
        body = self.claim.body
        return (
            self.grade.correct_lenient
            if isinstance(body, Algorithm) and body.variant is None
            else self.grade.correct_strict
        )


def _summary(
    rows: list[Observation],
    coverage: dict[str, set[tuple[str, str]]],
    weights: Counter[str],
    thresholds: list[float],
) -> Summary:
    def count(selected: list[Observation]) -> int:
        return sum(weights[row.program] for row in selected)

    def ratio(numerator: int | float, denominator: int) -> float | None:
        return numerator / denominator if denominator else None

    total = count(rows)
    targets = [row for row in rows if row.grade.on_target]
    reliable = [row for row in rows if row.outcome != "ERROR"]
    correct = [row for row in reliable if row.correct]
    wrong = [row for row in reliable if not row.correct]
    verified = [row for row in reliable if row.outcome == "VERIFIED"]
    denominator = sum(len(functions) * weights[program] for program, functions in coverage.items())
    metrics = {
        "strict_accuracy": ratio(
            count([row for row in targets if row.grade.correct_strict]), count(targets)
        ),
        "lenient_accuracy": ratio(
            count([row for row in targets if row.grade.correct_lenient]), count(targets)
        ),
        "granularity": ratio(
            count(
                [
                    row
                    for row in rows
                    if isinstance(row.claim.body, Algorithm) and row.claim.body.variant is None
                ]
            ),
            total,
        ),
        "false_label_rate": ratio(count([row for row in rows if row.false_label]), total),
        "brier": ratio(
            math.fsum(
                weights[row.program] * (row.claim.confidence - row.grade.correct_strict) ** 2
                for row in rows
            ),
            total,
        ),
        "decisiveness": ratio(
            count([row for row in reliable if row.outcome in ("VERIFIED", "CONTRADICTED")]),
            count(reliable),
        ),
        "catch_rate": ratio(
            count([row for row in wrong if row.outcome == "CONTRADICTED"]), count(wrong)
        ),
        "false_alarm_rate": ratio(
            count([row for row in correct if row.outcome == "CONTRADICTED"]), count(correct)
        ),
        "verification_precision": ratio(
            count([row for row in verified if row.correct]), count(verified)
        ),
    }
    for mode in ("strict", "lenient"):
        covered: dict[str, set[tuple[str, str]]] = {program: set() for program in coverage}
        for row in rows:
            identity = (row.claim.binary_sha256, row.claim.subject.address)
            if (
                isinstance(row.claim.body, Algorithm)
                and getattr(row.grade, "correct_" + mode)
                and identity in coverage[row.program]
            ):
                covered[row.program].add(identity)
        metrics["algorithm_coverage_" + mode] = ratio(
            sum(len(functions) * weights[program] for program, functions in covered.items()),
            denominator,
        )
        for threshold in sorted(set(thresholds)):
            confident = [row for row in rows if row.claim.confidence >= threshold]
            metrics[f"cwr_{mode}@{threshold:g}"] = ratio(
                count([row for row in confident if not getattr(row.grade, "correct_" + mode)]),
                count(confident),
            )
    outcomes = sorted({row.outcome for row in rows})
    confusion = {
        outcome: {
            "correct": count([row for row in rows if row.outcome == outcome and row.correct]),
            "wrong": count([row for row in rows if row.outcome == outcome and not row.correct]),
        }
        for outcome in outcomes
    }
    errors = count([row for row in rows if row.outcome == "ERROR"])
    return Summary(
        metrics=dict(sorted(metrics.items())),
        counts={
            "claims": total,
            "on_target": count(targets),
            "reliability_claims": count(reliable),
            "scorable_algorithm_functions": denominator,
        },
        confusion=confusion,
        exclusions={"ERROR": errors} if errors else {},
    )


def _percentile(values: list[float], fraction: float) -> float:
    position = (len(values) - 1) * fraction
    low = math.floor(position)
    high = math.ceil(position)
    return values[low] + (values[high] - values[low]) * (position - low)


def compute_metrics(
    grades: list[Grade],
    claims: list[Claim],
    verdicts: list[Verdict],
    cfg: Metrics,
    *,
    ground_truths: list[GroundTruth],
    method_results: dict[str, list[Aspect]],
    unmapped_counts: dict[str, dict[str, int]] | None = None,
) -> MetricsReport:
    """Keep controlled reliability separate; never infer method outcomes from a merged verdict."""
    claim_map = {claim.claim_id: claim for claim in claims}
    grade_map = {item.claim_id: item for item in grades}
    verdict_map = {item.claim_id: item for item in verdicts}
    if (
        len(claim_map) != len(claims)
        or len(grade_map) != len(grades)
        or len(verdict_map) != len(verdicts)
    ):
        raise ValueError("duplicate claim, grade or verdict identity")
    if claim_map.keys() != grade_map.keys() or claim_map.keys() != verdict_map.keys():
        raise ValueError("metrics require one grade and verdict per claim")
    if method_results.keys() != claim_map.keys():
        raise ValueError("metrics require complete per-method observations")
    truths = {gt.binary_sha256: gt for gt in ground_truths}
    if len(truths) != len(ground_truths):
        raise ValueError("duplicate ground-truth binary identity")
    programs = sorted({gt.program_id for gt in ground_truths})
    coverage: dict[str, set[tuple[str, str]]] = {program: set() for program in programs}
    none_functions: set[tuple[str, str]] = set()
    for gt in ground_truths:
        addresses = [function.address for function in gt.functions]
        if len(set(addresses)) != len(addresses):
            raise ValueError("duplicate ground-truth function address")
        for function in gt.functions:
            identity = (gt.binary_sha256, function.address)
            if function.algorithm.family == "none":
                none_functions.add(identity)
            elif function.scorable:
                coverage[gt.program_id].add(identity)
    rows: list[Observation] = []
    observations: dict[str, dict[str, Aspect]] = {}
    sources: dict[str, Source] = {}
    for claim_id, claim in sorted(claim_map.items()):
        if claim.binary_sha256 not in truths:
            raise ValueError("claim has no ground-truth binary")
        prior = sources.setdefault(claim.source.source_id, claim.source)
        if prior != claim.source:
            raise ValueError("inconsistent source metadata")
        methods = method_results[claim_id]
        by_method = {item.method: item for item in methods}
        if len(by_method) != len(methods) or set(by_method) != set(
            verdict_map[claim_id].methods_run
        ):
            raise ValueError("per-method observations differ from methods_run")
        observations[claim_id] = by_method
        rows.append(
            Observation(
                claim,
                grade_map[claim_id],
                truths[claim.binary_sha256].program_id,
                verdict_map[claim_id].intrinsic_verdict,
                isinstance(claim.body, Algorithm)
                and (claim.binary_sha256, claim.subject.address) in none_functions,
            )
        )
    unmapped = unmapped_counts or {}
    if unmapped.keys() - sources.keys() or any(
        type(count) is not int or count < 0
        for counts in unmapped.values()
        for count in counts.values()
    ):
        raise ValueError("invalid source unmapped counts")
    rng = random.Random(cfg.bootstrap_seed)
    weights = [
        Counter(rng.choices(programs, k=len(programs))) if programs else Counter[str]()
        for _ in range(cfg.bootstrap_resamples)
    ]

    def population(selected: list[Observation], scope: list[str] | None = None) -> Population:
        scoped = {program: coverage[program] for program in scope or programs}
        point = _summary(
            selected, scoped, Counter({program: 1 for program in scoped}), cfg.cwr_thresholds
        )
        samples: dict[str, list[float]] = {key: [] for key in point.metrics}
        for weight in weights:
            summary = _summary(selected, scoped, weight, cfg.cwr_thresholds)
            for key, value in summary.metrics.items():
                if value is not None:
                    samples[key].append(value)
        return Population(
            summary=point,
            intervals={
                key: Interval(
                    low=_percentile(sorted(values), 0.025) if values else None,
                    high=_percentile(sorted(values), 0.975) if values else None,
                    defined_resamples=len(values),
                )
                for key, values in samples.items()
            },
        )

    def methods_for(selected: list[Observation]) -> dict[str, Population]:
        names = sorted({name for row in selected for name in observations[row.claim.claim_id]})
        return {
            name: population(
                [
                    Observation(
                        row.claim,
                        row.grade,
                        row.program,
                        observations[row.claim.claim_id][name].verdict,
                        row.false_label,
                    )
                    for row in selected
                    if name in observations[row.claim.claim_id]
                ]
            )
            for name in names
        }

    reports: list[SourceReport] = []
    included: list[SourceLabel] = []
    excluded: list[SourceLabel] = []
    for source_id, source in sorted(sources.items()):
        selected = [row for row in rows if row.claim.source.source_id == source_id]
        label = (
            "shared Ghidra backend"
            if source.shares_backend
            else "controlled scripted"
            if source.origin == "scripted"
            else "tool-conditioned"
            if source.origin == "tool"
            else "non-controlled source"
        )
        metadata = SourceLabel(source=source, label=label)
        (
            included if source.origin == "scripted" and not source.shares_backend else excluded
        ).append(metadata)
        reports.append(
            SourceReport(
                source=source,
                label=label,
                aggregate=population(selected),
                programs={
                    program: population(
                        [row for row in selected if row.program == program], [program]
                    )
                    for program in programs
                },
                methods=methods_for(selected),
                unmapped_counts=dict(sorted(unmapped.get(source_id, {}).items())),
            )
        )
    independent = [
        row
        for row in rows
        if row.claim.source.origin == "scripted" and not row.claim.source.shares_backend
    ]

    def scenario(row: Observation) -> str:
        if row.claim.derived_from == "scripted_mutated":
            return "mutated"
        if row.claim.derived_from != "scripted_correct":
            raise ValueError("controlled scripted claim lacks scenario metadata")
        return (
            "family_only"
            if isinstance(row.claim.body, Algorithm) and row.claim.body.variant is None
            else "correct"
        )

    scenarios = sorted({scenario(row) for row in independent})
    return MetricsReport(
        sources=reports,
        independent=population(independent),
        independent_by_scenario={
            name: population([row for row in independent if scenario(row) == name])
            for name in scenarios
        },
        independent_by_type={
            name: population([row for row in independent if row.claim.type == name])
            for name in sorted({row.claim.type for row in independent})
        },
        independent_methods=methods_for(independent),
        included_sources=included,
        excluded_sources=excluded,
        program_clusters=programs,
        bootstrap_seed=cfg.bootstrap_seed,
        bootstrap_resamples=cfg.bootstrap_resamples,
        notes=[
            (
                "Independent verifier reliability includes controlled scripted claims only; "
                "other source populations remain separate."
            ),
            (
                "ERROR verdicts are excluded from reliability denominators and counted as "
                "defects; source accuracy and calibration retain all claims."
            ),
            (
                "Coverage denominators include all supplied scorable algorithm functions, "
                "including functions with no claim."
            ),
            (
                "95% percentile intervals resample whole programs with replacement using "
                "paired draws; undefined draws are omitted and counted."
            ),
            (
                "Only five programs are planned for Phase 1A; cluster intervals can be wide "
                "and are not held-out generalization evidence."
            ),
        ],
    )

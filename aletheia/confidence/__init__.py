"""Dev-only calibration and likelihood fitting; verification never imports this module."""

import math
from bisect import bisect_right
from collections import Counter, defaultdict
from graphlib import CycleError, TopologicalSorter
from typing import Literal, Self

from pydantic import Field, field_serializer, field_validator, model_validator

from aletheia.grade import claimed_correctness
from aletheia.schema.canonical import canonical_bytes
from aletheia.schema.models import (
    Claim,
    ClaimId,
    Grade,
    Outcome,
    Record,
    RunId,
    Source,
    Strength,
    Strict,
    Verdict,
)
from aletheia.verify.engine import REQUIRED_ASPECTS

ClaimType = Literal["algorithm_identity", "call_relation", "function_signature", "function_purpose"]


class LikelihoodKey(Strict):
    claim_type: ClaimType
    verdict: Outcome
    strength: Strength | None
    method: str = Field(min_length=1)


class Sample(Strict):
    claim_id: ClaimId
    run_id: RunId
    program: str = Field(min_length=1)
    split: Literal["dev", "heldout", "train"]
    source: Source
    claim_type: ClaimType
    confidence: float = Field(ge=0, le=1)
    correct_claimed: bool | None
    on_target: bool
    verdict: Outcome
    strength: Strength | None
    method: str = Field(min_length=1)
    depends_on: list[ClaimId] = Field(default_factory=list)

    @field_validator("confidence")
    @classmethod
    def wire_confidence(cls, value: float) -> float:
        return round(value, 6)

    @property
    def key(self) -> LikelihoodKey:
        return LikelihoodKey(
            claim_type=self.claim_type,
            verdict=self.verdict,
            strength=self.strength,
            method=self.method,
        )


def sample(
    claim: Claim,
    item: Grade,
    verdict: Verdict,
    program: str,
    split: Literal["dev", "heldout", "train"],
) -> Sample:
    if claim.claim_id != item.claim_id or claim.claim_id != verdict.claim_id:
        raise ValueError("confidence input identity mismatch")
    # Fit the joint method trail; multiplying method likelihoods assumes independence.
    methods = sorted(
        {
            verdict.aspects[name].method
            for name in REQUIRED_ASPECTS[claim.type]
            if name in verdict.aspects
        }
    )
    return Sample(
        claim_id=claim.claim_id,
        run_id=claim.run_id,
        program=program,
        split=split,
        source=claim.source,
        claim_type=claim.type,
        confidence=claim.confidence,
        correct_claimed=claimed_correctness(claim, item),
        on_target=item.on_target,
        verdict=verdict.intrinsic_verdict,
        strength=verdict.strength,
        method="+".join(methods) or "none",
        depends_on=sorted(set(claim.depends_on)),
    )


def _dev(samples: list[Sample]) -> None:
    if any(row.split != "dev" for row in samples):
        raise ValueError("confidence fitting accepts dev runs only")
    if len({row.claim_id for row in samples}) != len(samples):
        raise ValueError("duplicate fitting claim identity")


class Block(Strict):
    low: float = Field(ge=0, le=1)
    high: float = Field(ge=0, le=1)
    count: int = Field(gt=0)
    correct: int = Field(ge=0)

    @property
    def value(self) -> float:
        return self.correct / self.count

    @model_validator(mode="after")
    def consistent(self) -> Self:
        if self.low > self.high or self.correct > self.count:
            raise ValueError("inconsistent isotonic block")
        return self


class CalibrationMap(Record):
    source_id: str = Field(min_length=1)
    claim_type: ClaimType
    prediction_rule: Literal["lower_knot_step"] = "lower_knot_step"
    run_ids: list[RunId]
    blocks: list[Block] = Field(min_length=1)

    @model_validator(mode="after")
    def ordered(self) -> Self:
        if self.run_ids != sorted(set(self.run_ids)) or not self.run_ids:
            raise ValueError("calibration requires sorted dev provenance")
        if sum(block.count for block in self.blocks) < 30:
            raise ValueError("calibration requires at least 30 labels")
        for left, right in zip(self.blocks, self.blocks[1:], strict=False):
            if left.high >= right.low or left.value > right.value:
                raise ValueError("calibration blocks must be ordered and monotone")
        return self

    def predict(self, confidence: float) -> float:
        if not math.isfinite(confidence) or not 0 <= confidence <= 1:
            raise ValueError("invalid confidence")
        return self.blocks[
            max(0, bisect_right([block.low for block in self.blocks], round(confidence, 6)) - 1)
        ].value


class Unfitted(Strict):
    source_id: str = Field(min_length=1)
    claim_type: ClaimType
    eligible: int = Field(ge=0, lt=30)
    reason: Literal["insufficient_labels"] = "insufficient_labels"


class CalibrationFit(Record):
    run_ids: list[RunId] = Field(default_factory=list)
    maps: list[CalibrationMap]
    unfitted: list[Unfitted]

    @model_validator(mode="after")
    def unique(self) -> Self:
        keys = [(mapping.source_id, mapping.claim_type) for mapping in self.maps]
        unfitted = [(item.source_id, item.claim_type) for item in self.unfitted]
        if self.run_ids != sorted(set(self.run_ids)) or any(
            not set(mapping.run_ids) <= set(self.run_ids) for mapping in self.maps
        ):
            raise ValueError("calibration fit lacks sorted input provenance")
        if (
            keys != sorted(set(keys))
            or unfitted != sorted(set(unfitted))
            or set(keys) & set(unfitted)
        ):
            raise ValueError("calibration sources must be sorted, unique and disjoint")
        return self

    def find(self, source_id: str, claim_type: ClaimType) -> CalibrationMap | None:
        return next(
            (
                mapping
                for mapping in self.maps
                if mapping.source_id == source_id and mapping.claim_type == claim_type
            ),
            None,
        )


def fit_calibration(samples: list[Sample]) -> CalibrationFit:
    _dev(samples)
    groups: dict[tuple[str, ClaimType], list[Sample]] = defaultdict(list)
    for row in samples:
        groups.setdefault((row.source.source_id, row.claim_type), [])
        if row.on_target and row.correct_claimed is not None:
            groups[row.source.source_id, row.claim_type].append(row)
    maps: list[CalibrationMap] = []
    unfitted: list[Unfitted] = []
    for (source, kind), rows in sorted(groups.items()):
        if len(rows) < 30:
            unfitted.append(Unfitted(source_id=source, claim_type=kind, eligible=len(rows)))
            continue
        counts = Counter(row.confidence for row in rows)
        correct = Counter(row.confidence for row in rows if row.correct_claimed is True)
        blocks: list[Block] = []
        for confidence, n in sorted(counts.items()):
            blocks.append(
                Block(
                    low=confidence,
                    high=confidence,
                    count=n,
                    correct=correct[confidence],
                )
            )
            while (
                len(blocks) > 1
                and blocks[-2].correct * blocks[-1].count >= blocks[-1].correct * blocks[-2].count
            ):
                right, left = blocks.pop(), blocks.pop()
                n = left.count + right.count
                k = left.correct + right.correct
                blocks.append(Block(low=left.low, high=right.high, count=n, correct=k))
        maps.append(
            CalibrationMap(
                source_id=source,
                claim_type=kind,
                run_ids=sorted({row.run_id for row in rows}),
                blocks=blocks,
            )
        )
    return CalibrationFit(
        run_ids=sorted({row.run_id for row in samples}), maps=maps, unfitted=unfitted
    )


def effective_ratio(verdict: Outcome, ratio: float) -> float:
    if not math.isfinite(ratio) or ratio <= 0:
        raise ValueError("likelihood ratio must be positive and finite")
    if verdict in {"NOT_CHECKED", "ERROR", "UNVERIFIABLE", "INVALID_CLAIM"}:
        return 1.0
    return min(ratio, 1.0) if verdict == "INCONCLUSIVE" else ratio


class LikelihoodRow(Strict):
    key: LikelihoodKey
    n_correct: int = Field(ge=0)
    n_wrong: int = Field(ge=0)
    k_correct: int = Field(ge=0)
    k_wrong: int = Field(ge=0)
    pooled_scripted: bool

    @property
    def p_correct(self) -> float:
        return (self.k_correct + 1) / (self.n_correct + 2)

    @property
    def p_wrong(self) -> float:
        return (self.k_wrong + 1) / (self.n_wrong + 2)

    @property
    def likelihood_ratio(self) -> float:
        return effective_ratio(self.key.verdict, self.p_correct / self.p_wrong)

    @model_validator(mode="after")
    def probabilities(self) -> Self:
        if self.k_correct > self.n_correct or self.k_wrong > self.n_wrong:
            raise ValueError("inconsistent likelihood counts or ratio")
        return self


class LikelihoodFit(Record):
    run_ids: list[RunId]
    rows: list[LikelihoodRow]

    @model_validator(mode="after")
    def unique(self) -> Self:
        keys = [canonical_bytes(row.key) for row in self.rows]
        if (
            keys != sorted(set(keys))
            or self.run_ids != sorted(set(self.run_ids))
            or self.rows
            and not self.run_ids
        ):
            raise ValueError("likelihood rows and provenance must be sorted and unique")
        return self

    def ratio(
        self, key: LikelihoodKey
    ) -> tuple[float, Literal["fixed", "fitted", "neutral_unseen"]]:
        if key.verdict in {"NOT_CHECKED", "ERROR", "UNVERIFIABLE", "INVALID_CLAIM"}:
            return 1.0, "fixed"
        row = next((row for row in self.rows if row.key == key), None)
        return (row.likelihood_ratio, "fitted") if row else (1.0, "neutral_unseen")


def fit_likelihoods(samples: list[Sample]) -> LikelihoodFit:
    _dev(samples)
    groups: dict[ClaimType, list[Sample]] = defaultdict(list)
    for row in samples:
        if row.correct_claimed is not None:
            groups[row.claim_type].append(row)
    output: list[LikelihoodRow] = []
    run_ids: set[RunId] = set()
    for rows in groups.values():
        independent = [row for row in rows if row.source.origin != "scripted"]
        pooled = sum(row.correct_claimed is False for row in independent) < 20
        selected = rows if pooled else independent
        run_ids.update(row.run_id for row in selected)
        nc = sum(row.correct_claimed is True for row in selected)
        nw = sum(row.correct_claimed is False for row in selected)
        keys = {canonical_bytes(row.key): row.key for row in selected}
        for encoded, key in sorted(keys.items()):
            kc = sum(
                row.correct_claimed is True and canonical_bytes(row.key) == encoded
                for row in selected
            )
            kw = sum(
                row.correct_claimed is False and canonical_bytes(row.key) == encoded
                for row in selected
            )
            output.append(
                LikelihoodRow(
                    key=key,
                    n_correct=nc,
                    n_wrong=nw,
                    k_correct=kc,
                    k_wrong=kw,
                    pooled_scripted=pooled,
                )
            )
    return LikelihoodFit(
        run_ids=sorted(run_ids), rows=sorted(output, key=lambda row: canonical_bytes(row.key))
    )


class Adjustment(Strict):
    raw: float = Field(ge=0, le=1)
    prior: float = Field(ge=0, le=1)
    adjusted: float = Field(ge=0, le=1)
    calibration: Literal["calibrated", "uncalibrated"]
    likelihood: Literal["fixed", "fitted", "neutral_unseen"]
    likelihood_ratio: float = Field(gt=0)
    dependency_cap: float | None = None

    @field_validator(
        "raw",
        "prior",
        "adjusted",
        "likelihood_ratio",
        "dependency_cap",
        mode="before",
        json_schema_input_type=float | str | None,
    )
    @classmethod
    def read_exact_probability(cls, value: float | str | None) -> float | None:
        return float(value) if isinstance(value, str) else value

    @field_serializer(
        "raw", "prior", "adjusted", "likelihood_ratio", "dependency_cap", when_used="json"
    )
    def exact_probability(self, value: float | None) -> str | None:
        # Decimal strings retain decisions when canonical JSON rounds numeric floats.
        return repr(value) if value is not None else None


def adjust(
    row: Sample, maps: CalibrationFit, table: LikelihoodFit, parents: list[float] | None = None
) -> Adjustment:
    mapping = maps.find(row.source.source_id, row.claim_type)
    prior = mapping.predict(row.confidence) if mapping else row.confidence
    ratio, status = table.ratio(row.key)
    bounded = min(0.999, max(0.001, prior))
    # Algebraic odds update avoids overflow when the ratio is very large.
    posterior = bounded * ratio / ((1 - bounded) + bounded * ratio)
    value = min(0.98, max(0.02, posterior))
    if parents and any(
        not math.isfinite(parent) or not 0.02 <= parent <= 0.98 for parent in parents
    ):
        raise ValueError("reasoning parents require bounded adjusted confidence")
    cap = (
        min(parents)
        if parents and not (row.strength == "E2" and row.verdict in {"VERIFIED", "CONTRADICTED"})
        else None
    )
    return Adjustment(
        raw=row.confidence,
        prior=prior,
        adjusted=min(value, cap) if cap is not None else value,
        calibration="calibrated" if mapping else "uncalibrated",
        likelihood=status,
        likelihood_ratio=ratio,
        dependency_cap=cap,
    )


def adjust_graph(
    samples: list[Sample], maps: CalibrationFit, table: LikelihoodFit
) -> dict[str, Adjustment]:
    records = {row.claim_id: row for row in samples}
    if len(records) != len(samples):
        raise ValueError("duplicate confidence claim identity")
    for row in samples:
        if any(
            parent not in records or records[parent].run_id != row.run_id
            for parent in row.depends_on
        ):
            raise ValueError("reasoning dependency is missing or belongs to another run")
    try:
        order = list(
            TopologicalSorter(
                {key: sorted(set(row.depends_on)) for key, row in sorted(records.items())}
            ).static_order()
        )
    except CycleError as exc:
        raise ValueError("cyclic reasoning dependencies") from exc
    output: dict[str, Adjustment] = {}
    for key in order:
        row = records[key]
        output[key] = adjust(
            row, maps, table, [output[parent].adjusted for parent in row.depends_on]
        )
    return output

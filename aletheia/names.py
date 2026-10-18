"""Deterministic secondary name metric; never imported by primary scoring or gates."""

import json
import random
import re
from pathlib import Path
from typing import TYPE_CHECKING, Literal, Self

from pydantic import Field, field_serializer, field_validator, model_validator

from aletheia.schema.canonical import content_hash
from aletheia.schema.models import FunctionPurpose, GroundTruth, Sha256, Strict

if TYPE_CHECKING:
    from aletheia.orchestrate import Benchmark


class Lexicon(Strict):
    version: Literal["1.0"]
    threshold: float | None = Field(default=None, ge=0, le=1)
    abbreviations: dict[str, str]
    synonyms: list[list[str]]

    @field_validator("threshold", mode="before")
    @classmethod
    def exact_threshold(cls, value: float | str | None) -> float | None:
        return float(value) if isinstance(value, str) else value

    @field_serializer("threshold", when_used="json")
    def wire_threshold(self, value: float | None) -> str | None:
        return repr(value) if value is not None else None

    @model_validator(mode="after")
    def canonical_tokens(self) -> Self:
        members = [token for group in self.synonyms for token in group]
        all_tokens = [*self.abbreviations, *self.abbreviations.values(), *members]
        if any(re.fullmatch(r"[a-z]+", token) is None for token in all_tokens):
            raise ValueError("lexicon tokens must be lowercase alphabetic words")
        if len(members) != len(set(members)) or any(len(group) < 2 for group in self.synonyms):
            raise ValueError("synonym groups must be disjoint and contain at least two words")
        if set(self.abbreviations) & set(self.abbreviations.values()):
            raise ValueError("abbreviation values must be canonical words")
        return self

    @classmethod
    def read(cls, path: Path) -> Self:
        import yaml

        if any(p.is_symlink() for p in (path, *path.parents)):
            raise ValueError("lexicon cannot be a symlink")
        return cls.model_validate(yaml.safe_load(path.read_bytes()))


def tokens(name: str) -> list[str]:
    value = re.sub(r"([A-Z]+)([A-Z][a-z])", r"\1_\2", name)
    value = re.sub(r"([a-z])([A-Z])", r"\1_\2", value)
    return [part.lower() for part in re.findall(r"[A-Za-z]+|[0-9]+", value)]


def expanded(name: str, lexicon: Lexicon) -> set[str]:
    result: set[str] = set()
    for token in tokens(name):
        token = lexicon.abbreviations.get(token, token)
        group = next((group for group in lexicon.synonyms if token in group), None)
        result.update(group or [token])
    return result


def score(proposed: str, actual: str, lexicon: Lexicon) -> float:
    left, right = expanded(proposed, lexicon), expanded(actual, lexicon)
    return len(left & right) / len(left | right) if left | right else 0.0


class NamePair(Strict):
    pair_id: str = Field(min_length=1)
    proposed_name: str = Field(min_length=1)
    true_name: str = Field(min_length=1)
    match: bool | None = None


class NameLabels(Strict):
    split: Literal["dev"] = "dev"
    method: Literal["unlabeled", "human", "ai-assisted", "synthetic"]
    annotator_id: str = Field(min_length=1)
    human_validated: bool = False
    available: int = Field(ge=0)
    pairs: list[NamePair]

    @model_validator(mode="after")
    def provenance(self) -> Self:
        if (self.method == "human") != self.human_validated:
            raise ValueError("label provenance and human validation disagree")
        if len({pair.pair_id for pair in self.pairs}) != len(self.pairs) or self.available < len(
            self.pairs
        ):
            raise ValueError("label cohort requires unique IDs and valid population count")
        return self


class NameFit(Strict):
    threshold: float = Field(ge=0, le=1)
    agreement: float = Field(ge=0, le=1)
    kappa: float | None
    kappa_reason: str
    pairs: int = Field(ge=200)
    labels_sha256: Sha256
    lexicon_rules_sha256: Sha256
    method: str
    human_validated: bool
    secondary_only: Literal[True] = True

    @field_validator("threshold", mode="before")
    @classmethod
    def exact_threshold(cls, value: float | str) -> float:
        return float(value) if isinstance(value, str) else value

    @field_serializer("threshold", when_used="json")
    def wire_threshold(self, value: float) -> str:
        return repr(value)


def fit_threshold(labels: NameLabels, lexicon: Lexicon) -> NameFit:
    if labels.method == "unlabeled":
        raise ValueError("name threshold requires a labeling method")
    if len(labels.pairs) < 200 or any(pair.match is None for pair in labels.pairs):
        raise ValueError("name threshold requires at least 200 labeled dev pairs")
    scores = [score(pair.proposed_name, pair.true_name, lexicon) for pair in labels.pairs]
    candidates = sorted(set(scores) | {0.0, 1.0})

    def correct(threshold: float) -> int:
        return sum(
            (value >= threshold) == pair.match
            for value, pair in zip(scores, labels.pairs, strict=True)
        )

    threshold = max(candidates, key=lambda value: (correct(value), value))
    n = len(scores)
    observed = correct(threshold) / n
    predicted = sum(value >= threshold for value in scores)
    positive = sum(pair.match is True for pair in labels.pairs)
    expected = (predicted * positive + (n - predicted) * (n - positive)) / (n * n)
    kappa = (observed - expected) / (1 - expected) if expected < 1 else None
    return NameFit(
        threshold=threshold,
        agreement=observed,
        kappa=kappa,
        kappa_reason="ok" if kappa is not None else "undefined_expected_agreement",
        pairs=n,
        labels_sha256=content_hash(labels),
        lexicon_rules_sha256=content_hash(lexicon.model_dump(mode="json", exclude={"threshold"})),
        method=labels.method,
        human_validated=labels.human_validated,
    )


def export_dev_pairs(
    benchmark: "Benchmark", *, limit: int = 200, seed: int = 20261013
) -> NameLabels:
    if benchmark.config.guard.split != "dev":
        raise ValueError("name-label pairs must come from dev runs")
    if limit < 1:
        raise ValueError("positive name-label cohort size required")
    pairs: list[NamePair] = []
    with benchmark.store() as store:
        for run in benchmark.run_ids():
            metadata = json.loads((benchmark.directory(run) / "run.json").read_bytes())
            if metadata["origin"] != "agent":
                continue
            _, _, bundle = benchmark.bundle(metadata["program"], metadata.get("variant_id"))
            truth = GroundTruth.model_validate_json(
                (bundle / "private/ground_truth.json").read_bytes()
            )
            names = {fn.address: fn.name for fn in truth.functions if fn.scorable}
            for claim in benchmark.claims(store, run):
                if (
                    isinstance(claim.body, FunctionPurpose)
                    and claim.body.proposed_name
                    and claim.subject.address in names
                ):
                    pairs.append(
                        NamePair(
                            pair_id=claim.claim_id,
                            proposed_name=claim.body.proposed_name,
                            true_name=names[claim.subject.address],
                        )
                    )
    chosen = random.Random(seed).sample(pairs, min(limit, len(pairs)))
    return NameLabels(
        method="unlabeled",
        annotator_id="unlabeled-dev-export",
        available=len(pairs),
        pairs=sorted(chosen, key=lambda pair: pair.pair_id),
    )

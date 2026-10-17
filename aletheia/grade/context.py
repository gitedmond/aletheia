"""Aggregate annotation agreement, pinned separately from private per-function labels."""

import hashlib
import math
from pathlib import Path
from typing import Literal, Self

from pydantic import Field, model_validator

from aletheia.schema.models import Record, Sha256
from aletheia.schema.taxonomy import Taxonomy


class GradingContext(Record):
    taxonomy_version: Literal["1.0"] = "1.0"
    agreement_sha256: Sha256
    taxonomy_kappa: dict[str, float | None]
    human_validated: bool | None
    method: str = Field(min_length=1)

    @model_validator(mode="after")
    def valid_nodes(self) -> Self:
        nodes = {leaf.split(".")[0] for leaf in Taxonomy.bundled().leaves}
        if not set(self.taxonomy_kappa) <= nodes or any(
            value is not None and (not math.isfinite(value) or not -1 <= value <= 1)
            for value in self.taxonomy_kappa.values()
        ):
            raise ValueError("invalid aggregate annotation agreement")
        return self

    @classmethod
    def read(cls, path: Path) -> "GradingContext":
        return cls.snapshot(path)[0]

    @classmethod
    def snapshot(cls, path: Path) -> tuple["GradingContext", str]:
        if any(part.is_symlink() for part in (path, *path.parents)):
            raise ValueError("grading context cannot be a symlink")
        payload = path.read_bytes()
        return cls.model_validate_json(payload), hashlib.sha256(payload).hexdigest()

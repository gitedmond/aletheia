"""The public category vocabulary, independent of corpus truth and verifier methods."""

from pathlib import Path
from typing import Literal, Self

import yaml
from pydantic import Field, model_validator

from aletheia.schema.models import Strict


class Taxonomy(Strict):
    version: Literal["1.0"] = "1.0"
    leaves: list[str] = Field(min_length=1)

    @model_validator(mode="after")
    def leaf_contract(self) -> Self:
        if self.leaves != sorted(set(self.leaves)):
            raise ValueError("taxonomy leaves must be sorted and unique")
        for name in self.leaves:
            if len(name.split(".")) < 2 or any(
                not part.isidentifier() or part != part.lower() for part in name.split(".")
            ):
                raise ValueError("invalid taxonomy leaf: " + name)
            if any(other.startswith(name + ".") for other in self.leaves):
                raise ValueError("taxonomy may contain only leaves: " + name)
        return self

    @classmethod
    def read(cls, path: Path) -> "Taxonomy":
        return cls.model_validate(yaml.safe_load(path.read_text()))

    @classmethod
    def bundled(cls) -> "Taxonomy":
        return cls.read(Path(__file__).with_name("taxonomy.yaml"))

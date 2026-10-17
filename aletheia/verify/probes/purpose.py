"""Reviewed public taxonomy-to-behavior scopes; no category is an algorithm family."""

from pathlib import Path
from typing import Literal, Self

import yaml
from pydantic import Field, model_validator

from aletheia.schema.models import REGISTRY, Strict
from aletheia.schema.taxonomy import Taxonomy
from aletheia.verify.probes.oracles import PURPOSE_VARIANTS
from aletheia.verify.probes.pack import UniqueLoader


class PurposeScope(Strict):
    pack: str
    variants: list[str] = Field(min_length=1)
    composite: bool = False

    @model_validator(mode="after")
    def known_scope(self) -> Self:
        registry = REGISTRY | PURPOSE_VARIANTS
        if self.pack not in registry or len(self.variants) != len(set(self.variants)):
            raise ValueError("unknown or duplicate purpose scope")
        if not set(self.variants) <= set(registry[self.pack]):
            raise ValueError("unknown purpose variant")
        if self.composite and self.pack not in {"md5", "sha1", "sha256"}:
            raise ValueError("unsupported composite purpose")
        return self


class PurposeMapping(Strict):
    version: Literal["1.0"]
    taxonomy_version: Literal["1.0"]
    map: dict[str, PurposeScope]

    @model_validator(mode="after")
    def known_categories(self) -> Self:
        if not set(self.map) <= set(Taxonomy.bundled().leaves):
            raise ValueError("unknown purpose category")
        return self

    @classmethod
    def read(cls, path: Path) -> "PurposeMapping":
        return cls.model_validate(yaml.load(path.read_text(), Loader=UniqueLoader))

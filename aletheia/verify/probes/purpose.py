"""Reviewed public taxonomy-to-behavior scopes; no category is an algorithm family."""

from pathlib import Path
from typing import Literal, Self

import yaml
from pydantic import Field, model_validator

from aletheia.schema.models import REGISTRY, Strict
from aletheia.schema.taxonomy import Taxonomy
from aletheia.verify.probes.oracles import PURPOSE_VARIANTS
from aletheia.verify.probes.pack import UniqueLoader

HASH_COMPOSITE_PACKS = {"md5", "sha1", "sha256"}


class PurposeScope(Strict):
    pack: str
    variants: list[str] = Field(min_length=1)
    composite: bool = False
    composite_categories: list[str] = Field(default_factory=list)

    @model_validator(mode="after")
    def known_scope(self) -> Self:
        registry = REGISTRY | PURPOSE_VARIANTS
        if self.pack not in registry or len(self.variants) != len(set(self.variants)):
            raise ValueError("unknown or duplicate purpose scope")
        if not set(self.variants) <= set(registry[self.pack]):
            raise ValueError("unknown purpose variant")
        if self.composite:
            expected = (
                [f"crypto.hash.{self.pack}.{role}" for role in ("init", "update", "final")]
                if self.pack in HASH_COMPOSITE_PACKS
                else self.composite_categories
            )
            if not expected or self.composite_categories not in ([], expected):
                raise ValueError("unsupported composite purpose")
            self.composite_categories = list(expected)
        elif self.composite_categories:
            raise ValueError("composite categories require a composite scope")
        return self


class PurposeMapping(Strict):
    version: Literal["1.0"]
    taxonomy_version: Literal["1.0"]
    map: dict[str, PurposeScope]

    @model_validator(mode="after")
    def known_categories(self) -> Self:
        if not set(self.map) <= set(Taxonomy.bundled().leaves):
            raise ValueError("unknown purpose category")
        for category, scope in self.map.items():
            if scope.composite and category not in scope.composite_categories:
                raise ValueError("composite mapping requires a matching member category")
        return self

    @classmethod
    def read(cls, path: Path) -> "PurposeMapping":
        return cls.model_validate(yaml.load(path.read_text(), Loader=UniqueLoader))

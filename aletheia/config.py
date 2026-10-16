"""Validated configuration; Phase 1A never enables a provider."""

import tomllib
from pathlib import Path
from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, Field, PrivateAttr, field_validator

Positive = Annotated[int, Field(strict=True, gt=0)]


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)


class Paths(StrictModel):
    build: str = "build"
    runs: str = "runs"
    artifacts: str = "artifacts"
    private_root: str | None = None

    @field_validator("private_root")
    @classmethod
    def absolute_private_root(cls, value: str | None) -> str | None:
        if value is not None and not Path(value).is_absolute():
            raise ValueError("private_root must be an absolute path")
        return value


class Sandbox(StrictModel):
    image_analysis: str = ""
    image_build: str = ""
    concurrency: Positive = 4
    memory_gb: Positive = 6
    wall_timeout_s: Positive = 60


class Budgets(StrictModel):
    instructions_per_invocation: Positive = 10_000_000
    instructions_per_claim: Positive = 200_000_000
    heap_mb: Positive = 64
    stack_mb: Positive = 1


class Ghidra(StrictModel):
    analysis_options: str = "configs/ghidra-analysis.json"


class Source(StrictModel):
    enabled: bool = True
    mapping: str


class Sources(StrictModel):
    capa: Source = Field(default_factory=lambda: Source(mapping="mappings/capa.yaml"))
    findcrypt: Source = Field(default_factory=lambda: Source(mapping="mappings/findcrypt.yaml"))


class Llm(StrictModel):
    enabled: Literal[False] = False
    provider: Literal[""] = ""
    cost_cap_usd: Literal[0] = 0


class Metrics(StrictModel):
    bootstrap_resamples: Positive = 1000
    bootstrap_seed: int = 20261013
    cwr_thresholds: list[Annotated[float, Field(ge=0, le=1)]] = Field(
        default_factory=lambda: [0.8, 0.9]
    )


class Config(StrictModel):
    _split: Literal["dev", "heldout"] = PrivateAttr(default="dev")
    paths: Paths = Field(default_factory=Paths)
    sandbox: Sandbox = Field(default_factory=Sandbox)
    budgets: Budgets = Field(default_factory=Budgets)
    ghidra: Ghidra = Field(default_factory=Ghidra)
    sources: Sources = Field(default_factory=Sources)
    llm: Llm = Field(default_factory=Llm)
    metrics: Metrics = Field(default_factory=Metrics)

    @property
    def guard(self):
        from aletheia.heldout.guard import PrivateGuard

        root = Path(self.paths.private_root) if self.paths.private_root else None
        return PrivateGuard(root, self._split)

    def for_split(self, split: Literal["dev", "heldout"]) -> "Config":
        result = self.model_copy(deep=True)
        result._split = split
        guard = result.guard
        if split == "heldout":
            assert guard.root is not None
            for name in ("build", "runs", "artifacts"):
                setattr(result.paths, name, str(guard.root / name))
        else:
            for path in (result.paths.build, result.paths.runs, result.paths.artifacts):
                guard.public_path(Path(path))
        for path in (
            result.ghidra.analysis_options,
            result.sources.capa.mapping,
            result.sources.findcrypt.mapping,
        ):
            guard.access(Path(path))
        return result

    @classmethod
    def read(cls, path: Path) -> "Config":
        with path.open("rb") as stream:
            return cls.model_validate(tomllib.load(stream))

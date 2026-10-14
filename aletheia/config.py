"""Validated configuration; Phase 1A never enables a provider."""

import tomllib
from pathlib import Path
from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, Field

Positive = Annotated[int, Field(strict=True, gt=0)]


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)


class Paths(StrictModel):
    build: str = "build"
    runs: str = "runs"
    artifacts: str = "artifacts"


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
    paths: Paths = Field(default_factory=Paths)
    sandbox: Sandbox = Field(default_factory=Sandbox)
    budgets: Budgets = Field(default_factory=Budgets)
    ghidra: Ghidra = Field(default_factory=Ghidra)
    sources: Sources = Field(default_factory=Sources)
    llm: Llm = Field(default_factory=Llm)
    metrics: Metrics = Field(default_factory=Metrics)

    @classmethod
    def read(cls, path: Path) -> "Config":
        with path.open("rb") as stream:
            return cls.model_validate(tomllib.load(stream))

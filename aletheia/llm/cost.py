"""Hosted scheduling cap and private per-binary exposure accounting."""

import fcntl
import json
import math
from collections.abc import Generator
from contextlib import contextmanager
from decimal import Decimal
from pathlib import Path
from typing import Literal

from pydantic import JsonValue, TypeAdapter

from aletheia.heldout.guard import PrivateGuard
from aletheia.llm.provider import AgentConfig, Usage
from aletheia.schema.canonical import canonical_bytes
from aletheia.schema.models import RunId, Sha256


@contextmanager
def ledger(path: Path) -> Generator[list[dict[str, JsonValue]]]:
    if any(p.is_symlink() for p in (path, *path.parents)):
        raise ValueError("ledger cannot be a symlink")
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a+", encoding="utf-8") as stream:
        fcntl.flock(stream, fcntl.LOCK_EX)
        stream.seek(0)
        rows = [json.loads(line) for line in stream if line.strip()]
        old = len(rows)
        yield rows
        for row in rows[old:]:
            stream.write(canonical_bytes(row).decode() + "\n")
        stream.flush()


class CostGuard:
    def __init__(self, path: Path, *, cap_usd: float = 0.0):
        if not math.isfinite(cap_usd) or cap_usd < 0:
            raise ValueError("invalid hosted cost cap")
        self.path, self.cap = path, Decimal(str(cap_usd))

    @staticmethod
    def spent(rows: list[dict[str, JsonValue]]) -> Decimal:
        return sum((Decimal(str(row["usd"])) for row in rows if row["kind"] == "usage"), Decimal(0))

    def authorize(self, config: AgentConfig, *, pilot: bool = False) -> bool:
        if not config.hosted:
            return False
        with ledger(self.path) as rows:
            if self.spent(rows) >= self.cap:
                raise ValueError("budget_exhausted")
            projections = [
                row
                for row in rows
                if row["kind"] == "projection" and row["config_id"] == config.config_id
            ]
            if not pilot and (not projections or projections[-1]["allowed"] is not True):
                raise ValueError("hosted batch requires an approved three dev pilots projection")
        return True

    def project(self, config: AgentConfig, dev_pilot_costs: list[float], runs: int) -> bool:
        if len(dev_pilot_costs) != 3 or any(not math.isfinite(c) or c < 0 for c in dev_pilot_costs):
            raise ValueError("projection requires exactly three dev pilots")
        if runs < 0:
            raise ValueError("invalid projected run count")
        projected = sum((Decimal(str(c)) for c in dev_pilot_costs), Decimal(0)) / 3 * runs
        with ledger(self.path) as rows:
            allowed = self.spent(rows) + projected <= self.cap and self.spent(rows) < self.cap
            rows.append(
                {
                    "kind": "projection",
                    "config_id": config.config_id,
                    "pilot_costs": [float(c) for c in dev_pilot_costs],
                    "runs": runs,
                    "projected_usd": str(projected),
                    "allowed": allowed,
                }
            )
        return allowed

    def record(self, config: AgentConfig, usage: Usage, run_id: str) -> None:
        if not config.hosted:
            return
        TypeAdapter(RunId).validate_python(run_id)
        amount = (
            Decimal(str(config.price.input_per_mtok)) * usage.input_tokens
            + Decimal(str(config.price.output_per_mtok)) * usage.output_tokens
        ) / 1_000_000
        with ledger(self.path) as rows:
            rows.append(
                {
                    "kind": "usage",
                    "config_id": config.config_id,
                    "run_id": run_id,
                    "usd": str(amount),
                    **usage.model_dump(mode="json"),
                }
            )


class ExposureLog:
    def __init__(self, guard: PrivateGuard):
        if guard.root is None:
            raise ValueError("exposure log requires private_root")
        self.path = guard.private_output(guard.root / "exposures.jsonl")

    def count(self, digest: str) -> int:
        TypeAdapter(Sha256).validate_python(digest)
        with ledger(self.path) as rows:
            return sum(row["binary_sha256"] == digest for row in rows)

    def warning(self, digest: str) -> bool:
        return self.count(digest) >= 24

    def record(
        self, config: AgentConfig, digest: str, run_id: str, *, split: Literal["dev", "heldout"]
    ) -> int:
        if not config.hosted or split != "heldout":
            return 0
        TypeAdapter(Sha256).validate_python(digest)
        TypeAdapter(RunId).validate_python(run_id)
        with ledger(self.path) as rows:
            count = sum(row["binary_sha256"] == digest for row in rows)
            if any(
                row["binary_sha256"] == digest
                and row["run_id"] == run_id
                and row["config_id"] == config.config_id
                for row in rows
            ):
                return count
            if count >= 30:
                raise ValueError("exposure_limit")
            rows.append(
                {
                    "binary_sha256": digest,
                    "config_id": config.config_id,
                    "provider": config.provider,
                    "retention_setting": config.retention_setting,
                    "run_id": run_id,
                }
            )
            return count + 1

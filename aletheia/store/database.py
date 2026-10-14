"""SQLite metadata only; private ground truth is deliberately absent."""

import json
import sqlite3
from pathlib import Path
from types import TracebackType
from typing import Literal, Self

from pydantic import JsonValue

from aletheia.schema.canonical import canonical_bytes, content_hash
from aletheia.schema.models import Claim, ClaimId, Grade, Job, JobResult, Verdict

DDL = """
CREATE TABLE binaries (
 sha256 TEXT PRIMARY KEY, program_id TEXT NOT NULL, variant_id TEXT NOT NULL,
 split TEXT NOT NULL CHECK (split IN ('dev','heldout','train')),
 stripped_path TEXT NOT NULL, targets_hash TEXT NOT NULL);
CREATE TABLE runs (
 run_id TEXT PRIMARY KEY, origin TEXT NOT NULL, source_id TEXT NOT NULL,
 manifest_hash TEXT NOT NULL, state TEXT NOT NULL
 CHECK (state IN ('pending','running','completed','failed','budget_exhausted')), created_at TEXT);
CREATE TABLE claims (
 claim_id TEXT PRIMARY KEY, run_id TEXT NOT NULL REFERENCES runs(run_id),
 binary_sha256 TEXT NOT NULL REFERENCES binaries(sha256),
 subject_address TEXT NOT NULL, type TEXT NOT NULL, active_key TEXT NOT NULL,
 is_active INTEGER NOT NULL CHECK (is_active IN (0,1)), canonical_json TEXT NOT NULL);
CREATE UNIQUE INDEX claims_active ON claims(active_key) WHERE is_active = 1;
CREATE TABLE verdicts (
 claim_id TEXT PRIMARY KEY REFERENCES claims(claim_id), intrinsic_verdict TEXT NOT NULL,
 strength TEXT, reason TEXT, cache_key TEXT NOT NULL, canonical_json TEXT NOT NULL);
CREATE TABLE verdict_cache (cache_key TEXT PRIMARY KEY, canonical_json TEXT NOT NULL);
CREATE TABLE grades (
 claim_id TEXT PRIMARY KEY REFERENCES claims(claim_id),
 grader_version TEXT NOT NULL, canonical_json TEXT NOT NULL);
CREATE TABLE jobs (
 job_id TEXT PRIMARY KEY, type TEXT NOT NULL, input_hash TEXT NOT NULL,
 status TEXT NOT NULL, result_artifact TEXT);
PRAGMA user_version=1;
"""


class Store:
    def __init__(self, path: Path):
        path.parent.mkdir(parents=True, exist_ok=True)
        self.connection = sqlite3.connect(path)
        try:
            self.connection.execute("PRAGMA foreign_keys=ON")
            version = self.connection.execute("PRAGMA user_version").fetchone()[0]
            if version == 0:
                if self.connection.execute(
                    "SELECT name FROM sqlite_master WHERE type='table'"
                ).fetchone():
                    raise ValueError("unversioned existing database; refusing to modify")
                self.connection.executescript("BEGIN;\n" + DDL + "\nCOMMIT;")
            elif version != 1:
                raise ValueError(f"unsupported database version {version}")
        except Exception:
            self.connection.close()
            raise

    def __enter__(self) -> Self:
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        self.connection.close()

    def add_binary(
        self,
        sha256: str,
        program_id: str,
        variant_id: str,
        split: str,
        stripped_path: str,
        targets_hash: str,
    ) -> None:
        with self.connection:
            self.connection.execute(
                "INSERT INTO binaries VALUES (?,?,?,?,?,?)",
                (sha256, program_id, variant_id, split, stripped_path, targets_hash),
            )

    def add_run(
        self,
        run_id: str,
        origin: str,
        source_id: str,
        manifest_hash: str,
        created_at: str | None = None,
    ) -> None:
        with self.connection:
            self.connection.execute(
                "INSERT INTO runs VALUES (?,?,?,?,?,?)",
                (run_id, origin, source_id, manifest_hash, "pending", created_at),
            )

    def set_run_state(self, run_id: str, state: str) -> None:
        with self.connection:
            cursor = self.connection.execute(
                "UPDATE runs SET state=? WHERE run_id=?", (state, run_id)
            )
            if cursor.rowcount != 1:
                raise KeyError(run_id)

    def add_claim(self, claim: Claim) -> None:
        key: list[JsonValue] = [claim.run_id, claim.subject.address, claim.type]
        if claim.type == "call_relation":
            key.append(str(claim.body.model_dump()["callee"]))
        with self.connection:
            self.connection.execute(
                "INSERT INTO claims VALUES (?,?,?,?,?,?,?,?)",
                (
                    claim.claim_id,
                    claim.run_id,
                    claim.binary_sha256,
                    claim.subject.address,
                    claim.type,
                    canonical_bytes(key).decode(),
                    1,
                    canonical_bytes(claim).decode(),
                ),
            )

    def deactivate_claim(self, claim_id: str) -> None:
        with self.connection:
            cursor = self.connection.execute(
                "UPDATE claims SET is_active=0 WHERE claim_id=?", (claim_id,)
            )
            if cursor.rowcount != 1:
                raise KeyError(claim_id)

    def get_claim(self, claim_id: str) -> Claim:
        return Claim.model_validate_json(self._record("claims", claim_id))

    def get_verdict(self, claim_id: str) -> Verdict:
        return Verdict.model_validate_json(self._record("verdicts", claim_id))

    def get_grade(self, claim_id: str) -> Grade:
        return Grade.model_validate_json(self._record("grades", claim_id))

    def _record(self, table: Literal["claims", "verdicts", "grades"], claim_id: str) -> str:
        row = self.connection.execute(
            f"SELECT canonical_json FROM {table} WHERE claim_id=?", (claim_id,)
        ).fetchone()
        if row is None:
            raise KeyError(claim_id)
        return str(row[0])

    def add_verdict(self, verdict: Verdict, cache_key: str) -> None:
        with self.connection:
            self.connection.execute(
                "INSERT INTO verdicts VALUES (?,?,?,?,?,?)",
                (
                    verdict.claim_id,
                    verdict.intrinsic_verdict,
                    verdict.strength,
                    verdict.reason,
                    cache_key,
                    canonical_bytes(verdict).decode(),
                ),
            )

    def cache_verdict(self, cache_key: str, verdict: Verdict) -> None:
        payload = canonical_bytes(verdict.model_dump(mode="json", exclude={"claim_id"})).decode()
        with self.connection:
            existing = self.connection.execute(
                "SELECT canonical_json FROM verdict_cache WHERE cache_key=?", (cache_key,)
            ).fetchone()
            if existing is not None and existing[0] != payload:
                raise ValueError("non-deterministic verdict cache collision")
            self.connection.execute(
                "INSERT OR IGNORE INTO verdict_cache VALUES (?,?)", (cache_key, payload)
            )

    def cached_verdict(self, cache_key: str, claim_id: ClaimId) -> Verdict | None:
        row = self.connection.execute(
            "SELECT canonical_json FROM verdict_cache WHERE cache_key=?", (cache_key,)
        ).fetchone()
        if row is None:
            return None
        payload = json.loads(row[0])
        if "claim_id" in payload:
            raise ValueError("cache payload contains claim identity")
        return Verdict.model_validate(payload | {"claim_id": claim_id})

    def add_grade(self, grade: Grade) -> None:
        with self.connection:
            self.connection.execute(
                "INSERT INTO grades VALUES (?,?,?)",
                (grade.claim_id, grade.grader_version, canonical_bytes(grade).decode()),
            )

    def add_job(self, job: Job) -> None:
        input_hash = content_hash(job.model_dump(mode="json", exclude={"job_id"}))
        with self.connection:
            self.connection.execute(
                "INSERT INTO jobs VALUES (?,?,?,?,?)",
                (job.job_id, job.type, input_hash, "pending", None),
            )

    def finish_job(self, result: JobResult, artifact: str) -> None:
        with self.connection:
            cursor = self.connection.execute(
                "UPDATE jobs SET status=?, result_artifact=? WHERE job_id=?",
                (result.status, artifact, result.job_id),
            )
            if cursor.rowcount != 1:
                raise KeyError(result.job_id)

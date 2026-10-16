"""Source-job reuse; verification jobs always execute in a fresh sandbox."""

import threading
import time
from pathlib import Path
from typing import Any

from aletheia.analysis.ghidra_session import publish_immutable
from aletheia.config import Sandbox
from aletheia.sandbox.runner import JobHandle, JobRunner
from aletheia.schema.models import Job, JobResult
from aletheia.store.artifacts import ArtifactStore

SOURCE_JOBS = {"ghidra_analyze", "capa_scan", "findcrypt_scan"}


class SourceCacheMiss(RuntimeError):
    pass


class CachedJobRunner(JobRunner):
    def __init__(
        self,
        config: Sandbox,
        input_root: Path,
        jobs_root: Path,
        artifacts: ArtifactStore,
        *,
        cache_root: Path,
        no_cache: bool = False,
        require_cache: bool = False,
    ):
        super().__init__(config, input_root, jobs_root, artifacts)
        self.cache_root = cache_root
        self.cache_root.mkdir(parents=True, exist_ok=True)
        self.no_cache, self.require_cache = no_cache, require_cache
        self.records: list[dict[str, Any]] = []
        self.lock = threading.Lock()

    def cached_result(self, job: Job) -> tuple[JobResult, str]:
        pointer = self.cache_root / (job.job_id + ".artifact")
        try:
            if pointer.is_symlink():
                raise ValueError("source cache pointer is a symlink")
            artifact = pointer.read_text()
            result = JobResult.model_validate_json(self.artifacts.get(artifact))
            if result.job_id != job.job_id or result.status != "ok":
                raise ValueError("source cache identity/status mismatch")
            return result, artifact
        except (OSError, ValueError) as exc:
            raise SourceCacheMiss(f"{job.job_id}: {exc}") from exc

    def submit(self, job: Job) -> JobHandle:
        if job.type in SOURCE_JOBS and not self.no_cache:
            try:
                result, artifact = self.cached_result(job)
            except SourceCacheMiss:
                if self.require_cache:
                    raise
            else:
                return JobHandle(
                    job,
                    self.jobs_root,
                    None,
                    time.monotonic(),
                    early_result=result,
                    result_artifact=artifact,
                    cached=True,
                )
        return super().submit(job)

    def wait(self, handle: JobHandle) -> JobResult:
        if handle.cached:
            assert handle.early_result is not None
            result = handle.early_result
        else:
            result = super().wait(handle)
        with self.lock:
            self.records.append(
                {
                    "job": handle.job.model_dump(mode="json"),
                    "artifact": handle.result_artifact,
                    "cached": handle.cached,
                    "measurement": handle.measurement,
                }
            )
        if not handle.cached and handle.job.type in SOURCE_JOBS and result.status == "ok":
            assert handle.result_artifact is not None
            pointer = self.cache_root / (handle.job.job_id + ".artifact")
            publish_immutable(pointer, handle.result_artifact.encode())
        return result

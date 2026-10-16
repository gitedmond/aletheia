"""Fresh, bounded Docker jobs. The host transports opaque inputs and validated JSON only."""

import hashlib
import json
import os
import re
import shutil
import subprocess
import tempfile
import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from pathlib import Path

from aletheia.config import Sandbox
from aletheia.sandbox.policy import container_args
from aletheia.schema.canonical import canonical_bytes
from aletheia.schema.models import Job, JobResult
from aletheia.store.artifacts import ArtifactStore
from aletheia.worker.main import guarded_input


@dataclass
class JobHandle:
    job: Job
    directory: Path
    container_id: str | None
    started: float
    early_result: JobResult | None = None
    result_artifact: str | None = None
    cached: bool = False
    measurement: dict[str, int | float | str] | None = None


class JobRunner:
    def __init__(
        self, config: Sandbox, input_root: Path, jobs_root: Path, artifacts: ArtifactStore
    ):
        self.config = config
        self.input_root = input_root.resolve()
        self.jobs_root = jobs_root.resolve()
        self.jobs_root.mkdir(parents=True, exist_ok=True)
        self.artifacts = artifacts

    def submit(self, job: Job) -> JobHandle:
        directory = Path(tempfile.mkdtemp(prefix=job.job_id + "-", dir=self.jobs_root))
        inputs, outputs = directory / "in", directory / "out"
        inputs.mkdir()
        outputs.mkdir()
        handle = JobHandle(job, directory, None, time.monotonic())
        try:
            for name in job.inputs.values():
                source = guarded_input(self.input_root, name)
                if "private" in source.resolve().parts:
                    raise ValueError("private files cannot be submitted")
                destination = directory / name
                destination.parent.mkdir(parents=True, exist_ok=True)
                shutil.copyfile(source, destination)
                with destination.open("rb") as stream:
                    digest = hashlib.file_digest(stream, "sha256").hexdigest()
                if digest != destination.stem:
                    raise ValueError("input content does not match its pinned hash")
            (inputs / "job.json").write_bytes(canonical_bytes(job))
            args = container_args(self.config, inputs, outputs, os.getuid(), os.getgid())
            response = subprocess.run(
                ["docker", "create", *args, self.config.image_analysis, "/job"],
                check=True,
                capture_output=True,
                text=True,
                timeout=30,
            )
            cid = response.stdout.strip()
            if not re.fullmatch(r"[0-9a-f]{64}", cid):
                raise ValueError("invalid Docker container ID")
            handle.container_id = cid
            subprocess.run(["docker", "start", cid], capture_output=True, check=True, timeout=30)
        except (ValueError, OSError, subprocess.SubprocessError) as exc:
            code = "bad_input" if isinstance(exc, ValueError) else "internal"
            handle.early_result = JobResult(job_id=job.job_id, status="error", error_code=code)
        return handle

    def wait(self, handle: JobHandle) -> JobResult:
        result = handle.early_result
        cid = handle.container_id
        try:
            if result is None:
                if cid is None:
                    raise RuntimeError("job has no container")
                remaining = max(
                    0.001, self.config.wall_timeout_s - (time.monotonic() - handle.started)
                )
                exit_code = ""
                try:
                    waited = subprocess.run(
                        ["docker", "wait", cid],
                        check=True,
                        capture_output=True,
                        text=True,
                        timeout=remaining,
                    )
                    exit_code = waited.stdout.strip()
                except subprocess.TimeoutExpired:
                    subprocess.run(["docker", "kill", cid], capture_output=True, timeout=30)
                    result = JobResult(
                        job_id=handle.job.job_id, status="error", error_code="wall_timeout"
                    )
                if result is None:
                    oom = (
                        subprocess.run(
                            ["docker", "inspect", cid, "--format", "{{.State.OOMKilled}}"],
                            check=True,
                            capture_output=True,
                            text=True,
                            timeout=30,
                        ).stdout.strip()
                        == "true"
                    )
                    if oom:
                        result = JobResult(
                            job_id=handle.job.job_id, status="error", error_code="oom"
                        )
                    elif exit_code != "0":
                        code = "bad_input" if exit_code == "2" else "internal"
                        result = JobResult(
                            job_id=handle.job.job_id, status="error", error_code=code
                        )
                    else:
                        output = handle.directory / "out/result.json"
                        if (
                            output.is_symlink()
                            or not output.is_file()
                            or output.stat().st_size > 16_777_216
                        ):
                            raise ValueError("missing, unsafe, or oversized worker result")
                        result = JobResult.model_validate_json(output.read_bytes())
                        if result.job_id != handle.job.job_id:
                            raise ValueError("worker result identity mismatch")
        except (OSError, ValueError, RuntimeError, subprocess.SubprocessError):
            result = JobResult(job_id=handle.job.job_id, status="error", error_code="internal")
        finally:
            handle.measurement = {"wall_seconds": time.monotonic() - handle.started}
            try:
                resource = handle.directory / "out/resources.json"
                if resource.is_symlink() or resource.stat().st_size > 4096:
                    raise ValueError("unsafe resource measurement")
                data = json.loads(resource.read_bytes())
                for key in ("peak_memory_bytes", "cpu_microseconds"):
                    if type(data.get(key)) is not int or data[key] < 0:
                        raise ValueError(str(data.get("error", "missing resource measurement")))
                    handle.measurement[key] = data[key]
            except (OSError, ValueError, TypeError) as exc:
                handle.measurement["error"] = type(exc).__name__ + ": " + str(exc)[:200]
            if cid:
                try:
                    subprocess.run(
                        ["docker", "rm", "-f", cid], capture_output=True, check=True, timeout=30
                    )
                except (OSError, subprocess.SubprocessError):
                    result = JobResult(
                        job_id=handle.job.job_id,
                        status="error",
                        error_code="internal",
                        output={"detail": "container cleanup failed"},
                    )
        try:
            handle.result_artifact = self.artifacts.put(canonical_bytes(result))
        except (OSError, ValueError):
            handle.result_artifact = None
            result = JobResult(
                job_id=handle.job.job_id,
                status="error",
                error_code="internal",
                output={"detail": "result artifact storage failed"},
            )
        return result

    def run_many(self, jobs: list[Job]) -> list[JobResult]:
        def run(job: Job) -> JobResult:
            return self.wait(self.submit(job))

        with ThreadPoolExecutor(max_workers=self.config.concurrency) as pool:
            return list(pool.map(run, jobs))

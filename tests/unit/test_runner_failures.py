import subprocess
import time

from aletheia.config import Sandbox
from aletheia.sandbox.runner import JobHandle, JobRunner
from aletheia.schema.canonical import canonical_bytes
from aletheia.schema.models import Job, JobResult
from aletheia.store.artifacts import ArtifactStore


def handle(tmp_path, payload=None):
    job = Job.create("verify_static", {}, {})
    (tmp_path / "out").mkdir()
    result = JobResult(job_id=job.job_id, status="ok")
    (tmp_path / "out/result.json").write_bytes(
        canonical_bytes(result) if payload is None else payload
    )
    return JobHandle(job, tmp_path, "a" * 64, time.monotonic())


def docker_response(args, **kwargs):
    text = "false" if args[1] == "inspect" else "0"
    return subprocess.CompletedProcess(args, 0, stdout=text, stderr="")


def test_cleanup_failure_cannot_report_success(tmp_path, monkeypatch):
    def failed_cleanup(args, **kwargs):
        if args[1] == "rm":
            if kwargs.get("check"):
                raise subprocess.CalledProcessError(1, args)
            return subprocess.CompletedProcess(args, 1, stdout="", stderr="daemon failure")
        return docker_response(args, **kwargs)

    monkeypatch.setattr(subprocess, "run", failed_cleanup)
    run = JobRunner(Sandbox(), tmp_path, tmp_path / "jobs", ArtifactStore(tmp_path / "artifacts"))
    result = run.wait(handle(tmp_path))
    assert result.status == "error" and result.error_code == "internal"
    assert result.output["detail"] == "container cleanup failed"


def test_malformed_worker_result_is_not_accepted(tmp_path, monkeypatch):
    monkeypatch.setattr(subprocess, "run", docker_response)
    run = JobRunner(Sandbox(), tmp_path, tmp_path / "jobs", ArtifactStore(tmp_path / "artifacts"))
    result = run.wait(handle(tmp_path, b'{"status":"ok"}'))
    assert result.status == "error" and result.error_code == "internal"

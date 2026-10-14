import subprocess
import time

import pytest

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


@pytest.mark.parametrize("failure", [OSError("disk full"), ValueError("corrupt artifact")])
def test_result_storage_failure_returns_error_after_cleanup(tmp_path, monkeypatch, failure):
    cleaned = []

    def response(args, **kwargs):
        if args[1] == "rm":
            cleaned.append(args[2:])
        return docker_response(args, **kwargs)

    def failed_put(data):
        raise failure

    monkeypatch.setattr(subprocess, "run", response)
    run = JobRunner(Sandbox(), tmp_path, tmp_path / "jobs", ArtifactStore(tmp_path / "artifacts"))
    monkeypatch.setattr(run.artifacts, "put", failed_put)
    item = handle(tmp_path)
    result = run.wait(item)
    assert result.status == "error" and result.error_code == "internal"
    assert result.output["detail"] == "result artifact storage failed"
    assert item.result_artifact is None
    assert cleaned == [["-f", "a" * 64]]


def test_batch_survives_result_storage_failure(tmp_path, monkeypatch):
    run = JobRunner(
        Sandbox(concurrency=1), tmp_path, tmp_path / "jobs", ArtifactStore(tmp_path / "artifacts")
    )
    jobs = [Job.create("verify_static", {}, {"index": i}) for i in range(2)]

    def submit(job):
        return JobHandle(
            job, tmp_path, None, time.monotonic(), JobResult(job_id=job.job_id, status="ok")
        )

    def failed_put(data):
        raise OSError("disk full")

    monkeypatch.setattr(run, "submit", submit)
    monkeypatch.setattr(run.artifacts, "put", failed_put)
    results = run.run_many(jobs)
    assert [result.job_id for result in results] == [job.job_id for job in jobs]
    assert all(result.error_code == "internal" for result in results)

"""Real Docker acceptance checks; test handlers are absent from production images."""

import json
import os
import subprocess
from pathlib import Path

import pytest

from aletheia.config import Config
from aletheia.sandbox.runner import JobRunner
from aletheia.schema.models import Job
from aletheia.store.artifacts import ArtifactStore

pytestmark = pytest.mark.integration
TEST_WORKER = """
import errno, os, socket, sys, time
from pathlib import Path
from aletheia.schema.models import JobResult
from aletheia.worker.main import execute
def handler(job):
    mode = job.params.get("mode", "echo")
    if mode == "sleep":
        time.sleep(60)
    if mode == "oom":
        blocks = []
        while True:
            blocks.append(bytearray(32 * 1024 * 1024))
    if mode == "isolation":
        blocked = {}
        for name, path in [("root", Path("/forbidden")), ("input", Path("/job/in/job.json"))]:
            try:
                path.write_text("forbidden")
                blocked[name] = False
            except OSError as exc:
                blocked[name] = exc.errno in (errno.EROFS, errno.EACCES)
        try:
            socket.create_connection(("1.1.1.1", 443), timeout=1).close()
            blocked["network"] = False
        except OSError:
            blocked["network"] = True
        return JobResult(job_id=job.job_id, status="ok",
            output={"blocked": blocked, "uid": os.getuid()})
    if mode == "wrong":
        return JobResult(job_id="j_" + "f"*64, status="ok")
    return JobResult(job_id=job.job_id, status="ok", output=job.params)
execute(Path(sys.argv[1]), {"verify_static": handler})
"""


@pytest.fixture(scope="module")
def image(tmp_path_factory):
    cfg = Config.read(Path("aletheia.toml"))
    directory = tmp_path_factory.mktemp("sandbox-test-image")
    (directory / "test_worker.py").write_text(TEST_WORKER)
    # BuildKit resolves FROM as a named reference, not a Docker config image ID.
    base = "aletheia-test-base:" + cfg.sandbox.image_analysis.removeprefix("sha256:")
    subprocess.run(["docker", "image", "tag", cfg.sandbox.image_analysis, base], check=True)
    assert (
        subprocess.check_output(
            ["docker", "image", "inspect", base, "--format", "{{.Id}}"], text=True
        ).strip()
        == cfg.sandbox.image_analysis
    )
    (directory / "Dockerfile").write_text(
        f"FROM {base}\nCOPY test_worker.py /opt/test_worker.py\n"
        'ENTRYPOINT ["python","/opt/test_worker.py"]\n'
    )
    tag = "aletheia-test-worker:" + cfg.sandbox.image_analysis.removeprefix("sha256:")
    result = subprocess.run(
        ["docker", "build", "--quiet", "--pull=false", "--network=none", "-t", tag, str(directory)],
        capture_output=True,
        text=True,
        timeout=120,
    )
    assert result.returncode == 0, result.stderr
    assert (
        subprocess.check_output(
            ["docker", "image", "inspect", base, "--format", "{{.Id}}"], text=True
        ).strip()
        == cfg.sandbox.image_analysis
    )
    image = subprocess.check_output(
        ["docker", "image", "inspect", tag, "--format", "{{.Id}}"], text=True
    ).strip()
    try:
        yield image
    finally:
        subprocess.run(
            ["docker", "image", "rm", tag, base], capture_output=True, check=True, timeout=30
        )


def runner(tmp_path, image, **changes):
    cfg = Config.read(Path("aletheia.toml")).sandbox.model_dump()
    cfg.update(image_analysis=image, **changes)
    config = Config.read(Path("aletheia.toml")).sandbox.model_validate(cfg)
    (tmp_path / "in").mkdir()
    return JobRunner(config, tmp_path, tmp_path / "jobs", ArtifactStore(tmp_path / "artifacts"))


def test_echo_fresh_containers_and_order(tmp_path, image):
    run = runner(tmp_path, image, concurrency=2)
    jobs = [Job.create("verify_static", {}, {"number": n}) for n in range(4)]
    results = run.run_many(jobs)
    assert [r.output["number"] for r in results] == [0, 1, 2, 3]
    assert [r.job_id for r in results] == [j.job_id for j in jobs]
    assert all(r.status == "ok" and r.budget_used.instructions == 0 for r in results)


def test_network_root_inputs_uid_and_limits(tmp_path, image):
    run = runner(tmp_path, image)
    handle = run.submit(Job.create("verify_static", {}, {"mode": "isolation"}))
    inspection = json.loads(subprocess.check_output(["docker", "inspect", handle.container_id]))[0]
    assert inspection["HostConfig"]["Memory"] == 6 * 1024**3
    assert inspection["HostConfig"]["NanoCpus"] == 2_000_000_000
    assert inspection["HostConfig"]["PidsLimit"] == 256
    assert inspection["HostConfig"]["ReadonlyRootfs"] is True
    assert inspection["HostConfig"]["NetworkMode"] == "none"
    result = run.wait(handle)
    assert result.status == "ok"
    assert result.output == {
        "uid": os.getuid(),
        "blocked": {"root": True, "input": True, "network": True},
    }
    assert handle.result_artifact and run.artifacts.get(handle.result_artifact)


def test_wall_timeout_is_explicit_and_container_removed(tmp_path, image):
    run = runner(tmp_path, image, wall_timeout_s=1)
    handle = run.submit(Job.create("verify_static", {}, {"mode": "sleep"}))
    result = run.wait(handle)
    assert result.status == "error" and result.error_code == "wall_timeout"
    assert (
        subprocess.run(["docker", "inspect", handle.container_id], capture_output=True).returncode
        != 0
    )


def test_memory_limit_reports_oom(tmp_path, image):
    run = runner(tmp_path, image, memory_gb=1, wall_timeout_s=30)
    result = run.wait(run.submit(Job.create("verify_static", {}, {"mode": "oom"})))
    assert result.status == "error" and result.error_code == "oom"


def test_wrong_worker_identity_is_internal_error(tmp_path, image):
    run = runner(tmp_path, image)
    result = run.wait(run.submit(Job.create("verify_static", {}, {"mode": "wrong"})))
    assert result.status == "error" and result.error_code == "internal"


def test_production_unimplemented_job_is_bad_input(tmp_path):
    run = runner(tmp_path, Config.read(Path("aletheia.toml")).sandbox.image_analysis)
    result = run.wait(run.submit(Job.create("verify_static", {}, {})))
    assert result.status == "error" and result.error_code == "bad_input"


def test_contract_roundtrip_inside_installed_container(tmp_path):
    cfg = Config.read(Path("aletheia.toml")).sandbox
    script = (
        "from aletheia.schema.models import Job,JobResult; "
        "kinds=['ghidra_analyze','findcrypt_scan','capa_scan','verify_static','verify_probe']; "
        "jobs=[Job.create(t, {}, {}) for t in kinds]; "
        "assert all(Job.model_validate_json(j.model_dump_json()) == j for j in jobs); "
        "results=[JobResult(job_id=j.job_id,status='ok') for j in jobs]; "
        "assert all(JobResult.model_validate_json(r.model_dump_json()) == r for r in results)"
    )
    subprocess.run(
        [
            "docker",
            "run",
            "--rm",
            "--network",
            "none",
            "--read-only",
            "--user",
            f"{os.getuid()}:{os.getgid()}",
            "--entrypoint",
            "python",
            cfg.image_analysis,
            "-c",
            script,
        ],
        check=True,
        capture_output=True,
        timeout=30,
    )

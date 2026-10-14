import pytest

from aletheia.config import Sandbox
from aletheia.sandbox.policy import container_args
from aletheia.schema.canonical import canonical_bytes
from aletheia.schema.models import Job, JobResult
from aletheia.worker.main import execute, guarded_input


def test_worker_echo_and_explicit_unimplemented_handler(tmp_path):
    (tmp_path / "in").mkdir()
    (tmp_path / "out").mkdir()
    job = Job.create("verify_static", {}, {"message": "echo"})
    (tmp_path / "in/job.json").write_bytes(canonical_bytes(job))

    def echo(value):
        return JobResult(job_id=value.job_id, status="ok", output=value.params)

    result = execute(tmp_path, {"verify_static": echo})
    assert result.output == {"message": "echo"}
    assert JobResult.model_validate_json((tmp_path / "out/result.json").read_bytes()) == result
    result = execute(tmp_path, {})
    assert result.status == "error" and result.error_code == "bad_input"


def test_worker_handler_errors_and_wrong_identity(tmp_path):
    (tmp_path / "in").mkdir()
    (tmp_path / "out").mkdir()
    job = Job.create("verify_static", {}, {})
    (tmp_path / "in/job.json").write_bytes(canonical_bytes(job))

    def broken(value):
        raise RuntimeError("handler failed")

    assert execute(tmp_path, {"verify_static": broken}).error_code == "internal"

    def wrong(value):
        return JobResult(job_id="j_" + "f" * 64, status="ok")

    assert execute(tmp_path, {"verify_static": wrong}).error_code == "internal"


def test_runtime_paths_refuse_private_and_symlink_escape(tmp_path):
    inputs = tmp_path / "in"
    inputs.mkdir()
    good = inputs / "binary.bin"
    good.write_bytes(b"opaque")
    assert guarded_input(tmp_path, "in/binary.bin") == good
    (inputs / "escape").symlink_to(tmp_path.parent)
    for name in ("../private/x", "in/private/x", "/etc/passwd", "in/escape/secret"):
        with pytest.raises(ValueError):
            guarded_input(tmp_path, name)


def test_policy_is_fail_closed_and_has_no_repo_mount(tmp_path):
    cfg = Sandbox(image_analysis="sha256:" + "a" * 64)
    args = container_args(cfg, tmp_path / "in", tmp_path / "out", 1001, 1001)
    for pair in (
        ["--network", "none"],
        ["--user", "1001:1001"],
        ["--memory", "6g"],
        ["--cpus", "2"],
        ["--pids-limit", "256"],
        ["--pull", "never"],
    ):
        assert any(args[i : i + 2] == pair for i in range(len(args) - 1))
    assert "--read-only" in args
    assert "--privileged" not in args
    assert "docker.sock" not in " ".join(args)
    with pytest.raises(ValueError):
        container_args(Sandbox(image_analysis="latest"), tmp_path, tmp_path, 1001, 1001)
    with pytest.raises(ValueError):
        container_args(cfg, tmp_path, tmp_path, 0, 0)


@pytest.mark.parametrize(
    "name",
    [
        "in/ground_truth.json",
        "in/unstripped.bin",
        "in/o0.bin",
        "in/program.c",
        "in/program.h",
        "in/corpus/tests/test.bin",
    ],
)
def test_runtime_rejects_verifier_forbidden_inputs(tmp_path, name):
    path = tmp_path / name
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(b"forbidden")
    with pytest.raises(ValueError):
        guarded_input(tmp_path, name)

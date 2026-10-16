import json
import subprocess

import pytest
from typer.testing import CliRunner

from aletheia.cli import app
from aletheia.config import Config
from aletheia.heldout.guard import PrivateAccessError, PrivateGuard
from aletheia.heldout.hook import scan_staged
from aletheia.heldout.publish import aggregate_payload


def test_explicit_split_and_resolved_paths(tmp_path):
    root = tmp_path / "secret"
    root.mkdir()
    guard = PrivateGuard(root, "dev")
    alias = tmp_path / "alias"
    alias.symlink_to(root, target_is_directory=True)
    for path in [root / "claims.json", alias / "claims.json", root / "nested/../claims.json"]:
        with pytest.raises(PrivateAccessError):
            guard.access(path)
    PrivateGuard(root, "heldout").access(root / "claims.json")
    with pytest.raises(PrivateAccessError):
        PrivateGuard(None, "heldout")
    with pytest.raises(PrivateAccessError):
        guard.public_path(tmp_path)
    with pytest.raises(PrivateAccessError):
        PrivateGuard(root, "heldout").private_output(tmp_path / "report.md")


def test_config_routes_heldout_outputs_and_refuses_accidental_dev_access(tmp_path):
    root = tmp_path / "private"
    config = Config.model_validate({"paths": {"private_root": str(root)}})
    selected = config.for_split("heldout")
    assert selected.paths.build == str(root / "build")
    assert selected.paths.runs == str(root / "runs")
    assert selected.paths.artifacts == str(root / "artifacts")
    assert config.paths.runs == "runs"
    config.paths.runs = str(root / "runs")
    with pytest.raises(PrivateAccessError):
        config.for_split("dev")
    with pytest.raises(ValueError):
        Config.model_validate({"paths": {"private_root": "relative"}})


def test_public_cli_refuses_heldout_without_creating_outputs(tmp_path):
    config = tmp_path / "config.toml"
    config.write_text('[paths]\nruns="' + (tmp_path / "runs").as_posix() + '"\n')
    result = CliRunner().invoke(
        app, ["--config", str(config), "--split", "heldout", "run", "--source", "scripted"]
    )
    assert result.exit_code == 7, result.output
    assert not (tmp_path / "runs").exists()


def test_staged_private_token_is_blocked_and_unstaged_work_is_ignored(tmp_path):
    repo = tmp_path / "public"
    repo.mkdir()
    subprocess.run(["git", "init", "-q", str(repo)], check=True)
    private = tmp_path / "private"
    private.mkdir()
    (private / "leakage-index.json").write_text(
        json.dumps(
            {
                "program_ids": ["secret-program"],
                "function_names": ["secret_function"],
                "binary_sha256": ["a" * 64],
            }
        )
    )
    public_file = repo / "result.txt"
    public_file.write_text("safe aggregate counts only\n")
    subprocess.run(["git", "-C", str(repo), "add", "result.txt"], check=True)
    public_file.write_text("secret-program is an unstaged edit")
    assert scan_staged(repo, private) == []
    for token in ["secret-program", "secret_function", "a" * 64]:
        public_file.write_text(token)
        subprocess.run(["git", "-C", str(repo), "add", "result.txt"], check=True)
        findings = scan_staged(repo, private)
        assert len(findings) == 1
        assert findings[0]["path"] == "result.txt"
        assert token not in json.dumps(findings)
    (private / "leakage-index.json").unlink()
    with pytest.raises(PrivateAccessError):
        scan_staged(repo, private)


def test_public_aggregate_does_not_copy_identifiers_or_free_text():
    from aletheia.metrics import Interval, MetricsReport, Population, Summary

    pop = Population(
        summary=Summary(
            metrics={"decisiveness": 0.5}, counts={"claims": 2}, confusion={}, exclusions={}
        ),
        intervals={"decisiveness": Interval(low=0, high=1, defined_resamples=10)},
    )
    report = MetricsReport(
        sources=[],
        independent=pop,
        independent_by_scenario={},
        independent_by_type={},
        independent_methods={},
        included_sources=[],
        excluded_sources=[],
        program_clusters=["private-program"],
        bootstrap_seed=1,
        bootstrap_resamples=10,
        notes=["secret_function"],
    )
    result = aggregate_payload(report, ["b" * 64])
    assert result["independent"]["summary"]["counts"]["claims"] == 2
    encoded = json.dumps(result)
    assert "private-program" not in encoded
    assert "secret_function" not in encoded


def test_private_report_output_refused_before_loading_runs(tmp_path, monkeypatch):
    root = tmp_path / "private"
    config = tmp_path / "config.toml"
    config.write_text('[paths]\nprivate_root="' + root.as_posix() + '"\n')

    def unexpected(*args):
        raise AssertionError("must validate output before reading any run")

    monkeypatch.setattr("aletheia.report.collect", unexpected)
    result = CliRunner().invoke(
        app,
        [
            "--config",
            str(config),
            "--split",
            "heldout",
            "report",
            "--runs",
            "r_" + "a" * 16,
            "--private",
            "--out",
            str(tmp_path / "public.md"),
        ],
    )
    assert result.exit_code == 7, result.output
    assert not (tmp_path / "public.md").exists()


def test_schema_output_cannot_write_private_tree_without_scope(tmp_path):
    root = tmp_path / "private"
    config = tmp_path / "config.toml"
    config.write_text('[paths]\nprivate_root="' + root.as_posix() + '"\n')
    result = CliRunner().invoke(
        app, ["--config", str(config), "schema", "export", "--directory", str(root / "schemas")]
    )
    assert result.exit_code == 7, result.output
    assert not root.exists()


def test_hook_detects_binary_content_and_private_paths(tmp_path):
    import hashlib

    repo = tmp_path / "repo"
    repo.mkdir()
    private = tmp_path / "private"
    private.mkdir()
    subprocess.run(["git", "-C", str(repo), "init", "-q"], check=True)
    payload = b"opaque held-out executable bytes"
    (private / "leakage-index.json").write_text(
        json.dumps(
            {
                "program_ids": ["hidden-id"],
                "function_names": [],
                "binary_sha256": [hashlib.sha256(payload).hexdigest()],
            }
        )
    )
    (repo / "renamed.bin").write_bytes(payload)
    (repo / "hidden-id.txt").write_text("no secret tokens in this body")
    subprocess.run(["git", "-C", str(repo), "add", "."], check=True)
    assert {row["path"] for row in scan_staged(repo, private)} == {"renamed.bin", "hidden-id.txt"}


def test_opaque_binary_transport_under_private_root_retains_input_boundary(tmp_path, monkeypatch):
    import hashlib
    from types import SimpleNamespace

    from aletheia.config import Sandbox
    from aletheia.sandbox.runner import JobRunner
    from aletheia.schema.models import Job
    from aletheia.store.artifacts import ArtifactStore

    public = tmp_path / "private" / "runs" / "public"
    (public / "in").mkdir(parents=True)
    payload = b"opaque stripped test input"
    name = hashlib.sha256(payload).hexdigest() + ".bin"
    (public / "in" / name).write_bytes(payload)
    calls = []

    def command(args, **kwargs):
        calls.append(args)
        return SimpleNamespace(stdout="a" * 64, returncode=0)

    monkeypatch.setattr("aletheia.sandbox.runner.subprocess.run", command)
    runner = JobRunner(
        Sandbox(image_analysis="sha256:" + "a" * 64),
        public,
        tmp_path / "jobs",
        ArtifactStore(tmp_path / "artifacts"),
    )
    handle = runner.submit(Job.create("ghidra_analyze", {"binary": "in/" + name}, {}))
    assert handle.container_id == "a" * 64
    assert any(args[:2] == ["docker", "create"] for args in calls)
    assert (handle.directory / "in" / name).read_bytes() == payload
    with pytest.raises(ValueError):
        Job.create("ghidra_analyze", {"binary": "in/private/" + name}, {})
    private_input = public / "in" / "private"
    private_input.mkdir()
    (private_input / name).write_bytes(payload)
    (public / "in" / "alias").symlink_to(private_input, target_is_directory=True)
    rejected = runner.submit(Job.create("ghidra_analyze", {"binary": "in/alias/" + name}, {}))
    assert rejected.early_result is not None and rejected.early_result.error_code == "bad_input"
    assert len([args for args in calls if args[:2] == ["docker", "create"]]) == 1


def test_installed_hook_blocks_a_real_commit_and_preserves_existing_hooks(tmp_path):
    import os

    from aletheia.heldout.hook import install

    repo = tmp_path / "repo"
    private = tmp_path / "private"
    repo.mkdir()
    private.mkdir()
    subprocess.run(["git", "-C", str(repo), "init", "-q"], check=True)
    (private / "leakage-index.json").write_text(
        json.dumps({"program_ids": ["secret-program"], "function_names": [], "binary_sha256": []})
    )
    hook = install(repo, private)
    assert install(repo, private) == hook
    (repo / "notes.txt").write_text("secret-program")
    subprocess.run(["git", "-C", str(repo), "add", "notes.txt"], check=True)
    environment = dict(
        os.environ,
        GIT_AUTHOR_NAME="test",
        GIT_AUTHOR_EMAIL="test@example.invalid",
        GIT_COMMITTER_NAME="test",
        GIT_COMMITTER_EMAIL="test@example.invalid",
    )
    blocked = subprocess.run(
        ["git", "-C", str(repo), "commit", "-m", "must be blocked"],
        capture_output=True,
        env=environment,
    )
    assert blocked.returncode != 0
    assert b"heldout_content" in blocked.stderr
    (repo / "notes.txt").write_text("aggregate counts only")
    subprocess.run(["git", "-C", str(repo), "add", "notes.txt"], check=True)
    subprocess.run(
        ["git", "-C", str(repo), "commit", "-m", "safe aggregate"],
        check=True,
        capture_output=True,
        env=environment,
    )
    hook.write_text("#!/bin/sh\necho existing-user-hook\n")
    with pytest.raises(ValueError, match="preserving existing"):
        install(repo, private)
    assert hook.read_text() == "#!/bin/sh\necho existing-user-hook\n"


@pytest.mark.parametrize("operation", ["delete", "rename"])
def test_hook_scans_deleted_and_rename_source_metadata(tmp_path, operation):
    repo, private = tmp_path / "repo", tmp_path / "private"
    repo.mkdir()
    private.mkdir()
    subprocess.run(["git", "-C", str(repo), "init", "-q"], check=True)
    old = "secret-program.txt"
    (repo / old).write_text("safe body without identifiers")
    subprocess.run(["git", "-C", str(repo), "add", old], check=True)
    subprocess.run(
        [
            "git",
            "-C",
            str(repo),
            "-c",
            "user.name=test",
            "-c",
            "user.email=test@example.invalid",
            "commit",
            "-qm",
            "synthetic starting point",
        ],
        check=True,
    )
    (private / "leakage-index.json").write_text(
        json.dumps({"program_ids": ["secret-program"], "function_names": [], "binary_sha256": []})
    )
    command = ["rm", old] if operation == "delete" else ["mv", old, "safe.txt"]
    subprocess.run(["git", "-C", str(repo), *command], check=True, capture_output=True)
    assert scan_staged(repo, private) == [{"path": old, "reason": "heldout_content"}]

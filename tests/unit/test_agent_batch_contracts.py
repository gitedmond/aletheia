"""Fit populations reject verifier/grader drift; CLI failures preserve completed samples."""

from contextlib import nullcontext
from types import SimpleNamespace

import pytest

from aletheia.agent.batch import fit_dev
from aletheia.orchestrate import write_json
from aletheia.schema.models import ManifestInput, RunManifest


@pytest.mark.parametrize(
    "field",
    ["analysis_options_hash", "pack_hashes", "verifier_version", "grader_version", "run_config"],
)
def test_fit_rejects_verification_and_grading_scope_drift(tmp_path, field):
    base = ManifestInput(
        source_config={"source_id": "agent:fixture", "split": "dev", "run_config": {}},
        binaries=["a" * 64],
        versions={},
        image_digests={},
        analysis_options_hash="b" * 64,
        pack_hashes={},
        mapping_hashes={},
        verifier_version="1",
        grader_version="1",
        seeds={},
    )
    changed = base.model_copy(deep=True)
    if field == "run_config":
        changed.source_config["run_config"] = {"grading_context_hash": "c" * 64}
    else:
        setattr(
            changed,
            field,
            {"crc32": "c" * 64}
            if field == "pack_hashes"
            else "c" * 64
            if field.endswith("hash")
            else "2",
        )
    runs = []
    for item in (base, changed):
        manifest = RunManifest.create(item)
        runs.append(manifest.run_id)
        root = tmp_path / manifest.run_id
        write_json(root / "manifest.json", manifest)
        write_json(root / "run.json", {"program": "example"})
    benchmark = SimpleNamespace(
        config=SimpleNamespace(guard=SimpleNamespace(split="dev")),
        root=tmp_path,
        directory=lambda run: tmp_path / run,
        store=lambda: nullcontext(None),
        claims=lambda *_: [],
    )
    with pytest.raises(ValueError, match="configuration drift"):
        fit_dev(benchmark, runs)


def test_agent_cli_returns_completed_samples_on_later_error(tmp_path, monkeypatch):
    import json

    import yaml
    from typer.testing import CliRunner

    from aletheia.cli import app
    from aletheia.config import Config
    from aletheia.llm.provider import AgentConfig

    cfg = Config()
    cfg.paths.build = str(tmp_path / "build")
    cfg.paths.runs = str(tmp_path / "runs")
    cfg.paths.artifacts = str(tmp_path / "artifacts")
    cfg.sandbox.image_build = "sha256:" + "b" * 64
    monkeypatch.setattr("aletheia.cli.read_config", lambda _: cfg)
    agent = AgentConfig(
        config_id="fixture",
        base_url="http://127.0.0.1:11434/v1",
        model="fake",
        model_file_sha256="a" * 64,
    )
    path = tmp_path / "agent.yaml"
    path.write_text(yaml.safe_dump(agent.model_dump(mode="json")))
    monkeypatch.setattr("aletheia.agent.batch.provider_for", lambda _: None)

    def run(*args):
        if args[-1] == 0:
            return "r_" + "a" * 16, SimpleNamespace(status="completed", reason=None)
        raise ValueError("interrupted sample")

    monkeypatch.setattr("aletheia.agent.batch.run_agent", run)
    result = CliRunner().invoke(
        app, ["agents", "run", "--config", str(path), "--program", "example", "--samples", "2"]
    )
    assert result.exit_code == 1
    data = json.loads(result.stdout)
    assert data["status"] == "error" and data["error"] == "interrupted sample"
    assert data["runs"] == [{"run_id": "r_" + "a" * 16, "status": "completed", "reason": None}]


@pytest.mark.parametrize("missing", ["grade", "verdict"])
def test_fit_rejects_incomplete_run_with_run_identity(tmp_path, missing):
    manifest = RunManifest.create(
        ManifestInput(
            source_config={"source_id": "agent:fixture", "split": "dev"},
            binaries=["a" * 64],
            versions={},
            image_digests={},
            analysis_options_hash="b" * 64,
            pack_hashes={},
            mapping_hashes={},
            verifier_version="1",
            grader_version="1",
            seeds={},
        )
    )
    run = manifest.run_id
    write_json(tmp_path / run / "manifest.json", manifest)
    write_json(tmp_path / run / "run.json", {"program": "example"})

    def absent(_):
        raise KeyError(missing)

    store = SimpleNamespace(
        connection=SimpleNamespace(execute=lambda *_: SimpleNamespace(fetchone=lambda: ("dev",))),
        get_grade=absent if missing == "grade" else lambda _: None,
        get_verdict=absent,
    )
    benchmark = SimpleNamespace(
        config=SimpleNamespace(guard=SimpleNamespace(split="dev")),
        root=tmp_path,
        directory=lambda run: tmp_path / run,
        store=lambda: nullcontext(store),
        claims=lambda *_: [SimpleNamespace(claim_id="missing", binary_sha256="a" * 64)],
    )
    with pytest.raises(ValueError, match=run + " is incomplete"):
        fit_dev(benchmark, [run])

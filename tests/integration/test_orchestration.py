"""T22 acceptance: one real program, all sources, persisted runs and method audits."""

import json
from pathlib import Path

import pytest
from typer.testing import CliRunner

from aletheia.cli import app
from aletheia.config import Config
from aletheia.corpus.build import Variant, build_program
from aletheia.orchestrate import Benchmark
from aletheia.schema.models import RunManifest

pytestmark = [pytest.mark.integration, pytest.mark.slow]


def test_one_program_all_sources_and_idempotent_run(tmp_path):
    cfg = Config.read(Path("aletheia.toml"))
    cfg.paths.build = str(tmp_path / "programs")
    cfg.paths.runs = str(tmp_path / "runs")
    cfg.paths.artifacts = str(tmp_path / "artifacts")
    build_program(
        Path("corpus/tierA/crc32tool"),
        Variant(image=cfg.sandbox.image_build, output_root=Path(cfg.paths.build)),
    )
    benchmark = Benchmark(cfg)
    runs = []
    for source in ("scripted", "capa", "findcrypt"):
        produced = benchmark.run("crc32tool", source)
        assert produced
        runs.extend(produced)
        assert benchmark.run("crc32tool", source) == produced
    assert len(set(runs)) == len(runs)
    with benchmark.store() as store:
        for run in runs:
            manifest = RunManifest.model_validate_json(
                (Path(cfg.paths.runs) / run / "manifest.json").read_bytes()
            )
            assert manifest.run_id == run
            state = store.connection.execute(
                "SELECT state FROM runs WHERE run_id=?", (run,)
            ).fetchone()[0]
            assert state == "completed"
            claims = benchmark.claims(store, run)
            for claim in claims:
                verdict = store.get_verdict(claim.claim_id)
                store.get_grade(claim.claim_id)
                assert verdict.intrinsic_verdict != "ERROR", verdict
                assert any(item.kind == "method_results" for item in verdict.evidence)
            assert (Path(cfg.paths.runs) / run / "metrics.json").is_file()
    accounting = benchmark.accounting(runs)
    assert accounting["executed_jobs"] > 0
    assert accounting["cpu_seconds"] > 0
    assert accounting["peak_memory_bytes"] > 0
    assert accounting["measurement_errors"] == []
    metrics = benchmark.score(runs)
    assert metrics.independent.summary.counts["claims"] > 0
    assert {row.source.origin for row in metrics.sources} == {"scripted", "tool"}
    assert any(row.source.shares_backend for row in metrics.sources)
    config_path = tmp_path / "benchmark.toml"
    config_text = Path("aletheia.toml").read_text()
    for name in ("build", "runs", "artifacts"):
        config_text = config_text.replace(
            f'{name} = "{name}"', f"{name} = {json.dumps(getattr(cfg.paths, name))}"
        )
    config_path.write_text(config_text)
    cli = CliRunner()
    for command in (
        ["verify", "--run", runs[0]],
        ["score", "--run", runs[0]],
        ["tools", "run", "--tool", "capa,findcrypt", "--program", "crc32tool"],
        ["claims", "scripted", "--program", "crc32tool"],
    ):
        result = cli.invoke(app, ["--config", str(config_path), "--json", *command])
        assert result.exit_code == 0, result.output
    submission = next((Path(cfg.paths.runs) / "scripted/crc32tool").glob("*.jsonl"))
    result = cli.invoke(
        app,
        [
            "--config",
            str(config_path),
            "--json",
            "claims",
            "submit",
            "--file",
            str(submission),
            "--source",
            "scripted:v1",
        ],
    )
    assert result.exit_code == 0, result.output

    from aletheia.report import collect, render

    report_path = tmp_path / "report.md"
    result = cli.invoke(
        app,
        [
            "--config",
            str(config_path),
            "--json",
            "report",
            "--runs",
            ",".join(runs),
            "--out",
            str(report_path),
        ],
    )
    assert result.exit_code == 0, result.output
    assert report_path.read_text() == render(collect(benchmark, runs))
    assert "## Wrong claims the verifier did not catch" in report_path.read_text()
    assert "shared backend" in report_path.read_text()
    changed_metrics = cfg.model_copy(deep=True)
    changed_metrics.metrics.bootstrap_seed += 1
    with pytest.raises(ValueError, match="metric configuration drift"):
        collect(Benchmark(changed_metrics), runs)

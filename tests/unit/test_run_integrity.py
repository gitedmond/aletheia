"""Review regressions: preserve completed runs and explicit failure receipts/accounting."""

import hashlib
import time
from pathlib import Path

import pytest

from aletheia.config import Config
from aletheia.orchestrate import Benchmark
from aletheia.replay import replay
from aletheia.sandbox.runner import JobHandle
from aletheia.schema.canonical import canonical_bytes
from aletheia.schema.models import (
    Claim,
    ClaimSubmission,
    Grade,
    Job,
    JobResult,
    RunManifest,
    Targets,
    Verdict,
)


def prepared_run(tmp_path, *, with_claim):
    root = Path(__file__).resolve().parents[2]
    cfg = Config()
    cfg.paths.build, cfg.paths.runs, cfg.paths.artifacts = (
        str(tmp_path / name) for name in ("programs", "runs", "artifacts")
    )
    cfg.ghidra.analysis_options = str(root / "configs/ghidra-analysis.json")
    cfg.sources.capa.mapping = str(root / "mappings/capa.yaml")
    cfg.sources.findcrypt.mapping = str(root / "mappings/findcrypt.yaml")
    cfg.sandbox.image_analysis = cfg.sandbox.image_build = "sha256:" + "a" * 64
    payload = b"opaque public bytes; these tests never invoke an ELF parser"
    digest = hashlib.sha256(payload).hexdigest()
    bundle = Path(cfg.paths.build) / "example/test"
    (bundle / "stripped").mkdir(parents=True)
    (bundle / "private").mkdir()
    (bundle / "stripped" / (digest + ".bin")).write_bytes(payload)
    (bundle / "private/ground_truth.json").write_text("{}")
    (bundle / "targets.json").write_bytes(
        canonical_bytes(Targets(binary_sha256=digest, variant_id="test", targets=["0x00001000"]))
    )
    benchmark = Benchmark(cfg)
    inputs = benchmark.manifest_input("example", "human")
    manifest = RunManifest.create(
        inputs.model_copy(
            update={
                "source_config": inputs.source_config
                | {"origin": "human", "source_id": "human:integrity"}
            }
        )
    )
    claims = (
        [
            Claim.intake(
                ClaimSubmission.model_validate(
                    {
                        "run_id": manifest.run_id,
                        "source": {"origin": "human", "source_id": "human:integrity"},
                        "binary_sha256": digest,
                        "subject": {"address": "0x00001000"},
                        "type": "algorithm_identity",
                        "body": {"family": "fletcher16", "variant": "std"},
                        "confidence": 1.0,
                        "confidence_source": "stated",
                    }
                )
            )
        ]
        if with_claim
        else []
    )
    benchmark.ingest("example", manifest, claims)
    return benchmark, manifest.run_id, claims


def test_verify_with_no_pending_work_preserves_completed_state(tmp_path):
    benchmark, run, _ = prepared_run(tmp_path, with_claim=False)
    with benchmark.store() as store:
        store.set_run_state(run, "completed")
    benchmark.verify(run)
    with benchmark.store() as store:
        state = store.connection.execute(
            "SELECT state FROM runs WHERE run_id=?", (run,)
        ).fetchone()[0]
    assert state == "completed"


@pytest.mark.parametrize("damage", ["run_metadata", "missing_grade"])
def test_replay_missing_originals_returns_mismatch_receipt(tmp_path, damage):
    benchmark, run, claims = prepared_run(tmp_path, with_claim=True)
    with benchmark.store() as store:
        store.add_verdict(
            Verdict(
                claim_id=claims[0].claim_id,
                intrinsic_verdict="UNVERIFIABLE",
                reason="no_pack",
                verifier_version="0.1.0",
                env_digest="sha256:" + "a" * 64,
            ),
            "test",
        )
    if damage == "run_metadata":
        (benchmark.directory(run) / "run.json").unlink()
    result = replay(benchmark, run)
    assert result["exit_code"] == 5, result
    assert result["differences"]
    assert not list((benchmark.root / "jobs").iterdir())
    if damage == "run_metadata":
        (benchmark.directory(run) / "run.json").write_text("[]")
        assert replay(benchmark, run)["exit_code"] == 5
    else:
        with benchmark.store() as store:
            store.add_grade(
                Grade(
                    claim_id=claims[0].claim_id,
                    grader_version="0.1.0",
                    on_target=True,
                    phantom=False,
                    correct_strict=False,
                    correct_lenient=False,
                )
            )
        (benchmark.directory(run) / "hashes.json").write_text("[]")
        result = replay(benchmark, run)
        assert result["exit_code"] == 5 and "hash schema" in str(result["differences"])


def test_source_cache_publish_failure_preserves_completed_job_record(tmp_path):
    benchmark, _, _ = prepared_run(tmp_path, with_claim=False)
    runner = benchmark.runner()
    job = Job.create("capa_scan", {}, {"env_digest": runner.config.image_analysis})
    directory = tmp_path / "finished-job"
    (directory / "out").mkdir(parents=True)
    # Exercise the real JobRunner's already-completed protocol path, without Docker.
    result = JobResult(job_id=job.job_id, status="ok")
    handle = JobHandle(job, directory, None, time.monotonic(), early_result=result)
    (runner.cache_root / (job.job_id + ".artifact")).write_text("different existing result")
    with pytest.raises(ValueError, match="collision"):
        runner.wait(handle)
    assert len(runner.records) == 1
    assert runner.records[0]["artifact"] == handle.result_artifact
    assert runner.records[0]["measurement"] is not None
    assert handle.result_artifact is not None
    assert runner.artifacts.get(handle.result_artifact) == canonical_bytes(result)

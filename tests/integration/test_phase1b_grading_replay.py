"""Both new claim types survive real collection, verification, scoring and fresh replay."""

from pathlib import Path

import pytest

from aletheia.config import Config
from aletheia.corpus.build import Variant, build_program
from aletheia.orchestrate import Benchmark
from aletheia.replay import replay
from aletheia.schema.models import Claim, ClaimSubmission, GroundTruth, RunManifest

pytestmark = pytest.mark.integration


def test_v2_signature_and_purpose_scoring_replay_with_pinned_agreement(tmp_path):
    cfg = Config.read(Path("aletheia.toml"))
    cfg.paths.build = str(tmp_path / "build")
    cfg.paths.runs = str(tmp_path / "runs")
    cfg.paths.artifacts = str(tmp_path / "artifacts")
    cfg.grading.agreement = "configs/grading-phase1b.json"
    build_program(
        Path("corpus/tierA/crc32tool"),
        Variant(cfg.sandbox.image_build, Path(cfg.paths.build), ground_truth_version="2.0"),
    )
    benchmark = Benchmark(cfg)
    binary, _, bundle = benchmark.bundle("crc32tool")
    truth = GroundTruth.model_validate_json((bundle / "private/ground_truth.json").read_bytes())
    function = next(f for f in truth.functions if f.name == "crc32_update")
    assert function.source_types is not None
    manifest_input = benchmark.manifest_input("crc32tool", "human")
    manifest_input.source_config.update(origin="human", source_id="human:integration")
    manifest = RunManifest.create(manifest_input)
    claims = [
        Claim.intake(
            ClaimSubmission.model_validate(
                {
                    "run_id": manifest.run_id,
                    "source": {"origin": "human", "source_id": "human:integration"},
                    "binary_sha256": binary.binary_sha256,
                    "subject": {"address": function.address},
                    "type": kind,
                    "body": body,
                    "confidence": 0.8,
                    "confidence_source": "stated",
                    "algorithms_version": "2.0",
                }
            )
        )
        for kind, body in [
            (
                "function_signature",
                {
                    "return_type": function.source_types.return_type,
                    "params": [{"type": t} for t in function.source_types.params],
                },
            ),
            ("function_purpose", {"category": "checksum.crc32"}),
        ]
    ]
    run = benchmark.ingest("crc32tool", manifest, claims)
    benchmark.verify(run)
    benchmark.score([run])
    with benchmark.store() as store:
        assert all(store.get_grade(claim.claim_id).correct_claimed is True for claim in claims)
    result = replay(benchmark, run)
    assert result["exit_code"] == 0, result

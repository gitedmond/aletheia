"""An empty or malformed evidence directory must never satisfy the Phase 1A gate."""

from aletheia.config import Config
from aletheia.gate import evaluate, scripted_expected_count
from aletheia.orchestrate import Benchmark
from aletheia.schema.models import GroundTruth


def test_missing_or_unknown_version_evidence_fails_every_criterion(tmp_path):
    cfg = Config()
    cfg.paths.runs = str(tmp_path / "runs")
    cfg.paths.artifacts = str(tmp_path / "artifacts")
    benchmark = Benchmark(cfg)
    result = evaluate(benchmark)
    assert result["status"] == "failed"
    assert set(result["criteria"]) == {f"X{index}" for index in range(1, 11)}
    assert all(not value["passed"] for value in result["criteria"].values())
    directory = benchmark.root / "phase1a"
    directory.mkdir()
    (directory / "evidence.json").write_text('{"schema_version":"99.0"}')
    assert evaluate(benchmark)["status"] == "failed"


def test_scripted_count_retains_counted_wrong_callee_exclusions():
    truth = GroundTruth.model_validate(
        {
            "binary_sha256": "a" * 64,
            "program_id": "tierA/mini",
            "variant_id": "test",
            "build_flags": "test",
            "functions": [
                {
                    "address": "0x00001000",
                    "size": 32,
                    "name": "one",
                    "scorable": True,
                    "algorithm": {"family": "crc32", "variant": "ieee"},
                    "callees": [
                        {"target": "0x00002000", "kind": "direct"},
                        {"target": "0x00003000", "kind": "direct"},
                    ],
                },
                {
                    "address": "0x00002000",
                    "size": 32,
                    "name": "two",
                    "scorable": True,
                    "algorithm": {"family": "none"},
                },
                {
                    "address": "0x00003000",
                    "size": 32,
                    "name": "three",
                    "scorable": True,
                    "algorithm": {"family": "none"},
                },
            ],
        }
    )
    # A=1, N=2, E=2, X=2: neither edge has a false alternative callee.
    assert scripted_expected_count(truth) == 7

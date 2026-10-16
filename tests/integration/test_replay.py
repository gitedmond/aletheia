"""T23: fresh method execution, deterministic replay, drift, mismatch and cache miss."""

import json
from pathlib import Path

import pytest

from aletheia.config import Config
from aletheia.corpus.build import Variant, build_program
from aletheia.orchestrate import Benchmark
from aletheia.replay import replay

pytestmark = [pytest.mark.integration, pytest.mark.slow]


def test_native_replay_and_explicit_failures(tmp_path):
    cfg = Config.read(Path("aletheia.toml"))
    cfg.paths.build = str(tmp_path / "programs")
    cfg.paths.runs = str(tmp_path / "runs")
    cfg.paths.artifacts = str(tmp_path / "artifacts")
    build_program(
        Path("corpus/tierA/crc32tool"),
        Variant(image=cfg.sandbox.image_build, output_root=Path(cfg.paths.build)),
    )
    benchmark = Benchmark(cfg)
    run = benchmark.run("crc32tool", "findcrypt")[0]
    directory = benchmark.directory(run)
    original = (directory / "hashes.json").read_bytes()
    before = set((Path(cfg.paths.runs) / "jobs").iterdir())
    result = replay(benchmark, run)
    assert result["exit_code"] == 0, result
    assert (directory / "hashes.json").read_bytes() == original
    created = set((Path(cfg.paths.runs) / "jobs").iterdir()) - before
    types = {json.loads((path / "in/job.json").read_bytes())["type"] for path in created}
    assert types == {"verify_static", "verify_probe"}
    assert result["hashes"] == json.loads(original)
    drift = cfg.model_copy(deep=True)
    drift.budgets.instructions_per_claim += 1
    assert replay(Benchmark(drift), run)["exit_code"] == 4
    metadata = json.loads((directory / "run.json").read_bytes())
    scan = next(row for row in metadata["jobs"] if row["job"]["type"] == "findcrypt_scan")
    pointer = benchmark.cache_root / (scan["job"]["job_id"] + ".artifact")
    payload = pointer.read_bytes()
    before = set((Path(cfg.paths.runs) / "jobs").iterdir())
    try:
        pointer.unlink()
        assert replay(benchmark, run)["exit_code"] == 6
        assert set((Path(cfg.paths.runs) / "jobs").iterdir()) == before
    finally:
        pointer.write_bytes(payload)
    with benchmark.store() as store:
        claim = benchmark.claims(store, run)[0]
        original_grade = store.get_grade(claim.claim_id)
        damaged = original_grade.model_dump(mode="json")
        damaged["correct_lenient"] = not damaged["correct_lenient"]
        with store.connection:
            store.connection.execute(
                "UPDATE grades SET canonical_json=? WHERE claim_id=?",
                (json.dumps(damaged), claim.claim_id),
            )
    try:
        assert replay(benchmark, run)["exit_code"] == 5
    finally:
        with benchmark.store() as store, store.connection:
            store.connection.execute(
                "UPDATE grades SET canonical_json=? WHERE claim_id=?",
                (original_grade.model_dump_json(), claim.claim_id),
            )
    assert (directory / "hashes.json").read_bytes() == original

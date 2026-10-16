"""T09: real stripped-binary analysis, base zero, independent recall and cache."""

from pathlib import Path

import pytest

from aletheia.analysis.ghidra_session import GhidraAnalysisCache
from aletheia.config import Config
from aletheia.corpus.build import Variant, build_program
from aletheia.sandbox.runner import JobRunner
from aletheia.schema.canonical import canonical_bytes
from aletheia.schema.models import GroundTruth
from aletheia.sources.base import BinaryRef
from aletheia.store.artifacts import ArtifactStore

pytestmark = pytest.mark.integration


def test_base_zero_repeatable_analysis_recall_and_cached_result(tmp_path):
    cfg = Config.read(Path("aletheia.toml"))
    built = build_program(
        Path("corpus/tierA/crc32tool"),
        Variant(image=cfg.sandbox.image_build, output_root=tmp_path / "build"),
    )
    binary = BinaryRef(built.binary_sha256, built.stripped, built.variant_id)
    runner = JobRunner(
        cfg.sandbox, tmp_path / "public", tmp_path / "jobs", ArtifactStore(tmp_path / "artifacts")
    )
    cache = GhidraAnalysisCache(runner, tmp_path / "analysis-cache")
    first = cache.analyze(binary, Path("configs/ghidra-analysis.json"), no_cache=True)
    first_measurement = cache.last_measurement
    second = cache.analyze(binary, Path("configs/ghidra-analysis.json"), no_cache=True)
    assert canonical_bytes(first) == canonical_bytes(second)
    assert first.image_base == "0x00000000"
    assert first.binary_sha256 == binary.binary_sha256
    assert first_measurement["peak_rss_bytes"] > 0
    assert cache.last_measurement["peak_rss_bytes"] > 0
    truth = GroundTruth.model_validate_json(
        (built.unstripped.parent / "ground_truth.json").read_bytes()
    )
    expected = {fn.address for fn in truth.functions if fn.scorable}
    entries = {fn.entry for fn in first.functions}
    crc_entry = next(fn.address for fn in truth.functions if fn.name == "crc32_bitwise")
    assert crc_entry in entries
    assert expected <= entries, sorted(expected - entries)
    expected_imports = {
        (fn.address, edge.target, edge.kind)
        for fn in truth.functions
        if fn.scorable
        for edge in fn.callees
        if edge.target.startswith("import:") and edge.kind != "indirect"
    }
    actual_imports = {
        (fn.entry, site.target, site.kind) for fn in first.functions for site in fn.call_sites
    }
    assert expected_imports <= actual_imports, sorted(expected_imports - actual_imports)
    print(
        {
            "scorable_entries": len(expected),
            "recalled": len(expected & entries),
            "missed": sorted(expected - entries),
            "measurements": [first_measurement, cache.last_measurement],
        }
    )
    jobs = list((tmp_path / "jobs").iterdir())
    assert cache.analyze(binary, Path("configs/ghidra-analysis.json")) == first
    assert list((tmp_path / "jobs").iterdir()) == jobs
    assert cache.last_measurement is None

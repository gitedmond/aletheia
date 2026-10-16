"""Pinned assets belong to the checkout; explicitly configured data paths can live elsewhere."""

import hashlib
from pathlib import Path

from aletheia.config import Config
from aletheia.orchestrate import Benchmark
from aletheia.schema.canonical import canonical_bytes
from aletheia.schema.models import Targets


def test_manifest_pins_and_pack_coverage_do_not_depend_on_working_directory(tmp_path, monkeypatch):
    root = Path(__file__).resolve().parents[2]
    cfg = Config()
    cfg.paths.build = str(tmp_path / "programs")
    cfg.paths.runs = str(tmp_path / "runs")
    cfg.paths.artifacts = str(tmp_path / "artifacts")
    cfg.ghidra.analysis_options = str(root / "configs/ghidra-analysis.json")
    cfg.sources.capa.mapping = str(root / "mappings/capa.yaml")
    cfg.sources.findcrypt.mapping = str(root / "mappings/findcrypt.yaml")
    cfg.sandbox.image_analysis = "sha256:" + "a" * 64
    cfg.sandbox.image_build = "sha256:" + "b" * 64
    payload = b"opaque bytes: manifest creation does not parse ELF"
    digest = hashlib.sha256(payload).hexdigest()
    bundle = Path(cfg.paths.build) / "example/test"
    (bundle / "stripped").mkdir(parents=True)
    (bundle / "private").mkdir()
    (bundle / "stripped" / (digest + ".bin")).write_bytes(payload)
    (bundle / "private/ground_truth.json").write_bytes(b"opaque identity pin")
    (bundle / "targets.json").write_bytes(
        canonical_bytes(Targets(binary_sha256=digest, variant_id="test", targets=[]))
    )
    original = Benchmark(cfg).manifest_input("example", "scripted")
    assert set(original.pack_hashes) == {"crc32", "adler32", "fnv", "djb2", "base64"}
    elsewhere = tmp_path / "elsewhere"
    elsewhere.mkdir()
    monkeypatch.chdir(elsewhere)
    repeated = Benchmark(cfg).manifest_input("example", "scripted")
    assert canonical_bytes(repeated) == canonical_bytes(original)

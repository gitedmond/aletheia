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
    assert set(original.pack_hashes) == {
        "crc32",
        "adler32",
        "fnv",
        "djb2",
        "base64",
        "fletcher16",
        "md5",
        "sha1",
        "sha256",
        "strlen",
        "strcmp",
        "memcpy",
        "hex",
        "parse-int",
    }
    elsewhere = tmp_path / "elsewhere"
    elsewhere.mkdir()
    monkeypatch.chdir(elsewhere)
    repeated = Benchmark(cfg).manifest_input("example", "scripted")
    assert canonical_bytes(repeated) == canonical_bytes(original)


def test_explicit_variant_and_heldout_metadata_are_preserved(tmp_path):
    import pytest

    cfg = Config()
    cfg.paths.private_root = str(tmp_path / "hidden")
    cfg = cfg.for_split("heldout")
    cfg.sandbox.image_analysis = "sha256:" + "a" * 64
    cfg.sandbox.image_build = "sha256:" + "b" * 64
    digests = {}
    for variant in ["baseline", "hardened"]:
        data = variant.encode()
        digest = hashlib.sha256(data).hexdigest()
        digests[variant] = digest
        root = Path(cfg.paths.build) / "example" / variant
        (root / "stripped").mkdir(parents=True)
        (root / "private").mkdir()
        (root / "stripped" / (digest + ".bin")).write_bytes(data)
        (root / "private/ground_truth.json").write_bytes(b"opaque hash pin")
        (root / "targets.json").write_bytes(
            canonical_bytes(Targets(binary_sha256=digest, variant_id=variant, targets=[]))
        )
    with pytest.raises(ValueError, match="exactly one"):
        Benchmark(cfg).bundle("example")
    benchmark = Benchmark(cfg, variant="baseline", algorithms_version="2.0")
    assert benchmark.bundle("example")[0].binary_sha256 == digests["baseline"]
    manifest_input = benchmark.manifest_input("example", "human")
    assert manifest_input.algorithms_version == "2.0"
    manifest_input.source_config.update(origin="human", source_id="fixture")
    from aletheia.schema.models import RunManifest

    run = benchmark.ingest("example", RunManifest.create(manifest_input), [])
    with benchmark.store() as store:
        assert store.connection.execute("SELECT split FROM binaries").fetchone()[0] == "heldout"
    import json

    assert (
        json.loads((benchmark.directory(run) / "run.json").read_bytes())["variant_id"] == "baseline"
    )


def test_dev_fit_refuses_heldout_scope_before_reading_runs(tmp_path):
    import pytest

    from aletheia.agent.batch import fit_dev

    cfg = Config()
    cfg.paths.private_root = str(tmp_path / "hidden")
    with pytest.raises(ValueError, match="dev runs only"):
        fit_dev(Benchmark(cfg.for_split("heldout")))

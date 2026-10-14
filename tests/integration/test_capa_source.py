"""T18: real pinned capa jobs only receive stripped public binaries."""

import json
from pathlib import Path

import pytest

from aletheia.config import Config
from aletheia.corpus.build import Variant, build_program
from aletheia.sandbox.runner import JobRunner
from aletheia.schema.models import Algorithm, Targets
from aletheia.sources.base import BinaryRef
from aletheia.sources.capa import CapaMapping, CapaSource
from aletheia.store.artifacts import ArtifactStore

pytestmark = pytest.mark.integration


@pytest.mark.parametrize("program", ["crc32tool", "hashtable"])
def test_real_capa_job_normalizes_known_functions_and_counts_unmapped(tmp_path, program):
    config = Config.read(Path("aletheia.toml"))
    built = build_program(
        Path("corpus/tierA") / program,
        Variant(image=config.sandbox.image_build, output_root=tmp_path / "build"),
    )
    targets = Targets.model_validate_json((built.metadata.parent / "targets.json").read_bytes())
    mapping = CapaMapping(
        capa_version="9.4.0",
        rules_tag="9.4.0",
        address_base_field="meta.analysis.base_address.value",
        map={
            "hash data with CRC32": Algorithm(family="crc32"),
            "hash data using fnv": Algorithm(family="fnv"),
            "hash data using djb2": Algorithm(family="djb2"),
        },
    )
    runner = JobRunner(
        config.sandbox, tmp_path / "public", tmp_path / "jobs", ArtifactStore(tmp_path / "cas")
    )
    source = CapaSource(mapping, "r_" + "2" * 16, runner)
    binary = BinaryRef(built.binary_sha256, built.stripped, built.variant_id)
    claims = source.produce(binary, targets)
    assert len(claims) == (3 if program == "crc32tool" else 5)
    assert len({c.subject.address for c in claims}) == len(claims)
    assert all(c.binary_sha256 == binary.binary_sha256 for c in claims)
    result = source.last_result
    assert result is not None
    assert result.unmapped_scope == (5 if program == "crc32tool" else 6)
    assert result.unmapped_label == {"contain loop": 6 if program == "crc32tool" else 10}
    ground = json.loads((built.unstripped.parent / "ground_truth.json").read_bytes())
    expected_name = "crc32_update" if program == "crc32tool" else "fnv1a_32"
    expected = next(f["address"] for f in ground["functions"] if f["name"] == expected_name)
    assert expected in {c.subject.address for c in claims}
    again = source.produce(binary, targets)
    assert again == claims
    for path in (tmp_path / "jobs").rglob("in/*"):
        assert path.suffix not in (".c", ".h") and path.name not in (
            "unstripped.bin",
            "o0.bin",
            "ground_truth.json",
        )

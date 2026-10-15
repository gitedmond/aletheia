"""F4/F5 proposal: compare real pinned capa jobs with proposed protected inputs."""

from pathlib import Path

import pytest

from aletheia.config import Config
from aletheia.corpus.build import Variant, build_program
from aletheia.sandbox.runner import JobRunner
from aletheia.schema.canonical import canonical_bytes
from aletheia.schema.models import Targets
from aletheia.sources.base import BinaryRef
from aletheia.sources.capa import CapaMapping, CapaSource
from aletheia.store.artifacts import ArtifactStore

pytestmark = pytest.mark.integration


@pytest.mark.parametrize("program", ["crc32tool", "hashtable"])
def test_capa_output_equals_protected_candidate(tmp_path, program):
    """Check every normalized claim and unmapped count using the proposed mapping."""
    mapping = CapaMapping.read(Path("mappings/capa.yaml"))
    config = Config.read(Path("aletheia.toml"))
    built = build_program(
        Path("corpus/tierA") / program,
        Variant(image=config.sandbox.image_build, output_root=tmp_path / "build"),
    )
    targets = Targets.model_validate_json((built.metadata.parent / "targets.json").read_bytes())
    runner = JobRunner(
        config.sandbox, tmp_path / "public", tmp_path / "jobs", ArtifactStore(tmp_path / "cas")
    )
    source = CapaSource(mapping, "r_" + "2" * 16, runner)
    source.produce(BinaryRef(built.binary_sha256, built.stripped, built.variant_id), targets)
    result = source.last_result
    assert result is not None
    actual = {
        "claims": [claim.model_dump(mode="json") for claim in result.claims],
        "unmapped_scope": result.unmapped_scope,
        "unmapped_label": result.unmapped_label,
        "deduplicated_label": result.deduplicated_label,
    }
    expected = Path("tests/golden/adapters") / ("capa-" + program + ".json")
    assert canonical_bytes(actual) == expected.read_bytes()

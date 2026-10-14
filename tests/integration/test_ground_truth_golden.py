"""F1: compare extraction to the independently reviewed, protected CRC32 golden."""

from pathlib import Path

import pytest

from aletheia.config import Config
from aletheia.corpus.build import Variant, build_program
from aletheia.schema.canonical import canonical_bytes
from aletheia.schema.models import GroundTruth

pytestmark = pytest.mark.integration


def test_crc32_ground_truth_equals_protected_f1(tmp_path):
    golden = GroundTruth.model_validate_json(
        Path("tests/golden/crc32tool/ground_truth.json").read_bytes()
    )
    image = Config.read(Path("aletheia.toml")).sandbox.image_build
    build = build_program(
        Path("corpus/tierA/crc32tool"), Variant(image=image, output_root=tmp_path / "build")
    )
    actual = GroundTruth.model_validate_json(
        (build.unstripped.parent / "ground_truth.json").read_bytes()
    )
    assert canonical_bytes(actual) == canonical_bytes(golden)

"""T27 locates support in real stripped CRC32/FNV/djb2 code with clean Ghidra."""

from pathlib import Path

import pytest

from aletheia.analysis.ghidra_session import GhidraAnalysisCache
from aletheia.config import Config
from aletheia.corpus.build import Variant, build_program
from aletheia.sandbox.runner import JobRunner
from aletheia.schema.models import GroundTruth
from aletheia.sources.base import BinaryRef
from aletheia.store.artifacts import ArtifactStore

pytestmark = pytest.mark.integration


def test_expected_constants_are_found_without_verdicts(tmp_path):
    cfg = Config.read(Path("aletheia.toml"))
    cache = GhidraAnalysisCache(
        JobRunner(
            cfg.sandbox,
            tmp_path / "public",
            tmp_path / "jobs",
            ArtifactStore(tmp_path / "artifacts"),
        ),
        tmp_path / "analysis-cache",
    )
    for program, expected in (
        ("crc32tool", {"crc32_update": ("crc32", "ieee_table_prefix", "readonly_table")}),
        (
            "hashtable",
            {
                "fnv1a_32": ("fnv", "fnv1a32_basis", "immediate"),
                "djb2_buf": ("djb2", "djb2_seed", "immediate"),
            },
        ),
    ):
        built = build_program(
            Path("corpus/tierA") / program,
            Variant(image=cfg.sandbox.image_build, output_root=tmp_path / "build"),
        )
        truth = GroundTruth.model_validate_json(
            (built.unstripped.parent / "ground_truth.json").read_bytes()
        )
        entries = {fn.name: fn.address for fn in truth.functions}
        analysis = cache.analyze(
            BinaryRef(built.binary_sha256, built.stripped, built.variant_id),
            Path("configs/ghidra-analysis.json"),
        )
        functions = {fn.entry: fn for fn in analysis.functions}
        for name, pattern in expected.items():
            matches = functions[entries[name]].constants
            assert pattern in {(m.family, m.name, m.location) for m in matches}, (name, matches)
            assert all(
                m.kind == "constant_match" and "verdict" not in m.model_dump() for m in matches
            )
            print({"function": name, "matches": [m.model_dump() for m in matches]})

"""T11: production Ghidra arity matches independently reviewed F7, including varargs."""

from pathlib import Path

import pytest
import yaml

from aletheia.analysis.ghidra_session import GhidraAnalysisCache
from aletheia.config import Config
from aletheia.corpus.build import Variant, build_program
from aletheia.sandbox.runner import JobRunner
from aletheia.sources.base import BinaryRef
from aletheia.store.artifacts import ArtifactStore
from aletheia.verify.static.arity import infer_arity

pytestmark = pytest.mark.integration


def test_golden_arity_and_variadic_rejection(tmp_path):
    cfg = Config.read(Path("aletheia.toml"))
    golden = yaml.safe_load(Path("tests/golden/arity.yaml").read_text())
    cache = GhidraAnalysisCache(
        JobRunner(
            cfg.sandbox,
            tmp_path / "public",
            tmp_path / "jobs",
            ArtifactStore(tmp_path / "artifacts"),
        ),
        tmp_path / "cache",
    )
    for program in golden["programs"]:
        built = build_program(
            Path("corpus/tierA") / program["program"],
            Variant(image=cfg.sandbox.image_build, output_root=tmp_path / "build"),
        )
        assert built.binary_sha256 == program["binary_sha256"]
        analysis = cache.analyze(
            BinaryRef(built.binary_sha256, built.stripped, built.variant_id),
            Path("configs/ghidra-analysis.json"),
        )
        for case in program["cases"]:
            result = infer_arity(case["address"], analysis)
            assert result.model_dump() == {
                key: case[key] for key in ("arity", "decisive", "reason")
            }, (program["program"], case["name"], result)

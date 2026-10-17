"""Pinned native adapters on two public programs and both hardening variants."""

import json
from pathlib import Path

import pytest

from aletheia.config import Config
from aletheia.corpus.build import Variant, build_program
from aletheia.sandbox.runner import JobRunner
from aletheia.schema.models import Algorithm, Targets
from aletheia.sources.base import BinaryRef
from aletheia.sources.capa import CapaMapping, CapaSource
from aletheia.sources.findcrypt import FindcryptMapping, FindcryptSource
from aletheia.store.artifacts import ArtifactStore

pytestmark = pytest.mark.integration


@pytest.mark.parametrize("program", ["b64", "hashkit-sha"])
@pytest.mark.parametrize("hardening", ["hardoff", "hardened"])
def test_native_tool_outputs_match_independent_v2_tables(tmp_path, program, hardening):
    cfg = Config.read(Path("aletheia.toml"))
    built = build_program(
        Path("corpus/tierA") / program,
        Variant(image=cfg.sandbox.image_build, hardening=hardening, output_root=tmp_path / "build"),
    )
    targets = Targets.model_validate_json((built.metadata.parent / "targets.json").read_bytes())
    binary = BinaryRef(built.binary_sha256, built.stripped, built.variant_id)
    runner = JobRunner(
        cfg.sandbox, tmp_path / "public", tmp_path / "jobs", ArtifactStore(tmp_path / "artifacts")
    )
    sources = {
        "capa": CapaSource(CapaMapping.read(Path("mappings/capa.yaml")), "r_" + "6" * 16, runner),
        "findcrypt": FindcryptSource(
            FindcryptMapping.read(Path("mappings/findcrypt.yaml")),
            "r_" + "6" * 16,
            runner,
            Path(cfg.ghidra.analysis_options),
        ),
    }
    actual = {"binary_sha256": built.binary_sha256}
    for name, source in sources.items():
        claims = source.produce(binary, targets)
        result = source.last_result
        assert result is not None
        rows = []
        for claim in claims:
            assert isinstance(claim.body, Algorithm)
            if claim.body.family == "sha256":
                assert claim.algorithms_version == "2.0"
            rows.append(
                {
                    "address": claim.subject.address,
                    "family": claim.body.family,
                    "variant": claim.body.variant,
                    "label": claim.tool_label,
                }
            )
        table = {
            "claims": rows,
            "unmapped_label": result.unmapped_label,
            "deduplicated_label": result.deduplicated_label,
        }
        if isinstance(source, CapaSource):
            table["unmapped_scope"] = source.last_result.unmapped_scope
        actual[name] = table
    golden = Path("tests/golden/adapters") / f"phase1b-{program}-{hardening}.json"
    assert actual == json.loads(golden.read_bytes())

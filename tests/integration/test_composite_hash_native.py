"""Only the coordinator reads native fixture symbols/truth; jobs receive stripped inputs."""

import json
from pathlib import Path

import pytest

from aletheia.analysis.ghidra_session import GhidraAnalysisCache
from aletheia.config import Config
from aletheia.corpus.build import Variant, build_program
from aletheia.sandbox.runner import JobRunner
from aletheia.selftest import build_fixture
from aletheia.sources.base import BinaryRef
from aletheia.store.artifacts import ArtifactStore
from aletheia.verify.composite import CompositeMember, CompositeRequest
from aletheia.verify.composite_client import CompositeClient

pytestmark = pytest.mark.integration


def verify(cfg, tmp_path, binary, family, groups):
    artifacts = ArtifactStore(tmp_path / "artifacts")
    runner = JobRunner(cfg.sandbox, tmp_path / "public", tmp_path / "jobs", artifacts)
    cache = GhidraAnalysisCache(runner, tmp_path / "analysis-cache")
    subjects = sorted({address for members, expected in groups for address in members.values()})
    analysis = cache.analyze(binary, Path(cfg.ghidra.analysis_options), subjects=subjects)
    for members, expected in groups:
        request = CompositeRequest(
            binary_sha256=binary.binary_sha256,
            family=family,
            members=[
                CompositeMember(claim_id="c_" + str(i) * 24, subject=members[role], role=role)
                for i, role in enumerate(["init", "update", "final"], 1)
            ],
            budgets=cfg.budgets,
            env_digest="sha256:" + "d" * 64,
        )
        result = CompositeClient(runner).verify(
            binary, analysis, Path("packs") / (family + ".yaml"), request
        )
        assert len(result.verdicts) == 3
        assert all(
            v.intrinsic_verdict == expected and v.strength == "E2" for v in result.verdicts
        ), result
        assert len({v.evidence[0].artifact for v in result.verdicts}) == 1
        if expected == "CONTRADICTED":
            assert all(v.counterexample is not None for v in result.verdicts)


@pytest.mark.parametrize("family", ["md5", "sha1", "sha256"])
def test_composite_references_and_wrong_final(family, tmp_path):
    cfg = Config.read(Path("aletheia.toml"))
    root = tmp_path / "calibration"
    root.mkdir()
    binary, symbols, fixture = build_fixture(family, cfg, root, fixture_set="composite")
    groups = [
        (
            {role: symbols[getattr(case, role)] for role in ["init", "update", "final"]},
            case.expected,
        )
        for case in fixture.composite_cases
    ]
    verify(cfg, tmp_path, binary, family, groups)


@pytest.mark.parametrize("hardening", ["hardoff", "hardened"])
def test_public_sha_corpus_composites(hardening, tmp_path):
    cfg = Config.read(Path("aletheia.toml"))
    built = build_program(
        Path("corpus/tierA/hashkit-sha"),
        Variant(
            cfg.sandbox.image_build,
            tmp_path / "build",
            hardening=hardening,
            ground_truth_version="2.0",
        ),
    )
    truth = json.loads((built.metadata.parent / "private/ground_truth.json").read_bytes())
    addresses = {fn["name"]: fn["address"] for fn in truth["functions"]}
    binary = BinaryRef(built.binary_sha256, built.stripped, built.variant_id)
    for family in ["sha1", "sha256"]:
        group = {role: addresses[family + "_" + role] for role in ["init", "update", "final"]}
        verify(cfg, tmp_path / family, binary, family, [(group, "VERIFIED")])

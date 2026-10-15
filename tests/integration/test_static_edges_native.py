"""T10 Ghidra verdicts match protected cases independently derived from F1."""

import json
from pathlib import Path

import pytest

from aletheia.analysis.ghidra_session import GhidraAnalysisCache
from aletheia.config import Config
from aletheia.corpus.build import Variant, build_program
from aletheia.sandbox.runner import JobRunner
from aletheia.schema.models import Claim, ClaimSubmission
from aletheia.sources.base import BinaryRef
from aletheia.store.artifacts import ArtifactStore
from aletheia.verify.static.edges import verify_edges

pytestmark = pytest.mark.integration


def test_golden_direct_tail_import_and_missing_subject_cases(tmp_path):
    cfg = Config.read(Path("aletheia.toml"))
    cases = json.loads(Path("tests/golden/static-edges.json").read_bytes())
    built = build_program(
        Path("corpus/tierA/crc32tool"),
        Variant(image=cfg.sandbox.image_build, output_root=tmp_path / "build"),
    )
    assert built.binary_sha256 == cases["binary_sha256"]
    cache = GhidraAnalysisCache(
        JobRunner(
            cfg.sandbox,
            tmp_path / "public",
            tmp_path / "jobs",
            ArtifactStore(tmp_path / "artifacts"),
        ),
        tmp_path / "cache",
    )
    analysis = cache.analyze(
        BinaryRef(built.binary_sha256, built.stripped, built.variant_id),
        Path("configs/ghidra-analysis.json"),
        subjects=[case["subject"] for case in cases["cases"]],
    )
    assert analysis.missing_subjects == ["0x00000001"]
    for case in cases["cases"]:
        claim = Claim.intake(
            ClaimSubmission.model_validate(
                {
                    "run_id": "r_" + "1" * 16,
                    "source": {"origin": "human", "source_id": "human:static-edge-fixture"},
                    "binary_sha256": built.binary_sha256,
                    "subject": {"address": case["subject"]},
                    "type": "call_relation",
                    "body": {"callee": case["callee"], "kind": case["kind"]},
                    "confidence": 1.0,
                    "confidence_source": "stated",
                }
            )
        )
        verdict = verify_edges(claim, analysis, cfg.sandbox.image_analysis)
        assert (verdict.intrinsic_verdict, verdict.reason) == (case["verdict"], case["reason"]), (
            case["name"],
            verdict,
            analysis,
        )
        assert verdict.claim_id == claim.claim_id

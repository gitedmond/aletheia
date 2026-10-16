"""Reject an oversized opaque public binary before hashing or starting a job."""

from pathlib import Path

import pytest

from aletheia.analysis.ghidra_session import GhidraAnalysis
from aletheia.config import Budgets, Sandbox
from aletheia.sandbox.runner import JobRunner
from aletheia.schema.models import Claim, ClaimSubmission
from aletheia.sources.base import BinaryRef
from aletheia.store.artifacts import ArtifactStore
from aletheia.verify.probes.client import ProbeClient


def test_oversized_probe_binary_is_rejected_before_hashing(tmp_path):
    binary = tmp_path / "stripped" / ("a" * 64 + ".bin")
    binary.parent.mkdir()
    with binary.open("wb") as stream:
        stream.truncate(20 * 1024**2 + 1)
    claim = Claim.intake(
        ClaimSubmission.model_validate(
            {
                "run_id": "r_" + "2" * 16,
                "source": {"origin": "human", "source_id": "human:input-boundary"},
                "binary_sha256": "a" * 64,
                "subject": {"address": "0x00001000"},
                "type": "algorithm_identity",
                "body": {"family": "fnv", "variant": "fnv1a-32"},
                "confidence": 1.0,
                "confidence_source": "stated",
            }
        )
    )
    analysis = GhidraAnalysis(binary_sha256="a" * 64, options_sha256="b" * 64, functions=[])
    runner = JobRunner(
        Sandbox(), tmp_path / "public", tmp_path / "jobs", ArtifactStore(tmp_path / "artifacts")
    )
    with pytest.raises(ValueError, match="size limit"):
        ProbeClient(runner).probe(
            BinaryRef("a" * 64, binary, "oversized"),
            claim,
            analysis,
            Path("packs/fnv.yaml"),
            Budgets(),
            "sha256:" + "c" * 64,
        )
    assert not list((tmp_path / "jobs").iterdir())

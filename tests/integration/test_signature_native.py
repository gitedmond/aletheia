"""Frozen C/assembly expectations checked through Ghidra and production static jobs."""

import hashlib
import json
from pathlib import Path

import pytest

from aletheia.analysis.ghidra_session import GhidraAnalysisCache, publish_immutable
from aletheia.config import Config
from aletheia.sandbox.runner import JobRunner
from aletheia.schema.canonical import canonical_bytes
from aletheia.schema.models import Claim, ClaimSubmission, Job, Verdict
from aletheia.selftest import compile_fixture
from aletheia.store.artifacts import ArtifactStore
from aletheia.verify.static.worker import StaticRequest

pytestmark = pytest.mark.integration


def test_signature_decisions_from_stripped_calibration(tmp_path):
    cfg = Config.read(Path("aletheia.toml"))
    fixture = Path("tests/fixtures/static/signature")
    cases = json.loads((fixture / "cases.json").read_bytes())
    root = tmp_path / "compile"
    root.mkdir()
    binary, symbols = compile_fixture(fixture, cfg, root, cases["binary_sha256"])
    runner = JobRunner(
        cfg.sandbox, tmp_path / "public", tmp_path / "jobs", ArtifactStore(tmp_path / "artifacts")
    )
    analysis = GhidraAnalysisCache(runner, tmp_path / "cache").analyze(
        binary,
        Path(cfg.ghidra.analysis_options),
        subjects=[symbols[case["name"]] for case in cases["cases"]],
    )
    (tmp_path / "analysis.json").write_bytes(canonical_bytes(analysis))

    def stage(value):
        payload = canonical_bytes(value)
        name = "in/" + hashlib.sha256(payload).hexdigest() + ".json"
        publish_immutable(runner.input_root / name, payload)
        return name

    analysis_path = stage(analysis)
    failures = []
    for case in cases["cases"]:
        claim = Claim.intake(
            ClaimSubmission.model_validate(
                {
                    "run_id": "r_" + "a" * 16,
                    "source": {"origin": "human", "source_id": "human:synthetic-calibration"},
                    "binary_sha256": binary.binary_sha256,
                    "subject": {"address": symbols[case["name"]]},
                    "type": "function_signature",
                    "body": case["body"],
                    "confidence": 1.0,
                    "confidence_source": "stated",
                }
            )
        )
        request = StaticRequest(
            claim=claim,
            env_digest="sha256:" + "d" * 64,
            analysis_options_sha256=analysis.options_sha256,
        )
        for method in ["static.arity@2", "static.widths@1"]:
            result = runner.wait(
                runner.submit(
                    Job.create(
                        "verify_static",
                        {"request": stage(request), "analysis": analysis_path},
                        {"method": method},
                    )
                )
            )
            assert result.status == "ok", (case["name"], result)
            verdict = Verdict.model_validate(result.output["verdict"])
            for aspect, observed in verdict.aspects.items():
                expected = case["expected"][aspect]
                if observed.verdict != expected:
                    failures.append((case["name"], aspect, expected, observed.verdict))
    assert not failures, failures

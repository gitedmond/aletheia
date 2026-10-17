"""Composite corruption stays local; incomplete role groups never become one-shot claims."""

import hashlib
from pathlib import Path

import pytest

from aletheia.analysis.ghidra_session import GhidraAnalysis
from aletheia.config import Config
from aletheia.sandbox.runner import JobRunner
from aletheia.schema.models import Aspect, Claim, ClaimSubmission, Verdict
from aletheia.sources.base import BinaryRef
from aletheia.store.artifacts import ArtifactStore
from aletheia.store.database import Store
from aletheia.verify.composite_client import CompositeClient
from aletheia.verify.engine import Engine, MethodResult


@pytest.fixture
def group(tmp_path):
    cfg = Config()
    payload = b"opaque group transport input"
    digest = hashlib.sha256(payload).hexdigest()
    path = tmp_path / "stripped" / (digest + ".bin")
    path.parent.mkdir()
    path.write_bytes(payload)
    binary = BinaryRef(digest, path, "synthetic")
    runner = JobRunner(
        cfg.sandbox, tmp_path / "public", tmp_path / "jobs", ArtifactStore(tmp_path / "artifacts")
    )
    with Store(tmp_path / "db.sqlite") as store:
        engine = Engine(runner, store, cfg.budgets, Path("configs/ghidra-analysis.json"))
        analysis = GhidraAnalysis(
            binary_sha256=digest, options_sha256=engine.options_hash, functions=[]
        )
        claims = []
        for index, role in enumerate(["init", "update", "final"], 1):
            claims.append(
                Claim.intake(
                    ClaimSubmission.model_validate(
                        {
                            "run_id": "r_" + "1" * 16,
                            "source": {"origin": "human", "source_id": "human:synthetic"},
                            "binary_sha256": digest,
                            "subject": {"address": f"0x0000{index}000"},
                            "type": "function_purpose",
                            "body": {"category": "crypto.hash.md5." + role},
                            "confidence": 1.0,
                            "confidence_source": "stated",
                        }
                    )
                )
            )
        yield engine, binary, analysis, claims


def test_invalid_composite_result_becomes_errors_without_cached_decisions(group, monkeypatch):
    engine, binary, analysis, claims = group

    def broken(*args):
        raise ValueError("composite verdict identity mismatch")

    monkeypatch.setattr(CompositeClient, "verify", broken)
    data = claims[0].model_dump(mode="json", exclude={"claim_id"})
    data.update(type="call_relation", body={"callee": "import:puts", "kind": "direct"})
    unrelated = Claim.intake(ClaimSubmission.model_validate(data))
    claims.append(unrelated)

    def static(spec, claim, analysis):
        return MethodResult(
            spec,
            Verdict(
                claim_id=claim.claim_id,
                intrinsic_verdict="VERIFIED",
                strength="E1",
                harness="Controlled independent edge.",
                aspects={
                    "edge_exists": Aspect(verdict="VERIFIED", strength="E1", method=spec.name)
                },
                methods_run=[spec.name],
                verifier_version="0.1.0",
                env_digest=engine.env_digest,
            ),
        )

    monkeypatch.setattr(engine, "_static", static)
    results = engine.verify_claims(claims, binary, analysis)
    assert len(results) == 4
    for result in results:
        if result.verdict.claim_id == unrelated.claim_id:
            assert result.verdict.intrinsic_verdict == "VERIFIED"
        else:
            assert (
                result.verdict.intrinsic_verdict == "ERROR" and result.verdict.reason == "internal"
            )
    assert engine.store.connection.execute("SELECT count(*) FROM verdict_cache").fetchone()[0] == 1


def test_algorithm_inherits_incomplete_role_group_without_one_shot_probe(group, monkeypatch):
    engine, binary, analysis, claims = group
    claims = claims[:2]
    data = claims[1].model_dump(mode="json", exclude={"claim_id"})
    data.update(
        type="algorithm_identity",
        body={"family": "md5", "variant": "std"},
        algorithms_version="2.0",
    )
    claims.append(Claim.intake(ClaimSubmission.model_validate(data)))
    monkeypatch.setattr(engine, "_static", lambda spec, claim, analysis: MethodResult(spec, None))
    results = engine.verify_claims(claims, binary, analysis)
    assert all(
        result.verdict.intrinsic_verdict == "INCONCLUSIVE"
        and result.verdict.reason == "composite_incomplete"
        for result in results
    )
    assert all("probe.md5@1" not in result.verdict.methods_run for result in results)
    assert not list(engine.runner.jobs_root.iterdir())

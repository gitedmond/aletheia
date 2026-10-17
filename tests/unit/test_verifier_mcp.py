"""Every verifier tool and documented error without parsing an executable."""

import base64
import threading
from pathlib import Path
from types import SimpleNamespace

import pytest

from aletheia.config import Config, Mcp
from aletheia.mcp_server import VerifierSession
from aletheia.schema.models import ClaimSubmission, Verdict
from aletheia.store.artifacts import ArtifactStore


class Backend:
    def __init__(self):
        self.block = None
        self.error = None
        self.functions = 0

    def analyze(self, binary):
        if self.block:
            assert self.block.wait(5)
        if self.error:
            raise self.error
        return SimpleNamespace(functions=[None] * self.functions)

    def verify(self, claims, binary, analysis):
        return [
            Verdict(
                claim_id=c.claim_id,
                intrinsic_verdict="UNVERIFIABLE",
                reason="no_pack",
                verifier_version="test",
                env_digest="sha256:" + "a" * 64,
            )
            for c in reversed(claims)
        ]


@pytest.fixture
def session(tmp_path):
    allowed = tmp_path / "inputs"
    allowed.mkdir()
    backend = Backend()
    cfg = Config(mcp=Mcp(binary_root=str(allowed)))
    value = VerifierSession(cfg, tmp_path / "server", backend=backend)
    yield value
    if backend.block:
        backend.block.set()
    value.close()


def load(session):
    result = session.load_binary(bytes_b64=base64.b64encode(b"opaque bytes").decode())
    session.jobs[result["job_id"]][1].result(timeout=5)
    return result


def claim(digest, address="0x00001000"):
    return ClaimSubmission.model_validate(
        {
            "run_id": "r_" + "1" * 16,
            "source": {"origin": "human", "source_id": "caller"},
            "binary_sha256": digest,
            "subject": {"address": address},
            "type": "algorithm_identity",
            "body": {"family": "crc32", "variant": None},
            "confidence": 0.8,
            "confidence_source": "stated",
        }
    ).model_dump(mode="json")


def test_all_tools_and_purge_ownership(session):
    loaded = load(session)
    digest = loaded["binary_sha256"]
    assert session.get_job(loaded["job_id"])["job_status"] == "done"
    result = session.verify_claim(claim(digest))
    assert result["status"] == "ok" and result["calibration"] == "uncalibrated"
    assert "c_adj" not in result
    identity = result["verdict"]["claim_id"]
    assert session.explain_verdict(identity)["methods"] == []
    artifact = ArtifactStore(session.root / digest / "artifacts").put(b'{"trace":"excerpt"}')
    assert session.get_evidence(artifact)["evidence"] == {"trace": "excerpt"}
    supported = session.list_supported()
    assert len(supported["claim_types"]) == 4 and "sha256" in supported["families"]
    assert len(supported["snippet_sha256"]) == 64
    untouched = session.root / "unrelated"
    untouched.mkdir()
    assert session.purge(digest)["status"] == "ok"
    assert untouched.exists() and not (session.root / digest).exists()
    assert session.explain_verdict(identity)["error_code"] == "invalid_claim"
    assert session.get_job(loaded["job_id"])["error_code"] == "invalid_claim"


def test_batch_preserves_submission_order(session):
    digest = load(session)["binary_sha256"]
    result = session.verify_claims([claim(digest), claim(digest, "0x00002000")])
    assert result["status"] == "ok"
    addresses = [
        session.claims[r["verdict"]["claim_id"]].subject.address for r in result["results"]
    ]
    assert addresses == ["0x00001000", "0x00002000"]


def test_validation_and_unknown_identity_errors(session):
    assert session.load_binary()["error_code"] == "invalid_claim"
    assert session.load_binary(bytes_b64="!")["error_code"] == "invalid_claim"
    assert session.verify_claim({})["error_code"] == "invalid_claim"
    assert session.verify_claim(claim("b" * 64))["error_code"] == "unknown_binary"
    assert session.purge("b" * 64)["error_code"] == "unknown_binary"


def test_allowed_path_and_rejected_escape_symlink(session, tmp_path):
    allowed = Path(session.config.mcp.binary_root)
    (allowed / "input.bin").write_bytes(b"opaque bytes")
    assert session.load_binary(path="input.bin")["status"] == "pending"
    outside = tmp_path / "outside"
    outside.write_bytes(b"secret")
    (allowed / "link").symlink_to(outside)
    assert session.load_binary(path=str(outside))["error_code"] == "path_not_allowed"
    assert session.load_binary(path="../outside")["error_code"] == "path_not_allowed"
    assert session.load_binary(path="link")["error_code"] == "path_not_allowed"


def test_pending_analysis_job_and_purge(session):
    session.backend.block = threading.Event()
    loaded = session.load_binary(bytes_b64="eA==")
    try:
        assert session.get_job(loaded["job_id"])["status"] == "pending"
        assert (
            session.verify_claim(claim(loaded["binary_sha256"]))["error_code"] == "analysis_pending"
        )
        assert session.purge(loaded["binary_sha256"])["error_code"] == "analysis_pending"
    finally:
        session.backend.block.set()


def test_binary_size_and_function_limits(session, monkeypatch):
    monkeypatch.setattr("aletheia.mcp_server.MAX_BYTES", 4)
    assert (
        session.load_binary(bytes_b64=base64.b64encode(b"12345").decode())["error_code"]
        == "binary_too_large"
    )
    session.backend.functions = 2001
    loaded = session.load_binary(bytes_b64="eA==")
    try:
        session.jobs[loaded["job_id"]][1].result(timeout=5)
    except ValueError:
        pass
    assert session.get_job(loaded["job_id"])["error_code"] == "binary_too_large"


def test_failed_job_returns_internal_without_exception_text(session):
    session.backend.error = RuntimeError("implementation detail")
    loaded = session.load_binary(bytes_b64="eA==")
    try:
        session.jobs[loaded["job_id"]][1].result(timeout=5)
    except RuntimeError:
        pass
    error = session.get_job(loaded["job_id"])
    assert error["error_code"] == "internal"
    assert "implementation detail" not in error["message"]


def test_evidence_budget(session):
    digest = load(session)["binary_sha256"]
    artifact = ArtifactStore(session.root / digest / "artifacts").put(b" " * (512 * 1024 + 1))
    assert session.get_evidence(artifact)["error_code"] == "budget_exceeded"


def test_async_verification_job(session):
    digest = load(session)["binary_sha256"]
    event = threading.Event()
    original = session.backend.verify

    def verify(*args):
        assert event.wait(5)
        return original(*args)

    session.backend.verify = verify
    session.wait_seconds = 0
    pending = session.verify_claim(claim(digest))
    assert pending["status"] == "pending"
    event.set()
    session.jobs[pending["job_id"]][1].result(timeout=5)
    assert session.get_job(pending["job_id"])["result"]["results"][0]["status"] == "ok"


def test_adjusted_confidence_requires_matching_fitted_configuration(session):
    from aletheia.confidence import Block, CalibrationFit, CalibrationMap

    digest = load(session)["binary_sha256"]
    mapping = CalibrationMap(
        source_id="caller",
        claim_type="algorithm_identity",
        run_ids=["r_" + "2" * 16],
        blocks=[Block(low=0.1, high=0.9, count=30, correct=24)],
    )
    fit = CalibrationFit(run_ids=mapping.run_ids, maps=[mapping], unfitted=[])
    path = session.root / "maps.json"
    path.write_text(fit.model_dump_json())
    session.config.mcp.calibration_maps = str(path)
    assert "c_adj" not in session.verify_claim(claim(digest), "other")
    result = session.verify_claim(claim(digest), "caller")
    assert result["calibration"] == "calibrated" and result["c_adj"] == pytest.approx(0.8)


def test_excessive_batch_is_counted_before_parsing(session):
    assert session.verify_claims([{}] * 2001)["error_code"] == "budget_exceeded"


def test_reversed_calibrated_dependency_batch_is_atomic(session, monkeypatch):
    from aletheia.confidence import Block, CalibrationFit, CalibrationMap
    from aletheia.schema.models import Claim

    digest = load(session)["binary_sha256"]
    mapping = CalibrationMap(
        source_id="caller",
        claim_type="algorithm_identity",
        run_ids=["r_" + "2" * 16],
        blocks=[Block(low=0.1, high=0.9, count=30, correct=24)],
    )
    path = session.root / "maps.json"
    path.write_text(
        CalibrationFit(run_ids=mapping.run_ids, maps=[mapping], unfitted=[]).model_dump_json()
    )
    session.config.mcp.calibration_maps = str(path)
    parent = claim(digest)
    parent["confidence"] = 1.0
    parent["source"] = {"origin": "human", "source_id": "uncalibrated"}
    parent_id = Claim.intake(ClaimSubmission.model_validate(parent)).claim_id
    child = claim(digest, "0x00002000")
    child["depends_on"] = [parent_id]
    result = session.verify_claims([parent, child], "caller")
    assert result["status"] == "ok"
    assert result["results"][1]["calibration"] == "calibrated"
    assert result["results"][1]["c_adj"] == pytest.approx(0.8)
    before = dict(session.verdicts)

    def fail(*args):
        raise ValueError("unreadable map")

    monkeypatch.setattr(session, "confidence", fail)
    assert session.verify_claims([claim(digest, "0x00003000")], "caller")["status"] == "error"
    assert session.verdicts == before and len(session.claims) == 2


def test_native_function_limit_uses_structured_validation(session, monkeypatch):
    from pydantic import ValidationError

    from aletheia.mcp_server import McpError, NativeVerifier
    from aletheia.sources.base import BinaryRef

    error = ValidationError.from_exception_data(
        "GhidraAnalysis",
        [
            {
                "type": "too_long",
                "loc": ("functions",),
                "input": [],
                "ctx": {"field_type": "List", "max_length": 2000, "actual_length": 2001},
            }
        ],
    )

    def analyze(*args):
        raise error

    monkeypatch.setattr("aletheia.mcp_server.GhidraAnalysisCache.analyze", analyze)
    verifier = NativeVerifier(session.config, session.root)
    with pytest.raises(McpError, match="2,000"):
        verifier.analyze(
            BinaryRef("b" * 64, session.root / "stripped" / ("b" * 64 + ".bin"), "mcp")
        )

    def unrelated(*args):
        raise RuntimeError("unrelated output 2000")

    monkeypatch.setattr("aletheia.mcp_server.GhidraAnalysisCache.analyze", unrelated)
    with pytest.raises(RuntimeError, match="unrelated"):
        verifier.analyze(
            BinaryRef("b" * 64, session.root / "stripped" / ("b" * 64 + ".bin"), "mcp")
        )


def test_mcp_startup_errors_use_stderr(tmp_path):
    from typer.testing import CliRunner

    from aletheia.cli import app

    result = CliRunner().invoke(
        app, ["--config", str(tmp_path / "missing.toml"), "--split", "heldout", "serve-mcp"]
    )
    assert result.exit_code == 7 and not result.stdout
    assert '"error_code": "private_path"' in result.stderr

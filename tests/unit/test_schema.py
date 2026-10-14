"""Contract checks use literal expectations independent of the implementation."""

import hashlib
import json
from pathlib import Path

import jsonschema
import pytest
from pydantic import ValidationError

from aletheia.schema.canonical import canonical_bytes, content_hash
from aletheia.schema.export import export_schemas
from aletheia.schema.models import Claim, ClaimSubmission, Job, JobResult, Targets, Verdict


def submission():
    return {
        "run_id": "r_" + "1" * 16,
        "source": {"origin": "scripted", "source_id": "scripted:v1"},
        "binary_sha256": "a" * 64,
        "subject": {"kind": "function", "address": "0x00001230"},
        "type": "algorithm_identity",
        "body": {"family": "crc32", "variant": "ieee"},
        "confidence": 0.9,
        "confidence_source": "scripted",
        "algorithms_version": "1.0",
    }


def test_canonical_fixed_vector():
    expected = b'{"a":[true,null,1.123457],"z":0.0}'
    value = {"z": -0.0, "a": [True, None, 1.1234567]}
    assert canonical_bytes(value) == expected
    assert content_hash(value) == hashlib.sha256(expected).hexdigest()
    assert canonical_bytes({"z": 2, "a": 1}) == b'{"a":1,"z":2}'


@pytest.mark.parametrize("value", [float("nan"), float("inf"), -float("inf")])
def test_non_finite_rejected(value):
    with pytest.raises(ValueError):
        canonical_bytes({"a": value})


def test_intake_default_hash_roundtrip():
    claim = Claim.intake(ClaimSubmission.model_validate(submission()))
    body = claim.model_dump(exclude={"claim_id"})
    expected = hashlib.sha256(
        json.dumps(body, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()
    ).hexdigest()
    assert claim.claim_id == "c_" + expected[:24]
    assert Claim.model_validate_json(claim.model_dump_json()) == claim
    assert claim.source.shares_backend is False
    assert claim.rationale is None
    assert claim.evidence_refs == []
    with pytest.raises(ValidationError):
        Claim.model_validate(claim.model_dump() | {"claim_id": "c_" + "0" * 24})


@pytest.mark.parametrize(
    "change",
    [
        {"extra": 1},
        {"schema_version": "2.0"},
        {"confidence": 1.1},
        {"subject": {"kind": "function", "address": "0x1230"}},
        {"body": {"family": "crc32", "variant": "unknown"}},
        {"type": "call_relation", "body": {"family": "crc32", "variant": None}},
    ],
)
def test_claim_rejects_invalid(change):
    with pytest.raises(ValidationError):
        ClaimSubmission.model_validate(submission() | change)


@pytest.mark.parametrize(
    "kind", ["ghidra_analyze", "findcrypt_scan", "capa_scan", "verify_static", "verify_probe"]
)
def test_job_roundtrip_every_type(kind):
    job = Job.create(kind, {"binary": "in/" + "a" * 64 + ".bin"}, {})
    assert job.job_id.startswith("j_") and len(job.job_id) == 66
    assert Job.model_validate_json(job.model_dump_json()) == job
    result = JobResult(job_id=job.job_id, status="ok", output={"value": 1})
    assert JobResult.model_validate_json(result.model_dump_json()) == result
    with pytest.raises(ValidationError):
        JobResult(job_id=job.job_id, status="error")
    with pytest.raises(ValidationError):
        JobResult(job_id=job.job_id, status="ok", error_code="internal")


def test_verdict_requirements():
    data = {
        "claim_id": "c_" + "a" * 24,
        "intrinsic_verdict": "INCONCLUSIVE",
        "verifier_version": "0.1.0",
        "env_digest": "sha256:" + "b" * 64,
    }
    with pytest.raises(ValidationError):
        Verdict.model_validate(data)
    assert Verdict.model_validate(data | {"reason": "no_pack"}).reason == "no_pack"
    with pytest.raises(ValidationError):
        Verdict.model_validate(data | {"intrinsic_verdict": "VERIFIED", "strength": "E2"})


def test_sorted_targets():
    data = {
        "binary_sha256": "a" * 64,
        "variant_id": "test",
        "targets": ["0x00002000", "0x00001000"],
    }
    with pytest.raises(ValidationError):
        Targets.model_validate(data)


def test_export_validates_examples(tmp_path):
    export_schemas(tmp_path)
    model = ClaimSubmission.model_validate(submission())
    jsonschema.Draft202012Validator(
        json.loads((tmp_path / "claim-submission.json").read_text())
    ).validate(model.model_dump())
    first = {p.name: p.read_bytes() for p in tmp_path.iterdir()}
    export_schemas(tmp_path)
    assert first == {p.name: p.read_bytes() for p in tmp_path.iterdir()}
    for _name, data in first.items():
        jsonschema.Draft202012Validator.check_schema(json.loads(data))
    assert first == {p.name: p.read_bytes() for p in Path("spec/claims-v1").glob("*.json")}

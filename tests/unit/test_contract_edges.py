import json
import re
from pathlib import Path

import jsonschema
import pytest
import yaml
from pydantic import ValidationError

from aletheia.schema.canonical import content_hash
from aletheia.schema.models import (
    REGISTRY,
    Claim,
    ClaimSubmission,
    Job,
    ManifestInput,
    RunManifest,
    Verdict,
)


def test_registry_file_matches_versioned_contract():
    registry = yaml.safe_load(Path("algorithms.yaml").read_text())
    assert registry["version"] == "1.0"
    assert registry["families"] == {name: list(values) for name, values in REGISTRY.items()}


def test_manifest_informational_time_does_not_affect_hash():
    value = ManifestInput(
        source_config={"scenario": "correct", "case_index": 0},
        binaries=["a" * 64],
        versions={"python": "3.12.15"},
        image_digests={"analysis": "sha256:" + "b" * 64},
        analysis_options_hash="c" * 64,
        pack_hashes={},
        mapping_hashes={},
        verifier_version="v1",
        grader_version="v1",
        seeds={},
    )
    first = RunManifest.create(value, "yesterday")
    second = RunManifest.create(value, "today")
    assert first.run_id == second.run_id
    assert content_hash(first) == content_hash(second)


def test_exported_claim_schema_checks_body_discriminator():
    schema = json.loads(Path("spec/claims-v1/claim-submission.json").read_text())
    value = {
        "schema_version": "1.0",
        "run_id": "r_" + "1" * 16,
        "binary_sha256": "a" * 64,
        "source": {"origin": "scripted", "source_id": "test"},
        "subject": {"address": "0x00001230"},
        "type": "algorithm_identity",
        "body": {"callee": "import:printf", "kind": "direct"},
        "confidence": 0.9,
        "confidence_source": "scripted",
    }
    with pytest.raises(jsonschema.ValidationError):
        jsonschema.validate(value, schema)


def test_appendix_b_examples_validate_after_placeholder_substitution():
    text = Path("SPEC-PHASE-1A.md").read_text().split("## Appendix B: Examples")[1]
    blocks = re.findall(r"\x60\x60\x60(?:json)?\n(.*?)\x60\x60\x60", text, re.S)
    examples = [json.loads(line) for line in blocks[0].splitlines()]
    examples.append(json.loads(blocks[1]))
    for value in examples:
        value["run_id"] = "r_" + "1" * 16
        value["binary_sha256"] = "a" * 64
        value.pop("claim_id", None)
        normalized = ClaimSubmission.model_validate(value)
        schema = json.loads(Path("spec/claims-v1/claim-submission.json").read_text())
        jsonschema.validate(normalized.model_dump(mode="json"), schema)
        stored = Claim.intake(normalized)
        jsonschema.validate(
            stored.model_dump(mode="json"),
            json.loads(Path("spec/claims-v1/claim.json").read_text()),
        )
    verdict = json.loads(blocks[2])
    verdict["env_digest"] = "sha256:" + "b" * 64
    verdict["evidence"][0]["artifact"] = "sha256:" + "c" * 64
    normalized = Verdict.model_validate(verdict)
    jsonschema.validate(
        normalized.model_dump(mode="json"),
        json.loads(Path("spec/claims-v1/verdict.json").read_text()),
    )


def test_job_inputs_bind_opaque_content_to_full_hash_names():
    with pytest.raises(ValidationError):
        Job.create("ghidra_analyze", {"binary": "in/binary.bin"}, {})

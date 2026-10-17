
import jsonschema
import pytest

from aletheia.schema.export import export_schemas
from aletheia.schema.models import Claim, ClaimSubmission
from aletheia.schema.types import canonical_type


def value():
    return {
        "run_id": "r_" + "a" * 16,
        "source": {"origin": "human", "source_id": "human:synthetic"},
        "binary_sha256": "b" * 64,
        "subject": {"address": "0x00001000"},
        "type": "function_signature",
        "body": {
            "return_type": "size_t",
            "params": [{"type": "const char *", "role": "cstr", "name": None}],
        },
        "confidence": 0.8,
        "confidence_source": "stated",
    }


def test_new_claim_types_are_exact_and_match_exported_schema(tmp_path):
    import json

    export_schemas(tmp_path)
    schema = json.loads((tmp_path / "claim-submission.json").read_bytes())
    data = value()
    signature = Claim.intake(ClaimSubmission.model_validate(data))
    assert signature.body.return_type == "size_t"
    jsonschema.validate(data, schema)
    data["type"] = "function_purpose"
    with pytest.raises(ValueError):
        ClaimSubmission.model_validate(data)
    with pytest.raises(jsonschema.ValidationError):
        jsonschema.validate(data, schema)
    data["body"] = {"category": "string.length", "proposed_name": "length", "summary": None}
    assert Claim.intake(ClaimSubmission.model_validate(data)).body.category == "string.length"
    jsonschema.validate(data, schema)
    data["body"]["category"] = "unknown.leaf"
    with pytest.raises(ValueError, match="unknown_category"):
        ClaimSubmission.model_validate(data)
    with pytest.raises(jsonschema.ValidationError):
        jsonschema.validate(data, schema)


def test_signature_type_table_is_shared_and_unknown_types_stay_unknown():
    for spelling, kind, width in [
        ("const unsigned char", "int", 8),
        ("volatile uint16_t", "int", 16),
        ("enum tag", "int", 32),
        ("size_t", "int", 64),
        ("double", "float", 64),
        ("void (*)(int)", "ptr", 64),
        ("char []", "ptr", 64),
        ("void", "void", 0),
        ("custom_t", "unknown", None),
    ]:
        actual = canonical_type(spelling, return_type=True)
        assert (actual.kind, actual.width) == (kind, width)
    assert canonical_type("void").kind == "unknown"

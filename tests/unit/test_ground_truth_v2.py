import json

import jsonschema
import pytest
from pydantic import ValidationError

from aletheia.schema.export import export_schemas
from aletheia.schema.models import GroundTruth


def value():
    return {
        "schema_version": "2.0",
        "algorithms_version": "2.0",
        "binary_sha256": "a" * 64,
        "program_id": "tierA/example",
        "variant_id": "clang23-O2-x64-pie-hardoff",
        "build_flags": "test",
        "functions": [
            {
                "address": "0x00001000",
                "size": 32,
                "name": "sum",
                "algorithm": {"family": "none"},
                "scorable": True,
                "source_signature": "uint32_t (const uint8_t *, size_t)",
                "category": "checksum.other",
                "acceptable_categories": ["checksum.other"],
                "abi_signature": {
                    "return": {"class": "int", "width": 32},
                    "params": [{"class": "ptr", "width": 64}, {"class": "int", "width": 64}],
                    "abi_complex": False,
                    "variadic": False,
                },
                "roles": ["buf", "len"],
                "source_types": {
                    "return_type": "uint32_t",
                    "params": ["const uint8_t *", "size_t"],
                    "variadic": False,
                },
            }
        ],
    }


def test_v2_additions_are_versioned_in_runtime_and_export(tmp_path):
    payload = value()
    record = GroundTruth.model_validate(payload)
    assert record.functions[0].category == "checksum.other"
    assert (
        record.model_dump(mode="json")["functions"][0]["abi_signature"]["return"]["class"] == "int"
    )
    export_schemas(tmp_path)
    schema = json.loads((tmp_path / "ground-truth.json").read_bytes())
    jsonschema.validate(payload, schema)
    payload["schema_version"] = "1.0"
    with pytest.raises(ValidationError):
        GroundTruth.model_validate(payload)
    with pytest.raises(jsonschema.ValidationError):
        jsonschema.validate(payload, schema)


def test_invalid_v2_category_or_missing_scorable_abi_is_rejected():
    for field, replacement in [("category", "made.up"), ("abi_signature", None)]:
        payload = value()
        payload["functions"][0][field] = replacement
        with pytest.raises(ValidationError):
            GroundTruth.model_validate(payload)


def test_v1_does_not_acquire_v2_default_fields():
    payload = value()
    payload["schema_version"] = "1.0"
    for field in ["category", "acceptable_categories", "abi_signature", "roles", "source_types"]:
        del payload["functions"][0][field]
    record = GroundTruth.model_validate(payload)
    assert "category" not in record.model_dump()["functions"][0]

"""Stable schema files for the intake and stored record contracts."""

from pathlib import Path

from pydantic import BaseModel

from aletheia.schema.canonical import canonical_bytes
from aletheia.schema.models import (
    REGISTRY,
    REGISTRY_V1,
    Claim,
    ClaimSubmission,
    Grade,
    GroundTruth,
    Job,
    JobResult,
    RunManifest,
    Targets,
    Verdict,
)

MODELS: dict[str, type[BaseModel]] = {
    "claim-submission": ClaimSubmission,
    "claim": Claim,
    "verdict": Verdict,
    "ground-truth": GroundTruth,
    "targets": Targets,
    "grade": Grade,
    "run-manifest": RunManifest,
    "job": Job,
    "job-result": JobResult,
}


def export_schemas(directory: Path) -> None:
    directory.mkdir(parents=True, exist_ok=True)
    for name, model in sorted(MODELS.items()):
        schema = model.model_json_schema()
        # Registry relationships are runtime validators, so export them explicitly.
        for definition in ("Algorithm", "GroundAlgorithm"):
            algorithm = schema.get("$defs", {}).get(definition)
            if algorithm is None:
                continue
            families = {family: list(variants) for family, variants in sorted(REGISTRY.items())}
            if definition == "GroundAlgorithm":
                families["none"] = []
            algorithm["properties"]["family"]["enum"] = sorted(families)
            algorithm["allOf"] = [
                {
                    "if": {"properties": {"family": {"const": family}}, "required": ["family"]},
                    "then": {"properties": {"variant": {"enum": [None, *variants]}}},
                }
                for family, variants in families.items()
            ]
        if issubclass(model, ClaimSubmission):
            schema["allOf"] = [
                {
                    "if": {
                        "properties": {"type": {"const": "algorithm_identity"}},
                        "required": ["type"],
                    },
                    "then": {"properties": {"body": {"$ref": "#/$defs/Algorithm"}}},
                    "else": {"properties": {"body": {"$ref": "#/$defs/Call"}}},
                },
                {
                    "if": {"properties": {"algorithms_version": {"const": "1.0"}}},
                    "then": {
                        "properties": {
                            "body": {"properties": {"family": {"enum": sorted(REGISTRY_V1)}}}
                        }
                    },
                },
            ]
        elif model is GroundTruth:
            schema["allOf"] = [
                {
                    "if": {"properties": {"algorithms_version": {"const": "1.0"}}},
                    "then": {
                        "properties": {
                            "functions": {
                                "items": {
                                    "properties": {
                                        "algorithm": {
                                            "properties": {
                                                "family": {"enum": sorted([*REGISTRY_V1, "none"])}
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    },
                }
            ]
        if model is GroundTruth:
            from aletheia.schema.taxonomy import Taxonomy

            leaves = Taxonomy.bundled().leaves
            function = schema["$defs"]["GroundFunctionV2"]["properties"]
            function["category"] = {"enum": [None, *leaves]}
            function["acceptable_categories"]["items"] = {"enum": leaves}
            function["acceptable_categories"]["uniqueItems"] = True
            schema["$defs"]["GroundFunctionV2"]["allOf"] = [
                {
                    "if": {"properties": {"scorable": {"const": True}}, "required": ["scorable"]},
                    "then": {
                        "required": ["category", "abi_signature"],
                        "properties": {
                            "category": {"type": "string"},
                            "abi_signature": {"type": "object"},
                        },
                    },
                }
            ]
            schema.setdefault("allOf", []).extend(
                [
                    {
                        "if": {
                            "properties": {"schema_version": {"const": version}},
                            **({"required": ["schema_version"]} if version == "2.0" else {}),
                        },
                        "then": {
                            "properties": {
                                "functions": {"items": {"$ref": "#/$defs/" + function_model}}
                            }
                        },
                    }
                    for version, function_model in [
                        ("1.0", "GroundFunction"),
                        ("2.0", "GroundFunctionV2"),
                    ]
                ]
            )
        (directory / f"{name}.json").write_bytes(canonical_bytes(schema) + b"\n")

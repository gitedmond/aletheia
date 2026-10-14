"""Stable schema files for the intake and stored record contracts."""

from pathlib import Path

from pydantic import BaseModel

from aletheia.schema.canonical import canonical_bytes
from aletheia.schema.models import (
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
        if issubclass(model, ClaimSubmission):
            schema["allOf"] = [
                {
                    "if": {
                        "properties": {"type": {"const": "algorithm_identity"}},
                        "required": ["type"],
                    },
                    "then": {"properties": {"body": {"$ref": "#/$defs/Algorithm"}}},
                    "else": {"properties": {"body": {"$ref": "#/$defs/Call"}}},
                }
            ]
        (directory / f"{name}.json").write_bytes(canonical_bytes(schema) + b"\n")

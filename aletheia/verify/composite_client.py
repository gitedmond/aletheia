"""Stage only stripped inputs and public facts for composite sandbox jobs."""

import hashlib
from pathlib import Path
from typing import cast

from pydantic import JsonValue, TypeAdapter

from aletheia.analysis.ghidra_session import GhidraAnalysis, publish_immutable, read_public_binary
from aletheia.sandbox.runner import JobRunner
from aletheia.schema.canonical import canonical_bytes
from aletheia.schema.models import Job, Verdict
from aletheia.sources.base import BinaryRef
from aletheia.verify.composite import CompositeOutcome, CompositeRequest


class CompositeClient:
    def __init__(self, runner: JobRunner):
        self.runner = runner
        self.last_artifact: str | None = None

    def verify(
        self, binary: BinaryRef, analysis: GhidraAnalysis, pack: Path, request: CompositeRequest
    ) -> CompositeOutcome:
        if (
            binary.binary_sha256 != request.binary_sha256
            or analysis.binary_sha256 != request.binary_sha256
        ):
            raise ValueError("composite public input identity mismatch")
        if any(part.is_symlink() for part in (pack, *pack.parents)):
            raise ValueError("composite pack cannot be a symlink")
        root = self.runner.input_root / "in"

        def stage(payload: bytes, suffix: str):
            digest = hashlib.sha256(payload).hexdigest()
            publish_immutable(root / (digest + suffix), payload)
            return "in/" + digest + suffix

        job = Job.create(
            "verify_composite",
            {
                "binary": stage(read_public_binary(binary), ".bin"),
                "analysis": stage(canonical_bytes(analysis), ".json"),
                "request": stage(canonical_bytes(request), ".json"),
                "pack": stage(pack.read_bytes(), ".yaml"),
            },
            {},
        )
        handle = self.runner.submit(job)
        result = self.runner.wait(handle)
        self.last_artifact = handle.result_artifact
        if result.status != "ok":
            raise RuntimeError(
                f"verify_composite failed: {result.error_code}: {result.output.get('detail', '')}"
            )
        verdicts = TypeAdapter(list[Verdict]).validate_python(result.output["verdicts"])
        expected_ids = {member.claim_id for member in request.members}
        if (
            len(verdicts) != len(expected_ids)
            or {verdict.claim_id for verdict in verdicts} != expected_ids
            or any(verdict.env_digest != request.env_digest for verdict in verdicts)
        ):
            raise ValueError("composite verdict identity mismatch")
        payloads = result.output["artifacts"]
        if not isinstance(payloads, dict) or set(payloads) != {
            item.artifact for verdict in verdicts for item in verdict.evidence
        }:
            raise ValueError("composite evidence map mismatch")
        for digest, value in sorted(payloads.items()):
            if self.runner.artifacts.put(canonical_bytes(cast(JsonValue, value))) != digest:
                raise ValueError("composite evidence content/hash mismatch")
        return CompositeOutcome(verdicts, payloads)

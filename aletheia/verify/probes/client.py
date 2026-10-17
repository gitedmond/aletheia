"""Public-input probe transport; every invocation runs a production sandbox job."""

import hashlib
from pathlib import Path
from typing import cast

from pydantic import JsonValue

from aletheia.analysis.ghidra_session import GhidraAnalysis, publish_immutable, read_public_binary
from aletheia.config import Budgets
from aletheia.sandbox.runner import JobRunner
from aletheia.schema.canonical import canonical_bytes
from aletheia.schema.models import Claim, Digest, Job, Record, Verdict
from aletheia.sources.base import BinaryRef


class ProbeRequest(Record):
    claim: Claim
    budgets: Budgets
    env_digest: Digest


class ProbeClient:
    def __init__(self, runner: JobRunner):
        self.runner = runner
        self.last_artifact: str | None = None

    def probe(
        self,
        binary: BinaryRef,
        claim: Claim,
        analysis: GhidraAnalysis,
        pack: Path | None,
        budgets: Budgets,
        env_digest: Digest,
        purpose_mapping: Path | None = None,
    ) -> Verdict:
        self.last_artifact = None
        if (
            binary.binary_sha256 != claim.binary_sha256
            or analysis.binary_sha256 != claim.binary_sha256
        ):
            raise ValueError("probe public input identity mismatch")
        root = self.runner.input_root / "in"

        def stage(payload: bytes, suffix: str) -> str:
            digest = hashlib.sha256(payload).hexdigest()
            publish_immutable(root / (digest + suffix), payload)
            return "in/" + digest + suffix

        payload = read_public_binary(binary)
        request = ProbeRequest(claim=claim, budgets=budgets, env_digest=env_digest)
        inputs = {
            "binary": stage(payload, ".bin"),
            "analysis": stage(canonical_bytes(analysis), ".json"),
            "request": stage(canonical_bytes(request), ".json"),
        }
        if pack is not None:
            if any(part.is_symlink() for part in (pack, *pack.parents)):
                raise ValueError("probe pack cannot be a symlink")
            inputs["pack"] = stage(pack.read_bytes(), ".yaml")
        if purpose_mapping is not None:
            if any(part.is_symlink() for part in (purpose_mapping, *purpose_mapping.parents)):
                raise ValueError("purpose mapping cannot be a symlink")
            inputs["purpose_mapping"] = stage(purpose_mapping.read_bytes(), ".yaml")
        job = Job.create("verify_probe", inputs, {})
        handle = self.runner.submit(job)
        result = self.runner.wait(handle)
        self.last_artifact = handle.result_artifact
        if result.status != "ok":
            raise RuntimeError(
                f"verify_probe failed: {result.error_code}: {result.output.get('detail', '')}"
            )
        verdict = Verdict.model_validate(result.output["verdict"])
        if verdict.claim_id != claim.claim_id or verdict.env_digest != env_digest:
            raise ValueError("probe verdict identity mismatch")
        payloads = result.output["artifacts"]
        if not isinstance(payloads, dict) or set(payloads) != {
            item.artifact for item in verdict.evidence
        }:
            raise ValueError("probe evidence map mismatch")
        for digest, value in sorted(payloads.items()):
            if self.runner.artifacts.put(canonical_bytes(cast(JsonValue, value))) != digest:
                raise ValueError("probe evidence content/hash mismatch")
        return verdict

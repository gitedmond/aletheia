"""Static methods consume public facts in a production job; constants stay supporting only."""

from pathlib import Path
from typing import cast

from pydantic import JsonValue

from aletheia.analysis.ghidra_session import GhidraAnalysis
from aletheia.schema.models import Claim, Digest, Job, JobResult, Record, Sha256
from aletheia.verify.static.constants import constant_evidence
from aletheia.verify.static.edges import verify_edges
from aletheia.worker.containment import require_job_sandbox
from aletheia.worker.main import guarded_input


class StaticRequest(Record):
    claim: Claim
    env_digest: Digest
    analysis_options_sha256: Sha256


def verify_static(directory: Path, job: Job) -> JobResult:
    require_job_sandbox(directory)
    if set(job.inputs) != {"request", "analysis"} or set(job.params) != {"method"}:
        raise ValueError("verify_static requires exact public request, analysis and method")
    request = StaticRequest.model_validate_json(
        guarded_input(directory, job.inputs["request"]).read_bytes()
    )
    analysis = GhidraAnalysis.model_validate_json(
        guarded_input(directory, job.inputs["analysis"]).read_bytes()
    )
    if analysis.options_sha256 != request.analysis_options_sha256:
        raise ValueError("static analysis/options identity mismatch")
    method = job.params["method"]
    if method == "static.edges@1":
        verdict = verify_edges(request.claim, analysis, request.env_digest)
        output = {"verdict": cast(JsonValue, verdict.model_dump(mode="json"))}
    elif method == "static.constants@1":
        matches = constant_evidence(request.claim, analysis)
        output = {"matches": cast(JsonValue, [match.model_dump(mode="json") for match in matches])}
    else:
        raise ValueError("unregistered static method")
    return JobResult(job_id=job.job_id, status="ok", output=output)

"""Probe job boundary: no private fixtures, symbols, sources or truth are visible."""

from pathlib import Path
from typing import cast

from pydantic import JsonValue

from aletheia.analysis.ghidra_session import GhidraAnalysis
from aletheia.schema.models import Job, JobResult
from aletheia.verify.probes.client import ProbeRequest
from aletheia.verify.probes.pack import load_pack
from aletheia.verify.probes.runner import verify_algorithm
from aletheia.worker.containment import require_job_sandbox
from aletheia.worker.main import guarded_input


def verify_probe(directory: Path, job: Job) -> JobResult:
    require_job_sandbox(directory)
    if (
        set(job.inputs)
        not in ({"binary", "analysis", "request"}, {"binary", "analysis", "request", "pack"})
        or job.params
    ):
        raise ValueError(
            "verify_probe requires exact public binary, analysis, request and optional pack"
        )
    request = ProbeRequest.model_validate_json(
        guarded_input(directory, job.inputs["request"]).read_bytes()
    )
    analysis = GhidraAnalysis.model_validate_json(
        guarded_input(directory, job.inputs["analysis"]).read_bytes()
    )
    pack = load_pack(guarded_input(directory, job.inputs["pack"])) if "pack" in job.inputs else None
    result = verify_algorithm(
        request.claim,
        analysis,
        pack,
        guarded_input(directory, job.inputs["binary"]),
        request.budgets,
        request.env_digest,
    )
    return JobResult(
        job_id=job.job_id,
        status="ok",
        budget_used=result.verdict.budget_used,
        output={
            "verdict": cast(JsonValue, result.verdict.model_dump(mode="json")),
            "artifacts": cast(JsonValue, result.artifacts),
        },
    )

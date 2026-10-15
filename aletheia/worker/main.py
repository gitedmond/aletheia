"""Container protocol boundary. Future analysis handlers fail explicitly until implemented."""

import os
import sys
import tempfile
from collections.abc import Callable
from pathlib import Path

from pydantic import ValidationError

from aletheia.schema.canonical import canonical_bytes
from aletheia.schema.models import Job, JobResult, JobType

HANDLERS: dict[JobType, Callable[[Job], JobResult]] = {}


def guarded_input(job_directory: Path, name: str) -> Path:
    parts = name.split("/")
    if not parts or parts[0] != "in" or any(p in ("", ".", "..", "private") for p in parts):
        raise ValueError("input path must be beneath in/ and cannot include private/")
    if "\\" in name:
        raise ValueError("non-POSIX input path")
    forbidden = {
        "private",
        "corpus",
        "tests",
        "ground_truth.json",
        "unstripped.bin",
        "o0.bin",
        "annotations.json",
    }
    if any(part in forbidden for part in parts) or Path(name).suffix in (".c", ".h"):
        raise ValueError("verifier cannot read private truth, source, or corpus tests")
    root = (job_directory / "in").resolve()
    path = root.joinpath(*parts[1:])
    if not path.resolve().is_relative_to(root) or path.is_symlink():
        raise ValueError("input symlink escapes allowed inputs")
    if not path.is_file():
        raise ValueError("input does not exist or is not a regular file")
    return path


def execute(job_directory: Path, handlers: dict[JobType, Callable[[Job], JobResult]]) -> JobResult:
    # A malformed job has no trustworthy identity; main exits and the host records bad_input.
    job = Job.model_validate_json(guarded_input(job_directory, "in/job.json").read_bytes())
    try:
        for name in job.inputs.values():
            guarded_input(job_directory, name)
        handler = handlers.get(job.type)
        if handler is None:
            result = JobResult(
                job_id=job.job_id,
                status="error",
                error_code="bad_input",
                output={"detail": f"handler not implemented: {job.type}"},
            )
        else:
            result = handler(job)
            if result.job_id != job.job_id:
                raise RuntimeError("handler returned another job identity")
    except (ValueError, OSError) as exc:
        result = JobResult(
            job_id=job.job_id,
            status="error",
            error_code="bad_input",
            output={"detail": str(exc)[:300]},
        )
    except Exception:
        result = JobResult(job_id=job.job_id, status="error", error_code="internal")
    output = job_directory / "out"
    if output.is_symlink() or (output / "result.json").is_symlink():
        raise ValueError("output path cannot be a symlink")
    fd, name = tempfile.mkstemp(dir=output)
    try:
        with os.fdopen(fd, "wb") as stream:
            stream.write(canonical_bytes(result))
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(name, output / "result.json")
    finally:
        Path(name).unlink(missing_ok=True)
    return result


def main() -> None:
    if len(sys.argv) != 2:
        print("usage: python -m aletheia.worker /job", file=sys.stderr)
        raise SystemExit(2) from None
    try:
        from functools import partial

        from aletheia.analysis.ghidra_worker import analyze_ghidra
        from aletheia.sources.capa_worker import scan_capa

        directory = Path(sys.argv[1])
        handlers: dict[JobType, Callable[[Job], JobResult]] = dict(HANDLERS)
        handlers["capa_scan"] = partial(scan_capa, directory)
        handlers["ghidra_analyze"] = partial(analyze_ghidra, directory)
        execute(directory, handlers)
    except (OSError, ValueError, ValidationError):
        print("invalid sandbox job input", file=sys.stderr)
        raise SystemExit(2) from None

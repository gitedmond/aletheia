"""Pinned capa execution and any ELF/Vivisect fallback stay in the sandbox."""

import importlib
import importlib.metadata
import json
import os
import subprocess
from pathlib import Path
from typing import Any, cast

from pydantic import JsonValue, TypeAdapter

from aletheia.schema.models import Job, JobResult
from aletheia.worker.containment import require_job_sandbox
from aletheia.worker.main import guarded_input

REPORT = TypeAdapter(dict[str, JsonValue])


def _validate_stripped_elf(binary: Path) -> None:
    parser = cast(Any, importlib.import_module("elftools.elf.elffile"))
    with binary.open("rb") as stream:
        elf = parser.ELFFile(stream)
        if (
            elf.elfclass != 64
            or not elf.little_endian
            or elf["e_machine"] != "EM_X86_64"
            or elf["e_type"] != "ET_DYN"
            or elf.get_section_by_name(".symtab") is not None
        ):
            raise ValueError("capa input must be a stripped little-endian x86-64 PIE")


def _fallback_base(binary: Path) -> int:
    # This is precisely the pinned capa Vivisect extractor's filemeta policy.
    # No analysis is run and no workspace is saved to the read-only input mount.
    os.environ.setdefault("LOGNAME", str(os.getuid()))
    viv = cast(Any, importlib.import_module("viv_utils"))
    workspace = viv.getWorkspace(str(binary), analyze=False, should_save=False)
    files = list(workspace.filemeta.values())
    if len(files) != 1:
        raise ValueError("ambiguous capa ELF image base")
    value = files[0]["imagebase"]
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise ValueError("invalid capa ELF image base")
    return value


def scan_capa(directory: Path, job: Job) -> JobResult:
    require_job_sandbox(directory)
    if set(job.inputs) != {"binary"} or set(job.params) != {"capa_version", "rules_sha256"}:
        raise ValueError("capa_scan requires one public binary and exact pinned tool inputs")
    expected = job.params["capa_version"]
    actual = importlib.metadata.version("flare-capa")
    digest = os.environ.get("ALETHEIA_CAPA_RULES_SHA256")
    if (
        actual != expected
        or actual != "9.4.0"
        or digest is None
        or digest != job.params["rules_sha256"]
    ):
        raise ValueError("capa tool/rules pins mismatch")
    binary = guarded_input(directory, job.inputs["binary"])
    _validate_stripped_elf(binary)
    try:
        result = subprocess.run(
            ["capa", "--json", "--backend", "vivisect", "-r", "/opt/capa-rules", str(binary)],
            capture_output=True,
            text=True,
            timeout=55,
            env=os.environ | {"LOGNAME": str(os.getuid())},
        )
    except subprocess.TimeoutExpired:
        return JobResult(job_id=job.job_id, status="error", error_code="wall_timeout")
    except OSError:
        return JobResult(job_id=job.job_id, status="error", error_code="internal")
    if result.returncode:
        return JobResult(
            job_id=job.job_id,
            status="error",
            error_code="bad_input",
            output={"detail": "capa_scan failed: " + result.stderr[-1000:]},
        )
    report = REPORT.validate_python(json.loads(result.stdout))
    meta = cast(dict[str, JsonValue], report["meta"])
    analysis = cast(dict[str, JsonValue], meta["analysis"])
    base_source = "metadata"
    if "base_address" not in analysis:
        analysis["base_address"] = {"type": "absolute", "value": _fallback_base(binary)}
        base_source = "pinned_vivisect_elf_loader"
    # Wall-clock and invocation paths are informational, not content identity.
    meta.pop("timestamp", None)
    meta.pop("argv", None)
    sample = cast(dict[str, JsonValue], meta["sample"])
    sample.pop("path", None)
    return JobResult(
        job_id=job.job_id,
        status="ok",
        output={
            "capa": report,
            "capa_version": actual,
            "rules_sha256": digest,
            "address_base_source": base_source,
        },
    )

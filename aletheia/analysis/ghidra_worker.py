"""Pristine Ghidra analysis runs only inside the production job sandbox."""

import hashlib
import importlib
import importlib.metadata
import json
import resource
import tempfile
from pathlib import Path
from typing import Any, cast

from aletheia.analysis.ghidra_session import (
    BodyRange,
    FunctionInfo,
    GhidraAnalysis,
    GhidraOptions,
)
from aletheia.schema.models import Job, JobResult
from aletheia.worker.containment import require_job_sandbox
from aletheia.worker.main import guarded_input


def _validate_binary(path: Path) -> None:
    parser = cast(Any, importlib.import_module("elftools.elf.elffile"))
    with path.open("rb") as stream:
        elf = parser.ELFFile(stream)
        if (
            elf.elfclass != 64
            or not elf.little_endian
            or elf["e_machine"] != "EM_X86_64"
            or elf["e_type"] != "ET_DYN"
            or any(
                section.name == ".symtab" or section.name.startswith((".debug", ".zdebug"))
                for section in elf.iter_sections()
            )
        ):
            raise ValueError("Ghidra input must be a stripped little-endian x86-64 PIE")


def _apply_options(program: Any, manager: Any, config: GhidraOptions) -> None:
    manager.initializeOptions()
    options = program.getOptions(program.ANALYSIS_PROPERTIES)
    actual_names = {str(name) for name in options.getOptionNames()}
    expected_names = {item.name for item in config.options}
    if actual_names != expected_names:
        raise ValueError(
            "registered Ghidra options differ from F6: "
            + json.dumps(
                {
                    "extra": sorted(actual_names - expected_names),
                    "missing": sorted(expected_names - actual_names),
                }
            )
        )
    setters = {
        "BOOLEAN_TYPE": options.setBoolean,
        "INT_TYPE": options.setInt,
        "LONG_TYPE": options.setLong,
        "FLOAT_TYPE": options.setFloat,
        "STRING_TYPE": options.setString,
        "FILE_TYPE": options.setFile,
    }
    for item in config.options:
        if str(options.getType(item.name)) != item.type:
            raise ValueError("Ghidra option type mismatch: " + item.name)
        if item.type == "ENUM_TYPE":
            default = options.getObject(item.name, None)
            value = cast(Any, type(default)).valueOf(item.value)
            options.setEnum(item.name, value)
        else:
            setters[item.type](item.name, item.value)
        chosen = options.getObject(item.name, None)
        actual = (
            bool(chosen)
            if item.type == "BOOLEAN_TYPE"
            else int(chosen)
            if item.type in ("INT_TYPE", "LONG_TYPE")
            else float(chosen)
            if item.type == "FLOAT_TYPE"
            else str(chosen.name())
            if item.type == "ENUM_TYPE"
            else str(chosen)
            if chosen is not None
            else None
        )
        if actual != item.value:
            raise ValueError("Ghidra did not apply option: " + item.name)
    manager.initializeOptions(options)


def analyze_ghidra(directory: Path, job: Job) -> JobResult:
    require_job_sandbox(directory)
    if set(job.inputs) != {"binary", "options"} or set(job.params) != {
        "ghidra_version",
        "options_sha256",
        "env_digest",
    }:
        raise ValueError("ghidra_analyze requires a public binary and exact pinned options")
    binary = guarded_input(directory, job.inputs["binary"])
    options_path = guarded_input(directory, job.inputs["options"])
    config = GhidraOptions.read(options_path)
    option_hash = hashlib.sha256(options_path.read_bytes()).hexdigest()
    if (
        option_hash != job.params["options_sha256"]
        or config.ghidra_version != job.params["ghidra_version"]
        or importlib.metadata.version("pyghidra") != config.pyghidra_version
    ):
        raise ValueError("Ghidra tool/options pins mismatch")
    _validate_binary(binary)
    ghidra = cast(Any, importlib.import_module("pyghidra"))
    ghidra.start()
    jpype = cast(Any, importlib.import_module("jpype"))
    application = jpype.JClass("ghidra.framework.Application")
    if str(application.getApplicationVersion()) != config.ghidra_version:
        raise ValueError("Ghidra runtime version mismatch")
    manager_class = jpype.JClass("ghidra.app.plugin.core.analysis.AutoAnalysisManager")
    with tempfile.TemporaryDirectory(dir="/scratch", prefix="ghidra-") as scratch:
        with ghidra.open_program(
            binary,
            project_location=scratch,
            project_name="analysis",
            analyze=False,
            language=config.language_id,
            compiler=config.compiler_spec_id,
            loader="ghidra.app.util.opinion.ElfLoader",
        ) as api:
            program = api.getCurrentProgram()
            if str(program.getExecutableFormat()) != config.executable_format:
                raise ValueError("Ghidra imported an unexpected executable format")
            transaction = program.startTransaction("pin base and analysis options")
            commit = False
            try:
                address = program.getAddressFactory().getDefaultAddressSpace().getAddress(0)
                program.setImageBase(address, True)
                _apply_options(program, manager_class.getAnalysisManager(program), config)
                commit = True
            finally:
                program.endTransaction(transaction, commit)
            if int(program.getImageBase().getOffset()) != 0:
                raise ValueError("Ghidra image base is not zero")
            api.analyzeAll(program)
            functions: list[FunctionInfo] = []
            for function in program.getFunctionManager().getFunctions(True):
                ranges = [
                    BodyRange(
                        start=f"0x{int(region.getMinAddress().getOffset()):08x}",
                        end=f"0x{int(region.getMaxAddress().getOffset()) + 1:08x}",
                    )
                    for region in function.getBody().getAddressRanges()
                ]
                thunk = function.getThunkedFunction(True) if function.isThunk() else None
                functions.append(
                    FunctionInfo(
                        entry=f"0x{int(function.getEntryPoint().getOffset()):08x}",
                        body_ranges=ranges,
                        is_thunk=bool(function.isThunk()),
                        import_name=str(thunk.getName())
                        if thunk is not None and thunk.isExternal()
                        else None,
                    )
                )
            analysis = GhidraAnalysis(
                binary_sha256=binary.stem,
                options_sha256=option_hash,
                functions=sorted(functions, key=lambda fn: int(fn.entry, 16)),
            )
    # Resource observations are informational and must not enter deterministic cache identity.
    (directory / "out/measurement.json").write_text(
        json.dumps(
            {
                "peak_rss_bytes": resource.getrusage(resource.RUSAGE_SELF).ru_maxrss * 1024,
            },
            sort_keys=True,
        )
    )
    return JobResult(
        job_id=job.job_id, status="ok", output={"analysis": analysis.model_dump(mode="json")}
    )

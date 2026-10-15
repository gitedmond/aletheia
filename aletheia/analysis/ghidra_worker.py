"""Pristine Ghidra analysis runs only inside the production job sandbox."""

import hashlib
import importlib
import importlib.metadata
import json
import resource
import tempfile
from pathlib import Path
from typing import Any, cast

from pydantic import TypeAdapter

from aletheia.analysis.ghidra_session import (
    BodyRange,
    CallSite,
    FunctionInfo,
    GhidraAnalysis,
    GhidraOptions,
)
from aletheia.schema.models import Address, Job, JobResult
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


def _target(program: Any, address: Any) -> str | None:
    function = program.getFunctionManager().getFunctionAt(address)
    if function is not None:
        resolved = function.getThunkedFunction(True) if function.isThunk() else function
        if resolved is not None and resolved.isExternal():
            return "import:" + str(resolved.getName())
        return f"0x{int(function.getEntryPoint().getOffset()):08x}"
    if address.isExternalAddress():
        symbol = program.getSymbolTable().getPrimarySymbol(address)
        if symbol is not None:
            return "import:" + str(symbol.getName())
    return None


def _call_sites(program: Any, function: Any) -> tuple[list[CallSite], bool]:
    listing, body = program.getListing(), function.getBody()
    sites: dict[tuple[int, str, str], CallSite] = {}
    covered = 0
    uncertain_jump = False
    for instruction in listing.getInstructions(body, True):
        covered += int(instruction.getLength())
        flow = instruction.getFlowType()
        # Ghidra can override a tail JMP as CALL_RETURN; edge kind follows the machine mnemonic.
        mnemonic = str(instruction.getMnemonicString()).upper()
        if mnemonic not in ("CALL", "JMP"):
            continue
        is_call = mnemonic == "CALL"
        at = int(instruction.getAddress().getOffset())
        flows = list(instruction.getFlows())
        if flow.isComputed():
            imports: set[str] = set()
            for reference in instruction.getReferencesFrom():
                target = reference.getToAddress()
                name = _target(program, target)
                if name is not None and name.startswith("import:"):
                    imports.add(name)
                if target.isMemoryAddress():
                    for pointer in program.getReferenceManager().getReferencesFrom(target):
                        name = _target(program, pointer.getToAddress())
                        if name is not None and name.startswith("import:"):
                            imports.add(name)
            if len(imports) == 1:
                kind, target_name = ("direct" if is_call else "tail"), next(iter(imports))
            else:
                kind, target_name = "indirect", None
            sites[(at, kind, target_name or "")] = CallSite.model_validate(
                {
                    "address": f"0x{at:08x}",
                    "kind": kind,
                    "target": target_name,
                }
            )
            continue
        for target in flows:
            if not is_call and body.contains(target):
                continue
            name = _target(program, target)
            if name is None and is_call and target.isMemoryAddress():
                name = f"0x{int(target.getOffset()):08x}"
            if name is None:
                uncertain_jump = True
                continue
            kind = "direct" if is_call else "tail"
            sites[(at, kind, name)] = CallSite.model_validate(
                {
                    "address": f"0x{at:08x}",
                    "kind": kind,
                    "target": name,
                }
            )
    return [sites[key] for key in sorted(sites)], covered == int(
        body.getNumAddresses()
    ) and not uncertain_jump


def analyze_ghidra(directory: Path, job: Job) -> JobResult:
    require_job_sandbox(directory)
    required = {"ghidra_version", "options_sha256", "env_digest"}
    if (
        set(job.inputs) != {"binary", "options"}
        or not required <= set(job.params)
        or set(job.params) - required - {"subjects"}
    ):
        raise ValueError("ghidra_analyze requires a public binary and exact pinned options")
    subjects = TypeAdapter(list[Address]).validate_python(job.params.get("subjects", []))
    if len(subjects) > 2000 or subjects != sorted(set(subjects), key=lambda a: int(a, 16)):
        raise ValueError("requested subjects must be sorted, unique and bounded")
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
            missing: list[Address] = []
            created = False
            transaction = program.startTransaction("ensure claimed functions")
            try:
                for subject in subjects:
                    address = (
                        program.getAddressFactory()
                        .getDefaultAddressSpace()
                        .getAddress(int(subject, 16))
                    )
                    if program.getFunctionManager().getFunctionAt(address) is not None:
                        continue
                    block = program.getMemory().getBlock(address)
                    if block is None or not block.isExecute():
                        missing.append(subject)
                        continue
                    api.disassemble(address)
                    if api.createFunction(address, None) is None:
                        missing.append(subject)
                    else:
                        created = True
            finally:
                program.endTransaction(transaction, True)
            if created:
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
                sites, complete = _call_sites(program, function)
                thunk = function.getThunkedFunction(True) if function.isThunk() else None
                functions.append(
                    FunctionInfo(
                        entry=f"0x{int(function.getEntryPoint().getOffset()):08x}",
                        body_ranges=ranges,
                        is_thunk=bool(function.isThunk()),
                        call_sites=sites,
                        body_complete=complete,
                        import_name=str(thunk.getName())
                        if thunk is not None and thunk.isExternal()
                        else None,
                    )
                )
            analysis = GhidraAnalysis(
                binary_sha256=binary.stem,
                options_sha256=option_hash,
                functions=sorted(functions, key=lambda fn: int(fn.entry, 16)),
                missing_subjects=missing,
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

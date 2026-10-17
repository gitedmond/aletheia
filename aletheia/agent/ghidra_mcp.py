"""Container-only upstream: pinned Ghidra import with pyghidra-mcp read tools."""

import importlib
import importlib.metadata
import logging
import sys
import tempfile
from pathlib import Path
from types import SimpleNamespace
from typing import Any, cast

from aletheia.analysis.ghidra_session import GhidraOptions
from aletheia.analysis.ghidra_worker import apply_options, validate_binary
from aletheia.worker.containment import require_job_sandbox


def main() -> None:
    require_job_sandbox(Path("/job"))
    binary, option_path = map(Path, sys.argv[1:])
    if binary.parent != Path("/job/in") or option_path.parent != Path("/job/in"):
        raise ValueError("upstream inputs must be staged beneath /job/in")
    options = GhidraOptions.read(option_path)
    if (
        importlib.metadata.version("pyghidra-mcp") != "0.1.6"
        or importlib.metadata.version("mcp") != "1.30.0"
        or importlib.metadata.version("pyghidra") != options.pyghidra_version
    ):
        raise ValueError("MCP runtime pin mismatch")
    validate_binary(binary)
    logging.basicConfig(stream=sys.stderr)
    ghidra = cast(Any, importlib.import_module("pyghidra"))
    ghidra.start()
    jpype = cast(Any, importlib.import_module("jpype"))
    if (
        str(jpype.JClass("ghidra.framework.Application").getApplicationVersion())
        != options.ghidra_version
    ):
        raise ValueError("Ghidra runtime pin mismatch")
    # Upstream Ghidra tools receive our pristine, base-zero program rather than importing again.
    server = cast(Any, importlib.import_module("pyghidra_mcp.server"))
    context = cast(Any, importlib.import_module("pyghidra_mcp.context"))
    with tempfile.TemporaryDirectory(dir="/scratch") as directory:
        with ghidra.open_program(
            binary,
            project_location=directory,
            project_name="agent",
            analyze=False,
            language=options.language_id,
            compiler=options.compiler_spec_id,
            loader="ghidra.app.util.opinion.ElfLoader",
        ) as api:
            program = api.getCurrentProgram()
            if str(program.getExecutableFormat()) != options.executable_format:
                raise ValueError("unexpected executable format")
            transaction = program.startTransaction("pin agent analysis")
            commit = False
            try:
                program.setImageBase(
                    program.getAddressFactory().getDefaultAddressSpace().getAddress(0), True
                )
                manager = jpype.JClass(
                    "ghidra.app.plugin.core.analysis.AutoAnalysisManager"
                ).getAnalysisManager(program)
                apply_options(program, manager, options)
                commit = True
            finally:
                program.endTransaction(transaction, commit)
            if int(program.getImageBase().getOffset()) != 0:
                raise ValueError("agent image base is not zero")
            api.analyzeAll(program)
            decompiler = jpype.JClass("ghidra.app.decompiler.DecompInterface")()
            decompiler.openProgram(program)
            info = context.ProgramInfo(
                name="input",
                program=program,
                flat_api=api,
                decompiler=decompiler,
                metadata={"image_base": "0x00000000"},
                analysis_complete=True,
            )
            server.mcp._pyghidra_context = SimpleNamespace(programs={"input": info})
            try:
                server.mcp.run(transport="stdio")
            finally:
                decompiler.dispose()


if __name__ == "__main__":
    main()

"""T09 trust boundaries: typed reviewed options and containment before parsing."""

from pathlib import Path

import pytest

from aletheia.analysis.ghidra_session import GhidraOptions
from aletheia.analysis.ghidra_worker import analyze_ghidra
from aletheia.schema.models import Job


def test_approved_options_and_explicit_rejection_of_changed_pins():
    options = GhidraOptions.read(Path("configs/ghidra-analysis.json"))
    raw = options.model_dump()
    raw["image_base"] = "0x00100000"
    with pytest.raises(ValueError):
        GhidraOptions.model_validate(raw)
    raw = options.model_dump()
    next(item for item in raw["options"] if item["name"] == "Find Crypt")["value"] = True
    with pytest.raises(ValueError, match="disabled"):
        GhidraOptions.model_validate(raw)


def test_handler_rejects_host_execution_before_importing_native_tools(tmp_path):
    job = Job.create("ghidra_analyze", {}, {})
    with pytest.raises(ValueError, match="sandbox"):
        analyze_ghidra(tmp_path, job)


def test_unrecognized_lazy_plt_entry_resolves_its_first_jump():
    from unittest.mock import Mock

    from aletheia.analysis.ghidra_worker import _target

    program, function, instruction, slot = Mock(), Mock(), Mock(), Mock()
    program.getFunctionManager.return_value.getFunctionAt.return_value = function
    program.getListing.return_value.getInstructionAt.return_value = instruction
    function.isThunk.return_value = function.isExternal.return_value = False
    function.getEntryPoint.return_value.getOffset.return_value = 0x2000
    function.getBody.return_value.getNumAddresses.return_value = 16
    instruction.getLength.return_value = 6
    instruction.getMnemonicString.return_value = "JMP"
    instruction.getFlowType.return_value.isComputed.return_value = True
    instruction.getReferencesFrom.return_value = [Mock(getToAddress=lambda: slot)]
    slot.isMemoryAddress.return_value = True
    slot.getOffset.return_value = 0x4000
    assert _target(program, Mock(), {0x4000: "import:fwrite"}) == "import:fwrite"

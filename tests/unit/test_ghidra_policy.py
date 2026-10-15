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

"""F6 proposal: freeze the analyzer list without treating it as author-approved."""

import json
import math
from pathlib import Path

from aletheia.doctor import read_lock


def test_proposed_f6_envelope_types_and_disabled_label_detectors():
    value = json.loads(Path("configs/ghidra-analysis.json").read_bytes())
    lock = read_lock(Path("versions.lock.md"))
    assert value["schema_version"] == "1.0"
    assert value["ghidra_version"] == lock["pins"]["ghidra"]["version"]
    assert value["pyghidra_version"] == lock["packages"]["pyghidra"]
    assert value["image_base"] == "0x00000000"
    assert value["language_id"] == "x86:LE:64:default"
    assert value["compiler_spec_id"] == "gcc"
    assert value["executable_format"] == "Executable and Linking Format (ELF)"
    options = value["options"]
    assert len(options) == 127
    names = [item["name"] for item in options]
    assert names == sorted(set(names))
    by_name = {item["name"]: item for item in options}
    for name in ("Function ID", "Find Crypt"):
        assert by_name[name] == {"name": name, "type": "BOOLEAN_TYPE", "value": False}
    assert by_name["Stack.Max Threads"]["value"] == 1
    assert by_name["x86 Constant Reference Analyzer.Max Threads"]["value"] == 1
    for item in options:
        kind, chosen = item["type"], item["value"]
        if kind == "BOOLEAN_TYPE":
            assert type(chosen) is bool
        elif kind in ("INT_TYPE", "LONG_TYPE"):
            assert type(chosen) is int
        elif kind == "FLOAT_TYPE":
            assert type(chosen) is float and math.isfinite(chosen)
        elif kind in ("STRING_TYPE", "ENUM_TYPE"):
            assert chosen is None or isinstance(chosen, str)
        else:
            assert kind == "FILE_TYPE" and chosen is None

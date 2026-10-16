"""Optimized compiler definitions produce independent private ABI metadata."""

import json
from pathlib import Path

import pytest

from aletheia.config import Config
from aletheia.corpus.build import Variant, build_program

pytestmark = pytest.mark.integration


def test_real_optimized_ir_matches_crc_register_contract(tmp_path):
    image = Config.read(Path("aletheia.toml")).sandbox.image_build
    build = build_program(Path("corpus/tierA/crc32tool"), Variant(image, tmp_path / "build"))
    record = json.loads((build.o0.parent / "abi.json").read_bytes())
    assert record["binary_sha256"] == build.binary_sha256
    crc = record["functions"]["crc32_update"]
    assert crc["return"] == {"class": "int", "width": 32}
    assert crc["params"] == [
        {"class": "int", "width": 32},
        {"class": "ptr", "width": 64},
        {"class": "int", "width": 64},
    ]
    assert crc["abi_complex"] is False
    assert record["functions"]["crc32_table_init"]["return"] == {"class": "void", "width": 0}
    assert json.loads(build.metadata.read_bytes())["ir_hashes"]

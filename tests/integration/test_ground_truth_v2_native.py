"""V2 annotations and compiler ABI are joined privately; v1 serialization stays separate."""

import json
import re
import shutil
from pathlib import Path

import pytest

from aletheia.config import Config
from aletheia.corpus.build import Variant, build_program
from aletheia.schema.models import GroundTruth

pytestmark = pytest.mark.integration


def test_native_v2_joins_categories_roles_and_ir_without_scoring_crt(tmp_path):
    corpus = tmp_path / "corpus"
    source = corpus / "tierA/crc32tool"
    shutil.copytree("corpus/tierA/crc32tool", source)
    shutil.copytree("corpus/include", corpus / "include")
    categories = {
        "main": "control.main",
        "read_input": "io.file.read",
        "hex_print32": "io.file.write",
        "crc32_table_init": "util.init",
        "crc32_selftest": "util.other",
    }
    for path in (source / "src").glob("*.c"):
        text = path.read_text()
        if "// @category " not in text:
            pattern = re.compile(r"(// @algorithm [^\n]+\n)([^\n]*?\b(\w+)\([^;{}]*\)\s*\{)")
            text = pattern.sub(
                lambda m: (
                    m[1] + "// @category " + categories.get(m[3], "checksum.crc32") + "\n" + m[2]
                ),
                text,
            )
        text = text.replace(
            "// @category checksum.crc32\nALETHEIA_TARGET uint32_t crc32_update(",
            "// @category checksum.crc32\n// @roles seed,buf,len\n"
            "ALETHEIA_TARGET uint32_t crc32_update(",
        )
        path.write_text(text)
    nested = source / "src/nested"
    nested.mkdir()
    # Nested sources use the same annotation scan as compilation and lint.
    for path in sorted((source / "src").glob("*.c")):
        if "crc32_update(" in path.read_text() and path.name != "main.c":
            path.rename(nested / path.name)
    image = Config.read(Path("aletheia.toml")).sandbox.image_build
    build = build_program(source, Variant(image, tmp_path / "build", ground_truth_version="2.0"))
    truth = GroundTruth.model_validate_json((build.o0.parent / "ground_truth.json").read_bytes())
    assert truth.schema_version == truth.algorithms_version == "2.0"
    function = next(f for f in truth.functions if f.name == "crc32_update")
    assert function.category == "checksum.crc32"
    assert function.roles == ["seed", "buf", "len"]
    assert function.abi_signature.return_type.width == 32
    assert function.source_types.params == ["uint32_t", "const uint8_t *", "size_t"]
    excluded = next(f for f in truth.functions if f.name == "_start")
    assert not excluded.scorable and excluded.exclusion_reason == "abi_unavailable"
    targets = json.loads((build.metadata.parent / "targets.json").read_bytes())["targets"]
    assert excluded.address not in targets

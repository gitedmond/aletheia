"""B17 is checked from independently decoded O0 ELF edges inside the compiler sandbox."""

from pathlib import Path

import pytest

from aletheia.config import Config
from aletheia.corpus.build import BuildError, Variant, build_program
from aletheia.corpus.ground_truth import extract_ground_truth

pytestmark = pytest.mark.integration


@pytest.mark.parametrize("mode", ["allowed", "forbidden", "categoryless", "indirect"])
def test_probe_target_imports_use_emitted_o0_edges(tmp_path, mode):
    forbidden = mode != "allowed"
    root = tmp_path / "corpus"
    program = root / "tierA/policy-sample"
    (program / "src").mkdir(parents=True)
    (program / "tests").mkdir()
    (root / "include").mkdir()
    (root / "include/aletheia.h").write_text("#define ALETHEIA_TARGET __attribute__((noinline))\n")
    operation = 'puts("hello");' if forbidden else "memcpy(out, buf, len);"
    source = (
        """#include "aletheia.h"
#include <stdint.h>
#include <stdio.h>
#include <string.h>
// @algorithm none
// @category memory.copy
// @roles out,buf,len
ALETHEIA_TARGET void target(uint8_t *out, const uint8_t *buf, size_t len) {
"""
        + operation
        + """
}
// @algorithm none
// @category control.main
int main(void) {
    uint8_t buf[16], out[16];
    size_t len = fread(buf, 1, sizeof buf, stdin);
    target(out, buf, len);
    printf("%x", (unsigned)len);
    return 0;
}
"""
    )
    if mode == "categoryless":
        source = source.replace(
            "// @algorithm none\n// @category memory.copy", "// @algorithm crc32/ieee"
        )
    if mode == "indirect":
        source = source.replace(
            "// @algorithm none\n// @category memory.copy",
            "// @algorithm none\n// @category util.other\n"
            "static int allowed(const char *s) { return *s; }\n"
            "// @algorithm none\n// @category memory.copy\n// @indirect-targets allowed",
        )
        source = source.replace(
            'puts("hello");', 'int (*volatile fn)(const char *) = puts; fn("hello");'
        )
    (program / "src/main.c").write_text(source)
    (program / "Makefile").write_text("test:\n\ttrue\n")
    (program / "tests/test.c").write_text("int main(void) {return 0;}\n")
    image = Config.read(Path("aletheia.toml")).sandbox.image_build
    variant = Variant(image=image, output_root=tmp_path / "build")
    if forbidden:
        with pytest.raises(BuildError, match="unsupported_target_import"):
            build_program(program, variant)
        assert not (variant.output_root / program.name / variant.id).exists()
    else:
        result = build_program(program, variant)
        truth = extract_ground_truth(result, program)
        assert any(f.name == "target" for f in truth.functions)

import json

import pytest
from typer.testing import CliRunner

from aletheia.cli import app
from aletheia.corpus.lint import lint_program

SOURCE = """
#include "aletheia.h"
#include <stdint.h>
#include <stdio.h>
// @algorithm fnv/fnv1a-32
ALETHEIA_TARGET uint32_t fnv1a_32(const uint8_t *buf, size_t len) {
    uint32_t hash = 0x811c9dc5u;
    for (size_t i = 0; i < len; ++i) hash = (hash ^ buf[i]) * 0x01000193u;
    return hash;
}
// @algorithm none
int main(void) {
    uint8_t buf[128];
    size_t len = fread(buf, 1, sizeof buf, stdin);
    printf("%08x\\n", fnv1a_32(buf, len));
    return 0;
}
"""


def program(tmp_path, source=SOURCE):
    root = tmp_path / "sample"
    (root / "src").mkdir(parents=True)
    (root / "tests").mkdir()
    (root / "src/program.c").write_text(source)
    (root / "src/aletheia.h").write_text("#define ALETHEIA_TARGET __attribute__((noinline))\n")
    (root / "tests/test.c").write_text("int main(void) { return 0; }\n")
    (root / "Makefile").write_text("test:\n\t@true\n")
    return root


def rules(root):
    return {error.rule for error in lint_program(root)}


def test_complete_c17_program_passes(tmp_path):
    assert lint_program(program(tmp_path)) == []


@pytest.mark.parametrize(
    ("old", "new", "rule"),
    [
        ("#include <stdint.h>", "#include <vendor/crypto.h>", "libc_only"),
        ("fnv1a_32(buf, len)", "fnv1a_32(buf, len)", None),
        ("// @algorithm fnv/fnv1a-32\n", "", "annotation_required"),
        ("// @algorithm fnv/fnv1a-32", "// @algorithm fnv/unknown", "annotation_invalid"),
        ("// @algorithm none\nint main", "// @algorithm none\n\nint main", "annotation_adjacent"),
        ("ALETHEIA_TARGET uint32_t fnv1a_32", "uint32_t fnv1a_32", "target_noinline"),
        ('"%08x\\n"', '"fnv %08x\\n"', "label_string"),
        ("int main(void)", "__attribute__((constructor)) int main(void)", "constructor"),
        ("size_t len = fread(buf, 1, sizeof buf, stdin);", "size_t len = 0;", "main_input"),
        ('printf("%08x\\n", fnv1a_32(buf, len));', "(void)fnv1a_32(buf, len);", "main_hex"),
        ('printf("%08x\\n", fnv1a_32(buf, len));', 'printf("%08x\\n", 0u);', "main_target"),
    ],
)
def test_each_source_rule_has_passing_and_failing_case(tmp_path, old, new, rule):
    root = program(tmp_path, SOURCE.replace(old, new))
    if rule is None:
        assert lint_program(root) == []
    else:
        assert rule in rules(root)


def test_names_unique_across_translation_units(tmp_path):
    root = program(tmp_path)
    (root / "src/other.c").write_text(
        "// @algorithm none\nstatic int fnv1a_32(void) { return 0; }\n"
    )
    assert "duplicate_function" in rules(root)


def test_missing_tests_and_constructor_section_are_rejected(tmp_path):
    root = program(tmp_path, SOURCE + '\nvoid *x __attribute__((section(".init_array")));\n')
    (root / "tests/test.c").unlink()
    assert {"native_tests", "constructor"} <= rules(root)


def test_macro_must_really_define_noinline(tmp_path):
    root = program(tmp_path)
    (root / "src/aletheia.h").write_text("#define ALETHEIA_TARGET\n")
    assert "target_noinline" in rules(root)


def test_comment_and_include_names_do_not_become_binary_labels(tmp_path):
    root = program(
        tmp_path,
        SOURCE.replace(
            '#include "aletheia.h"', '#include "fnv.h"\n// crc32 __attribute__((constructor))'
        ),
    )
    (root / "src/fnv.h").write_text("#define ALETHEIA_TARGET __attribute__((noinline))\n")
    assert lint_program(root) == []


def test_escaped_and_concatenated_algorithm_strings_are_rejected(tmp_path):
    root = program(tmp_path, SOURCE.replace('"%08x\\n"', '"f" "nv %08x\\n"'))
    assert "label_string" in rules(root)
    (root / "src/program.c").write_text(SOURCE.replace('"%08x\\n"', '"\\x66nv %08x\\n"'))
    assert "label_string" in rules(root)


def test_indirect_targets_must_be_registered_function_names(tmp_path):
    root = program(
        tmp_path,
        SOURCE.replace(
            "// @algorithm fnv/fnv1a-32", "// @algorithm fnv/fnv1a-32\n// @indirect-targets missing"
        ),
    )
    assert "indirect_target_missing" in rules(root)


def test_cli_lint_json_and_failure_status(tmp_path):
    root = program(tmp_path)
    result = CliRunner().invoke(app, ["--json", "corpus", "lint", str(root)])
    assert result.exit_code == 0
    assert json.loads(result.output)["errors"] == []
    (root / "src/program.c").write_text(SOURCE.replace("// @algorithm none\n", ""))
    result = CliRunner().invoke(app, ["--json", "corpus", "lint", str(root)])
    assert result.exit_code == 1
    assert any(e["rule"] == "annotation_required" for e in json.loads(result.output)["errors"])


def test_no_programs_is_explicit_failure(tmp_path):
    result = CliRunner().invoke(app, ["--json", "corpus", "lint", str(tmp_path)])
    assert result.exit_code == 1
    assert json.loads(result.output)["errors"][0]["rule"] == "program_missing"


def test_cli_selects_named_program(tmp_path):
    program(tmp_path)
    result = CliRunner().invoke(
        app, ["--json", "corpus", "lint", str(tmp_path), "--program", "sample"]
    )
    assert result.exit_code == 0
    assert json.loads(result.output) == {"programs": 1, "errors": []}


def test_cli_missing_named_program_is_explicit_failure(tmp_path):
    program(tmp_path)
    result = CliRunner().invoke(
        app, ["--json", "corpus", "lint", str(tmp_path), "--program", "missing"]
    )
    assert result.exit_code == 1
    assert json.loads(result.output)["errors"][0]["rule"] == "program_missing"

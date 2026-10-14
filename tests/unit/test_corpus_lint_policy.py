from aletheia.corpus.lint import lint_program


def project(tmp_path, extra="", header=None, make="test:\n\ttrue\n"):
    (tmp_path / "src").mkdir()
    (tmp_path / "tests").mkdir()
    (tmp_path / "tests/test.c").write_text("int main(void) {return 0;}\n")
    (tmp_path / "Makefile").write_text(make)
    (tmp_path / "src/shared.h").write_text(
        header if header is not None else "#define ALETHEIA_TARGET __attribute__((noinline))\n"
    )
    (tmp_path / "src/main.c").write_text(
        """
#include <stdio.h>
#include "shared.h"
// @algorithm none
ALETHEIA_TARGET int target(int x) {return x + 1;}
// @algorithm none
int main(void) {
    int x = getchar();
    printf("%x", target(x));
    return 0;
}
"""
        + extra
    )
    return tmp_path


def rules(root):
    return {e.rule for e in lint_program(root)}


def test_macro_strings_must_not_leak_algorithm_names(tmp_path):
    root = project(tmp_path, '\n#define MESSAGE "CRC32"\n')
    assert "label_string" in rules(root)


def test_noinline_definition_in_comment_does_not_count(tmp_path):
    root = project(tmp_path, header="/* #define ALETHEIA_TARGET __attribute__((noinline)) */\n")
    assert "target_noinline" in rules(root)


def test_third_party_link_dependencies_are_rejected(tmp_path):
    root = project(tmp_path, make="LDLIBS=-lcrypto\ntest:\n\ttrue\n")
    assert "libc_only" in rules(root)


def test_inline_assembly_is_not_c17(tmp_path):
    root = project(
        tmp_path, '\n// @algorithm none\nint extra(void) { __asm__("nop"); return 0; }\n'
    )
    assert "c17_only" in rules(root)


def test_local_header_escape_is_rejected(tmp_path):
    root = project(tmp_path)
    outside = tmp_path.parent / "outside-lint.h"
    outside.write_text("#define X 1\n")
    source = root / "src/main.c"
    source.write_text(
        source.read_text().replace(
            '#include "shared.h"', '#include "shared.h"\n#include "../../outside-lint.h"'
        )
    )
    assert "libc_only" in rules(root)

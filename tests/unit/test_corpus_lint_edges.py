from aletheia.corpus.lint import lint_program


def make_program(tmp_path, extra="", prefix=""):
    root = tmp_path / "sample"
    (root / "src").mkdir(parents=True)
    (root / "tests").mkdir()
    (root / "Makefile").write_text("test:\n\ttrue\n")
    (root / "tests/test.c").write_text("int main(void){return 0;}\n")
    (root / "src/common.h").write_text("#define ALETHEIA_TARGET __attribute__((noinline))\n")
    (root / "src/main.c").write_text(
        prefix
        + """
#include <stdio.h>
#include "common.h"
// @algorithm none
ALETHEIA_TARGET int target(int value) { return value + 1; }
// @algorithm none
int main(void) {
  int value = getchar();
  printf("%x", target(value));
  return 0;
}
"""
        + extra
    )
    return root


def codes(root):
    return {e.rule for e in lint_program(root)}


def test_compact_pointer_and_multiline_definition_are_annotated(tmp_path):
    root = make_program(tmp_path, '\nstatic const char* hidden(void) {return "x";}\n')
    assert "annotation_required" in codes(root)


def test_annotations_on_helpers_and_main_are_required(tmp_path):
    root = make_program(tmp_path)
    file = root / "src/main.c"
    file.write_text(file.read_text().replace("// @algorithm none\nint main", "int main"))
    assert "annotation_required" in codes(root)


def test_cpp_source_and_missing_main_fail(tmp_path):
    root = make_program(tmp_path)
    (root / "src/extra.cpp").write_text("class X {};")
    assert "c17_only" in codes(root)
    source = root / "src/main.c"
    source.write_text(source.read_text().replace("int main(void)", "int renamed(void)"))
    assert "main_required" in codes(root)


def test_indirect_call_requires_annotation_and_known_targets(tmp_path):
    root = make_program(
        tmp_path,
        """
// @algorithm none
int caller(struct item *t) { return t->fn(1); }
""",
    )
    assert "indirect_targets_required" in codes(root)
    source = root / "src/main.c"
    source.write_text(
        source.read_text().replace(
            "// @algorithm none\nint caller",
            "// @algorithm none\n// @indirect-targets target\nint caller",
        )
    )
    assert "indirect_targets_required" not in codes(root)
    assert "indirect_target_missing" not in codes(root)


def test_comments_char_literals_and_strings_do_not_define_functions(tmp_path):
    root = make_program(
        tmp_path,
        """
/* static int target(void) { } */
// @algorithm none
int helper(void) { return '}'; }
""",
    )
    assert lint_program(root) == []


def test_source_symlink_escape_is_rejected(tmp_path):
    root = make_program(tmp_path)
    outside = tmp_path / "external.c"
    outside.write_text("int external(void) {return 1;}")
    (root / "src/escape.c").symlink_to(outside)
    assert "source_escape" in codes(root)


def test_invalid_registry_annotations_and_unbalanced_body(tmp_path):
    root = make_program(
        tmp_path,
        """
// @algorithm unknown/foo
int helper(void) { return 1; }
""",
    )
    assert "annotation_invalid" in codes(root)
    source = root / "src/main.c"
    source.write_text(source.read_text() + "int broken(void) {")
    assert "source_invalid" in codes(root)


def test_a_comment_containing_init_array_is_harmless(tmp_path):
    root = make_program(tmp_path, '\n/* ".init_array" constructor */\n')
    assert lint_program(root) == []

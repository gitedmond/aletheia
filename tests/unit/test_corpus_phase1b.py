from pathlib import Path

import pytest

from aletheia.corpus.lint import lint_program
from aletheia.schema.taxonomy import Taxonomy


def program(tmp_path, annotations):
    root = tmp_path / "sample"
    (root / "src").mkdir(parents=True)
    (root / "tests").mkdir()
    (root / "src/aletheia.h").write_text("#define ALETHEIA_TARGET __attribute__((noinline))\n")
    (root / "src/main.c").write_text(
        """#include "aletheia.h"
#include <stdio.h>
// @algorithm none
"""
        + annotations
        + """
ALETHEIA_TARGET int target(int value) { return value + 1; }
// @algorithm none
// @category control.main
int main(void) {
    int value = getchar();
    printf("%x", target(value));
    return 0;
}
"""
    )
    (root / "tests/test.c").write_text("int main(void){return 0;}\n")
    (root / "Makefile").write_text("test:\n\ttrue\n")
    return root


def test_valid_category_alternatives_and_parameter_roles(tmp_path):
    root = program(tmp_path, "// @category util.other\n// @acceptable util.init\n// @roles other")
    assert lint_program(root, phase="1b") == []


@pytest.mark.parametrize(
    ("annotation", "rule"),
    [
        ("// @roles other", "category_required"),
        ("// @category missing.leaf", "category_invalid"),
        ("// @category util.other\n// @acceptable no.such.leaf", "acceptable_invalid"),
        ("// @category util.other\n// @roles imaginary", "roles_invalid"),
        ("// @category util.other\n// @roles buf,len", "roles_arity"),
        ("// @category util.other\n// @category util.init", "category_invalid"),
    ],
)
def test_each_new_annotation_rule_rejects_a_bad_case(tmp_path, annotation, rule):
    errors = lint_program(program(tmp_path, annotation), phase="1b")
    assert rule in {e.rule for e in errors}


def test_taxonomy_is_versioned_and_rejects_non_leaves():
    taxonomy = Taxonomy.read(Path("taxonomy.yaml"))
    assert taxonomy.version == "1.0"
    assert "crypto.hash.sha256.update" in taxonomy.leaves
    assert "hash.noncrypto.fnv1" in taxonomy.leaves
    assert "crypto.hash" not in taxonomy.leaves

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


def test_new_families_require_v2_in_both_runtime_and_exported_contract(tmp_path):
    import json

    import jsonschema
    from pydantic import ValidationError

    from aletheia.schema.export import export_schemas
    from aletheia.schema.models import ClaimSubmission

    export_schemas(tmp_path)
    validator = jsonschema.Draft202012Validator(
        json.loads((tmp_path / "claim-submission.json").read_bytes())
    )
    value = {
        "run_id": "r_" + "1" * 16,
        "source": {"origin": "scripted", "source_id": "test"},
        "binary_sha256": "a" * 64,
        "subject": {"address": "0x00001000"},
        "type": "algorithm_identity",
        "body": {"family": "md5", "variant": "std"},
        "confidence": 0.9,
        "confidence_source": "scripted",
    }
    with pytest.raises(ValidationError, match="algorithms_version"):
        ClaimSubmission.model_validate(value)
    with pytest.raises(jsonschema.ValidationError):
        validator.validate(value)
    value["algorithms_version"] = "2.0"
    validator.validate(value)
    assert ClaimSubmission.model_validate(value).algorithms_version == "2.0"


def test_variadic_roles_count_only_named_parameters_and_taxonomy_is_bundled():
    from aletheia.corpus.lint import parameter_count

    assert parameter_count("const char *fmt, ...") == 1
    assert parameter_count("void (*callback)(int, int), const char *fmt, ...") == 2
    assert Taxonomy.bundled() == Taxonomy.read(Path("taxonomy.yaml"))

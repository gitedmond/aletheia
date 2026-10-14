import ast
from pathlib import Path


def prohibited_imports(source):
    tree = ast.parse(source)
    result = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            result.extend(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom):
            result.append("." * node.level + (node.module or ""))
    return [
        name
        for name in result
        if name.startswith(
            (
                "aletheia.corpus",
                "aletheia.sources.scripted",
                "..corpus",
                "...corpus",
                "..sources.scripted",
                "...sources.scripted",
            )
        )
    ]


def test_verifier_import_boundary():
    for path in Path("aletheia/verify").rglob("*.py"):
        assert prohibited_imports(path.read_text()) == [], path


def test_boundary_detector_checks_both_import_forms():
    assert prohibited_imports("import aletheia.corpus.build")
    assert prohibited_imports("from aletheia.sources.scripted import generate")
    assert prohibited_imports("from ..corpus import truth")
    assert not prohibited_imports("from aletheia.schema.models import Claim")

"""T15 acceptance uses real fixture callers and the production arity and probe jobs."""

import json
from pathlib import Path

import pytest
from typer.testing import CliRunner

from aletheia.cli import app

pytestmark = pytest.mark.integration


def invoke_selftest(tmp_path, family=None):
    config = tmp_path / "selftest.toml"
    config.write_text(
        Path("aletheia.toml")
        .read_text()
        .replace('build = "build"', 'build = "' + str(tmp_path / "build") + '"')
    )
    args = ["--config", str(config), "--json", "selftest"]
    if family is not None:
        args += ["--family", family]
    result = CliRunner().invoke(app, args)
    assert result.exit_code == 0, result.output + repr(result.exception)
    report = json.loads(result.stdout)
    assert report["status"] == "ok" and report["failed"] == 0
    assert report["cases"] and all(case["passed"] for case in report["cases"])
    return report


def test_fnv_production_binding_contradiction_and_incomplete_family_scope(tmp_path):
    report = invoke_selftest(tmp_path, "fnv")
    assert {case["expected"] for case in report["cases"]} >= {
        "VERIFIED",
        "CONTRADICTED",
        "INCONCLUSIVE",
        "UNVERIFIABLE",
    }
    assert any(case["reason"] == "binding_not_verified" for case in report["cases"])
    assert any(case["reason"] == "no_pack" for case in report["cases"])


@pytest.mark.slow
def test_all_supported_references_near_misses_and_required_outcomes(tmp_path):
    report = invoke_selftest(tmp_path)
    assert report["families"] == ["adler32", "base64", "crc32", "djb2", "fnv"]
    assert report["static_fixtures_passed"]

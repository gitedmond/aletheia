"""Missing/stale evidence and AI labels cannot turn into a passing Phase 1B gate."""

from pathlib import Path
from types import SimpleNamespace

from aletheia.gate_phase1b import _package_hash, evaluate
from aletheia.orchestrate import file_hash, write_json


def test_missing_and_changed_evidence_fails_every_criterion(tmp_path):
    benchmark = SimpleNamespace(root=tmp_path)
    result = evaluate(benchmark)
    assert result["status"] == "failed" and len(result["criteria"]) == 14
    assert all(not value["passed"] for value in result["criteria"].values())
    root = tmp_path / "phase1b"
    context = Path("configs/grading-phase1b.json").read_bytes()
    (root / "agreement.json").write_bytes(context)
    evidence = {
        "package_source_hash": _package_hash(),
        "receipts": {
            "agreement": {"path": "agreement.json", "sha256": file_hash(root / "agreement.json")}
        },
    }
    write_json(root / "evidence.json", evidence)
    result = evaluate(benchmark)
    assert result["criteria"]["X7"]["details"]["human_validated"] is False
    assert result["criteria"]["X7"]["passed"] is False
    (root / "agreement.json").write_text("{}")
    result = evaluate(benchmark)
    assert result["criteria"]["X7"]["details"] == "Missing, stale or invalid required evidence"


def test_empty_test_suites_and_escaped_receipts_do_not_pass(tmp_path):
    root = tmp_path / "phase1b"
    root.mkdir()
    (root / "tests.xml").write_text("<testsuites/>")
    write_json(
        root / "evidence.json",
        {
            "package_source_hash": _package_hash(),
            "receipts": {
                "mcp_tests": {"path": "tests.xml", "sha256": file_hash(root / "tests.xml")},
                "agreement": {"path": "../../outside.json", "sha256": "a" * 64},
            },
        },
    )
    result = evaluate(SimpleNamespace(root=tmp_path))
    assert not result["criteria"]["X11"]["passed"]
    assert not result["criteria"]["X7"]["passed"]

"""Fail closed on missing evidence while preserving assisted-label provenance."""

from pathlib import Path
from types import SimpleNamespace

import pytest

from aletheia.gate_phase1b import _package_hash, evaluate
from aletheia.orchestrate import file_hash, write_json


def test_missing_and_changed_evidence_fails_closed(tmp_path):
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
    assert result["criteria"]["X7"]["passed"] is True
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


@pytest.mark.parametrize(
    "value, passed",
    [
        (None, False),
        (False, False),
        ({"status": "failed"}, False),
        (True, True),
        ({"status": "passed"}, True),
    ],
)
def test_agent_replay_requires_explicit_success(tmp_path, value, passed):
    root = tmp_path / "phase1b"
    root.mkdir()
    receipts = {
        "plan": {
            "slots": [
                {"source": "agent:local", "runs": ["agent"]},
                {"source": "scripted", "runs": ["tool"]},
            ]
        },
        "replays": {"runs": {"agent": {"exit_code": 0}, "tool": {"exit_code": 0}}},
    }
    if value is not None:
        receipts["replays"]["runs"]["agent"]["agent_replay"] = value
    evidence = {"package_source_hash": _package_hash(), "receipts": {}}
    for name, data in receipts.items():
        write_json(root / (name + ".json"), data)
        evidence["receipts"][name] = {
            "path": name + ".json",
            "sha256": file_hash(root / (name + ".json")),
        }
    write_json(root / "evidence.json", evidence)
    result = evaluate(SimpleNamespace(root=tmp_path))
    assert result["criteria"]["X9"]["passed"] is passed


def test_malformed_receipt_container_still_writes_gate(tmp_path):
    root = tmp_path / "phase1b"
    write_json(root / "evidence.json", {"package_source_hash": _package_hash(), "receipts": []})
    result = evaluate(SimpleNamespace(root=tmp_path))
    assert len(result["criteria"]) == 14
    assert all(not row["passed"] for row in result["criteria"].values())
    assert (root / "gate.json").exists()


def test_algorithm_false_alarm_rate_cannot_be_diluted_with_purpose_fixtures(tmp_path):
    root = tmp_path / "phase1b"
    scripted = {"correct_e2_algorithm_identity": {"total": 1, "contradicted": 1}}
    rows = [
        {
            "name": "crc32:reference:known",
            "family": "crc32",
            "expected": "VERIFIED",
            "actual": "VERIFIED",
        }
    ]
    rows += [
        {
            "name": f"print:reference:{i}",
            "family": "print",
            "expected": "VERIFIED",
            "actual": "VERIFIED",
        }
        for i in range(1000)
    ]
    evidence = {"package_source_hash": _package_hash(), "receipts": {}}
    for name, payload in (("scripted", scripted), ("selftest", {"cases": rows})):
        path = root / f"{name}.json"
        write_json(path, payload)
        evidence["receipts"][name] = {"path": path.name, "sha256": file_hash(path)}
    write_json(root / "evidence.json", evidence)
    result = evaluate(SimpleNamespace(root=tmp_path))
    assert result["criteria"]["X4"]["details"]["correct_e2"] == 2
    assert not result["criteria"]["X4"]["passed"]


@pytest.mark.parametrize("complete", [False, True])
def test_agreement_reports_every_node_even_when_kappa_is_undefined(tmp_path, complete):
    from aletheia.grade.context import GradingContext
    from aletheia.schema.taxonomy import Taxonomy

    nodes = {leaf.split(".")[0] for leaf in Taxonomy.bundled().leaves}
    values = {node: None for node in nodes}
    if not complete:
        values.pop(sorted(nodes)[0])
    context = GradingContext(
        agreement_sha256="a" * 64,
        taxonomy_kappa=values,
        human_validated=False,
        method="ai-assisted",
    )
    root = tmp_path / "phase1b"
    write_json(root / "agreement.json", context)
    write_json(
        root / "evidence.json",
        {
            "package_source_hash": _package_hash(),
            "receipts": {
                "agreement": {
                    "path": "agreement.json",
                    "sha256": file_hash(root / "agreement.json"),
                }
            },
        },
    )
    result = evaluate(SimpleNamespace(root=tmp_path))
    assert result["criteria"]["X7"]["passed"] is complete
    assert result["criteria"]["X7"]["details"]["human_validated"] is False
    assert all(value is None for value in context.primary_kappa.values())
    assert result["status"] == "failed"

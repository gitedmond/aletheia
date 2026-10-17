"""Harness contracts and allowlisting, using an opaque fake upstream."""

import json

import pytest

from aletheia.agent.proxy import HarnessProxy, ReportClaim, canonical_output
from aletheia.heldout.guard import PrivateGuard
from aletheia.llm.provider import AgentBudgets


class Upstream:
    def __init__(self):
        self.calls = []

    def call(self, name, arguments):
        self.calls.append((name, arguments))
        return {"address": "0X001234", "timestamp": "unstable", "code": "return 0x10;"}


def proxy(tmp_path, **budget):
    return HarnessProxy(
        run_id="r_" + "1" * 16,
        binary_sha256="a" * 64,
        source_id="agent:fake",
        upstream=Upstream(),
        trajectory=tmp_path / "trajectory.jsonl",
        guard=PrivateGuard(None),
        budgets=AgentBudgets(**budget),
    )


def arguments(**changes):
    return {
        "type": "function_signature",
        "subject_address": "0x00001234",
        "body": {"return_type": "uint32_t", "params": []},
        "confidence": 0.8,
        "evidence_refs": [],
        "depends_on": [],
        **changes,
    }


def test_allowlist_canonicalization_ids_and_separate_budgets(tmp_path):
    p = proxy(tmp_path, re_tool_calls=1, harness_tool_calls=2)
    assert p.call("run_script", {})["reason"] == "tool_not_allowed"
    result = p.call("decompile_function", {"binary_name": "input", "name": "FUN_00001234"})
    assert result["result"] == {"address": "0x00001234", "code": "return 0x10;"}
    assert p.call("decompile_function", {})["reason"] == "budget_exhausted"
    assert p.call("report_claim", arguments())["status"] == "ok"
    assert p.re_calls == 1 and p.harness_calls == 1
    assert p.call("report_claim", arguments())["reason"] == "duplicate_active_claim"
    assert p.call("finish", {})["status"] == "ok" and p.finished
    rows = [json.loads(s) for s in (tmp_path / "trajectory.jsonl").read_text().splitlines()]
    assert [r["tool_call_id"] for r in rows] == [f"tc-{i:04d}" for i in range(1, 7)]


def test_claim_validation_revisions_client_refs_and_dependency_resolution(tmp_path):
    p = proxy(tmp_path)
    assert p.call("report_claim", arguments(confidence=2.0))["reason"] == "invalid_claim"
    assert (
        p.call("report_claim", arguments(evidence_refs=["tc-9999"]))["reason"]
        == "invalid_evidence_ref"
    )
    first = p.call("report_claim", arguments(client_ref="sig"))["claim_id"]
    assert (
        p.call("report_claim", arguments(client_ref="sig", subject_address="0x00004567"))["reason"]
        == "duplicate_client_ref"
    )
    new = p.call("revise_claim", arguments(client_ref="sig", confidence=0.6))["claim_id"]
    assert len(p.claims) == 2 and p.claims[-1].supersedes == first
    assert [c.claim_id for c in p.active_claims] == [new]
    dependent = p.call(
        "report_claim",
        {
            "type": "function_purpose",
            "subject_address": "0x00001234",
            "body": {"category": "util.other"},
            "confidence": 0.4,
            "depends_on": ["sig"],
        },
    )
    assert dependent["status"] == "ok"
    assert p.claims[-1].depends_on == [new]
    assert p.call("report_claim", arguments(subject_address="0x1234"))["reason"] == "invalid_claim"
    assert ReportClaim.model_json_schema()["properties"]["body"]


def test_call_keys_include_callee_and_output_normalization_is_not_code_rewriting(tmp_path):
    p = proxy(tmp_path)
    for callee in ["import:puts", "import:printf"]:
        assert (
            p.call(
                "report_claim",
                arguments(type="call_relation", body={"callee": callee, "kind": "direct"}),
            )["status"]
            == "ok"
        )
    assert len(p.active_claims) == 2
    assert (
        canonical_output({"text": "return 0X10;", "address": "00000010"})["text"] == "return 0X10;"
    )
    with pytest.raises(ValueError, match="private output"):
        HarnessProxy(
            run_id="r_" + "1" * 16,
            binary_sha256="a" * 64,
            source_id="agent:fake",
            upstream=Upstream(),
            trajectory=tmp_path / "outside.jsonl",
            guard=PrivateGuard(tmp_path / "private", "heldout"),
            budgets=AgentBudgets(),
        )

"""T10 decisions respect edge kind, complete disassembly and missing subjects."""

import pytest

from aletheia.analysis.ghidra_session import GhidraAnalysis
from aletheia.schema.models import Claim, ClaimSubmission
from aletheia.verify.static.edges import verify_edges


def claim(kind="direct", callee="import:printf"):
    return Claim.intake(
        ClaimSubmission.model_validate(
            {
                "run_id": "r_" + "1" * 16,
                "source": {"origin": "scripted", "source_id": "scripted:v1"},
                "binary_sha256": "a" * 64,
                "subject": {"address": "0x00001000"},
                "type": "call_relation",
                "body": {"callee": callee, "kind": kind},
                "confidence": 0.9,
                "confidence_source": "scripted",
            }
        )
    )


def analysis(complete=True):
    return GhidraAnalysis.model_validate(
        {
            "binary_sha256": "a" * 64,
            "options_sha256": "b" * 64,
            "functions": [
                {
                    "entry": "0x00001000",
                    "body_ranges": [{"start": "0x00001000", "end": "0x00001020"}],
                    "is_thunk": False,
                    "body_complete": complete,
                    "call_sites": [
                        {"address": "0x00001010", "kind": "tail", "target": "import:printf"}
                    ],
                }
            ],
        }
    )


def test_import_tail_and_direct_kind_decisions_have_static_harnesses():
    for kind, expected in [
        ("tail", "VERIFIED"),
        ("direct", "CONTRADICTED"),
        ("indirect", "INCONCLUSIVE"),
    ]:
        result = verify_edges(claim(kind), analysis(), "sha256:" + "c" * 64)
        assert result.intrinsic_verdict == expected
        assert result.methods_run == ["static.edges@1"]
        if expected in ("VERIFIED", "CONTRADICTED"):
            assert result.strength == "E1" and "Static analysis (Ghidra" in result.harness
        else:
            assert result.strength is None and result.reason == "indirect_unresolved"


def test_incomplete_body_and_missing_subject_are_explicit():
    result = verify_edges(claim(), analysis(False), "sha256:" + "c" * 64)
    assert result.intrinsic_verdict == "INCONCLUSIVE" and result.reason == "indirect_unresolved"
    result = verify_edges(
        claim(), analysis().model_copy(update={"functions": []}), "sha256:" + "c" * 64
    )
    assert result.intrinsic_verdict == "ERROR" and result.reason == "subject_not_found"
    with pytest.raises(ValueError, match="binary"):
        verify_edges(
            claim(), analysis().model_copy(update={"binary_sha256": "d" * 64}), "sha256:" + "c" * 64
        )

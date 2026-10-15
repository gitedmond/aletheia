"""T27 only adds support evidence, never a verifier decision."""

import pytest

from aletheia.analysis.ghidra_session import GhidraAnalysis
from aletheia.schema.models import Claim, ClaimSubmission
from aletheia.verify.static.constants import constant_evidence


def test_constants_are_filtered_by_claim_family_without_setting_a_verdict():
    claim = Claim.intake(
        ClaimSubmission.model_validate(
            {
                "run_id": "r_" + "1" * 16,
                "source": {"origin": "scripted", "source_id": "scripted:v1"},
                "binary_sha256": "a" * 64,
                "subject": {"address": "0x00001000"},
                "type": "algorithm_identity",
                "body": {"family": "crc32", "variant": "ieee"},
                "confidence": 0.9,
                "confidence_source": "scripted",
            }
        )
    )
    analysis = GhidraAnalysis.model_validate(
        {
            "binary_sha256": "a" * 64,
            "options_sha256": "b" * 64,
            "functions": [
                {
                    "entry": "0x00001000",
                    "body_ranges": [{"start": "0x00001000", "end": "0x00001100"}],
                    "is_thunk": False,
                    "constants": [
                        {
                            "family": "crc32",
                            "name": "ieee_polynomial",
                            "address": "0x00001010",
                            "location": "immediate",
                        },
                        {
                            "family": "fnv",
                            "name": "fnv1a32_basis",
                            "address": "0x00001020",
                            "location": "immediate",
                        },
                    ],
                }
            ],
        }
    )
    evidence = constant_evidence(claim, analysis)
    assert len(evidence) == 1 and evidence[0].kind == "constant_match"
    assert evidence[0].name == "ieee_polynomial"
    assert "verdict" not in evidence[0].model_dump()
    with pytest.raises(ValueError, match="binary"):
        constant_evidence(claim, analysis.model_copy(update={"binary_sha256": "c" * 64}))
    with pytest.raises(ValueError, match="subject_not_found"):
        constant_evidence(claim, analysis.model_copy(update={"functions": []}))
    analysis.functions[0].constants.clear()
    assert constant_evidence(claim, analysis) == []

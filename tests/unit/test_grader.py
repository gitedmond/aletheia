"""T20: fixed grade expectations and the approved CRC32 scripted population."""

from pathlib import Path

import pytest

from aletheia.grade import grade
from aletheia.schema.models import (
    Claim,
    ClaimSubmission,
    GroundTruth,
    ManifestInput,
    Targets,
    Verdict,
)
from aletheia.sources.scripted import generate

SHA = "a" * 64
VARIANT = "clang23-O2-x64-pie-hardoff"


def truth():
    return GroundTruth.model_validate(
        {
            "binary_sha256": SHA,
            "program_id": "tierA/example",
            "variant_id": VARIANT,
            "build_flags": "test",
            "functions": [
                {
                    "address": "0x00001000",
                    "size": 32,
                    "name": "checksum",
                    "algorithm": {"family": "crc32", "variant": "ieee"},
                    "scorable": True,
                },
                {
                    "address": "0x00002000",
                    "size": 32,
                    "name": "helper",
                    "algorithm": {"family": "none"},
                    "scorable": True,
                    "callees": [
                        {"target": "0x00001000", "kind": "direct"},
                        {"target": "import:puts", "kind": "tail"},
                        {"target": "0x00003000", "kind": "indirect"},
                    ],
                },
                {
                    "address": "0x00003000",
                    "size": 8,
                    "name": "excluded",
                    "algorithm": {"family": "crc32", "variant": "jamcrc"},
                    "scorable": False,
                },
            ],
        }
    )


def claim(address, body):
    return Claim.intake(
        ClaimSubmission.model_validate(
            {
                "run_id": "r_" + "1" * 16,
                "source": {"origin": "scripted", "source_id": "scripted:v1"},
                "binary_sha256": SHA,
                "subject": {"address": address},
                "type": "algorithm_identity" if "family" in body else "call_relation",
                "body": body,
                "confidence": 0.9,
                "confidence_source": "scripted",
            }
        )
    )


def verdict(claim, outcome):
    return Verdict(
        claim_id=claim.claim_id,
        intrinsic_verdict=outcome,
        strength="E2" if outcome in ("VERIFIED", "CONTRADICTED") else None,
        harness="fixed test harness" if outcome in ("VERIFIED", "CONTRADICTED") else None,
        reason="binding_not_verified" if outcome == "INCONCLUSIVE" else None,
        verifier_version="0.1.0",
        env_digest="sha256:" + "b" * 64,
    )


@pytest.mark.parametrize(
    "address,body,outcome,expected",
    [
        # expected: on_target, phantom, family, variant, edge, strict, lenient, verdict_correct
        (
            "0x00001000",
            {"family": "crc32", "variant": "ieee"},
            "VERIFIED",
            (True, False, True, True, None, True, True, True),
        ),
        (
            "0x00001000",
            {"family": "crc32", "variant": "jamcrc"},
            "CONTRADICTED",
            (True, False, True, False, None, False, True, True),
        ),
        (
            "0x00001000",
            {"family": "crc32"},
            "VERIFIED",
            (True, False, True, None, None, False, True, True),
        ),
        (
            "0x00001000",
            {"family": "crc32"},
            "CONTRADICTED",
            (True, False, True, None, None, False, True, False),
        ),
        (
            "0x00002000",
            {"family": "crc32", "variant": "ieee"},
            "VERIFIED",
            (True, False, False, False, None, False, False, False),
        ),
        (
            "0x00001001",
            {"family": "crc32", "variant": "ieee"},
            "VERIFIED",
            (False, True, False, False, None, False, False, False),
        ),
        (
            "0x00003000",
            {"family": "crc32", "variant": "jamcrc"},
            "VERIFIED",
            (False, False, True, True, None, True, True, True),
        ),
        (
            "0x00002000",
            {"callee": "0x00001000", "kind": "direct"},
            "VERIFIED",
            (True, False, None, None, True, True, True, True),
        ),
        (
            "0x00002000",
            {"callee": "0x00001000", "kind": "tail"},
            "CONTRADICTED",
            (True, False, None, None, False, False, True, True),
        ),
        (
            "0x00002000",
            {"callee": "0x00003000", "kind": "indirect"},
            "VERIFIED",
            (True, False, None, None, True, True, True, True),
        ),
        (
            "0x00002000",
            {"callee": "import:puts", "kind": "tail"},
            "VERIFIED",
            (True, False, None, None, True, True, True, True),
        ),
        (
            "0x00001000",
            {"family": "crc32", "variant": "ieee"},
            "INCONCLUSIVE",
            (True, False, True, True, None, True, True, None),
        ),
    ],
)
def test_hand_computed_grade_table(address, body, outcome, expected):
    item = claim(address, body)
    targets = Targets(binary_sha256=SHA, variant_id=VARIANT, targets=["0x00001000", "0x00002000"])
    (result,) = grade([item], [verdict(item, outcome)], truth(), targets)
    assert result.claim_id == item.claim_id
    assert result.grader_version == "0.1.0"
    assert (
        result.on_target,
        result.phantom,
        result.family_correct,
        result.variant_correct,
        result.edge_correct,
        result.correct_strict,
        result.correct_lenient,
        result.verdict_correct,
    ) == expected


def test_approved_crc32_scripted_grade_totals_and_order():
    gt = GroundTruth.model_validate_json(
        Path("tests/golden/crc32tool/ground_truth.json").read_bytes()
    )
    targets = Targets(
        binary_sha256=gt.binary_sha256,
        variant_id=gt.variant_id,
        targets=[f.address for f in gt.functions if f.scorable],
    )
    base = ManifestInput(
        source_config={},
        binaries=[gt.binary_sha256],
        versions={},
        image_digests={"analysis": "sha256:" + "b" * 64},
        analysis_options_hash="c" * 64,
        pack_hashes={},
        mapping_hashes={},
        verifier_version="0.1.0",
        grader_version="0.1.0",
        seeds={},
    )
    claims = [claim for case in generate(gt, base).cases for claim in case.claims]
    result = grade(claims, [], gt, targets)
    assert len(result) == 58
    assert sum(g.correct_strict for g in result) == 24
    assert sum(g.correct_lenient for g in result) == 32
    assert all(g.on_target and not g.phantom and g.verdict_correct is None for g in result)
    assert [g.claim_id for g in result] == sorted(c.claim_id for c in claims)
    assert result == grade(list(reversed(claims)), [], gt, targets)
    with pytest.raises(ValueError, match="identity"):
        grade(claims, [], gt, targets.model_copy(update={"binary_sha256": "d" * 64}))

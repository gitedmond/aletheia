"""T24: fixed mini run with a contradiction, an honest miss and a family-only truth."""

from pathlib import Path

from aletheia.config import Metrics
from aletheia.grade import grade
from aletheia.metrics import compute_metrics
from aletheia.report import ReportData, render
from aletheia.schema.models import (
    Aspect,
    Claim,
    ClaimSubmission,
    GroundTruth,
    ManifestInput,
    RunManifest,
    Targets,
    Verdict,
)


def mini_report():
    truth = GroundTruth.model_validate(
        {
            "binary_sha256": "a" * 64,
            "program_id": "tierA/mini",
            "variant_id": "test",
            "build_flags": "test",
            "functions": [
                {
                    "address": "0x00001000",
                    "size": 32,
                    "name": "checksum",
                    "scorable": True,
                    "algorithm": {"family": "crc32", "variant": "ieee"},
                },
                {
                    "address": "0x00002000",
                    "size": 32,
                    "name": "other",
                    "scorable": True,
                    "algorithm": {"family": "none"},
                },
            ],
            "excluded_functions": [{"name": "tiny", "reason": "trivial"}],
        }
    )
    targets = Targets(
        binary_sha256=truth.binary_sha256, variant_id="test", targets=["0x00001000", "0x00002000"]
    )
    manifests, claims, verdicts, grades, methods = [], [], [], [], {}
    for source, origin, shared, specifications in [
        (
            "scripted:v1",
            "scripted",
            False,
            [
                ("0x00001000", "crc32", "jamcrc", "CONTRADICTED"),
                ("0x00002000", "fnv", "fnv1a-64", "UNVERIFIABLE"),
            ],
        ),
        ("tool:findcrypt@3.1.10", "tool", True, [("0x00001000", "crc32", None, "VERIFIED")]),
        ("tool:capa@9.4.0", "tool", False, []),
    ]:
        manifest = RunManifest.create(
            ManifestInput(
                source_config={
                    "program": "mini",
                    "source": "findcrypt"
                    if shared
                    else "scripted"
                    if origin == "scripted"
                    else "capa",
                    "origin": origin,
                    "source_id": source,
                    "scenario": "mutated" if origin == "scripted" else "tool",
                },
                binaries=[truth.binary_sha256],
                versions={"benchmark": "0.1.0", "ghidra": "11.4.3"},
                image_digests={"analysis": "sha256:" + "b" * 64},
                analysis_options_hash="c" * 64,
                pack_hashes={},
                mapping_hashes={},
                verifier_version="0.1.0",
                grader_version="0.1.0",
                seeds={"bootstrap": 7},
            )
        )
        manifests.append(manifest)
        for address, family, variant, outcome in specifications:
            claim = Claim.intake(
                ClaimSubmission.model_validate(
                    {
                        "run_id": manifest.run_id,
                        "source": {"origin": origin, "source_id": source, "shares_backend": shared},
                        "binary_sha256": truth.binary_sha256,
                        "subject": {"address": address},
                        "type": "algorithm_identity",
                        "body": {"family": family, "variant": variant},
                        "confidence": 0.9 if origin == "scripted" else 1.0,
                        "confidence_source": "scripted" if origin == "scripted" else "tool_default",
                        "derived_from": "scripted_mutated"
                        if origin == "scripted"
                        else "constant_xref",
                        "tool_label": "CRYPT_CRC32_m_tab" if shared else None,
                    }
                )
            )
            method = "probe." + family + "@1"
            decisive = outcome in ("VERIFIED", "CONTRADICTED")
            observation = Aspect(
                verdict=outcome, strength="E2" if decisive else None, method=method
            )
            counterexample = (
                {
                    "input_hex": "",
                    "expected_hex": "ffffffff",
                    "actual_hex": "00000000",
                    "call_shape": "seed_buf_len",
                    "variant": "jamcrc",
                    "matches_variant": "ieee",
                }
                if outcome == "CONTRADICTED"
                else None
            )
            verdict = Verdict.model_validate(
                {
                    "claim_id": claim.claim_id,
                    "intrinsic_verdict": outcome,
                    "strength": "E2" if decisive else None,
                    "reason": None if decisive else "no_pack",
                    "methods_run": [method],
                    "aspects": {"output_match": observation.model_dump(mode="json")},
                    "harness": (
                        "Function-level emulation; seed_buf_len; stubs S1; "
                        "fixed published CRC vector."
                    )
                    if decisive
                    else None,
                    "counterexample": counterexample,
                    "verifier_version": "0.1.0",
                    "env_digest": "sha256:" + "b" * 64,
                }
            )
            claims.append(claim)
            verdicts.append(verdict)
            grades.extend(grade([claim], [verdict], truth, targets))
            methods[claim.claim_id] = [observation]
    metrics = compute_metrics(
        grades,
        claims,
        verdicts,
        Metrics(bootstrap_resamples=10, bootstrap_seed=7),
        ground_truths=[truth],
        method_results=methods,
    )
    return ReportData(
        manifests,
        metrics,
        [
            (claim, verdict, item, "tierA/mini")
            for claim, verdict, item in zip(claims, verdicts, grades, strict=True)
        ],
        {"tool:capa@9.4.0": {"unmapped_label:example": 2}},
        {truth.program_id: truth.excluded_functions},
        {
            manifest.run_id: {
                "cpu_seconds": 1.0,
                "peak_memory_bytes": 1024,
                "executed_jobs": 2,
                "measurement_errors": [],
            }
            for manifest in manifests
        },
    )


def test_fixed_mini_report_snapshot_and_claimed_granularity():
    data = mini_report()
    text = render(data)
    assert text == Path("tests/golden/report-mini.md").read_text()
    assert data.metrics.independent.summary.metrics["catch_rate"] == 0.5
    assert data.metrics.independent.summary.metrics["false_alarm_rate"] is None
    assert "shared backend" in text
    assert "fnv1a-64" in text and "no_pack" in text
    assert "ffffffff" in text and "00000000" in text and "ieee" in text
    assert render(data) == render(
        ReportData(
            list(reversed(data.manifests)),
            data.metrics,
            list(reversed(data.claims)),
            data.unmapped,
            data.excluded,
            data.accounting,
        )
    )

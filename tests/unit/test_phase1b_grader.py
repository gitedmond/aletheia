"""Compiler ABI types, explicit agreement gates and overlap at claimed granularity."""

from pathlib import Path

import pytest

from aletheia.grade import grade
from aletheia.schema.models import Claim, ClaimSubmission, GroundTruth, Targets


def truth():
    return GroundTruth.model_validate_json(
        Path("tests/golden/ground-truth-v2/crc32tool.json").read_bytes()
    )


def claim(gt, kind, body, run="1", derived=None):
    fn = next(f for f in gt.functions if f.name == "crc32_update")
    return Claim.intake(
        ClaimSubmission.model_validate(
            {
                "run_id": "r_" + run * 16,
                "source": {"origin": "scripted", "source_id": "scripted:grading-v2"},
                "binary_sha256": gt.binary_sha256,
                "subject": {"address": fn.address},
                "type": kind,
                "body": body,
                "confidence": 0.9,
                "confidence_source": "scripted",
                "algorithms_version": "2.0",
                "derived_from": derived,
            }
        )
    )


def apply(gt, claims, kappa=None):
    return grade(
        claims,
        [],
        gt,
        Targets(
            binary_sha256=gt.binary_sha256,
            variant_id=gt.variant_id,
            targets=sorted(
                [f.address for f in gt.functions if f.scorable], key=lambda a: int(a, 16)
            ),
        ),
        taxonomy_kappa=kappa,
    )


@pytest.mark.parametrize(
    "return_type,params,strict,lenient",
    [
        ("uint32_t", ["uint32_t", "const char *", "size_t"], True, True),
        ("uint64_t", ["uint32_t", "const char *", "size_t"], False, True),
        ("uint32_t", ["uint32_t", "uintptr_t", "size_t"], False, False),
        ("uint32_t", ["unknown_t", "const char *", "size_t"], False, False),
    ],
)
def test_signature_compiler_class_width_and_source_parameter_grading(
    return_type, params, strict, lenient
):
    gt = truth()
    item = claim(
        gt,
        "function_signature",
        {"return_type": return_type, "params": [{"type": s} for s in params]},
    )
    (result,) = apply(gt, [item])
    assert (result.correct_strict, result.correct_lenient, result.correct_claimed) == (
        strict,
        lenient,
        strict,
    )


@pytest.mark.parametrize("kappa,strict", [(0.7, True), (0.69, None), (None, None)])
def test_purpose_kappa_is_explicit_and_unknown_is_not_wrong(kappa, strict):
    gt = truth()
    item = claim(gt, "function_purpose", {"category": "checksum.crc32"})
    (result,) = apply(gt, [item], {"checksum": kappa})
    assert result.correct_strict is strict
    assert result.correct_lenient is True
    assert result.correct_claimed is strict
    assert result.correct_partial == 1.0
    with pytest.raises(ValueError, match="agreement"):
        apply(gt, [item])


def test_same_run_purpose_suppresses_only_algorithm_family_credit():
    gt = truth()
    purpose = claim(gt, "function_purpose", {"category": "checksum.crc32"})
    family = claim(gt, "algorithm_identity", {"family": "crc32", "variant": None})
    variant = claim(gt, "algorithm_identity", {"family": "crc32", "variant": "jamcrc"})
    for algorithm in [family, variant]:
        result = next(
            g
            for g in apply(gt, [purpose, algorithm], {"checksum": 1.0})
            if g.claim_id == algorithm.claim_id
        )
        assert result.family_correct is True and result.family_credit_suppressed
        assert result.correct_claimed is (None if algorithm.body.variant is None else False)
        assert result.correct_lenient is (None if algorithm.body.variant is None else False)
    different = claim(gt, "function_purpose", {"category": "checksum.crc32"}, run="2")
    result = next(
        g
        for g in apply(gt, [different, family], {"checksum": 1.0})
        if g.claim_id == family.claim_id
    )
    assert result.correct_claimed is True and not result.family_credit_suppressed


def test_complex_abi_and_three_of_four_source_parameters():
    from aletheia.schema.models import GroundFunctionV2

    gt = truth()
    fn = next(f for f in gt.functions if f.name == "crc32_update")
    assert isinstance(fn, GroundFunctionV2)
    data = fn.model_dump(mode="json")
    data["abi_signature"]["params"] = [{"class": "int", "width": 32}] * 4
    data["source_types"]["params"] = ["uint32_t"] * 4
    replacement = GroundFunctionV2.model_validate(data)
    gt = gt.model_copy(
        update={"functions": [replacement if f.address == fn.address else f for f in gt.functions]}
    )
    item = claim(
        gt,
        "function_signature",
        {
            "return_type": "uint32_t",
            "params": [{"type": s} for s in ["uint32_t"] * 3 + ["uint64_t"]],
        },
    )
    (result,) = apply(gt, [item])
    assert result.correct_strict is False and result.correct_lenient is True
    data["abi_signature"]["abi_complex"] = True
    replacement = GroundFunctionV2.model_validate(data)
    gt = gt.model_copy(
        update={"functions": [replacement if f.address == fn.address else f for f in gt.functions]}
    )
    (result,) = apply(gt, [item])
    assert result.correct_strict is None and result.correct_claimed is None
    assert result.strict_exclusion_reason == "abi_complex"
    assert all(value is None for value in result.aspect_correct.values())


def test_ungraded_purpose_is_excluded_from_confident_wrong_counts():
    from aletheia.config import Metrics
    from aletheia.metrics import compute_metrics
    from aletheia.schema.models import Verdict

    gt = truth()
    item = claim(gt, "function_purpose", {"category": "checksum.crc32"}, derived="scripted_correct")
    verdict = Verdict(
        claim_id=item.claim_id,
        intrinsic_verdict="CONTRADICTED",
        strength="E1",
        harness="Controlled static result.",
        verifier_version="0.1.0",
        env_digest="sha256:" + "a" * 64,
    )
    targets = Targets(
        binary_sha256=gt.binary_sha256,
        variant_id=gt.variant_id,
        targets=sorted([f.address for f in gt.functions if f.scorable], key=lambda a: int(a, 16)),
    )
    grades = grade([item], [verdict], gt, targets, taxonomy_kappa={"checksum": 0.69})
    assert grades[0].verdict_correct is None
    report = compute_metrics(
        grades,
        [item],
        [verdict],
        Metrics(bootstrap_resamples=10),
        ground_truths=[gt],
        method_results={item.claim_id: []},
    )
    summary = report.sources[0].aggregate.summary
    assert summary.metrics["cwr_claimed@0.8"] is None
    assert summary.metrics["false_alarm_rate"] is None
    assert summary.exclusions["ungraded"] == 1
    assert summary.confusion["CONTRADICTED"]["wrong"] == 0


def test_scripted_grades_equal_protected_expectations_on_two_public_programs():
    import json

    fixture = json.loads(Path("tests/golden/grades-phase1b.json").read_bytes())
    assert len(fixture["programs"]) == 2
    for program in fixture["programs"]:
        gt = GroundTruth.model_validate_json(
            Path("tests/golden/ground-truth-v2", program["program"] + ".json").read_bytes()
        )
        assert gt.binary_sha256 == program["binary_sha256"]
        targets = Targets(
            binary_sha256=gt.binary_sha256,
            variant_id=gt.variant_id,
            targets=sorted(
                [f.address for f in gt.functions if f.scorable], key=lambda a: int(a, 16)
            ),
        )
        for case in program["cases"]:
            claims = [
                Claim.intake(
                    ClaimSubmission.model_validate(
                        {
                            "run_id": "r_" + "1" * 16,
                            "source": {"origin": "scripted", "source_id": "scripted:grading-v2"},
                            "binary_sha256": gt.binary_sha256,
                            "subject": {"address": program["subject"]},
                            "type": row["type"],
                            "body": row["body"],
                            "confidence": 0.9,
                            "confidence_source": "scripted",
                            "derived_from": case["scenario"],
                            "algorithms_version": "2.0",
                        }
                    )
                )
                for row in case["claims"]
            ]
            results = {
                result.claim_id: result
                for result in grade(
                    claims, [], gt, targets, taxonomy_kappa=fixture["taxonomy_kappa"]
                )
            }
            for claim, row in zip(claims, case["claims"], strict=True):
                assert {
                    key: getattr(results[claim.claim_id], key) for key in row["expected"]
                } == row["expected"], (program["program"], case["name"])


def test_purpose_role_segment_and_invalid_agreement():
    from aletheia.schema.models import GroundFunctionV2

    gt = truth()
    fn = next(f for f in gt.functions if f.name == "crc32_update")
    data = fn.model_dump(mode="json")
    data.update(category="protocol.encode", acceptable_categories=["protocol.encode"])
    replacement = GroundFunctionV2.model_validate(data)
    gt = gt.model_copy(
        update={"functions": [replacement if f.address == fn.address else f for f in gt.functions]}
    )
    item = claim(gt, "function_purpose", {"category": "protocol.decode"})
    (result,) = apply(gt, [item], {"protocol": 0.7})
    assert result.role_correct is False and result.correct_partial == 0.5
    assert result.correct_strict is False and result.correct_lenient is True
    with pytest.raises(ValueError, match="agreement kappa"):
        apply(gt, [item], {"protocol": float("nan")})


def test_public_grading_context_is_pinned_for_benchmark_and_replay(tmp_path):
    import hashlib

    from aletheia.config import Config
    from aletheia.grade.context import GradingContext
    from aletheia.orchestrate import Benchmark
    from aletheia.replay import pin_differences
    from aletheia.schema.canonical import canonical_bytes
    from aletheia.schema.models import RunManifest

    context = GradingContext.read(Path("configs/grading-phase1b.json"))
    assert context.human_validated is False
    policy = tmp_path / "agreement.json"
    policy.write_text(context.model_dump_json())
    cfg = Config()
    cfg.paths.build = str(tmp_path / "programs")
    cfg.paths.runs = str(tmp_path / "runs")
    cfg.paths.artifacts = str(tmp_path / "artifacts")
    cfg.grading.agreement = str(policy)
    cfg.sandbox.image_analysis = "sha256:" + "a" * 64
    cfg.sandbox.image_build = "sha256:" + "b" * 64
    data = b"opaque input: metadata test never parses ELF"
    digest = hashlib.sha256(data).hexdigest()
    bundle = Path(cfg.paths.build) / "example/unit"
    (bundle / "stripped").mkdir(parents=True)
    (bundle / "private").mkdir()
    (bundle / "stripped" / (digest + ".bin")).write_bytes(data)
    (bundle / "private/ground_truth.json").write_bytes(b"opaque truth identity")
    (bundle / "targets.json").write_bytes(
        canonical_bytes(Targets(binary_sha256=digest, variant_id="unit", targets=[]))
    )
    benchmark = Benchmark(cfg)
    original = benchmark.manifest_input("example", "scripted")
    assert original.source_config["run_config"]["grading_context"] == context.model_dump(
        mode="json"
    )
    # Sub-wire-precision agreement edits must still invalidate the run pin.
    changed = context.model_copy(
        update={"taxonomy_kappa": context.taxonomy_kappa | {"checksum": 0.99999999}}
    )
    policy.write_text(changed.model_dump_json())
    assert benchmark.grading_context == context
    differences = pin_differences(Benchmark(cfg), RunManifest.create(original))
    assert "source_config.run_config" in differences


def test_dev_configuration_rejects_a_private_grading_context(tmp_path):
    from aletheia.config import Config
    from aletheia.heldout.guard import PrivateAccessError

    cfg = Config()
    cfg.paths.private_root = str(tmp_path / "private")
    cfg.grading.agreement = str(
        Path(cfg.paths.private_root) / "annotations/annotation_agreement.json"
    )
    with pytest.raises(PrivateAccessError, match="--split heldout"):
        cfg.for_split("dev")

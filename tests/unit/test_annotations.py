from aletheia.corpus.annotate import agreement, strip_annotations


def test_kappa_matches_hand_calculation_and_degenerate_is_explicit():
    first = ["checksum.crc32"] * 4 + ["string.length"] * 4
    second = ["checksum.crc32"] * 3 + ["string.length", "checksum.crc32"] + ["string.length"] * 3
    result = agreement(first, second)
    # po=6/8, pe=1/2: kappa=(3/4-1/2)/(1-1/2)=1/2.
    assert result["top_level"]["kappa"] == 0.5
    assert result["nodes"]["checksum"]["top_level"]["kappa"] == 0.5
    assert result["nodes"]["string"]["top_level"]["kappa"] == 0.5
    assert result["nodes"]["checksum"]["strict_scoring"] is False
    same = agreement(["util.init"], ["util.init"])
    assert same["top_level"]["kappa"] is None
    assert same["top_level"]["reason"] == "undefined_expected_agreement"


def test_blinding_removes_every_annotation_and_keeps_source():
    source = (
        "// @algorithm crc32/ieee\n// @category checksum.crc32\n"
        "// @roles buf,len\nint x(void) { return 3; }\n"
    )
    assert strip_annotations(source) == "int x(void) { return 3; }\n"


def test_human_import_requires_exact_cohort_and_preserves_original_labels(tmp_path):
    import json
    from pathlib import Path

    import pytest

    from aletheia.corpus.annotate import import_labels
    from aletheia.heldout.guard import PrivateGuard

    root = tmp_path / "private"
    annotations = root / "annotations"
    annotations.mkdir(parents=True)
    (annotations / "primary.json").write_text(
        json.dumps({"exported_at": "2026-10-16", "items": {"item-1": {"category": "util.init"}}})
    )
    guard = PrivateGuard(root, "heldout")
    path = root / "submitted.json"
    submission = {
        "annotator_id": "synthetic-test-only",
        "method": "intra-rater",
        "completed_at": "2026-10-17",
        "human_attestation": True,
        "labels": [{"item_id": "item-1", "category": "util.init"}],
    }
    path.write_text(json.dumps(submission))
    with pytest.raises(ValueError, match="14 days"):
        import_labels(path, guard, Path("taxonomy.yaml"))
    submission["method"] = "independent"
    path.write_text(json.dumps(submission))
    result = import_labels(path, guard, Path("taxonomy.yaml"))
    before = result.read_bytes()
    with pytest.raises(FileExistsError):
        import_labels(path, guard, Path("taxonomy.yaml"))
    assert result.read_bytes() == before


def test_ai_labels_cannot_claim_human_provenance():
    import json

    import pytest
    from pydantic import ValidationError

    from aletheia.corpus.annotate import SecondaryLabels

    value = {
        "annotator_id": "test-model",
        "method": "ai-assisted",
        "completed_at": "2026-10-16",
        "human_attestation": True,
        "model_provenance": {"model": "test"},
        "labels": [],
    }
    with pytest.raises(ValidationError, match="no human attestation"):
        SecondaryLabels.model_validate_json(json.dumps(value))
    value["human_attestation"] = False
    assert SecondaryLabels.model_validate_json(json.dumps(value)).method == "ai-assisted"

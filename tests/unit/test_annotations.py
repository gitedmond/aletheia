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


def test_export_write_failure_rolls_back_only_new_files(tmp_path, monkeypatch):
    import pytest

    from aletheia.corpus import annotate

    root = tmp_path / "annotations"
    root.mkdir()
    saved = root / "agreement.json"
    saved.write_text("preserve")
    original = annotate._write_new

    def fail_second(path, value):
        if path.name == "export.json":
            raise OSError("simulated full disk")
        original(path, value)

    monkeypatch.setattr(annotate, "_write_new", fail_second)
    with pytest.raises(OSError, match="full disk"):
        annotate._write_export(root, {"primary": 1}, {"second": 2})
    assert not (root / "primary.json").exists()
    assert saved.read_text() == "preserve"
    monkeypatch.setattr(annotate, "_write_new", original)
    annotate._write_export(root, {"primary": 1}, {"second": 2})
    with pytest.raises(ValueError, match="already exists"):
        annotate._write_export(root, {}, {})
    assert (root / "primary.json").stat().st_mode & 0o777 == 0o600


def test_partial_record_is_removed_and_created_private(tmp_path, monkeypatch):
    import json

    import pytest

    from aletheia.corpus import annotate

    path = tmp_path / "record.json"

    def failed_dump(value, stream, **kwargs):
        assert path.stat().st_mode & 0o777 == 0o600
        stream.write("partial")
        raise OSError("full disk")

    monkeypatch.setattr(json, "dump", failed_dump)
    with pytest.raises(OSError, match="full disk"):
        annotate._write_new(path, {})
    assert not path.exists()


def test_export_includes_nested_sources_and_distinct_program_roots(tmp_path, monkeypatch):
    import json
    from pathlib import Path

    from aletheia.corpus import annotate
    from aletheia.heldout.guard import PrivateGuard

    programs = []
    for tier in ["public", "private"]:
        source = tmp_path / tier / "example"
        nested = source / "src/nested"
        nested.mkdir(parents=True)
        (nested / "helper.h").write_text(
            "// @category util.init\nint initialize(void) { return 1; }\n"
        )
        build = tmp_path / tier / "build/variant"
        build.mkdir(parents=True)
        (build / "build.json").write_text('{"image":"test"}')
        programs.append((source, build))

    def worker(image, inputs, corpus, results):
        (results / "review.json").write_text('{"o0_instruction_counts":{"initialize":11}}')

    monkeypatch.setattr(annotate, "run_private_worker", worker)
    monkeypatch.setattr(annotate, "snapshot_program", lambda source, corpus: None)
    root = tmp_path / "records"
    with __import__("pytest").raises(ValueError, match="duplicate annotation"):
        annotate.export_sample(
            [programs[0], programs[0]],
            PrivateGuard(root, "heldout"),
            sample=1,
            seed=1,
            taxonomy_path=Path("taxonomy.yaml"),
        )
    export = annotate.export_sample(
        programs,
        PrivateGuard(root, "heldout"),
        sample=1,
        seed=1,
        taxonomy_path=Path("taxonomy.yaml"),
    )
    assert len(json.loads(export.read_bytes())["items"]) == 2
    primary = json.loads((root / "annotations/primary.json").read_bytes())
    assert primary["population"] == 2
    with __import__("pytest").raises(ValueError, match="already exists"):
        annotate.export_sample(
            programs,
            PrivateGuard(root, "heldout"),
            sample=1,
            seed=1,
            taxonomy_path=Path("taxonomy.yaml"),
        )

"""T17 acceptance: independent counts, false mutations, cases and JSONL intake."""

import json
from pathlib import Path

import pytest
from typer.testing import CliRunner

from aletheia.cli import app
from aletheia.schema.canonical import canonical_bytes, content_hash
from aletheia.schema.models import Algorithm, Call, GroundTruth, ManifestInput, Targets
from aletheia.sources.base import BinaryRef
from aletheia.sources.scripted import ScriptedSource, generate
from aletheia.store.database import Store

SHA = "a" * 64
VARIANT = "clang23-O2-x64-pie-hardoff"


def truth():
    def fn(address, family, variant, callees=(), scorable=True):
        return {
            "address": address,
            "size": 32,
            "name": "f" + address,
            "algorithm": {"family": family, "variant": variant},
            "scorable": scorable,
            "callees": [{"target": target, "kind": kind} for target, kind in callees],
        }

    return GroundTruth.model_validate(
        {
            "binary_sha256": SHA,
            "program_id": "tierA/example",
            "variant_id": VARIANT,
            "build_flags": "test",
            "functions": [
                fn(
                    "0x00001000",
                    "crc32",
                    "ieee",
                    [
                        ("0x00002000", "direct"),
                        ("0x00002000", "tail"),
                        ("0x00002000", "direct"),
                        ("0x00003000", "indirect"),
                    ],
                ),
                fn("0x00002000", "adler32", "zlib"),
                fn(
                    "0x00003000",
                    "none",
                    None,
                    [
                        ("0x00001000", "direct"),
                        ("0x00002000", "direct"),
                        ("0x00004000", "direct"),
                    ],
                ),
                fn("0x00004000", "none", None, scorable=False),
            ],
        }
    )


def manifest():
    return ManifestInput(
        source_config={},
        binaries=[SHA],
        versions={"python": "3.12.15"},
        image_digests={"analysis": "sha256:" + "b" * 64},
        analysis_options_hash="c" * 64,
        pack_hashes={},
        mapping_hashes={},
        verifier_version="0.1.0",
        grader_version="0.1.0",
        seeds={},
    )


def public(tmp_path):
    binary = BinaryRef(SHA, tmp_path / "stripped" / (SHA + ".bin"), VARIANT)
    targets = Targets(
        binary_sha256=SHA, variant_id=VARIANT, targets=["0x00001000", "0x00002000", "0x00003000"]
    )
    return binary, targets


def test_counts_scenarios_false_mutations_and_collision_free_intake(tmp_path):
    gt = truth()
    result = generate(gt, manifest(), seed=19)
    reordered = gt.model_copy(deep=True)
    reordered.functions.reverse()
    for function in reordered.functions:
        function.callees.reverse()
    assert result == generate(reordered, manifest(), seed=19)
    assert result.exclusions == {"no_wrong_callee_candidate": 3}
    assert sum(len(case.claims) for case in result.cases) == 3 * 2 + 1 + 2 * 5 - 3
    assert len({case.manifest.run_id for case in result.cases}) == len(result.cases)
    assert [
        (c.manifest.source_config["scenario"], c.manifest.source_config["case_index"])
        for c in result.cases
        if c.manifest.source_config["scenario"] == "correct"
    ] == [("correct", 0), ("correct", 1)]
    binary, targets = public(tmp_path)
    with Store(tmp_path / "claims.db") as store:
        store.add_binary(
            SHA, gt.program_id, VARIANT, "dev", str(binary.stripped), content_hash(targets)
        )
        for case in result.cases:
            assert case.claims
            scenario = case.manifest.source_config["scenario"]
            store.add_run(
                case.manifest.run_id, "scripted", "scripted:v1", content_hash(case.manifest)
            )
            path = tmp_path / (case.manifest.run_id + ".jsonl")
            path.write_bytes(
                b"".join(
                    canonical_bytes(c.model_dump(mode="json", exclude={"claim_id"})) + b"\n"
                    for c in case.claims
                )
            )
            loaded = ScriptedSource(path, case.manifest.run_id).produce(binary, targets)
            assert loaded == case.claims
            for claim in loaded:
                store.add_claim(claim)
                function = next(f for f in gt.functions if f.address == claim.subject.address)
                assert claim.confidence == 0.9 and claim.confidence_source == "scripted"
                assert claim.derived_from == (
                    "scripted_mutated" if scenario == "mutated" else "scripted_correct"
                )
                if isinstance(claim.body, Call):
                    present = any(
                        e.target == claim.body.callee and e.kind == claim.body.kind
                        for e in function.callees
                    )
                    assert present == (scenario == "correct")
                elif scenario == "family_only":
                    assert claim.body == Algorithm(family=function.algorithm.family)
                elif scenario == "correct":
                    assert claim.body.model_dump() == function.algorithm.model_dump()
                elif function.algorithm.family == "crc32":
                    assert claim.body.family == "crc32" and claim.body.variant != "ieee"
                else:
                    assert claim.body.family != function.algorithm.family


def test_generator_rejects_identity_drift_and_emits_no_empty_runs():
    with pytest.raises(ValueError, match="binary"):
        generate(truth(), manifest().model_copy(update={"binaries": ["d" * 64]}), seed=19)
    empty = truth().model_copy(update={"functions": []})
    assert generate(empty, manifest(), seed=19).cases == []


def test_jsonl_rejects_duplicate_keys_and_foreign_identity(tmp_path):
    case = generate(truth(), manifest(), seed=19).cases[0]
    binary, targets = public(tmp_path)
    path = tmp_path / "claims.jsonl"
    submission = case.claims[0].model_dump(mode="json", exclude={"claim_id"})
    path.write_bytes((canonical_bytes(submission) + b"\n") * 2)
    with pytest.raises(ValueError, match="duplicate_active_claim"):
        ScriptedSource(path, case.manifest.run_id).produce(binary, targets)
    path.write_bytes(canonical_bytes(submission | {"binary_sha256": "d" * 64}) + b"\n")
    with pytest.raises(ValueError, match="identity"):
        ScriptedSource(path, case.manifest.run_id).produce(binary, targets)


def test_cli_generates_repeatable_jsonl_cases_without_overwriting_changes(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    ground = tmp_path / "build" / "example" / VARIANT / "private" / "ground_truth.json"
    ground.parent.mkdir(parents=True)
    ground.write_bytes(canonical_bytes(truth()))
    Path("aletheia.toml").write_text("")
    Path("input.json").write_bytes(canonical_bytes(manifest()))
    args = [
        "--json",
        "claims",
        "scripted",
        "--program",
        "example",
        "--manifest",
        "input.json",
        "--seed",
        "19",
    ]
    runner = CliRunner()
    first = runner.invoke(app, args)
    assert first.exit_code == 0, first.output
    output = json.loads(first.output)
    assert output["claims"] == 14
    assert output["exclusions"] == {"no_wrong_callee_candidate": 3}
    assert runner.invoke(app, args).output == first.output
    claim_path = Path(output["cases"][0]["claims_file"])
    claim_path.write_text("preserve local edit\n")
    assert runner.invoke(app, args).exit_code == 1
    assert claim_path.read_text() == "preserve local edit\n"


def test_algorithm_version_is_consistent_between_truth_manifest_and_claims():
    gt = truth().model_copy(update={"algorithms_version": "2.0"})
    with pytest.raises(ValueError, match="algorithm version"):
        generate(gt, manifest())
    result = generate(gt, manifest().model_copy(update={"algorithms_version": "2.0"}))
    assert result.cases
    assert all(case.manifest.algorithms_version == "2.0" for case in result.cases)
    assert all(claim.algorithms_version == "2.0" for case in result.cases for claim in case.claims)

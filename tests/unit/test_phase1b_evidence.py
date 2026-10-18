"""A synthetic preparation -> receipt -> gate pass proves the Phase 1B wiring."""

from pathlib import Path
from types import SimpleNamespace

from aletheia import phase1b
from aletheia.config import Config
from aletheia.gate_phase1b import evaluate
from aletheia.heldout.guard import PrivateGuard
from aletheia.orchestrate import write_json
from aletheia.schema.models import ManifestInput, RunManifest
from aletheia.verify.engine import DEFAULT_PACK_DIRECTORY

DEV_PROGRAMS = [f"p{index:02d}" for index in range(12)]
HELDOUT_PROGRAMS = [f"h{index:02d}" for index in range(8)]
RUNS = {}


def _run_id(index: int) -> str:
    return f"r_{index:016x}"


def synthetic_plan() -> dict:
    slots = []
    index = 0
    for program in DEV_PROGRAMS + HELDOUT_PROGRAMS:
        split = "dev" if program in DEV_PROGRAMS else "heldout"
        for variant in ("baseline", "hardened"):
            for source in ("scripted", "capa", "findcrypt"):
                slots.append(
                    {
                        "split": split,
                        "program": program,
                        "variant": variant,
                        "source": source,
                        "sample": 0,
                        "status": "executed",
                        "runs": [_run_id(index)],
                        "reason": None,
                    }
                )
                RUNS[_run_id(index)] = False
                index += 1
            for config in ("local-a", "local-b", "local-c"):
                for sample in range(3 if variant == "baseline" else 1):
                    slots.append(
                        {
                            "split": split,
                            "program": program,
                            "variant": variant,
                            "source": "agent:" + config,
                            "sample": sample,
                            "status": "executed",
                            "runs": [_run_id(index)],
                            "reason": None,
                        }
                    )
                    RUNS[_run_id(index)] = True
                    index += 1
    return {"slots": slots}


def synthetic_replays() -> dict:
    return {
        "runs": {
            run: {"exit_code": 0, **({"agent_replay": True} if agent else {})}
            for run, agent in sorted(RUNS.items())
        }
    }


def ground_truth(program: str, index: int) -> dict:
    functions = []
    for slot, category in enumerate(("memory.set", "memory.set", "checksum.other")):
        functions.append(
            {
                "address": f"0x0000{0x1000 + slot:04x}",
                "size": 32,
                "name": f"f{slot}",
                "algorithm": {"family": "none"},
                "scorable": True,
                "source_signature": "uint32_t (const uint8_t *, size_t)",
                "category": category,
                "acceptable_categories": [category],
                "abi_signature": {
                    "return": {"class": "int", "width": 32},
                    "params": [
                        {"class": "ptr", "width": 64},
                        {"class": "int", "width": 32},
                        {"class": "int", "width": 64},
                    ],
                    "abi_complex": False,
                    "variadic": False,
                },
                "roles": ["buf", "len"],
                "source_types": {
                    "return_type": "uint32_t",
                    "params": ["const uint8_t *", "size_t"],
                    "variadic": False,
                },
            }
        )
    return {
        "schema_version": "2.0",
        "algorithms_version": "2.0",
        "binary_sha256": f"{index:064x}",
        "program_id": "tierA/" + program,
        "variant_id": "synthetic-hardoff",
        "build_flags": "test",
        "functions": functions,
    }


def synthetic_builds() -> dict:
    rows = []
    for program in DEV_PROGRAMS + HELDOUT_PROGRAMS:
        for variant in ("baseline", "hardened"):
            rows.append(
                {
                    "program": program,
                    "variant": variant,
                    "first_sha256": "a" * 64,
                    "second_sha256": "a" * 64,
                    "metadata_sha256": "b" * 64,
                    "leakage_hits": [],
                }
            )
    return {"builds": rows}


def synthetic_selftest() -> dict:
    cases = []
    for pack in sorted(DEFAULT_PACK_DIRECTORY.glob("*.yaml")):
        cases.append(
            {
                "name": f"{pack.stem}:reference:one",
                "family": pack.stem,
                "expected": "VERIFIED",
                "actual": "VERIFIED",
                "passed": True,
                "reason": None,
            }
        )
    for family in ("md5", "sha1", "sha256"):
        cases.append(
            {
                "name": f"{family}:composite:one",
                "family": family,
                "expected": "CONTRADICTED",
                "actual": "CONTRADICTED",
                "passed": True,
                "reason": None,
            }
        )
    return {"status": "ok", "families": [], "cases": cases, "failed": 0}


def synthetic_manifest(index: int) -> dict:
    manifest = RunManifest.create(
        ManifestInput(
            source_config={
                "split": "dev",
                "program": "p00",
                "source_id": "scripted",
                "seed": index,
            },
            binaries=[f"{index:064x}"],
            versions={"aletheia": "test"},
            image_digests={"build": "sha256:" + "c" * 64},
            analysis_options_hash="d" * 64,
            pack_hashes={},
            mapping_hashes={},
            verifier_version="test",
            grader_version="test",
            seeds={"probe": 1},
        )
    )
    return manifest.model_dump(mode="json")


def junit(names: list[str]) -> str:
    cases = "".join(f'<testcase classname="tests.{name}" name="{name}_case"/>' for name in names)
    return f"<testsuites><testsuite>{cases}</testsuite></testsuites>"


def synthetic_evidence(tmp_path: Path) -> Path:
    root = tmp_path / "runs"
    directory = root / "phase1b"
    directory.mkdir(parents=True)
    benchmark = SimpleNamespace(root=root)
    config = Config()
    config = config.model_copy(
        update={
            "grading": config.grading.model_copy(
                update={"agreement": "configs/grading-phase1b.json"}
            )
        }
    )
    plan_payload = phase1b.plan(synthetic_plan())
    replays_payload = phase1b.replays(plan_payload, synthetic_replays())
    truths = [
        phase1b_ground_truth(program, index)
        for index, program in enumerate(DEV_PROGRAMS + HELDOUT_PROGRAMS)
    ]
    coverage = phase1b.coverage(truths, variant_id="synthetic-hardoff", label="baseline")
    dev_runs = sorted(
        run for row in plan_payload["slots"] if row["split"] == "dev" for run in row["runs"]
    )
    manifests = {run: synthetic_manifest(index) for index, run in enumerate(dev_runs[:5])}
    fit_payload = {
        "status": "ok",
        "input_run_ids": sorted(manifests),
        "calibration_hash": "e" * 64,
        "likelihoods_hash": "f" * 64,
    }
    report_payload = {
        "split": "heldout",
        "cluster_count": 8,
        "sections": ["RQ1", "RQ5", "RQ9"],
        "populations": [{"intervals": [0.0, 1.0]}],
        "calibration_sha256": fit_payload["calibration_hash"],
        "likelihoods_sha256": fit_payload["likelihoods_hash"],
    }
    files = {}
    for name, names in (
        ("golden_tests", ["golden", "abi"]),
        ("mcp_tests", ["mcp"]),
        ("guard_tests", ["heldout"]),
    ):
        path = directory / (name + ".xml")
        path.write_text(junit(names))
        files[name] = path
    payloads = {
        "builds": synthetic_builds(),
        "history": {"status": "clean", "scanned_commits": 7},
        "scripted": {
            "heldout_algorithm_identity": {"VERIFIED": 6, "CONTRADICTED": 2},
            "correct_e2_algorithm_identity": {"total": 6, "contradicted": 0},
        },
        "selftest": synthetic_selftest(),
        "coverage": coverage,
        "plan": plan_payload,
        "replays": replays_payload,
        "fit": fit_payload,
        "fit_manifests": manifests,
        "report": report_payload,
        "exposures": phase1b.exposures(
            PrivateGuard(root=(tmp_path / "private").resolve(), split="heldout")
        ),
        "agreement": phase1b.agreement(config),
    }
    return phase1b.assemble(benchmark, payloads, files)


def phase1b_ground_truth(program: str, index: int):
    from aletheia.schema.models import GroundTruth

    return GroundTruth.model_validate(ground_truth(program, index))


def test_synthetic_experiment_passes_mechanical_criteria(tmp_path):
    evidence = synthetic_evidence(tmp_path)
    result = evaluate(SimpleNamespace(root=evidence.parents[1]))
    criteria = {key: row["passed"] for key, row in result["criteria"].items()}
    assert criteria == {
        "X1": True,
        "X2": True,
        "X3": True,
        "X4": True,
        "X5": True,
        "X6": True,
        "X7": False,
        "X8": True,
        "X9": True,
        "X10": True,
        "X11": True,
        "X12": True,
        "X13": True,
        "X14": False,
    }
    assert result["criteria"]["X7"]["details"]["human_validated"] is False
    assert (evidence.parent / "gate.json").exists()


def test_tampered_receipt_and_stale_scope_fail_closed(tmp_path):
    evidence = synthetic_evidence(tmp_path)
    root = evidence.parents[1]
    selftest = evidence.parent / "selftest.json"
    payload = selftest.read_bytes() + b" "
    selftest.write_bytes(payload)
    result = evaluate(SimpleNamespace(root=root))
    assert result["criteria"]["X6"]["passed"] is False
    assert result["criteria"]["X5"]["passed"] is True
    write_json(
        evidence,
        {"package_source_hash": "0" * 64, "receipts": {}},
    )
    result = evaluate(SimpleNamespace(root=root))
    assert all(not row["passed"] for row in result["criteria"].values())


def test_plan_rejects_wrong_cartesian_cohort_and_reused_runs():
    import copy

    import pytest

    original = synthetic_plan()
    for field, value in (
        ("sample", 99),
        ("variant", "unknown"),
        ("split", "heldout"),
        ("status", "running"),
        ("program", "foreign"),
    ):
        payload = copy.deepcopy(original)
        payload["slots"][0][field] = value
        with pytest.raises(ValueError):
            phase1b.plan(payload)
    payload = copy.deepcopy(original)
    payload["slots"][1]["runs"] = payload["slots"][0]["runs"]
    with pytest.raises(ValueError):
        phase1b.plan(payload)


def test_false_alarm_population_excludes_correct_abstentions(monkeypatch):
    from aletheia import report

    claim = SimpleNamespace(
        type="algorithm_identity",
        source=SimpleNamespace(origin="scripted"),
        derived_from="scripted_correct",
    )
    rows = [
        (claim, SimpleNamespace(intrinsic_verdict=v, strength=strength), None, None)
        for v, strength in (
            ("VERIFIED", "E2"),
            ("CONTRADICTED", "E2"),
            ("INCONCLUSIVE", None),
            ("UNVERIFIABLE", None),
        )
    ]
    monkeypatch.setattr(report, "collect", lambda *args: SimpleNamespace(claims=rows))
    result = phase1b.scripted(SimpleNamespace(), ["run"])
    assert result["correct_e2_algorithm_identity"] == {"total": 2, "contradicted": 1}


def test_corpus_reference_evidence_requires_all_fixed_inputs_and_clean_outputs():
    import copy

    from aletheia.verify.probes.pack import load_pack

    pack = load_pack(Path("packs/crc32.yaml"))
    inputs = pack.inputs.model_copy(
        update={
            "boundary_lengths": False,
            "fixed": ["123456789", "abc"],
            "fixed_hex": [],
            "random": pack.inputs.random.model_copy(update={"count": 0}),
        }
    )
    pack = pack.model_copy(update={"inputs": inputs})
    rows = [
        {
            "shape": "buf_len",
            "variant": "ieee",
            "input_hex": data.hex(),
            "status": "match",
            "expected_hex": "ab",
            "actual_hex": "ab",
        }
        for data in (b"123456789", b"abc")
    ]
    assert phase1b.reference_matches(pack, {"observations": rows})
    assert not phase1b.reference_matches(pack, {"observations": rows[:1]})
    assert not phase1b.reference_matches(pack, {"observations": []})
    changed = copy.deepcopy(rows)
    changed[1]["actual_hex"] = "cd"
    assert not phase1b.reference_matches(pack, {"observations": changed})

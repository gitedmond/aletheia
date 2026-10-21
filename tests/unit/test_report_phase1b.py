"""Independently computed ECE/cluster examples and potential E2 scope exclusions."""

from pathlib import Path

import pytest

from aletheia.confidence import Adjustment, Sample
from aletheia.confidence.headline import Scored
from aletheia.corpus.verifiability import table_v2
from aletheia.report.phase1b import equal_mass_ece, population
from aletheia.schema.models import GroundTruth
from aletheia.verify.probes.pack import load_pack


def test_ece_equal_mass_bins_and_bootstrap_zero_claim_cluster():
    assert equal_mass_ece([]) is None
    assert equal_mass_ece(
        [(0.9, True), (0.8, False), (0.3, False), (0.2, True)], 2
    ) == pytest.approx(0.3)
    assert equal_mass_ece([(0.9, True), (0.8, False)], 10) == pytest.approx(0.45)
    with pytest.raises(ValueError):
        equal_mass_ece([(float("nan"), True)])
    row = Scored(
        sample=Sample(
            claim_id="c_" + "a" * 24,
            run_id="r_" + "b" * 16,
            program="private_marker",
            split="heldout",
            source={"origin": "agent", "source_id": "agent:test"},
            claim_type="function_signature",
            confidence=0.9,
            correct_claimed=False,
            on_target=True,
            verdict="CONTRADICTED",
            strength="E1",
            method="static.arity",
        ),
        confidence=Adjustment(
            raw=0.9,
            prior=0.8,
            adjusted=0.2,
            calibration="calibrated",
            likelihood="fitted",
            likelihood_ratio=1,
            dependency_cap=None,
        ),
    )
    result = population([row], ["private_marker", "zero_claim_marker"], resamples=100, seed=4)
    assert result["metrics"]["raw_overconfidence_gap"] == 0.9
    assert result["metrics"]["raw_cwr"] == 1
    assert result["metrics"]["adjusted_cwr"] is None
    assert result["intervals"]["raw_ece"]["defined_resamples"] < 100
    assert "marker" not in str(result)
    assert result == population(
        [row], ["private_marker", "zero_claim_marker"], resamples=100, seed=4
    )


def test_v2_potential_does_not_count_static_signatures_or_incomplete_composites():
    categories = ["string.length", "crypto.hash.md5.init", "util.other"]
    # util.other may not be a taxonomy leaf; take an intentionally unsupported real leaf.
    from aletheia.schema.taxonomy import Taxonomy

    categories[-1] = next(
        leaf for leaf in Taxonomy.bundled().leaves if leaf.startswith("compression.")
    )
    functions = [
        {
            "address": f"0x{i:08x}",
            "size": 32,
            "name": f"f{i}",
            "scorable": True,
            "algorithm": {"family": "none"},
            "category": category,
            "acceptable_categories": [category],
            "abi_signature": {
                "return": {"class": "int", "width": 32},
                "params": (
                    [{"class": "ptr", "width": 64}]
                    if category in {"string.length", "crypto.hash.md5.init"}
                    else []
                ),
                "variadic": False,
                "abi_complex": False,
            },
            "source_types": None,
            "roles": [],
        }
        for i, category in enumerate(categories, 4096)
    ]
    gt = GroundTruth.model_validate(
        {
            "schema_version": "2.0",
            "algorithms_version": "2.0",
            "binary_sha256": "a" * 64,
            "program_id": "tierA/test",
            "variant_id": "baseline",
            "build_flags": "test",
            "functions": functions,
        }
    )
    packs = [load_pack(Path("packs") / (name + ".yaml")) for name in ("strlen", "md5")]
    result = table_v2([gt], packs)
    assert result["scorable_functions"] == 3 and result["decidable_functions"] == 1
    assert result["decidable_share"] == 1 / 3
    assert "static E1 signatures excluded" in result["population"]

    complete = gt.model_copy(deep=True)
    complete.program_id = "tierA/complete"
    complete.binary_sha256 = "b" * 64
    for i, role in enumerate(("update", "final"), 8192):
        fn = gt.functions[1].model_copy(deep=True)
        fn.address = f"0x{i:08x}"
        fn.category = "crypto.hash.md5." + role
        fn.abi_signature.params = [
            gt.functions[1].abi_signature.params[0].model_copy()
            for _ in range(3 if role == "update" else 2)
        ]
        if role == "update":
            fn.abi_signature.params[-1].kind = "int"
        fn.acceptable_categories = [fn.category]
        complete.functions.append(fn)
    mixed = table_v2([gt, complete], packs)
    init_rows = [row for row in mixed["rows"] if row["leaf"] == "crypto.hash.md5.init"]
    assert sorted((row["scorable_functions"], bool(row["decisive_for"])) for row in init_rows) == [
        (1, False),
        (1, True),
    ]


def test_coverage_requires_a_supported_compiler_abi():
    from aletheia.schema.models import GroundTruth
    from aletheia.verify.probes.pack import load_pack

    functions = []
    for index, (category, kinds) in enumerate(
        [
            ("io.file.read", ["ptr", "ptr", "ptr"]),
            ("io.file.read", ["ptr", "ptr"]),
            ("io.file.write", ["ptr", "int"]),
            ("io.file.write", ["int", "ptr"]),
        ],
        4096,
    ):
        functions.append(
            {
                "address": f"0x{index:08x}",
                "size": 32,
                "name": f"fn{index}",
                "algorithm": {"family": "none"},
                "scorable": True,
                "category": category,
                "acceptable_categories": [category],
                "roles": [],
                "source_types": None,
                "abi_signature": {
                    "return": {"class": "int", "width": 32},
                    "params": [{"class": kind, "width": 64} for kind in kinds],
                    "abi_complex": False,
                    "variadic": False,
                },
            }
        )
    gt = GroundTruth.model_validate(
        {
            "schema_version": "2.0",
            "algorithms_version": "2.0",
            "binary_sha256": "a" * 64,
            "program_id": "tierA/shapes",
            "variant_id": "baseline",
            "build_flags": "test",
            "functions": functions,
        }
    )
    result = table_v2(
        [gt], [load_pack(Path("packs") / f"{name}.yaml") for name in ("file-read", "print")]
    )
    assert result["scorable_functions"] == 4
    assert result["decidable_functions"] == 2


def test_report_clusters_follow_source_variant_runs_including_empty_runs(tmp_path, monkeypatch):
    from types import SimpleNamespace

    from aletheia.confidence import CalibrationFit, LikelihoodFit
    from aletheia.config import Config
    from aletheia.orchestrate import file_hash, write_json
    from aletheia.report import phase1b

    fit = tmp_path / "fit"
    write_json(fit / "calibration.json", CalibrationFit(run_ids=[], maps=[], unfitted=[]))
    write_json(fit / "likelihoods.json", LikelihoodFit(run_ids=[], rows=[]))
    write_json(
        fit / "fit.json",
        {
            "input_run_ids": [],
            "calibration_hash": file_hash(fit / "calibration.json"),
            "likelihoods_hash": file_hash(fit / "likelihoods.json"),
        },
    )
    manifests, claims = [], []
    # X has a zero-claim run on B; only Y runs on C. Hardened X only runs on A.
    slots = [
        ("x", "base", "a", True),
        ("x", "base", "b", False),
        ("y", "base", "c", True),
        ("x", "hard", "a", True),
    ]
    bundles = {}
    for i, (source, variant, program, has_claim) in enumerate(slots):
        run = "r_" + str(i) * 16
        info = {"source_id": source, "variant_id": variant, "program": program}
        write_json(tmp_path / run / "run.json", info)
        write_json(tmp_path / run / "manifest.json", {})
        manifests.append(SimpleNamespace(run_id=run, source_config={"split": "heldout"}))
        gt = GroundTruth.model_validate(
            {
                "schema_version": "2.0",
                "algorithms_version": "2.0",
                "binary_sha256": str(i) * 64,
                "program_id": "tierA/" + program,
                "variant_id": variant,
                "build_flags": "test",
                "functions": [],
            }
        )
        bundle = tmp_path / "build" / program / variant
        write_json(bundle / "private/ground_truth.json", gt)
        bundles[(program, variant)] = bundle
        if has_claim:
            claim = SimpleNamespace(
                run_id=run,
                claim_id="c_" + str(i) * 24,
                source=SimpleNamespace(source_id=source),
                type="algorithm_identity",
                binary_sha256=gt.binary_sha256,
                subject=SimpleNamespace(address="0x00001000"),
            )
            verdict = SimpleNamespace(
                aspects={
                    "algorithm_behavior": SimpleNamespace(
                        method="probe", strength="E2", verdict="VERIFIED"
                    )
                }
            )
            grade = SimpleNamespace(
                on_target=True,
                correct_strict=True,
                correct_claimed=True,
                aspect_correct={"algorithm_behavior": True},
            )
            claims.append((claim, verdict, grade, "tierA/" + program))
    data = SimpleNamespace(manifests=manifests, claims=claims)
    cfg = Config()
    cfg.metrics.bootstrap_resamples = 20
    benchmark = SimpleNamespace(
        config=SimpleNamespace(
            guard=SimpleNamespace(split="heldout", access=lambda _: None), metrics=cfg.metrics
        ),
        directory=lambda run: tmp_path / run,
        bundle=lambda p, v: (None, None, bundles[(p, v)]),
        grading_context=None,
        observations=lambda _: [],
    )
    monkeypatch.setattr(phase1b, "collect", lambda *_: data)

    def sampled(c, v, g, program, split):
        return Sample(
            claim_id=c.claim_id,
            run_id=c.run_id,
            program=program,
            split=split,
            source={"origin": "agent", "source_id": c.source.source_id},
            claim_type=c.type,
            confidence=0.8,
            correct_claimed=True,
            on_target=True,
            verdict="VERIFIED",
            strength="E2",
            method="probe",
        )

    monkeypatch.setattr(phase1b, "sample", sampled)
    adjustment = Adjustment(
        raw=0.8,
        prior=0.8,
        adjusted=0.8,
        calibration="uncalibrated",
        likelihood="neutral_unseen",
        likelihood_ratio=1,
        dependency_cap=None,
    )
    monkeypatch.setattr(
        phase1b, "adjust_graph", lambda rows, *_: {r.claim_id: adjustment for r in rows}
    )
    truth_groups = []

    def metrics(*args, ground_truths, **kwargs):
        truth_groups.append({g.program_id for g in ground_truths})
        return SimpleNamespace(
            sources=[SimpleNamespace(aggregate=SimpleNamespace(model_dump=lambda **_: {}))]
        )

    monkeypatch.setattr(phase1b, "compute_metrics", metrics)
    seen = []
    real_population = phase1b.population

    def population(rows, programs, **kwargs):
        seen.append(set(programs))
        return real_population(rows, programs, **kwargs)

    monkeypatch.setattr(phase1b, "population", population)
    result = phase1b.generate(benchmark, [m.run_id for m in manifests], fit)
    assert seen[:3] == truth_groups == [{"tierA/a", "tierA/b"}, {"tierA/a"}, {"tierA/c"}]
    assert seen[3:] == [{"tierA/a", "tierA/b"}, {"tierA/c"}, {"tierA/a"}]
    assert all(p["coverage"] is None for p in result["populations"])

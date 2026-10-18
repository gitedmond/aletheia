"""New aspects, purpose proofs and composite inheritance through real sandbox jobs."""

import json
from pathlib import Path

import pytest

from aletheia.analysis.ghidra_session import GhidraAnalysisCache
from aletheia.config import Config
from aletheia.sandbox.runner import JobRunner
from aletheia.schema.models import Claim, ClaimSubmission
from aletheia.selftest import build_fixture, compile_fixture
from aletheia.store.artifacts import ArtifactStore
from aletheia.store.database import Store
from aletheia.verify.engine import Engine

pytestmark = pytest.mark.integration


def make(binary, address, kind, body, source="first"):
    return Claim.intake(
        ClaimSubmission.model_validate(
            {
                "run_id": "r_" + ("1" if source == "first" else "2") * 16,
                "source": {"origin": "human", "source_id": "human:synthetic-" + source},
                "binary_sha256": binary.binary_sha256,
                "subject": {"address": address},
                "type": kind,
                "body": body,
                "algorithms_version": "2.0",
                "confidence": 1.0,
                "confidence_source": "stated",
            }
        )
    )


def setup(tmp_path):
    cfg = Config.read(Path("aletheia.toml"))
    runner = JobRunner(
        cfg.sandbox, tmp_path / "public", tmp_path / "jobs", ArtifactStore(tmp_path / "artifacts")
    )
    cache = GhidraAnalysisCache(runner, tmp_path / "cache")
    return cfg, runner, cache


@pytest.mark.parametrize("kind", ["signature", "purpose"])
def test_signature_and_purpose_decisions_through_engine(kind, tmp_path):
    cfg, runner, cache = setup(tmp_path)
    source = Path(
        "tests/fixtures/static/signature"
        if kind == "signature"
        else "tests/fixtures/purpose/calibration"
    )
    fixture = json.loads((source / "cases.json").read_bytes())
    binary, symbols = compile_fixture(source, cfg, tmp_path, fixture["binary_sha256"])
    if kind == "signature":
        cases = [
            case
            for case in fixture["cases"]
            if case["name"] in {"sig_ret32", "sig_write32_read64", "sig_void_written"}
        ]
        claims = [
            make(binary, symbols[case["name"]], "function_signature", case["body"])
            for case in cases
        ]
        expected = ["VERIFIED", "INCONCLUSIVE", "CONTRADICTED"]
    else:
        claims = [
            make(binary, symbols[name], "function_purpose", {"category": "string.length"})
            for name in ["length_ref", "length_plus"]
        ]
        expected = ["VERIFIED", "CONTRADICTED"]
    analysis = cache.analyze(
        binary,
        Path(cfg.ghidra.analysis_options),
        subjects=[claim.subject.address for claim in claims],
    )
    with Store(tmp_path / "db.sqlite") as store:
        engine = Engine(runner, store, cfg.budgets, Path(cfg.ghidra.analysis_options))
        for claim, wanted in zip(claims, expected, strict=True):
            result = engine.verify(claim, binary, analysis)
            assert result.verdict.intrinsic_verdict == wanted, result
            if kind == "signature":
                assert {
                    "arity",
                    "return_width",
                    "param_widths",
                    "param_types",
                } <= result.verdict.aspects.keys()
            else:
                assert result.verdict.strength == "E2"
                assert result.verdict.aspects["category_behavior"].verdict == wanted


def test_composite_groups_order_inheritance_and_cross_source_cache(tmp_path):
    cfg, runner, cache = setup(tmp_path)
    binary, symbols, fixture = build_fixture("md5", cfg, tmp_path, fixture_set="composite")
    subjects = [
        symbols[getattr(case, role)]
        for case in fixture.composite_cases
        for role in ["init", "update", "final"]
    ]
    analysis = cache.analyze(binary, Path(cfg.ghidra.analysis_options), subjects=subjects)
    with Store(tmp_path / "db.sqlite") as store:
        engine = Engine(runner, store, cfg.budgets, Path(cfg.ghidra.analysis_options))
        for case in fixture.composite_cases:

            def claims(source, case=case):
                roles = [
                    make(
                        binary,
                        symbols[getattr(case, role)],
                        "function_purpose",
                        {"category": "crypto.hash.md5." + role},
                        source,
                    )
                    for role in ["init", "update", "final"]
                ]
                signature = make(
                    binary,
                    symbols[case.update],
                    "function_signature",
                    {
                        "return_type": "void",
                        "params": [
                            {"type": "void *"},
                            {"type": "const unsigned char *"},
                            {"type": "size_t"},
                        ],
                    },
                    source,
                )
                algorithm = make(
                    binary,
                    symbols[case.update],
                    "algorithm_identity",
                    {"family": "md5", "variant": "std"},
                    source,
                )
                return [algorithm, *reversed(roles), signature]

            first = claims("first")
            results = engine.verify_claims(first, binary, analysis)
            assert results[0].verdict.claim_id == first[-1].claim_id
            assert len(engine.last_verification_edges) == 3
            behavioral = [result.verdict for result in results[1:]]
            assert all(
                v.intrinsic_verdict == case.expected and v.strength == "E2" for v in behavioral
            ), results
            refs = [
                next(e.artifact for e in v.evidence if e.kind == "composite_results")
                for v in behavioral
            ]
            assert len(set(refs)) == 1
            jobs = len(list(runner.jobs_root.iterdir()))
            repeated = engine.verify_claims(claims("second"), binary, analysis)
            assert all(result.cache_hit for result in repeated)
            assert len(list(runner.jobs_root.iterdir())) == jobs


def test_benchmark_uses_one_shared_composite_job(tmp_path):
    import shutil

    from aletheia.orchestrate import Benchmark
    from aletheia.schema.canonical import canonical_bytes
    from aletheia.schema.models import ManifestInput, RunManifest, Targets

    cfg = Config.read(Path("aletheia.toml"))
    binary, symbols, fixture = build_fixture("md5", cfg, tmp_path, fixture_set="composite")
    case = next(case for case in fixture.composite_cases if case.expected == "VERIFIED")
    cfg.paths.build = str(tmp_path / "programs")
    cfg.paths.runs = str(tmp_path / "benchmark-runs")
    cfg.paths.artifacts = str(tmp_path / "benchmark-artifacts")
    bundle = Path(cfg.paths.build) / "calibration" / binary.variant_id
    (bundle / "stripped").mkdir(parents=True)
    shutil.copyfile(binary.stripped, bundle / "stripped" / binary.stripped.name)
    targets = Targets(
        binary_sha256=binary.binary_sha256,
        variant_id=binary.variant_id,
        targets=sorted(
            {symbols[getattr(case, role)] for role in ["init", "update", "final"]},
            key=lambda address: int(address, 16),
        ),
    )
    (bundle / "targets.json").write_bytes(canonical_bytes(targets))
    manifest = RunManifest.create(
        ManifestInput(
            algorithms_version="2.0",
            source_config={
                "origin": "human",
                "source_id": "human:synthetic-first",
                "source": "human",
                "program": "calibration",
            },
            binaries=[binary.binary_sha256],
            versions={},
            image_digests={
                "analysis": cfg.sandbox.image_analysis,
                "build": cfg.sandbox.image_build,
            },
            analysis_options_hash="a" * 64,
            pack_hashes={},
            mapping_hashes={},
            verifier_version="0.1.0",
            grader_version="0.1.0",
            seeds={},
        )
    )
    claims = [
        make(
            binary,
            symbols[getattr(case, role)],
            "function_purpose",
            {"category": "crypto.hash.md5." + role},
        )
        for role in ["init", "update", "final"]
    ]
    claims.append(
        make(
            binary, symbols[case.update], "algorithm_identity", {"family": "md5", "variant": "std"}
        )
    )
    claims = [
        Claim.intake(
            ClaimSubmission.model_validate(
                claim.model_dump(mode="json", exclude={"claim_id"}) | {"run_id": manifest.run_id}
            )
        )
        for claim in claims
    ]
    benchmark = Benchmark(cfg)
    run = benchmark.ingest("calibration", manifest, claims)
    benchmark.verify(run)
    with benchmark.store() as store:
        verdicts = [store.get_verdict(claim.claim_id) for claim in claims]
    assert all(
        verdict.intrinsic_verdict == "VERIFIED" and verdict.strength == "E2" for verdict in verdicts
    )
    metadata = json.loads((benchmark.directory(run) / "run.json").read_bytes())
    assert sum(record["job"]["type"] == "verify_composite" for record in metadata["jobs"]) == 1

"""Executable Phase 1A evidence preparation and independently checked exit criteria."""

import json
import sqlite3
import sys
from dataclasses import asdict
from pathlib import Path
from typing import Any, Literal, cast

import yaml
from pydantic import Field, JsonValue

from aletheia.corpus.build import Variant, build_program
from aletheia.corpus.ground_truth import check_leakage
from aletheia.corpus.verifiability import markdown, table
from aletheia.orchestrate import Benchmark, file_hash, write_json
from aletheia.replay import pin_differences, replay
from aletheia.report import collect, render
from aletheia.sandbox.cached import SOURCE_JOBS
from aletheia.schema.canonical import canonical_bytes, content_hash
from aletheia.schema.models import (
    Algorithm,
    GroundTruth,
    Job,
    Record,
    RunId,
    RunManifest,
    Sha256,
    Strict,
)
from aletheia.selftest import Fixture, run_selftest
from aletheia.verify.engine import DEFAULT_PACK_DIRECTORY
from aletheia.verify.probes.pack import load_pack

ROOT = Path(__file__).resolve().parent.parent
PROGRAMS = ("adlerfletch", "b64", "cmd-dispatch", "crc32tool", "hashtable")
REVIEW_SCOPES = {
    "T06": ["corpus/**/*"],
    "T08": ["tests/golden/crc32tool/ground_truth.json"],
    "F6": ["configs/ghidra-analysis.json"],
    "static_edges": ["tests/golden/static-edges.json"],
    "T11": ["aletheia/verify/static/arity.py", "tests/golden/arity.yaml"],
    "T12": ["aletheia/verify/emulate/core.py"],
    "T15": ["packs/*.yaml", "tests/golden/vectors.yaml", "tests/fixtures/near_miss/**/*"],
    "T16": ["aletheia/verify/engine.py"],
    "T18": ["mappings/capa.yaml", "tests/golden/adapters/capa-*.json"],
    "T19": ["mappings/findcrypt.yaml", "tests/golden/adapters/findcrypt-*.json"],
    "T21": ["aletheia/metrics/__init__.py", "tests/unit/test_metrics.py"],
    "report_snapshot": ["tests/golden/report-mini.md"],
}


class BuildProof(Strict):
    first_sha256: Sha256
    second_sha256: Sha256
    metadata_sha256: Sha256
    leakage_hits: list[dict[str, str]]


class PhaseEvidence(Record):
    runs: list[RunId] = Field(min_length=1)
    manifests: dict[RunId, Sha256]
    builds: dict[str, BuildProof]
    selftest_sha256: Sha256
    report_sha256: Sha256
    verifiability_sha256: Sha256


class ReviewDisposition(Strict):
    authority: Literal["author", "author_delegated"]
    decision: Literal["accepted"]
    scope_sha256: Sha256
    references: list[str] = Field(min_length=1)
    note: str = Field(min_length=1)


class ReviewLedger(Record):
    authorization: str = Field(min_length=1)
    dispositions: dict[str, ReviewDisposition]


def review_scope_hash(task: str) -> str:
    paths = {
        path for pattern in REVIEW_SCOPES[task] for path in ROOT.glob(pattern) if path.is_file()
    }
    if not paths:
        raise ValueError("empty review scope: " + task)
    return content_hash(
        {path.relative_to(ROOT).as_posix(): file_hash(path) for path in sorted(paths)}
    )


def scripted_expected_count(truth: GroundTruth) -> int:
    functions = truth.functions
    algorithms = sum(fn.scorable and fn.algorithm.family != "none" for fn in functions)
    none = sum(fn.scorable and fn.algorithm.family == "none" for fn in functions)
    addresses = {fn.address for fn in functions}
    edges = exclusions = 0
    for function in functions:
        calls = {
            (edge.target, edge.kind) for edge in function.callees if edge.kind in ("direct", "tail")
        }
        edges += len(calls)
        for _, kind in calls:
            if not any(
                address != function.address and (address, kind) not in calls
                for address in addresses
            ):
                exclusions += 1
    return 3 * algorithms + none + 2 * edges - exclusions


def _receipt(directory: Path, name: str, digest: str) -> Any:
    path = directory / name
    if file_hash(path) != digest:
        raise ValueError("changed evidence receipt: " + name)
    return json.loads(path.read_bytes())


def prepare(benchmark: Benchmark) -> PhaseEvidence:
    """Prepare the actual five-program experiment and retain its reviewable receipts."""
    directory = benchmark.root / "phase1a"
    directory.mkdir(parents=True, exist_ok=True)
    stage = "builds"
    try:
        builds: dict[str, BuildProof] = {}
        truths: list[GroundTruth] = []
        for program in PROGRAMS:
            print("phase1a: reproducible build and leakage " + program, file=sys.stderr, flush=True)
            source = ROOT / "corpus/tierA" / program
            variant = Variant(
                image=benchmark.config.sandbox.image_build,
                output_root=Path(benchmark.config.paths.build),
            )
            first = build_program(source, variant)
            first_hash = file_hash(first.stripped)
            second = build_program(source, variant)
            truth = GroundTruth.model_validate_json(
                (second.metadata.parent / "private/ground_truth.json").read_bytes()
            )
            hits = check_leakage(second.stripped, truth, source)
            builds[program] = BuildProof(
                first_sha256=first_hash,
                second_sha256=file_hash(second.stripped),
                metadata_sha256=file_hash(second.metadata),
                leakage_hits=[asdict(hit) for hit in hits],
            )
            truths.append(truth)
        stage = "selftest"
        print("phase1a: full production-arity selftest", file=sys.stderr, flush=True)
        write_json(directory / "selftest.json", run_selftest(benchmark.config))
        stage = "source runs"
        runs: list[str] = []
        for program in PROGRAMS:
            for source in ("scripted", "capa", "findcrypt"):
                print(f"phase1a: run {program} / {source}", file=sys.stderr, flush=True)
                runs.extend(benchmark.run(program, source))
        runs = sorted(set(runs))
        stage = "replay"
        for index, run in enumerate(runs, 1):
            print(f"phase1a: replay {index}/{len(runs)} {run}", file=sys.stderr, flush=True)
            result = replay(benchmark, run)
            if result["exit_code"] != 0:
                raise ValueError("replay failed: " + canonical_bytes(result).decode())
        stage = "report"
        print("phase1a: report and verifiability", file=sys.stderr, flush=True)
        (directory / "report.md").write_text(render(collect(benchmark, runs)))
        coverage = table(
            truths, [load_pack(path) for path in sorted(DEFAULT_PACK_DIRECTORY.glob("*.yaml"))]
        )
        write_json(directory / "verifiability.json", coverage)
        (directory / "verifiability.md").write_text(markdown(coverage))
        evidence = PhaseEvidence(
            runs=runs,
            manifests={run: file_hash(benchmark.directory(run) / "manifest.json") for run in runs},
            builds=builds,
            selftest_sha256=file_hash(directory / "selftest.json"),
            report_sha256=file_hash(directory / "report.md"),
            verifiability_sha256=file_hash(directory / "verifiability.json"),
        )
        write_json(directory / "evidence.json", evidence)
        return evidence
    except Exception as exc:
        write_json(
            directory / "preparation-error.json",
            {"stage": stage, "error": type(exc).__name__ + ": " + str(exc)[:500]},
        )
        raise


def _selftest_expected() -> dict[str, tuple[Any, str | None]]:
    expected: dict[str, tuple[Any, str | None]] = {}
    for path in sorted(DEFAULT_PACK_DIRECTORY.glob("*.yaml")):
        pack = load_pack(path)
        fixture = Fixture.model_validate_json(
            (ROOT / "tests/fixtures/near_miss" / pack.family / "cases.json").read_bytes()
        )
        for ref in fixture.references:
            expected[f"{pack.family}:reference:{ref.name}"] = ("VERIFIED", None)
        for case in fixture.near_miss:
            expected[f"{pack.family}:near:{case.name}"] = ("CONTRADICTED", None)
        for variant in sorted(pack.variants):
            if any(case.variant == variant for case in fixture.near_miss):
                continue
            other = next((ref for ref in fixture.references if ref.variant != variant), None)
            if other is not None:
                expected[f"{pack.family}:cross:{other.name}:{variant}"] = ("CONTRADICTED", None)
        for index, case in enumerate(fixture.conservative_cases):
            expected[f"{pack.family}:conservative:{index}:{case.name}"] = (
                case.expected,
                case.reason,
            )
    arities = yaml.safe_load((ROOT / "tests/golden/arity.yaml").read_text())
    for program in arities["programs"]:
        for case in program["cases"]:
            expected[f"static.arity:{program['program']}:{case['name']}"] = (
                {key: case[key] for key in ("arity", "decisive", "reason")},
                case["reason"],
            )
    for case in json.loads((ROOT / "tests/golden/static-edges.json").read_bytes())["cases"]:
        expected["static.edges:" + case["name"]] = (case["verdict"], case["reason"])
    return expected


def evaluate(benchmark: Benchmark) -> dict[str, Any]:
    directory = benchmark.root / "phase1a"
    criteria: dict[str, dict[str, Any]] = {}
    try:
        evidence = PhaseEvidence.model_validate_json((directory / "evidence.json").read_bytes())
        if evidence.runs != sorted(set(evidence.runs)) or set(evidence.manifests) != set(
            evidence.runs
        ):
            raise ValueError("run manifest set/order mismatch")
        manifests: list[RunManifest] = []
        for run in evidence.runs:
            path = benchmark.directory(run) / "manifest.json"
            if file_hash(path) != evidence.manifests[run]:
                raise ValueError("changed manifest: " + run)
            manifest = RunManifest.model_validate_json(path.read_bytes())
            differences = pin_differences(benchmark, manifest)
            if differences:
                raise ValueError("pin drift " + run + ": " + ", ".join(differences))
            manifests.append(manifest)
        populations = {
            (str(item.source_config["program"]), str(item.source_config["source"]))
            for item in manifests
        }
        if populations != {
            (program, source)
            for program in PROGRAMS
            for source in ("scripted", "capa", "findcrypt")
        }:
            raise ValueError("five-program/all-source population incomplete")
        data = collect(benchmark, evidence.runs)
        selftest = _receipt(directory, "selftest.json", evidence.selftest_sha256)
    except (OSError, ValueError, KeyError, TypeError, RuntimeError, sqlite3.Error) as exc:
        return {
            "schema_version": "1.0",
            "status": "failed",
            "criteria": {
                f"X{index}": {"passed": False, "error": str(exc)} for index in range(1, 11)
            },
        }

    def check(name: str, action: Any) -> None:
        try:
            detail = action()
            criteria[name] = {"passed": True, "detail": detail}
        except (OSError, ValueError, KeyError, TypeError, RuntimeError, sqlite3.Error) as exc:
            criteria[name] = {"passed": False, "error": type(exc).__name__ + ": " + str(exc)}

    def builds() -> Any:
        if set(evidence.builds) != set(PROGRAMS):
            raise ValueError("missing reproducible builds")
        for program, proof in sorted(evidence.builds.items()):
            binary, _, bundle = benchmark.bundle(program)
            if not (
                proof.first_sha256
                == proof.second_sha256
                == binary.binary_sha256
                == file_hash(binary.stripped)
            ):
                raise ValueError("build mismatch: " + program)
            if proof.leakage_hits or proof.metadata_sha256 != file_hash(bundle / "build.json"):
                raise ValueError("leakage or changed build metadata: " + program)
            metadata = json.loads((bundle / "build.json").read_bytes())
            if metadata["image"] != benchmark.config.sandbox.image_build:
                raise ValueError("build image drift")
            for name, digest in metadata["source_hashes"].items():
                path = ROOT / "corpus" / name
                if not path.resolve().is_relative_to(ROOT / "corpus") or file_hash(path) != digest:
                    raise ValueError("corpus source drift: " + name)
        return {name: proof.second_sha256 for name, proof in sorted(evidence.builds.items())}

    def golden() -> Any:
        _, _, bundle = benchmark.bundle("crc32tool")
        actual = GroundTruth.model_validate_json(
            (bundle / "private/ground_truth.json").read_bytes()
        )
        expected = GroundTruth.model_validate_json(
            (ROOT / "tests/golden/crc32tool/ground_truth.json").read_bytes()
        )
        if canonical_bytes(actual) != canonical_bytes(expected):
            raise ValueError("crc32tool ground truth differs from F1")
        return {"exact_match": True, "functions": len(actual.functions)}

    def calibration() -> Any:
        expected = _selftest_expected()
        cases = {row["name"]: row for row in selftest["cases"]}
        if (
            len(cases) != len(selftest["cases"])
            or set(cases) != set(expected)
            or selftest["families"] != ["adler32", "base64", "crc32", "djb2", "fnv"]
            or selftest["status"] != "ok"
            or selftest["failed"] != 0
            or selftest["static_fixtures_passed"] is not True
        ):
            raise ValueError("incomplete or failed selftest population")
        for name, (outcome, reason) in expected.items():
            row = cases[name]
            if row["passed"] is not True or (row["actual"], row["reason"]) != (outcome, reason):
                raise ValueError("selftest failure: " + name)
            if row["family"] != "static" and outcome in ("VERIFIED", "CONTRADICTED"):
                if not row["arity"]["decisive"] or (
                    outcome == "CONTRADICTED" and row["counterexample"] is None
                ):
                    raise ValueError("missing production binding/counterexample: " + name)
        return {"cases": len(cases), "production_arity": True}

    def false_alarms() -> Any:
        cohort: dict[str, int] = {}
        for program in PROGRAMS:
            _, _, bundle = benchmark.bundle(program)
            truth = GroundTruth.model_validate_json(
                (bundle / "private/ground_truth.json").read_bytes()
            )
            actual = sum(
                claim.source.origin == "scripted" and name == truth.program_id
                for claim, _, _, name in data.claims
            )
            if actual != scripted_expected_count(truth):
                raise ValueError("incomplete scripted cohort: " + program)
            cohort[program] = actual
        correct = [
            (claim, verdict, grade)
            for claim, verdict, grade, _ in data.claims
            if claim.source.origin == "scripted"
            and claim.type == "algorithm_identity"
            and claim.derived_from == "scripted_correct"
        ]
        if not correct:
            raise ValueError("missing scripted correct algorithm population")
        for claim, verdict, grade in correct:
            valid = (
                grade.correct_lenient
                if isinstance(claim.body, Algorithm) and claim.body.variant is None
                else grade.correct_strict
            )
            if not valid or verdict.intrinsic_verdict == "CONTRADICTED":
                raise ValueError("correct algorithm false alarm: " + claim.claim_id)
        return {
            "correct_algorithm_claims": len(correct),
            "contradicted": 0,
            "scripted_claims": cohort,
        }

    def designated() -> Any:
        truths: dict[str, GroundTruth] = {}
        for program in PROGRAMS:
            _, _, bundle = benchmark.bundle(program)
            truth = GroundTruth.model_validate_json(
                (bundle / "private/ground_truth.json").read_bytes()
            )
            truths[truth.binary_sha256] = truth
        names = {
            (truth.binary_sha256, fn.address): fn.name
            for truth in truths.values()
            for fn in truth.functions
        }
        found: dict[str, Any] = {}
        for claim, verdict, _, _ in data.claims:
            if (
                claim.source.origin != "scripted"
                or claim.derived_from != "scripted_correct"
                or not isinstance(claim.body, Algorithm)
                or claim.body.variant is None
            ):
                continue
            key = claim.body.family + "/" + claim.body.variant
            if names[(claim.binary_sha256, claim.subject.address)] == "crc32_update_rt":
                if (verdict.intrinsic_verdict, verdict.reason) != (
                    "INCONCLUSIVE",
                    "state_dependent",
                ):
                    raise ValueError("runtime CRC state policy mismatch")
                found["crc32_update_rt"] = verdict.reason
            if key in ("fletcher16/std", "base64/std-padded-decode"):
                if (verdict.intrinsic_verdict, verdict.reason) != ("UNVERIFIABLE", "no_pack"):
                    raise ValueError("unsupported exact variant mismatch: " + key)
                found[key] = verdict.reason
        cases = {row["name"]: row for row in selftest["cases"]}
        fixture = Fixture.model_validate_json(
            (ROOT / "tests/fixtures/near_miss/fnv/cases.json").read_bytes()
        )
        for index, case in enumerate(fixture.conservative_cases):
            key = "fnv/" + str(case.variant)
            if case.variant in ("fnv1a-64", "fnv1-64") or case.variant is None:
                row = cases[f"fnv:conservative:{index}:{case.name}"]
                expected = (
                    ("INCONCLUSIVE", "no_pack")
                    if case.variant is None
                    else ("UNVERIFIABLE", "no_pack")
                )
                if (row["actual"], row["reason"]) != expected:
                    raise ValueError("unsupported/incomplete FNV coverage mismatch")
                if case.variant is None and row["arity"]["decisive"] is not True:
                    raise ValueError("incomplete-family control must have a verified binding")
                found["incomplete_fnv_family" if case.variant is None else key] = row["reason"]
        log = cases["static.arity:cmd-dispatch:log_msg"]["actual"]
        if log["decisive"] is not False:
            raise ValueError("variadic log_msg unexpectedly decisive")
        found["log_msg"] = log
        required = {
            "crc32_update_rt",
            "fletcher16/std",
            "base64/std-padded-decode",
            "fnv/fnv1a-64",
            "fnv/fnv1-64",
            "incomplete_fnv_family",
            "log_msg",
        }
        if set(found) != required:
            raise ValueError(
                "missing designated control: " + ", ".join(sorted(required - found.keys()))
            )
        return found

    def replays() -> Any:
        runner = benchmark.runner(require_cache=True)
        for run in evidence.runs:
            path = benchmark.directory(run)
            receipt = json.loads((path / "replay.json").read_bytes())
            baseline = json.loads((path / "hashes.json").read_bytes())
            if receipt["exit_code"] != 0 or receipt["hashes"] != baseline:
                raise ValueError("replay mismatch: " + run)
            with benchmark.store() as store:
                claims = benchmark.claims(store, run)
            expected = sum(2 if claim.type == "algorithm_identity" else 1 for claim in claims)
            fresh = 0
            for record in receipt["jobs"]:
                job = Job.model_validate(record["job"])
                benchmark.artifacts.get(record["artifact"])
                if job.type in SOURCE_JOBS:
                    if record["cached"] is not True:
                        raise ValueError("source job reran during replay")
                else:
                    if record["cached"] is not False:
                        raise ValueError("verifier job reused during replay")
                    fresh += 1
            if fresh != expected:
                raise ValueError("not every method reran: " + run)
            metadata = json.loads((path / "run.json").read_bytes())
            for record in metadata["jobs"]:
                job = Job.model_validate(record["job"])
                if job.type in SOURCE_JOBS:
                    _, artifact = runner.cached_result(job)
                    if artifact != record["artifact"]:
                        raise ValueError("source cache changed: " + job.job_id)
        return {"identical_runs": len(evidence.runs), "fresh_methods": True}

    def report() -> Any:
        path = directory / "report.md"
        if file_hash(path) != evidence.report_sha256 or path.read_text() != render(data):
            raise ValueError("report changed or omits current results")
        contradicted = sum(
            verdict.intrinsic_verdict == "CONTRADICTED" for _, verdict, _, _ in data.claims
        )
        missed = sum(
            verdict.intrinsic_verdict != "CONTRADICTED"
            and not (
                grade.correct_lenient
                if isinstance(claim.body, Algorithm) and claim.body.variant is None
                else grade.correct_strict
            )
            for claim, verdict, grade, _ in data.claims
        )
        if not contradicted or not missed:
            raise ValueError("full benchmark must retain observed counterexamples and misses")
        return {"path": str(path), "contradicted": contradicted, "misses": missed}

    def accounting() -> Any:
        for run, values in data.accounting.items():
            if (
                values["measurement_errors"]
                or values["cpu_seconds"] < 0
                or values["peak_memory_bytes"] < 0
            ):
                raise ValueError("missing/invalid resource measurements: " + run)
            if values["executed_jobs"] and (
                values["cpu_seconds"] == 0 or values["peak_memory_bytes"] == 0
            ):
                raise ValueError("executed jobs lack measured resources: " + run)
        return data.accounting

    def coverage() -> Any:
        current = _receipt(directory, "verifiability.json", evidence.verifiability_sha256)
        truths = [
            GroundTruth.model_validate_json(
                (benchmark.bundle(program)[2] / "private/ground_truth.json").read_bytes()
            )
            for program in PROGRAMS
        ]
        actual = table(
            truths, [load_pack(path) for path in sorted(DEFAULT_PACK_DIRECTORY.glob("*.yaml"))]
        )
        if canonical_bytes(current) != canonical_bytes(cast(JsonValue, actual)):
            raise ValueError("verifiability table drift")
        return {
            "decidable_share": actual["decidable_share"],
            "scorable_functions": actual["scorable_functions"],
            "phase1b_threshold_applied": False,
        }

    def reviews() -> Any:
        ledger = ReviewLedger.model_validate_json((directory / "reviews.json").read_bytes())
        expected = {task: review_scope_hash(task) for task in REVIEW_SCOPES} | {
            "T25": file_hash(directory / "evidence.json")
        }
        if set(ledger.dispositions) != set(expected):
            raise ValueError("review ledger lacks required scopes")
        for task, digest in expected.items():
            if ledger.dispositions[task].scope_sha256 != digest:
                raise ValueError("review disposition stale: " + task)
        return {
            task: disposition.authority for task, disposition in sorted(ledger.dispositions.items())
        }

    for name, action in zip(
        (f"X{index}" for index in range(1, 11)),
        (
            builds,
            golden,
            calibration,
            false_alarms,
            designated,
            replays,
            report,
            accounting,
            coverage,
            reviews,
        ),
        strict=True,
    ):
        check(name, action)
    result = {
        "schema_version": "1.0",
        "status": "passed" if all(value["passed"] for value in criteria.values()) else "failed",
        "criteria": criteria,
    }
    write_json(directory / "gate.json", result)
    return result

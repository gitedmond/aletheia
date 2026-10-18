"""Assemble the Phase 1B receipt bundle that the fail-closed gate consumes."""

import json
import subprocess
from collections import Counter
from collections.abc import Mapping
from dataclasses import asdict
from pathlib import Path
from typing import Any

from aletheia.config import Config
from aletheia.corpus.build import Variant, build_program
from aletheia.corpus.ground_truth import check_leakage
from aletheia.corpus.split import history_scan
from aletheia.gate_phase1b import package_hash, validate_plan
from aletheia.grade.context import GradingContext
from aletheia.heldout.guard import PrivateAccessError, PrivateGuard
from aletheia.llm.cost import ledger
from aletheia.orchestrate import Benchmark, file_hash, write_json
from aletheia.schema.models import GroundTruth, RunManifest
from aletheia.verify.engine import DEFAULT_PACK_DIRECTORY

REPO = Path(__file__).parents[1]


def truths(build_root: Path, variant: str) -> list[GroundTruth]:
    paths = sorted(
        path
        for path in build_root.glob("*/*/private/ground_truth.json")
        if path.parents[1].name == variant
    )
    if not paths:
        raise ValueError("no built ground truth for variant " + variant)
    records = [GroundTruth.model_validate_json(path.read_bytes()) for path in paths]
    for record, path in zip(records, paths, strict=True):
        if record.program_id != "tierA/" + path.parents[2].name or record.variant_id != variant:
            raise ValueError("ground-truth program identity mismatch")
    return records


def coverage(
    records: list[GroundTruth], variant_id: str | None = None, label: str = "baseline"
) -> dict[str, Any]:
    from aletheia.corpus.verifiability import table_v2
    from aletheia.verify.probes.pack import load_pack

    if variant_id is not None and any(record.variant_id != variant_id for record in records):
        raise ValueError("coverage population mixes built variants")
    report: dict[str, Any] = dict(
        table_v2(
            records, [load_pack(path) for path in sorted(DEFAULT_PACK_DIRECTORY.glob("*.yaml"))]
        )
    )
    report["program_count"] = len(records)
    report["variant"] = label
    report["strength"] = "E2"
    return report


def plan(ledger_payload: Mapping[str, Any]) -> dict[str, Any]:
    """Fail fast on an incomplete cohort instead of sealing a broken evidence bundle."""
    rows = list(ledger_payload["slots"])
    validate_plan(rows)
    scope = ledger_payload.get("scope", {}).get("programs")
    if scope is not None and any(
        set(scope.get(split, [])) != {row["program"] for row in rows if row["split"] == split}
        for split in ("dev", "heldout")
    ):
        raise ValueError("plan differs from the frozen program cohort")
    return {"slots": rows}


def replays(plan_payload: Mapping[str, Any], records: Mapping[str, Any]) -> dict[str, Any]:
    slots = plan_payload["slots"]
    planned = {run for row in slots for run in row.get("runs", [])}
    agent_runs = {
        run for row in slots if row["source"].startswith("agent:") for run in row.get("runs", [])
    }
    rows = dict(records["runs"])
    if set(rows) != planned:
        raise ValueError("replay receipt does not cover the planned runs")
    for run, row in rows.items():
        if row["exit_code"] != 0:
            raise ValueError("replay failed: " + run)
        if run in agent_runs and not (
            row.get("agent_replay") is True
            or (
                isinstance(row.get("agent_replay"), dict)
                and row["agent_replay"].get("status") == "passed"
            )
        ):
            raise ValueError("agent replay lacks explicit success: " + run)
    return {"runs": rows}


def exposures(guard: PrivateGuard) -> dict[str, Any]:
    if guard.root is None:
        raise PrivateAccessError("exposure accounting requires private_root")
    path = guard.private_output(guard.root / "exposures.jsonl")
    counts: Counter[tuple[str, str]] = Counter()
    if path.exists():
        with ledger(path) as rows:
            for row in rows:
                counts[(str(row["binary_sha256"]), str(row["config_id"]))] += 1
    output: list[dict[str, Any]] = [
        {"binary_sha256": binary, "config_id": config, "count": count}
        for (binary, config), count in sorted(counts.items())
    ]
    if any(row["count"] >= 30 for row in output):
        raise ValueError("hosted exposure limit reached")
    return {"counts": output}


def agreement(config: Config) -> dict[str, Any]:
    if config.grading.agreement is None:
        raise ValueError("no grading agreement configured")
    path = config.guard.access(Path(config.grading.agreement))
    return GradingContext.model_validate_json(path.read_bytes()).model_dump(mode="json")


def history(guard: PrivateGuard) -> dict[str, Any]:
    if guard.root is None:
        raise PrivateAccessError("history scan requires private_root")
    record = json.loads(guard.private_output(guard.root / "split.json").read_bytes())
    heldout = {
        str(name): guard.private_output(guard.root / "corpus/tierA" / str(name))
        for name in record["heldout"]
    }
    return history_scan(REPO, heldout)


def builds(sets: Mapping[tuple[str, str], Benchmark]) -> dict[str, Any]:
    rows: list[dict[str, Any]] = []
    for (split, variant), benchmark in sorted(sets.items()):
        for program in benchmark.programs():
            if split == "dev":
                source = REPO / "corpus/tierA" / program
            else:
                guard = benchmark.config.guard
                if guard.root is None:
                    raise PrivateAccessError("held-out build requires private_root")
                source = guard.root / "corpus/tierA" / program
            build_variant = Variant(
                image=benchmark.config.sandbox.image_build,
                output_root=Path(benchmark.config.paths.build),
                hardening="hardoff" if variant == "baseline" else "hardened",
                ground_truth_version="2.0",
            )
            first = build_program(source, build_variant)
            second = build_program(source, build_variant)
            truth = GroundTruth.model_validate_json(
                (second.metadata.parent / "private/ground_truth.json").read_bytes()
            )
            hits = check_leakage(second.stripped, truth, source)
            rows.append(
                {
                    "program": program,
                    "variant": variant,
                    "first_sha256": first.binary_sha256,
                    "second_sha256": second.binary_sha256,
                    "metadata_sha256": file_hash(second.metadata),
                    "leakage_hits": [asdict(hit) for hit in hits],
                }
            )
    return {"builds": rows}


def reference_matches(pack: Any, payload: Mapping[str, Any]) -> bool:
    """Require a clean trial group containing every applicable fixed reference input."""
    from aletheia.verify.probes.inputs import generate_inputs, inputs_for_call
    from aletheia.verify.probes.oracles import byte_pair

    fixed = generate_inputs(
        pack.inputs.model_copy(
            update={"random": pack.inputs.random.model_copy(update={"count": 0})}
        )
    )
    groups: dict[tuple[str, str], list[dict[str, Any]]] = {}
    for row in payload.get("observations", []):
        key = (row.get("shape", row.get("final_shape", "")), row.get("variant", "std"))
        groups.setdefault(key, []).append(row)
    for (shape_id, variant), rows in groups.items():
        if not rows or not all(
            row["status"] == "match" and row["expected_hex"] == row["actual_hex"] for row in rows
        ):
            continue
        if "members" in payload:
            wanted = (
                {(byte_pair(value)[0].hex(), byte_pair(value)[1].hex()) for value in fixed}
                if pack.family == "rc4"
                else {(value.hex(), "") for value in fixed}
            )
        else:
            shape = next((shape for shape in pack.call_shapes if shape.id == shape_id), None)
            if shape is None or variant not in pack.variants:
                continue
            wanted = {
                (value.hex(), "") for value in inputs_for_call(fixed, pack.variants[variant], shape)
            }
        seen = {(row["input_hex"], row.get("key_hex", "")) for row in rows}
        if wanted and wanted <= seen:
            return True
    return False


def corpus_targets(
    benchmark: Benchmark, expected_abstentions: Mapping[tuple[str, str], str] | None = None
) -> dict[str, Any]:
    """T49: real hardened corpus jobs; raw identities/evidence stay in the split's store."""
    from aletheia.analysis.ghidra_session import GhidraAnalysisCache
    from aletheia.corpus.verifiability import supports_abi
    from aletheia.schema.models import Claim, ClaimSubmission, GroundFunctionV2
    from aletheia.verify.engine import Engine
    from aletheia.verify.probes.pack import load_pack
    from aletheia.verify.probes.purpose import PurposeMapping

    expected_abstentions = expected_abstentions or {}
    observed_expectations: set[tuple[str, str]] = set()
    if not benchmark.variant or not benchmark.variant.endswith("-hardened"):
        raise ValueError("T49 calibration requires an explicit hardened build variant")
    packs = {
        pack.family: pack
        for pack in (load_pack(path) for path in sorted(DEFAULT_PACK_DIRECTORY.glob("*.yaml")))
    }
    mapping = PurposeMapping.read(REPO / "mappings/purpose_packs.yaml")
    runner = benchmark.runner()
    cache = GhidraAnalysisCache(runner, benchmark.root / "analysis-cache")
    output: dict[str, Any] = {
        "package_source_hash": package_hash(),
        "split": benchmark.config.guard.split,
        "variant": benchmark.variant,
        "analysis_image": benchmark.config.sandbox.image_analysis,
        "targets": [],
        "exclusions": [],
        "builds": [],
        "status": "incomplete",
    }
    with benchmark.store() as store:
        engine = Engine(
            runner, store, benchmark.config.budgets, Path(benchmark.config.ghidra.analysis_options)
        )
        for program in benchmark.programs():
            binary, _targets, directory = benchmark.bundle(program)
            truth = GroundTruth.model_validate_json(
                (directory / "private/ground_truth.json").read_bytes()
            )
            output["builds"].append(
                {
                    "program": program,
                    "binary_sha256": binary.binary_sha256,
                    "ground_truth_sha256": file_hash(directory / "private/ground_truth.json"),
                }
            )
            functions = [
                fn for fn in truth.functions if isinstance(fn, GroundFunctionV2) and fn.scorable
            ]
            claims: list[Claim] = []
            for fn in functions:
                scope = mapping.map.get(fn.category or "")
                pack = packs.get(scope.pack) if scope else None
                reason = "no_pack"
                if scope and pack:
                    reason = "unsupported_abi"
                    if supports_abi(fn, pack, scope.variants, composite=scope.composite):
                        reason = ""
                        if scope.composite:
                            categories = Counter(
                                other.category
                                for other in functions
                                if supports_abi(other, pack, scope.variants, composite=True)
                            )
                            if any(
                                categories[category] < count
                                for category, count in Counter(scope.composite_categories).items()
                            ):
                                reason = "composite_incomplete"
                if reason:
                    output["exclusions"].append(
                        {
                            "program": program,
                            "subject": fn.address,
                            "category": fn.category,
                            "reason": reason,
                        }
                    )
                    continue
                claims.append(
                    Claim.intake(
                        ClaimSubmission.model_validate(
                            {
                                "run_id": "r_" + "4" * 16,
                                "source": {
                                    "origin": "scripted",
                                    "source_id": "scripted:t49-reference",
                                },
                                "binary_sha256": binary.binary_sha256,
                                "subject": {"address": fn.address},
                                "type": "function_purpose",
                                "body": {"category": fn.category},
                                "confidence": 1.0,
                                "confidence_source": "scripted",
                                "algorithms_version": "2.0",
                            }
                        )
                    )
                )
            if claims:
                analysis = cache.analyze(
                    binary,
                    Path(benchmark.config.ghidra.analysis_options),
                    subjects=[claim.subject.address for claim in claims],
                )
                for result in engine.verify_claims(claims, binary, analysis):
                    verdict = result.verdict
                    claim = next(claim for claim in claims if claim.claim_id == verdict.claim_id)
                    scope = mapping.map[claim.body.model_dump()["category"]]
                    artifacts = [
                        e.artifact
                        for e in verdict.evidence
                        if e.kind in {"probe_results", "composite_results"}
                    ]
                    matched = any(
                        reference_matches(
                            packs[scope.pack], json.loads(benchmark.artifacts.get(digest))
                        )
                        for digest in artifacts
                    )
                    fn = next(fn for fn in functions if fn.address == claim.subject.address)
                    expected_reason = expected_abstentions.get((program, fn.name))
                    if expected_reason:
                        observed_expectations.add((program, fn.name))
                    passed = (
                        verdict.intrinsic_verdict == "INCONCLUSIVE"
                        and verdict.reason == expected_reason
                        if expected_reason
                        else matched and verdict.intrinsic_verdict == "VERIFIED"
                    )
                    output["targets"].append(
                        {
                            "program": program,
                            "subject": claim.subject.address,
                            "category": claim.body.model_dump()["category"],
                            "verdict": verdict.intrinsic_verdict,
                            "reason": verdict.reason,
                            "reference_inputs_match": matched,
                            "expected_abstention": expected_reason,
                            "passed": passed,
                            "evidence": artifacts,
                        }
                    )
            write_json(benchmark.root / "phase1b/corpus_targets.json", output)
    output["status"] = (
        "passed"
        if output["targets"]
        and observed_expectations == set(expected_abstentions)
        and all(row["passed"] for row in output["targets"])
        else "failed"
    )
    write_json(benchmark.root / "phase1b/corpus_targets.json", output)
    return output


def junit(directory: Path, name: str, targets: list[str]) -> Path:
    path = directory / (name + ".xml")
    completed = subprocess.run(
        ["uv", "run", "pytest", "-q", "--junitxml=" + str(path), *targets],
        cwd=REPO,
        capture_output=True,
        text=True,
    )
    path.with_suffix(".log").write_text(completed.stdout + completed.stderr)
    if completed.returncode != 0:
        raise ValueError("test suite failed: " + name)
    return path


def selftest(cfg: Config) -> dict[str, Any]:
    from aletheia.selftest import run_selftest

    payload: dict[str, Any] = run_selftest(cfg)
    return payload


def scripted(benchmark: Benchmark, runs: list[str]) -> dict[str, Any]:
    from aletheia.report import collect

    data = collect(benchmark, runs)
    identity = Counter(
        verdict.intrinsic_verdict
        for claim, verdict, _grade, _program in data.claims
        if claim.type == "algorithm_identity" and claim.source.origin == "scripted"
    )
    if not identity:
        raise ValueError("no scripted held-out algorithm identity claims")
    correct = [
        verdict.intrinsic_verdict
        for claim, verdict, _grade, _program in data.claims
        if claim.type == "algorithm_identity"
        and claim.source.origin == "scripted"
        and claim.derived_from == "scripted_correct"
        and verdict.strength == "E2"
    ]
    if not correct:
        raise ValueError("no scripted correct algorithm population")
    return {
        "heldout_algorithm_identity": dict(identity),
        "correct_e2_algorithm_identity": {
            "total": len(correct),
            "contradicted": sum(verdict == "CONTRADICTED" for verdict in correct),
        },
    }


def fit(dev_benchmark: Benchmark, runs: list[str]) -> tuple[dict[str, Any], dict[str, Any]]:
    from aletheia.agent.batch import fit_dev

    receipt = fit_dev(dev_benchmark, runs)
    manifests = {
        run: RunManifest.model_validate_json(
            (dev_benchmark.directory(run) / "manifest.json").read_bytes()
        ).model_dump(mode="json")
        for run in receipt["input_run_ids"]
    }
    return receipt, manifests


def report(benchmark: Benchmark, runs: list[str], fit_root: Path) -> dict[str, Any]:
    from aletheia.report.phase1b import generate

    payload: dict[str, Any] = generate(benchmark, runs, fit_root)
    return payload


def assemble(
    benchmark: Benchmark,
    payloads: Mapping[str, Any],
    files: Mapping[str, Path] | None = None,
) -> Path:
    directory = benchmark.root / "phase1b"
    directory.mkdir(parents=True, exist_ok=True)
    receipts: dict[str, dict[str, str]] = {}
    for name, payload in payloads.items():
        path = directory / (name + ".json")
        write_json(path, payload)
        receipts[name] = {"path": path.name, "sha256": file_hash(path)}
    for name, source in (files or {}).items():
        if source.parent.resolve() != directory.resolve():
            raise ValueError("evidence file must live in the phase1b directory: " + name)
        receipts[name] = {"path": source.name, "sha256": file_hash(source)}
    evidence = directory / "evidence.json"
    write_json(
        evidence,
        {"package_source_hash": package_hash(), "receipts": receipts},
    )
    return evidence

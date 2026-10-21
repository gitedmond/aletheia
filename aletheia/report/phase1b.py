"""Held-out configuration/type/variant report, with an aggregate-only public projection."""

import json
import math
import random
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any

from aletheia.confidence import CalibrationFit, LikelihoodFit, Sample, adjust_graph, sample
from aletheia.confidence.headline import Scored, headline
from aletheia.metrics import Interval, compute_metrics, percentile
from aletheia.orchestrate import Benchmark, file_hash
from aletheia.report import ReportData, collect
from aletheia.schema.models import GroundFunctionV2, GroundTruth


def equal_mass_ece(rows: list[tuple[float, bool]], bins: int = 10) -> float | None:
    if bins < 1:
        raise ValueError("positive bin count required")
    if any(not math.isfinite(c) or not 0 <= c <= 1 for c, _ in rows):
        raise ValueError("confidence outside [0,1]")
    if not rows:
        return None
    ordered = sorted(rows)
    # Integer partition gives bin sizes differing by at most one, including N < bins.
    groups = [ordered[i * len(rows) // bins : (i + 1) * len(rows) // bins] for i in range(bins)]
    return sum(abs(sum(c - int(y) for c, y in group)) for group in groups) / len(rows)


def _metrics(rows: list[Scored], weights: Counter[str]) -> dict[str, float | None]:
    expanded = [row for row in rows for _ in range(weights[row.sample.program])]
    graded = [
        row for row in expanded if row.sample.on_target and row.sample.correct_claimed is not None
    ]
    n = len(graded)
    output: dict[str, float | None] = {
        "accuracy_claimed": sum(row.sample.correct_claimed is True for row in graded) / n
        if n
        else None,
        "decisiveness": sum(row.sample.verdict in {"VERIFIED", "CONTRADICTED"} for row in expanded)
        / len(expanded)
        if expanded
        else None,
    }
    correct = [row for row in graded if row.sample.correct_claimed is True]
    wrong = [row for row in graded if row.sample.correct_claimed is False]
    verified = [row for row in graded if row.sample.verdict == "VERIFIED"]
    for name, numerator, denominator in (
        (
            "false_alarm_rate",
            sum(r.sample.verdict == "CONTRADICTED" for r in correct),
            len(correct),
        ),
        ("catch_rate", sum(r.sample.verdict == "CONTRADICTED" for r in wrong), len(wrong)),
        (
            "verification_precision",
            sum(r.sample.correct_claimed is True for r in verified),
            len(verified),
        ),
    ):
        output[name] = numerator / denominator if denominator else None
    for arm in ("raw", "prior", "adjusted"):
        pairs = [
            (getattr(row.confidence, arm), row.sample.correct_claimed is True) for row in graded
        ]
        confident = [(c, y) for c, y in pairs if c >= 0.8]
        output.update(
            {
                arm + "_overconfidence_gap": sum(c - int(y) for c, y in pairs) / n if n else None,
                arm + "_brier": sum((c - int(y)) ** 2 for c, y in pairs) / n if n else None,
                arm + "_ece": equal_mass_ece(pairs),
                arm + "_cwr": sum(not y for _, y in confident) / len(confident)
                if confident
                else None,
            }
        )
    return output


def population(
    rows: list[Scored], programs: list[str], *, resamples: int, seed: int
) -> dict[str, Any]:
    if not programs or len(programs) != len(set(programs)) or resamples < 1:
        raise ValueError("complete program population and positive resamples required")
    if any(row.sample.program not in programs for row in rows):
        raise ValueError("row outside cluster population")
    values = _metrics(rows, Counter({p: 1 for p in programs}))
    samples: dict[str, list[float]] = {key: [] for key in values}
    rng = random.Random(seed)
    for _ in range(resamples):
        for key, value in _metrics(rows, Counter(rng.choices(programs, k=len(programs)))).items():
            if value is not None:
                samples[key].append(value)
    return {
        "metrics": values,
        "counts": {
            "claims": len(rows),
            "graded": sum(
                r.sample.on_target and r.sample.correct_claimed is not None for r in rows
            ),
        },
        "intervals": {
            k: Interval(
                low=percentile(sorted(v), 0.025) if v else None,
                high=percentile(sorted(v), 0.975) if v else None,
                defined_resamples=len(v),
            ).model_dump(mode="json")
            for k, v in samples.items()
        },
    }


def _coverage(
    benchmark: Benchmark, data: ReportData, runs: list[str]
) -> dict[tuple[str, str, str], dict[str, float | int | None]]:
    eligible: dict[tuple[str, str, str], set[tuple[str, str]]] = defaultdict(set)
    covered: dict[tuple[str, str, str], set[tuple[str, str]]] = defaultdict(set)
    variant_by_run: dict[str, str] = {}
    for run in runs:
        metadata = json.loads((benchmark.directory(run) / "run.json").read_bytes())
        variant = metadata["variant_id"]
        variant_by_run[run] = variant
        _, _, bundle = benchmark.bundle(metadata["program"], variant)
        gt = GroundTruth.model_validate_json((bundle / "private/ground_truth.json").read_bytes())
        for fn in gt.functions:
            if isinstance(fn, GroundFunctionV2) and fn.scorable:
                identity = (gt.binary_sha256, fn.address)
                eligible[(metadata["source_id"], variant, "function_purpose")].add(identity)
                if fn.abi_signature and not fn.abi_signature.abi_complex:
                    eligible[(metadata["source_id"], variant, "function_signature")].add(identity)
    for claim, _, grade, _ in data.claims:
        key = (claim.source.source_id, variant_by_run[claim.run_id], claim.type)
        identity = (claim.binary_sha256, claim.subject.address)
        if (
            grade.on_target
            and grade.correct_strict is True
            and identity in eligible.get(key, set())
        ):
            covered[key].add(identity)
    return {
        key: {
            "eligible_functions": len(functions),
            "correct_functions": len(covered[key]),
            "coverage": len(covered[key]) / len(functions)
            if functions
            and (
                key[2] != "function_purpose"
                or (
                    benchmark.grading_context is not None
                    and benchmark.grading_context.human_validated is True
                )
            )
            else None,
        }
        for key, functions in eligible.items()
    }


def generate(benchmark: Benchmark, runs: list[str], fit_root: Path) -> dict[str, Any]:
    if benchmark.config.guard.split != "heldout":
        raise ValueError("Phase 1B headline/reliability requires held-out runs")
    benchmark.config.guard.access(fit_root)
    maps = CalibrationFit.model_validate_json((fit_root / "calibration.json").read_bytes())
    likelihoods = LikelihoodFit.model_validate_json((fit_root / "likelihoods.json").read_bytes())
    receipt = json.loads((fit_root / "fit.json").read_bytes())
    if receipt["calibration_hash"] != file_hash(fit_root / "calibration.json") or receipt[
        "likelihoods_hash"
    ] != file_hash(fit_root / "likelihoods.json"):
        raise ValueError("changed dev fit artifact")
    if set(maps.run_ids) - set(receipt["input_run_ids"]) or set(likelihoods.run_ids) - set(
        receipt["input_run_ids"]
    ):
        raise ValueError("fit run provenance mismatch")
    if set(runs) & set(receipt["input_run_ids"]):
        raise ValueError("held-out headline overlaps dev fit")
    data = collect(benchmark, runs)
    variants: dict[str, str] = {}
    programs: set[str] = set()
    clusters: dict[tuple[str, str], set[str]] = defaultdict(set)
    run_info: dict[str, dict[str, Any]] = {}
    for manifest in data.manifests:
        if manifest.source_config.get("split") != "heldout":
            raise ValueError("mixed dev/held-out report population")
        info = json.loads((benchmark.directory(manifest.run_id) / "run.json").read_bytes())
        run_info[manifest.run_id] = info
        variants[manifest.run_id] = info["variant_id"]
        program = (
            info["program"] if info["program"].startswith("tierA/") else "tierA/" + info["program"]
        )
        programs.add(program)
        clusters[(info["source_id"], info["variant_id"])].add(program)
    rows: list[Sample] = [sample(c, g, v, program=p, split="heldout") for c, v, g, p in data.claims]
    adjusted = adjust_graph(rows, maps, likelihoods)
    groups: dict[tuple[str, str, str], list[Scored]] = defaultdict(list)
    for row in rows:
        groups[(row.source.source_id, variants[row.run_id], row.claim_type)].append(
            Scored(sample=row, confidence=adjusted[row.claim_id])
        )
    coverage = _coverage(benchmark, data, runs)
    truths: dict[tuple[str, str], dict[str, GroundTruth]] = defaultdict(dict)
    for info in run_info.values():
        variant = info["variant_id"]
        _, _, bundle = benchmark.bundle(info["program"], variant)
        gt = GroundTruth.model_validate_json((bundle / "private/ground_truth.json").read_bytes())
        truths[(info["source_id"], variant)][gt.binary_sha256] = gt
    settings = benchmark.config.metrics
    populations: list[dict[str, Any]] = []
    for (source, variant, kind), selected in sorted(groups.items()):
        result = population(
            selected,
            sorted(clusters[(source, variant)]),
            resamples=settings.bootstrap_resamples,
            seed=settings.bootstrap_seed,
        )
        head = headline(
            selected,
            sorted(clusters[(source, variant)]),
            bootstrap_resamples=settings.bootstrap_resamples,
            bootstrap_seed=settings.bootstrap_seed,
        )
        ids = {row.sample.claim_id for row in selected}
        group = [(c, v, g) for c, v, g, _ in data.claims if c.claim_id in ids]
        legacy = compute_metrics(
            [g for _, _, g in group],
            [c for c, _, _ in group],
            [v for _, v, _ in group],
            settings,
            ground_truths=list(truths[(source, variant)].values()),
            method_results=benchmark.observations([v for _, v, _ in group]),
        )
        # Whitelist aggregates: Headline also contains private program cluster identities.
        item: dict[str, Any] = {
            "source_id": source,
            "variant": variant,
            "claim_type": kind,
            **result,
            "benchmark_metrics": legacy.sources[0].aggregate.model_dump(mode="json"),
            "headline": {
                "metrics": head.metrics,
                "counts": head.counts,
                "intervals": {k: v.model_dump(mode="json") for k, v in head.intervals.items()},
            },
            "coverage": coverage.get((source, variant, kind)),
            "arity_capped_misses": sum(
                c.source.source_id == source
                and c.type == kind
                and variants[c.run_id] == variant
                and g.correct_claimed is False
                and v.intrinsic_verdict == "INCONCLUSIVE"
                and v.reason == "no_matching_call_shape"
                for c, v, g, _ in data.claims
            ),
        }
        populations.append(item)
    reliability: dict[str, dict[str, int]] = {}
    aspect_groups: dict[str, list[Scored]] = defaultdict(list)
    aspect_programs: dict[str, set[str]] = {}
    scored_by_id = {row.claim_id: row for row in rows}
    for claim, verdict, grade, _ in data.claims:
        for name, aspect in verdict.aspects.items():
            correct = grade.aspect_correct.get(name)
            if claim.type == "function_purpose" and grade.correct_strict is None:
                correct = None
            key = "/".join(
                (
                    claim.source.source_id,
                    variants[claim.run_id],
                    claim.type,
                    name,
                    aspect.method,
                    aspect.strength or "none",
                )
            )
            aspect_programs[key] = clusters[(claim.source.source_id, variants[claim.run_id])]
            counts = reliability.setdefault(
                key,
                {
                    "claims": 0,
                    "ungraded": 0,
                    "correct": 0,
                    "wrong": 0,
                    "false_alarms": 0,
                    "caught": 0,
                },
            )
            aspect_sample = scored_by_id[claim.claim_id].model_copy(
                update={
                    "correct_claimed": correct,
                    "verdict": aspect.verdict,
                    "strength": aspect.strength,
                    "method": aspect.method,
                }
            )
            aspect_groups[key].append(
                Scored(sample=aspect_sample, confidence=adjusted[claim.claim_id])
            )
            counts["claims"] += 1
            counts["ungraded"] += correct is None
            counts["correct"] += correct is True
            counts["wrong"] += correct is False
            counts["false_alarms"] += correct is True and aspect.verdict == "CONTRADICTED"
            counts["caught"] += correct is False and aspect.verdict == "CONTRADICTED"
    failures: dict[str, Counter[str]] = defaultdict(Counter)
    for info in run_info.values():
        if "agent_result" in info:
            failures[info["source_id"]][info["agent_result"]["status"]] += 1
    return {
        "schema_version": "1.0",
        "phase": "1b",
        "split": "heldout",
        "cluster_count": len(programs),
        "bootstrap_seed": settings.bootstrap_seed,
        "bootstrap_resamples": settings.bootstrap_resamples,
        "manifest_digests": sorted(
            file_hash(benchmark.directory(run) / "manifest.json") for run in runs
        ),
        "calibration_sha256": receipt["calibration_hash"],
        "likelihoods_sha256": receipt["likelihoods_hash"],
        "populations": populations,
        "reliability": {
            key: {
                **counts,
                **population(
                    aspect_groups[key],
                    sorted(aspect_programs[key]),
                    resamples=settings.bootstrap_resamples,
                    seed=settings.bootstrap_seed,
                ),
            }
            for key, counts in reliability.items()
        },
        "failures": dict(failures),
        "sections": {
            "RQ1": "Overconfidence gaps, ECE and three-arm CWR with program-cluster CIs.",
            "RQ5": "Baseline/hardened populations, retaining zero-claim program clusters.",
            "RQ9": "Purpose/signature coverage and aspect/method/strength reliability.",
        },
        "notes": [
            (
                "Preliminary held-out results; small program population can "
                "produce wide or undefined intervals."
            ),
            "Name quality is secondary and is excluded from calibration and these primary results.",
        ],
    }

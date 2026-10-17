"""Deterministic Markdown reports with explicit reliability populations and honest misses."""

import html
import json
from collections import Counter
from dataclasses import dataclass
from typing import Any, cast

from pydantic import JsonValue

from aletheia import __version__
from aletheia.grade import claimed_correctness
from aletheia.metrics import MetricsReport, Population, compute_metrics
from aletheia.orchestrate import Benchmark, file_hash
from aletheia.schema.canonical import canonical_bytes, content_hash
from aletheia.schema.models import (
    Claim,
    ExcludedFunction,
    Grade,
    GroundTruth,
    RunManifest,
    Verdict,
)


@dataclass(frozen=True)
class ReportData:
    manifests: list[RunManifest]
    metrics: MetricsReport
    claims: list[tuple[Claim, Verdict, Grade, str]]
    unmapped: dict[str, dict[str, int]]
    excluded: dict[str, list[ExcludedFunction]]
    accounting: dict[str, dict[str, Any]]


def collect(benchmark: Benchmark, runs: list[str]) -> ReportData:
    manifests: list[RunManifest] = []
    rows: list[tuple[Claim, Verdict, Grade, str]] = []
    truths: dict[str, GroundTruth] = {}
    unmapped: dict[str, dict[str, int]] = {}
    exclusions_seen: set[str] = set()
    for run in sorted(set(runs)):
        directory = benchmark.directory(run)
        manifest = RunManifest.model_validate_json((directory / "manifest.json").read_bytes())
        metadata = json.loads((directory / "run.json").read_bytes())
        if metadata["source_id"] != manifest.source_config.get("source_id"):
            raise ValueError("report source metadata drift: " + run)
        _, targets, bundle = benchmark.bundle(
            str(manifest.source_config["program"]), metadata.get("variant_id")
        )
        if file_hash(bundle / "private/ground_truth.json") != manifest.source_config.get(
            "ground_truth_hash"
        ) or content_hash(targets) != manifest.source_config.get("targets_hash"):
            raise ValueError("report ground truth/targets drift: " + run)
        run_config = manifest.source_config.get("run_config")
        if not isinstance(run_config, dict) or canonical_bytes(
            run_config.get("metrics")
        ) != canonical_bytes(benchmark.config.metrics):
            raise ValueError("report metric configuration drift: " + run)
        truth = GroundTruth.model_validate_json((bundle / "private/ground_truth.json").read_bytes())
        truths[truth.binary_sha256] = truth
        manifests.append(manifest)
        with benchmark.store() as store:
            state = store.connection.execute(
                "SELECT state FROM runs WHERE run_id=?", (run,)
            ).fetchone()
            if state is None or state[0] != "completed":
                raise ValueError("report requires completed run: " + run)
            claims = benchmark.claims(store, run)
            verdicts = [store.get_verdict(claim.claim_id) for claim in claims]
            grades = [store.get_grade(claim.claim_id) for claim in claims]
        baseline = json.loads((directory / "hashes.json").read_bytes())
        actual = {
            "verdicts": content_hash([v.model_dump(mode="json") for v in verdicts]),
            "grades": content_hash([g.model_dump(mode="json") for g in grades]),
            "metrics": content_hash(
                MetricsReport.model_validate_json((directory / "metrics.json").read_bytes())
            ),
        }
        if baseline != actual:
            raise ValueError("persisted report inputs differ from baseline: " + run)
        rows.extend(
            (claim, verdict, item, truth.program_id)
            for claim, verdict, item in zip(claims, verdicts, grades, strict=True)
        )
        counts = unmapped.setdefault(metadata["source_id"], {})
        for key, value in metadata["unmapped_counts"].items():
            counts[key] = counts.get(key, 0) + value
        identity = content_hash(
            {
                "program": truth.program_id,
                "source": metadata["source_id"],
                "seed": manifest.source_config.get("seed"),
                "exclusions": metadata["exclusions"],
            }
        )
        if identity not in exclusions_seen:
            for key, value in metadata["exclusions"].items():
                name = "generated_exclusion:" + key
                counts[name] = counts.get(name, 0) + value
            exclusions_seen.add(identity)
    if not manifests:
        raise ValueError("report requires at least one run")
    claims = [row[0] for row in rows]
    verdicts = [row[1] for row in rows]
    present = {claim.source.source_id for claim in claims}
    metrics = compute_metrics(
        [row[2] for row in rows],
        claims,
        verdicts,
        benchmark.config.metrics,
        ground_truths=list(truths.values()),
        method_results=benchmark.observations(verdicts),
        unmapped_counts={
            source: counts for source, counts in unmapped.items() if source in present
        },
    )
    return ReportData(
        manifests,
        metrics,
        rows,
        unmapped,
        {truth.program_id: truth.excluded_functions for truth in truths.values()},
        {run: benchmark.accounting([run]) for run in sorted(set(runs))},
    )


def cell(value: object) -> str:
    return html.escape(str(value), quote=False).replace("|", "\\|").replace("\n", " ")


def number(value: float | None) -> str:
    return "undefined" if value is None else f"{value:.6g}"


def render(data: ReportData) -> str:
    lines = [
        "# Aletheia Phase 1A report",
        "",
        f"Benchmark {__version__}; schema 1.0; split dev.",
        "",
        "## Runs",
        "",
        "| Run | Program | Source | Scenario |",
        "| --- | --- | --- | --- |",
    ]
    sources: dict[str, str] = {}
    for manifest in sorted(data.manifests, key=lambda item: item.run_id):
        config = manifest.source_config
        source = str(config["source_id"])
        label = source + (" (shared backend)" if config.get("source") == "findcrypt" else "")
        sources[source] = label
        lines.append(
            "| "
            + " | ".join(
                cell(value)
                for value in (
                    manifest.run_id,
                    config.get("program"),
                    label,
                    config.get("scenario", "tool"),
                )
            )
            + " |"
        )
    lines.extend(["", "## Versions and pins", ""])
    pins: dict[str, dict[str, Any]] = {}
    for manifest in data.manifests:
        value = manifest.model_dump(
            mode="json", exclude={"source_config", "run_id", "created_at", "binaries"}
        )
        pins[content_hash(value)] = value
    for digest, value in sorted(pins.items()):
        lines.extend(
            [
                f"Pin set `{digest}`:",
                "",
                "```json",
                json.dumps(value, indent=2, sort_keys=True),
                "```",
                "",
            ]
        )
    lines.extend(
        [
            "## Per-source metrics",
            "",
            "Intervals use a seeded program-cluster bootstrap. With only five Phase "
            "1A programs, intervals are wide; a mini run has fewer clusters.",
            "Undefined means the denominator is zero. ERROR is excluded from "
            "reliability metrics and retained in source accuracy and defect counts.",
            "",
        ]
    )

    def population(title: str, value: Population) -> None:
        lines.extend(
            [
                "### " + cell(title),
                "",
                "| Metric | Estimate | 95% CI | Defined resamples |",
                "| --- | ---: | --- | ---: |",
            ]
        )
        for metric, estimate in sorted(value.summary.metrics.items()):
            interval = value.intervals[metric]
            lines.append(
                f"| {cell(metric)} | {number(estimate)} | "
                f"[{number(interval.low)}, {number(interval.high)}] | "
                f"{interval.defined_resamples} |"
            )
        lines.extend(
            [
                "",
                "Counts: `"
                + canonical_bytes(cast(JsonValue, value.summary.counts)).decode()
                + "`.",
                "",
                "| Verdict | Correct at claimed granularity | Wrong |",
                "| --- | ---: | ---: |",
            ]
        )
        for verdict, counts in sorted(value.summary.confusion.items()):
            lines.append(f"| {verdict} | {counts['correct']} | {counts['wrong']} |")
        lines.append("")

    reported: set[str] = set()
    for source in sorted(data.metrics.sources, key=lambda item: item.source.source_id):
        name = source.source.source_id
        reported.add(name)
        population(sources.get(name, source.label), source.aggregate)
        for program, value in sorted(source.programs.items()):
            population(sources.get(name, source.label) + " / " + program, value)
        for method, value in sorted(source.methods.items()):
            population(sources.get(name, source.label) + " / " + method, value)
    for name in sorted(sources.keys() - reported):
        lines.extend(
            [
                "### " + cell(sources[name]),
                "",
                "0 claims; metrics undefined. Adapter counts are retained below.",
                "",
            ]
        )
    lines.extend(
        [
            "## Independent scripted verifier reliability",
            "",
            "Included: scripted claims with shares_backend=false. Excluded: capa, "
            "FindCrypt, human and agent claims, and every shared-backend source.",
            "Family-only algorithm claims use lenient correctness; exact variants "
            "and call relations use strict correctness. Tool-conditioned results "
            "remain separate above.",
            "Static constants are supporting evidence; their method rows are "
            "non-decision observations, never claim verdicts.",
            "",
        ]
    )
    population("Independent aggregate", data.metrics.independent)
    for label, values in (
        ("Scenario", data.metrics.independent_by_scenario),
        ("Claim type", data.metrics.independent_by_type),
        ("Method", data.metrics.independent_methods),
    ):
        for name, value in sorted(values.items()):
            population(label + ": " + name, value)
    lines.extend(["## Contradicted claims", ""])
    ordered = sorted(
        data.claims,
        key=lambda row: (
            row[0].source.source_id,
            row[3],
            int(row[0].subject.address, 16),
            row[0].type,
            row[0].claim_id,
        ),
    )

    def correct(claim: Claim, item: Grade) -> bool | None:
        return claimed_correctness(claim, item)

    def describe(row: tuple[Claim, Verdict, Grade, str]) -> None:
        claim, verdict, item, program = row
        lines.extend(
            [
                f"- `{claim.claim_id}`: "
                f"{cell(sources.get(claim.source.source_id, claim.source.source_id))}; "
                f"{cell(program)}; subject `{claim.subject.address}`; "
                f"tool label {cell(claim.tool_label or 'none')}.",
                "  Claim: `"
                + canonical_bytes(claim.body).decode()
                + "`; "
                + (
                    "not applicable"
                    if correct(claim, item) is None
                    else "correct"
                    if correct(claim, item)
                    else "wrong"
                )
                + " at claimed granularity; "
                + f"on_target={str(item.on_target).lower()}, phantom={str(item.phantom).lower()}.",
                f"  Verdict: {verdict.intrinsic_verdict}; reason {cell(verdict.reason or 'none')}.",
            ]
        )

    contradicted = [row for row in ordered if row[1].intrinsic_verdict == "CONTRADICTED"]
    for row in contradicted:
        describe(row)
        verdict = row[1]
        lines.append("  Harness: " + cell(verdict.harness))
        if verdict.counterexample is not None:
            lines.append(
                "  Counterexample: `" + canonical_bytes(verdict.counterexample).decode() + "`."
            )
        else:
            lines.append("  Counterexample: not applicable (static proof).")
        lines.append("")
    if not contradicted:
        lines.extend(["None.", ""])
    lines.extend(["## Wrong claims the verifier did not catch", ""])
    missed = [
        row
        for row in ordered
        if correct(row[0], row[2]) is False and row[1].intrinsic_verdict != "CONTRADICTED"
    ]
    for row in missed:
        describe(row)
        lines.append("")
    if not missed:
        lines.extend(["None.", ""])
    lines.extend(["## Off-target and phantom claims", ""])
    off_target = [row for row in ordered if not row[2].on_target or row[2].phantom]
    for row in off_target:
        describe(row)
        lines.append("")
    if not off_target:
        lines.extend(["None.", ""])
    lines.extend(
        [
            "## Adapter counts and generator exclusions",
            "",
            "| Source | Counted label or scope | Count |",
            "| --- | --- | ---: |",
        ]
    )
    for source, counts in sorted(data.unmapped.items()):
        for label, count in sorted(counts.items()):
            lines.append(f"| {cell(sources.get(source, source))} | {cell(label)} | {count} |")
    lines.extend(
        ["", "## Excluded functions", "", "| Program | Function | Reason |", "| --- | --- | --- |"]
    )
    for program, functions in sorted(data.excluded.items()):
        for function in sorted(functions, key=lambda item: (item.name, item.reason)):
            lines.append(f"| {cell(program)} | {cell(function.name)} | {function.reason} |")
    lines.extend(
        [
            "",
            "## Compute and memory",
            "",
            "CPU is measured container CPU time. Peak memory is the maximum "
            "per-container cgroup memory.peak for that run, not concurrent aggregate "
            "memory. Cache hits do not claim new execution cost.",
            "",
            "| Run | Executed jobs | CPU seconds | Peak job memory bytes | Measurement errors |",
            "| --- | ---: | ---: | ---: | --- |",
        ]
    )
    for run, values in sorted(data.accounting.items()):
        lines.append(
            f"| {run} | {values['executed_jobs']} | {number(values['cpu_seconds'])} | "
            f"{values['peak_memory_bytes']} | {cell(values['measurement_errors'])} |"
        )
    defects = Counter(
        row[1].reason or "unknown" for row in ordered if row[1].intrinsic_verdict == "ERROR"
    )
    lines.extend(
        [
            "",
            "Defects (ERROR outcomes): `"
            + canonical_bytes(dict(sorted(defects.items()))).decode()
            + "`.",
            "",
        ]
    )
    lines.extend(cell(note) + "\n" for note in sorted(data.metrics.notes))
    return "\n".join(lines).rstrip() + "\n"

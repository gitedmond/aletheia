"""Strict Phase 1A replay: source-job cache required, verdict cache forbidden."""

import sqlite3
import tempfile
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Any

from pydantic import TypeAdapter

from aletheia.analysis.ghidra_session import GhidraAnalysisCache
from aletheia.grade import grade
from aletheia.metrics import MetricsReport, compute_metrics
from aletheia.orchestrate import Benchmark, write_json
from aletheia.sandbox.cached import SOURCE_JOBS, SourceCacheMiss
from aletheia.schema.canonical import canonical_bytes, content_hash
from aletheia.schema.models import Claim, GroundTruth, Job, RunManifest
from aletheia.store.database import Store
from aletheia.verify.engine import Engine, EngineResult


def pin_differences(benchmark: Benchmark, manifest: RunManifest) -> list[str]:
    program, source = manifest.source_config.get("program"), manifest.source_config.get("source")
    if not isinstance(program, str) or not isinstance(source, str):
        raise ValueError("manifest lacks program/source")
    current = benchmark.manifest_input(program, source)
    expected = manifest.model_dump(mode="json", exclude={"run_id", "created_at"})
    actual = current.model_dump(mode="json")
    differences = [
        name
        for name in sorted(actual)
        if name != "source_config"
        and canonical_bytes(expected[name]) != canonical_bytes(actual[name])
    ]
    differences.extend(
        "source_config." + name
        for name, value in sorted(current.source_config.items())
        if canonical_bytes(manifest.source_config.get(name)) != canonical_bytes(value)
    )
    return sorted(differences)


def replay(benchmark: Benchmark, run: str) -> dict[str, Any]:
    directory = benchmark.directory(run)
    receipt: dict[str, Any] = {"run_id": run}
    try:
        manifest = RunManifest.model_validate_json((directory / "manifest.json").read_bytes())
        differences = pin_differences(benchmark, manifest)
    except (OSError, ValueError, KeyError) as exc:
        return receipt | {"exit_code": 4, "differences": ["manifest/pins: " + str(exc)]}
    if differences:
        return receipt | {"exit_code": 4, "differences": differences}
    try:
        metadata = TypeAdapter(dict[str, Any]).validate_json((directory / "run.json").read_bytes())
        if not isinstance(metadata.get("jobs"), list):
            raise ValueError("invalid job records in run metadata")
        binary, targets, bundle = benchmark.bundle(str(manifest.source_config["program"]))
    except (OSError, ValueError, KeyError, TypeError) as exc:
        return receipt | {"exit_code": 5, "differences": ["run metadata: " + str(exc)[:300]]}
    runner = benchmark.runner(require_cache=True)
    try:
        seen: set[str] = set()
        for record in metadata["jobs"]:
            job = Job.model_validate(record["job"])
            if job.type in SOURCE_JOBS and job.job_id not in seen:
                _, artifact = runner.cached_result(job)
                if artifact != record["artifact"]:
                    raise SourceCacheMiss(job.job_id + ": source artifact changed")
                seen.add(job.job_id)
    except SourceCacheMiss as exc:
        return receipt | {"exit_code": 6, "cache_misses": [str(exc)]}
    except (OSError, ValueError, KeyError, TypeError) as exc:
        return receipt | {"exit_code": 5, "differences": ["run metadata: " + str(exc)[:300]]}
    try:
        with benchmark.store() as store:
            claims = benchmark.claims(store, run)
            original_verdicts = [store.get_verdict(claim.claim_id) for claim in claims]
            original_grades = [store.get_grade(claim.claim_id) for claim in claims]
        try:
            expected = TypeAdapter(dict[str, str]).validate_json(
                (directory / "hashes.json").read_bytes()
            )
        except ValueError as exc:
            raise ValueError("invalid baseline hash schema: " + str(exc)) from exc
        if set(expected) != {"verdicts", "grades", "metrics"}:
            raise ValueError("invalid baseline hash schema")
        originals = {
            "verdicts": content_hash([item.model_dump(mode="json") for item in original_verdicts]),
            "grades": content_hash([item.model_dump(mode="json") for item in original_grades]),
            "metrics": content_hash(
                MetricsReport.model_validate_json((directory / "metrics.json").read_bytes())
            ),
        }
    except (OSError, ValueError, KeyError, TypeError, sqlite3.Error) as exc:
        return receipt | {"exit_code": 5, "differences": ["persisted originals: " + str(exc)[:300]]}
    if originals != expected:
        return receipt | {
            "exit_code": 5,
            "differences": [
                "persisted original " + key
                for key in sorted(expected)
                if originals.get(key) != expected[key]
            ],
        }
    try:
        if claims:
            analysis = GhidraAnalysisCache(runner, benchmark.root / "analysis-cache").analyze(
                binary,
                Path(benchmark.config.ghidra.analysis_options),
                no_cache=True,
                subjects=sorted(
                    set(targets.targets) | {claim.subject.address for claim in claims},
                    key=lambda address: int(address, 16),
                ),
            )
            # A separate empty store prevents replay from reading or replacing baseline verdicts.
            with tempfile.TemporaryDirectory(prefix="replay-", dir=benchmark.root) as temporary:
                database = Path(temporary) / "metadata.sqlite"
                with Store(database):
                    pass

                def verify(claim: Claim) -> EngineResult:
                    with Store(database) as store:
                        engine = Engine(
                            runner,
                            store,
                            benchmark.config.budgets,
                            Path(benchmark.config.ghidra.analysis_options),
                        )
                        return engine.verify(claim, binary, analysis, no_cache=True)

                if any(
                    claim.type in {"function_signature", "function_purpose"} for claim in claims
                ):
                    with Store(database) as store:
                        results = Engine(
                            runner,
                            store,
                            benchmark.config.budgets,
                            Path(benchmark.config.ghidra.analysis_options),
                        ).verify_claims(claims, binary, analysis, no_cache=True)
                else:
                    with ThreadPoolExecutor(
                        max_workers=benchmark.config.sandbox.concurrency
                    ) as pool:
                        results = list(pool.map(verify, claims))
            verdicts = sorted(
                (result.verdict for result in results), key=lambda verdict: verdict.claim_id
            )
        else:
            verdicts = []
        truth = GroundTruth.model_validate_json((bundle / "private/ground_truth.json").read_bytes())
        grades = grade(
            claims,
            verdicts,
            truth,
            targets,
            taxonomy_kappa=benchmark.grading_context.taxonomy_kappa
            if benchmark.grading_context
            else None,
        )
        metrics = compute_metrics(
            grades,
            claims,
            verdicts,
            benchmark.config.metrics,
            ground_truths=[truth],
            method_results=benchmark.observations(verdicts),
            unmapped_counts={metadata["source_id"]: metadata["unmapped_counts"]} if claims else {},
        )
        hashes = {
            "verdicts": content_hash([v.model_dump(mode="json") for v in verdicts]),
            "grades": content_hash([g.model_dump(mode="json") for g in grades]),
            "metrics": content_hash(metrics),
        }
        receipt.update(
            exit_code=0 if hashes == expected else 5,
            hashes=hashes,
            differences=[key for key in sorted(expected) if hashes.get(key) != expected[key]],
        )
    except SourceCacheMiss as exc:
        receipt.update(exit_code=6, cache_misses=[str(exc)])
    except (OSError, ValueError, RuntimeError, KeyError) as exc:
        receipt.update(exit_code=5, differences=[type(exc).__name__ + ": " + str(exc)[:300]])
    receipt["jobs"] = runner.records
    write_json(directory / "replay.json", receipt)
    return receipt

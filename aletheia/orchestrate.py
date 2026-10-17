"""Phase 1A run lifecycle. Private grading stays outside the public verifier boundary."""

import hashlib
import json
import os
import re
import tempfile
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Any, Literal, cast

from pydantic import JsonValue, TypeAdapter

from aletheia import __version__
from aletheia.analysis.ghidra_session import (
    GhidraAnalysisCache,
    publish_immutable,
    read_public_binary,
)
from aletheia.config import Config
from aletheia.doctor import read_lock
from aletheia.grade import grade
from aletheia.grade.context import GradingContext
from aletheia.metrics import MetricsReport, compute_metrics
from aletheia.sandbox.cached import SOURCE_JOBS, CachedJobRunner
from aletheia.schema.canonical import canonical_bytes, content_hash
from aletheia.schema.models import (
    Aspect,
    Call,
    Claim,
    ClaimSubmission,
    Grade,
    GroundTruth,
    Job,
    ManifestInput,
    RunManifest,
    Targets,
    Verdict,
)
from aletheia.sources.base import BinaryRef
from aletheia.sources.capa import CapaMapping, CapaResult, CapaSource
from aletheia.sources.findcrypt import FindcryptMapping, FindcryptSource
from aletheia.sources.scripted import generate
from aletheia.store.artifacts import ArtifactStore
from aletheia.store.database import Store
from aletheia.verify.engine import Engine, EngineResult


def write_json(path: Path, value: Any) -> None:
    """Atomically replace mutable run metadata; identity-bearing manifests are immutable."""
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, name = tempfile.mkstemp(dir=path.parent)
    try:
        with os.fdopen(fd, "wb") as stream:
            stream.write(canonical_bytes(value) + b"\n")
        os.replace(name, path)
    finally:
        Path(name).unlink(missing_ok=True)


def file_hash(path: Path) -> str:
    if any(part.is_symlink() for part in (path, *path.parents)):
        raise ValueError("pinned file cannot be a symlink")
    return hashlib.sha256(path.read_bytes()).hexdigest()


class Benchmark:
    def __init__(
        self,
        config: Config,
        *,
        variant: str | None = None,
        algorithms_version: Literal["1.0", "2.0"] = "1.0",
    ):
        self.variant = variant
        self.algorithms_version: Literal["1.0", "2.0"] = algorithms_version
        for path in (config.paths.build, config.paths.runs, config.paths.artifacts):
            if config.guard.split == "heldout":
                config.guard.private_output(Path(path))
            else:
                config.guard.public_path(Path(path))
        self.config = config.model_copy(deep=True)
        self.grading_context, self.grading_context_hash = (
            GradingContext.snapshot(config.guard.access(Path(config.grading.agreement)))
            if config.grading.agreement is not None
            else (None, None)
        )
        self.root = Path(config.paths.runs)
        self.root.mkdir(parents=True, exist_ok=True)
        self.artifacts = ArtifactStore(Path(config.paths.artifacts))
        self.cache_root = self.root / "source-cache"

    def store(self) -> Store:
        return Store(self.root / "metadata.sqlite")

    def directory(self, run: str) -> Path:
        if re.fullmatch(r"r_[0-9a-f]{16}", run) is None:
            raise ValueError("invalid run ID")
        return self.root / run

    def runner(self, *, no_cache: bool = False, require_cache: bool = False) -> CachedJobRunner:
        return CachedJobRunner(
            self.config.sandbox,
            self.root / "public",
            self.root / "jobs",
            self.artifacts,
            cache_root=self.cache_root,
            no_cache=no_cache,
            require_cache=require_cache,
        )

    def programs(self) -> list[str]:
        return sorted(
            path.name
            for path in Path(self.config.paths.build).iterdir()
            if path.is_dir() and list(path.glob("*/targets.json"))
        )

    def bundle(self, program: str, variant: str | None = None) -> tuple[BinaryRef, Targets, Path]:
        if re.fullmatch(r"[a-z][a-z0-9-]*", program) is None:
            raise ValueError("invalid program name")
        paths = sorted((Path(self.config.paths.build) / program).glob("*/targets.json"))
        selected = variant or self.variant
        if selected is not None:
            paths = [path for path in paths if path.parent.name == selected]
        if len(paths) != 1:
            raise ValueError("program requires exactly one built variant")
        targets = Targets.model_validate_json(paths[0].read_bytes())
        binary = BinaryRef(
            targets.binary_sha256,
            paths[0].parent / "stripped" / (targets.binary_sha256 + ".bin"),
            targets.variant_id,
        )
        read_public_binary(binary)
        return binary, targets, paths[0].parent

    @staticmethod
    def claims(store: Store, run: str) -> list[Claim]:
        return [
            Claim.model_validate_json(row[0])
            for row in store.connection.execute(
                "SELECT canonical_json FROM claims WHERE run_id=? AND is_active=1 "
                "ORDER BY claim_id",
                (run,),
            )
        ]

    def manifest_input(
        self, program: str, source: str, *, variant: str | None = None
    ) -> ManifestInput:
        binary, targets, directory = self.bundle(program, variant)
        package = Path(__file__).parent
        code_hash = content_hash(
            {
                path.relative_to(package).as_posix(): file_hash(path)
                for path in sorted(package.rglob("*.py"))
            }
        )
        with self.store() as store:
            engine = Engine(
                self.runner(), store, self.config.budgets, Path(self.config.ghidra.analysis_options)
            )
        return ManifestInput(
            algorithms_version=self.algorithms_version,
            source_config=cast(
                dict[str, JsonValue],
                {
                    "program": program,
                    "variant_id": binary.variant_id,
                    "split": self.config.guard.split,
                    "source": source,
                    "targets_hash": content_hash(targets),
                    "ground_truth_hash": file_hash(directory / "private/ground_truth.json"),
                    "run_config": {
                        "harness": engine.harness,
                        "metrics": self.config.metrics.model_dump(mode="json"),
                    }
                    | (
                        {
                            "grading_context": self.grading_context.model_dump(mode="json"),
                            "grading_context_hash": self.grading_context_hash,
                        }
                        if self.grading_context
                        else {}
                    ),
                },
            ),
            binaries=[binary.binary_sha256],
            versions=cast(dict[str, JsonValue], read_lock(package.parent / "versions.lock.md"))
            | {
                "package_source_hash": code_hash,
                "algorithms_hash": file_hash(package.parent / "algorithms.yaml"),
                "taxonomy_hash": file_hash(package / "schema/taxonomy.yaml"),
                "taxonomy_version": engine.harness["taxonomy_version"],
            },
            image_digests={
                "analysis": self.config.sandbox.image_analysis,
                "build": self.config.sandbox.image_build,
            },
            analysis_options_hash=file_hash(Path(self.config.ghidra.analysis_options)),
            pack_hashes=engine.pack_hashes,
            mapping_hashes={
                name: file_hash(Path(getattr(self.config.sources, name).mapping))
                for name in ("capa", "findcrypt")
            }
            | {"purpose_packs": engine.purpose_mapping_hash},
            verifier_version=__version__,
            grader_version=__version__,
            seeds={"scripted": 20261013, "bootstrap": self.config.metrics.bootstrap_seed},
        )

    def record_jobs(self, records: list[dict[str, Any]]) -> None:
        with self.store() as store:
            for record in records:
                job = Job.model_validate(record["job"])
                prior = store.connection.execute(
                    "SELECT input_hash FROM jobs WHERE job_id=?", (job.job_id,)
                ).fetchone()
                digest = content_hash(job.model_dump(mode="json", exclude={"job_id"}))
                if prior and prior[0] != digest:
                    raise ValueError("job input collision")
                if not prior:
                    store.add_job(job)
                if record["artifact"] is not None:
                    from aletheia.schema.models import JobResult

                    store.finish_job(
                        JobResult.model_validate_json(self.artifacts.get(record["artifact"])),
                        record["artifact"],
                    )

    def ingest(
        self,
        program: str,
        manifest: RunManifest,
        claims: list[Claim],
        *,
        source_jobs: list[dict[str, Any]] | None = None,
        counts: dict[str, int] | None = None,
        exclusions: dict[str, int] | None = None,
    ) -> str:
        binary, targets, _ = self.bundle(
            program, str(manifest.source_config.get("variant_id", self.variant or "")) or None
        )
        if manifest.binaries != [binary.binary_sha256] or any(
            claim.run_id != manifest.run_id or claim.binary_sha256 != binary.binary_sha256
            for claim in claims
        ):
            raise ValueError("run/claim/public binary identity mismatch")
        if len({claim.claim_id for claim in claims}) != len(claims):
            raise ValueError("duplicate intake claim")
        source_config = manifest.source_config
        source_id = str(source_config["source_id"])
        origin = str(source_config["origin"])
        if any(
            claim.source.source_id != source_id or claim.source.origin != origin for claim in claims
        ):
            raise ValueError("claim/source identity mismatch")
        keys = [
            (c.subject.address, c.type, c.body.callee if isinstance(c.body, Call) else "")
            for c in claims
        ]
        if len(keys) != len(set(keys)):
            raise ValueError("duplicate active claim")
        self.record_jobs(source_jobs or [])
        run = manifest.run_id
        destination = self.directory(run)
        publish_immutable(destination / "manifest.json", canonical_bytes(manifest))
        with self.store() as store:
            prior = store.connection.execute(
                "SELECT manifest_hash FROM runs WHERE run_id=?", (run,)
            ).fetchone()
            if prior:
                if prior[0] != content_hash(manifest):
                    raise ValueError("run manifest collision")
                existing = self.claims(store, run)
                if canonical_bytes(
                    [c.model_dump(mode="json") for c in existing]
                ) != canonical_bytes(
                    [c.model_dump(mode="json") for c in sorted(claims, key=lambda c: c.claim_id)]
                ):
                    raise ValueError("run claim set differs")
                return run
            prior_binary = store.connection.execute(
                "SELECT program_id,variant_id,targets_hash FROM binaries WHERE sha256=?",
                (binary.binary_sha256,),
            ).fetchone()
            identity = ("tierA/" + program, binary.variant_id, content_hash(targets))
            if prior_binary and prior_binary != identity:
                raise ValueError("binary metadata collision")
            if not prior_binary:
                store.add_binary(
                    binary.binary_sha256,
                    identity[0],
                    binary.variant_id,
                    self.config.guard.split,
                    str(binary.stripped),
                    identity[2],
                )
            store.add_run(run, origin, source_id, content_hash(manifest), manifest.created_at)
            try:
                for claim in sorted(claims, key=lambda c: c.claim_id):
                    store.add_claim(claim)
            except Exception:
                store.set_run_state(run, "failed")
                raise
        write_json(
            destination / "run.json",
            {
                "program": program,
                "variant_id": binary.variant_id,
                "source_id": source_id,
                "origin": origin,
                "unmapped_counts": counts or {},
                "exclusions": exclusions or {},
                "jobs": source_jobs or [],
            },
        )
        return run

    def create(self, program: str, source: str, *, no_cache: bool = False) -> list[str]:
        if source not in ("scripted", "capa", "findcrypt"):
            raise ValueError("unknown Phase 1A source")
        binary, targets, directory = self.bundle(program)
        manifest = self.manifest_input(program, source)
        if source == "scripted":
            truth = GroundTruth.model_validate_json(
                (directory / "private/ground_truth.json").read_bytes()
            )
            manifest.algorithms_version = truth.algorithms_version
            manifest = manifest.model_copy(update={"algorithms_version": truth.algorithms_version})
            generated = generate(truth, manifest, manifest.seeds["scripted"])
            return [
                self.ingest(program, case.manifest, case.claims, exclusions=generated.exclusions)
                for case in generated.cases
            ]
        config = getattr(self.config.sources, source)
        if not config.enabled:
            raise ValueError(source + " source disabled")
        runner = self.runner(no_cache=no_cache)
        if source == "capa":
            producer = CapaSource(CapaMapping.read(Path(config.mapping)), "r_" + "0" * 16, runner)
        else:
            producer = FindcryptSource(
                FindcryptMapping.read(Path(config.mapping)),
                "r_" + "0" * 16,
                runner,
                Path(self.config.ghidra.analysis_options),
            )
        claims = producer.produce(binary, targets)
        result = producer.last_result
        assert result is not None
        counts = {
            "unmapped_label:" + label: count for label, count in result.unmapped_label.items()
        }
        counts.update(
            {
                "deduplicated_label:" + label: count
                for label, count in result.deduplicated_label.items()
            }
        )
        counts["unmapped_scope"] = result.unmapped_scope if isinstance(result, CapaResult) else 0
        source_config = manifest.source_config | {
            "origin": producer.origin,
            "source_id": producer.source_id,
            "claims_hash": content_hash(
                [claim.model_dump(mode="json", exclude={"claim_id", "run_id"}) for claim in claims]
            ),
        }
        run_manifest = RunManifest.create(
            manifest.model_copy(
                update={
                    "source_config": source_config,
                    "algorithms_version": "2.0"
                    if any(c.algorithms_version == "2.0" for c in claims)
                    else manifest.algorithms_version,
                }
            )
        )
        rebound = [
            Claim.intake(
                ClaimSubmission.model_validate(
                    claim.model_dump(mode="json", exclude={"claim_id"})
                    | {"run_id": run_manifest.run_id}
                )
            )
            for claim in claims
        ]
        return [
            self.ingest(program, run_manifest, rebound, source_jobs=runner.records, counts=counts)
        ]

    def run_ids(self, run: str | None = None) -> list[str]:
        if run is not None:
            self.directory(run)
            return [run]
        with self.store() as store:
            return [
                row[0]
                for row in store.connection.execute("SELECT run_id FROM runs ORDER BY run_id")
            ]

    def verify(self, run: str, *, no_cache: bool = False) -> None:
        destination = self.directory(run)
        metadata = json.loads((destination / "run.json").read_bytes())
        binary, targets, _ = self.bundle(metadata["program"], metadata.get("variant_id"))
        runner = self.runner(no_cache=no_cache)
        with self.store() as store:
            claims = self.claims(store, run)
            pending = [
                claim
                for claim in claims
                if no_cache
                or store.connection.execute(
                    "SELECT 1 FROM verdicts WHERE claim_id=?", (claim.claim_id,)
                ).fetchone()
                is None
            ]
            if pending:
                store.set_run_state(run, "running")
        try:
            if pending:
                analysis = GhidraAnalysisCache(runner, self.root / "analysis-cache").analyze(
                    binary,
                    Path(self.config.ghidra.analysis_options),
                    no_cache=True,
                    subjects=sorted(
                        set(targets.targets) | {claim.subject.address for claim in claims},
                        key=lambda a: int(a, 16),
                    ),
                )

                def verify_claim(claim: Claim) -> EngineResult:
                    with self.store() as worker_store:
                        engine = Engine(
                            runner,
                            worker_store,
                            self.config.budgets,
                            Path(self.config.ghidra.analysis_options),
                        )
                        return engine.verify(claim, binary, analysis, no_cache=no_cache)

                if any(
                    claim.type in {"function_signature", "function_purpose"} for claim in claims
                ):
                    with self.store() as worker_store:
                        results = Engine(
                            runner,
                            worker_store,
                            self.config.budgets,
                            Path(self.config.ghidra.analysis_options),
                        ).verify_claims(claims, binary, analysis, no_cache=no_cache)
                else:
                    with ThreadPoolExecutor(max_workers=self.config.sandbox.concurrency) as pool:
                        results = list(pool.map(verify_claim, pending))
                with self.store() as store:
                    for result in results:
                        value = result.verdict
                        existing = store.connection.execute(
                            "SELECT canonical_json FROM verdicts WHERE claim_id=?",
                            (value.claim_id,),
                        ).fetchone()
                        if existing:
                            if existing[0] != canonical_bytes(value).decode():
                                raise ValueError("fresh verification changed a persisted verdict")
                        else:
                            store.add_verdict(value, result.cache_key)
            self.record_jobs(runner.records)
            metadata["jobs"].extend(runner.records)
            write_json(destination / "run.json", metadata)
        except Exception as exc:
            metadata["jobs"].extend(runner.records)
            metadata["failure"] = type(exc).__name__ + ": " + str(exc)[:300]
            write_json(destination / "run.json", metadata)
            with self.store() as store:
                store.set_run_state(run, "failed")
            raise

    def observations(self, verdicts: list[Verdict]) -> dict[str, list[Aspect]]:
        observations: dict[str, list[Aspect]] = {}
        for verdict in verdicts:
            refs = [item.artifact for item in verdict.evidence if item.kind == "method_results"]
            if len(refs) != 1:
                raise ValueError("verdict requires a unique method audit")
            payload = json.loads(self.artifacts.get(refs[0]))
            values = TypeAdapter(dict[str, Aspect]).validate_python(payload["observations"])
            observations[verdict.claim_id] = [values[name] for name in sorted(values)]
        return observations

    def score(self, runs: list[str]) -> MetricsReport:
        all_claims: list[Claim] = []
        all_verdicts: list[Verdict] = []
        all_grades: list[Grade] = []
        truths: dict[str, GroundTruth] = {}
        unmapped: dict[str, dict[str, int]] = {}
        for run in sorted(set(runs)):
            destination = self.directory(run)
            metadata = json.loads((destination / "run.json").read_bytes())
            _, targets, directory = self.bundle(metadata["program"], metadata.get("variant_id"))
            truth = GroundTruth.model_validate_json(
                (directory / "private/ground_truth.json").read_bytes()
            )
            with self.store() as store:
                claims = self.claims(store, run)
                verdicts = [store.get_verdict(claim.claim_id) for claim in claims]
                grades = grade(
                    claims,
                    verdicts,
                    truth,
                    targets,
                    taxonomy_kappa=self.grading_context.primary_kappa
                    if self.grading_context
                    else None,
                )
                for item in grades:
                    prior = store.connection.execute(
                        "SELECT canonical_json FROM grades WHERE claim_id=?", (item.claim_id,)
                    ).fetchone()
                    if prior and prior[0] != canonical_bytes(item).decode():
                        raise ValueError("grade drift")
                    if not prior:
                        store.add_grade(item)
            observed = self.observations(verdicts)
            counted = {metadata["source_id"]: metadata["unmapped_counts"]} if claims else {}
            report = compute_metrics(
                grades,
                claims,
                verdicts,
                self.config.metrics,
                ground_truths=[truth],
                method_results=observed,
                unmapped_counts=counted,
            )
            publish_immutable(destination / "metrics.json", canonical_bytes(report))
            hashes: dict[str, JsonValue] = {
                "verdicts": content_hash([v.model_dump(mode="json") for v in verdicts]),
                "grades": content_hash([g.model_dump(mode="json") for g in grades]),
                "metrics": content_hash(report),
            }
            publish_immutable(destination / "hashes.json", canonical_bytes(hashes))
            with self.store() as store:
                store.set_run_state(run, "completed")
            all_claims.extend(claims)
            all_verdicts.extend(verdicts)
            all_grades.extend(grades)
            truths[truth.binary_sha256] = truth
            if claims:
                counts = unmapped.setdefault(metadata["source_id"], {})
                for key, value in metadata["unmapped_counts"].items():
                    counts[key] = counts.get(key, 0) + value
        return compute_metrics(
            all_grades,
            all_claims,
            all_verdicts,
            self.config.metrics,
            ground_truths=list(truths.values()),
            method_results=self.observations(all_verdicts),
            unmapped_counts=unmapped,
        )

    def run(self, program: str, source: str, *, no_cache: bool = False) -> list[str]:
        runs = self.create(program, source, no_cache=no_cache)
        for run in runs:
            self.verify(run, no_cache=no_cache)
        self.score(runs)
        return runs

    def accounting(self, runs: list[str]) -> dict[str, Any]:
        records: list[dict[str, Any]] = []
        source_jobs: set[str] = set()
        for run in sorted(set(runs)):
            metadata = json.loads((self.directory(run) / "run.json").read_bytes())
            for record in metadata["jobs"]:
                job = Job.model_validate(record["job"])
                if job.type in SOURCE_JOBS:
                    if job.job_id in source_jobs:
                        continue
                    source_jobs.add(job.job_id)
                if not record["cached"]:
                    records.append(record)
        measurements: list[dict[str, Any]] = [record["measurement"] or {} for record in records]
        return {
            "executed_jobs": len(records),
            "cpu_seconds": sum(row.get("cpu_microseconds", 0) for row in measurements) / 1_000_000,
            "wall_seconds_sum": sum(row.get("wall_seconds", 0) for row in measurements),
            "peak_memory_bytes": max(
                (row.get("peak_memory_bytes", 0) for row in measurements), default=0
            ),
            "measurement_errors": sorted(
                str(row.get("error", "missing measurement"))
                for row in measurements
                if "cpu_microseconds" not in row
            ),
            "memory_measure": "maximum per-container cgroup memory.peak; not concurrent aggregate",
        }

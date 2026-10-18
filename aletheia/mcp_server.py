"""Per-client stdio verifier. Only the sandbox reads executable structure."""

import asyncio
import base64
import binascii
import hashlib
import json
import logging
import re
import shutil
import threading
from collections.abc import Callable
from concurrent.futures import Future, ThreadPoolExecutor, TimeoutError
from graphlib import CycleError, TopologicalSorter
from pathlib import Path
from typing import Any, Literal, Protocol

from pydantic import ValidationError

from aletheia import __version__
from aletheia.analysis.ghidra_session import GhidraAnalysis, GhidraAnalysisCache, publish_immutable
from aletheia.config import Config
from aletheia.heldout.guard import PrivateAccessError
from aletheia.sandbox.runner import JobRunner
from aletheia.schema.canonical import content_hash
from aletheia.schema.models import REGISTRY, Claim, ClaimSubmission, Verdict
from aletheia.schema.taxonomy import Taxonomy
from aletheia.sources.base import BinaryRef
from aletheia.store.artifacts import ArtifactStore
from aletheia.store.database import Store
from aletheia.verify.engine import REQUIRED_ASPECTS, Engine

MAX_BYTES = 20 * 1024 * 1024
ErrorCode = Literal[
    "invalid_claim",
    "unknown_binary",
    "analysis_pending",
    "budget_exceeded",
    "path_not_allowed",
    "binary_too_large",
    "internal",
]


class McpError(ValueError):
    def __init__(self, code: ErrorCode, message: str):
        self.code: ErrorCode = code
        self.message = message
        super().__init__(message)


def response(
    status: str = "ok", error_code: ErrorCode | None = None, message: str = "", **payload: Any
) -> dict[str, Any]:
    return {"status": status, "error_code": error_code, "message": message, **payload}


def failure(exc: Exception) -> dict[str, Any]:
    if isinstance(exc, PrivateAccessError):
        return response(
            "error", "path_not_allowed", "Private paths cannot enter the public MCP store"
        )
    if isinstance(exc, McpError):
        return response("error", exc.code, exc.message)
    logging.getLogger(__name__).error(
        "MCP job failed", exc_info=(type(exc), exc, exc.__traceback__)
    )
    return response(
        "error", "internal", "Verification job failed; inspect local server diagnostics."
    )


class VerifierBackend(Protocol):
    def analyze(self, binary: BinaryRef) -> GhidraAnalysis: ...
    def verify(
        self, claims: list[Claim], binary: BinaryRef, analysis: GhidraAnalysis
    ) -> list[Verdict]: ...


class NativeVerifier:
    def __init__(self, config: Config, root: Path):
        self.config, self.root = config, root

    def runner(self, digest: str) -> JobRunner:
        root = self.root / digest
        return JobRunner(
            self.config.sandbox, root / "public", root / "jobs", ArtifactStore(root / "artifacts")
        )

    def analyze(self, binary: BinaryRef) -> GhidraAnalysis:
        try:
            return GhidraAnalysisCache(
                self.runner(binary.binary_sha256), self.root / binary.binary_sha256 / "analysis"
            ).analyze(binary, Path(self.config.ghidra.analysis_options))
        except ValidationError as exc:
            if any(
                error["loc"] == ("functions",) and error["type"] == "too_long"
                for error in exc.errors()
            ):
                raise McpError("binary_too_large", "Binary exceeds 2,000 functions") from exc
            raise

    def verify(
        self, claims: list[Claim], binary: BinaryRef, analysis: GhidraAnalysis
    ) -> list[Verdict]:
        with Store(self.root / binary.binary_sha256 / "store.sqlite") as store:
            engine = Engine(
                self.runner(binary.binary_sha256),
                store,
                self.config.budgets,
                Path(self.config.ghidra.analysis_options),
                mode="runtime",
            )
            return [item.verdict for item in engine.verify_claims(claims, binary, analysis)]


class VerifierSession:
    def __init__(
        self,
        config: Config,
        root: Path,
        *,
        backend: VerifierBackend | None = None,
        wait_seconds: float = 10.0,
    ):
        self.config = config
        self.root = config.guard.public_path(root).resolve()
        if any(p.is_symlink() for p in (root, *root.parents)):
            raise ValueError("MCP store cannot be a symlink")
        self.root.mkdir(parents=True, exist_ok=True)
        self.backend = backend or NativeVerifier(config, self.root)
        self.wait_seconds = wait_seconds
        self.executor = ThreadPoolExecutor(max_workers=1, thread_name_prefix="aletheia-mcp")
        self.lock = threading.RLock()
        self.binaries: dict[str, BinaryRef] = {}
        self.analyses: dict[str, GhidraAnalysis] = {}
        self.jobs: dict[str, tuple[str, Future[dict[str, Any]]]] = {}
        self.claims: dict[str, Claim] = {}
        self.verdicts: dict[str, dict[str, Any]] = {}

    def close(self) -> None:
        self.executor.shutdown(wait=True)

    def schedule(self, digest: str, identity: Any, work: Callable[[], dict[str, Any]], wait: bool):
        with self.lock:
            job_id = "j_" + content_hash({"operation": identity, "sequence": len(self.jobs)})
            if job_id not in self.jobs:
                self.jobs[job_id] = (digest, self.executor.submit(work))
            future = self.jobs[job_id][1]
        if wait:
            try:
                return future.result(timeout=self.wait_seconds)
            except TimeoutError:
                pass
            except Exception as exc:
                return failure(exc)
        return response("pending", job_id=job_id)

    def load_binary(self, bytes_b64: str | None = None, path: str | None = None):
        try:
            if (bytes_b64 is None) == (path is None):
                raise McpError("invalid_claim", "Supply exactly one of bytes_b64 or path")
            if bytes_b64 is not None:
                if len(bytes_b64) > 4 * ((MAX_BYTES + 2) // 3):
                    raise McpError("binary_too_large", "Binary exceeds 20 MB")
                try:
                    payload = base64.b64decode(bytes_b64, validate=True)
                except (binascii.Error, ValueError) as exc:
                    raise McpError("invalid_claim", "Invalid base64 bytes") from exc
            else:
                if self.config.mcp.binary_root is None:
                    raise McpError("path_not_allowed", "No MCP binary_root is configured")
                allowed = self.config.guard.public_path(Path(self.config.mcp.binary_root)).resolve()
                assert path is not None
                selected = Path(path)
                if not selected.is_absolute():
                    selected = allowed / selected
                if any(
                    p.is_symlink() for p in (selected, *selected.parents)
                ) or not selected.resolve().is_relative_to(allowed):
                    raise McpError(
                        "path_not_allowed", "Path must be beneath binary_root without symlinks"
                    )
                self.config.guard.public_path(selected)
                with selected.open("rb") as stream:
                    payload = stream.read(MAX_BYTES + 1)
            if len(payload) > MAX_BYTES:
                raise McpError("binary_too_large", "Binary exceeds 20 MB")
            digest = hashlib.sha256(payload).hexdigest()
            with self.lock:
                target = self.root / digest / "stripped" / (digest + ".bin")
                target.parent.mkdir(parents=True, exist_ok=True)
                publish_immutable(target, payload)
                binary = BinaryRef(digest, target, "mcp")
                self.binaries[digest] = binary

                def analyze() -> dict[str, Any]:
                    result = self.backend.analyze(binary)
                    if len(result.functions) > 2000:
                        raise McpError("binary_too_large", "Binary exceeds 2,000 functions")
                    with self.lock:
                        self.analyses[digest] = result
                    return response(binary_sha256=digest, functions=len(result.functions))

                result = self.schedule(digest, {"analysis": digest}, analyze, False)
            return {**result, "binary_sha256": digest}
        except (OSError, ValueError) as exc:
            return failure(exc)

    def get_job(self, job_id: str):
        with self.lock:
            item = self.jobs.get(job_id)
        if item is None:
            return response("error", "invalid_claim", "Unknown job ID")
        future = item[1]
        if not future.done():
            return response(
                "pending", job_id=job_id, job_status="running" if future.running() else "pending"
            )
        try:
            return response(job_id=job_id, job_status="done", result=future.result())
        except Exception as exc:
            return {**failure(exc), "job_id": job_id, "job_status": "error"}

    def confidence(
        self, claim: Claim, verdict: Verdict, config_id: str | None, parents: list[float]
    ) -> dict[str, Any]:
        result: dict[str, Any] = {"confidence": claim.confidence, "calibration": "uncalibrated"}
        if config_id is None or self.config.mcp.calibration_maps is None:
            return result
        from aletheia.confidence import CalibrationFit, LikelihoodFit, Sample, adjust

        source = claim.source.source_id
        if source not in {config_id, "agent:" + config_id}:
            return result
        path = self.config.guard.public_path(Path(self.config.mcp.calibration_maps))
        if any(p.is_symlink() for p in (path, *path.parents)):
            raise ValueError("calibration map cannot be a symlink")
        raw = path.read_bytes()
        maps = CalibrationFit.model_validate_json(raw)
        if maps.find(source, claim.type) is None:
            return result
        table = LikelihoodFit(run_ids=[], rows=[])
        if self.config.mcp.likelihood_table:
            path = self.config.guard.public_path(Path(self.config.mcp.likelihood_table))
            if any(p.is_symlink() for p in (path, *path.parents)):
                raise ValueError("likelihood table cannot be a symlink")
            table = LikelihoodFit.model_validate_json(path.read_bytes())
        methods = sorted(
            {
                verdict.aspects[name].method
                for name in REQUIRED_ASPECTS[claim.type]
                if name in verdict.aspects
            }
        )
        row = Sample(
            claim_id=claim.claim_id,
            run_id=claim.run_id,
            program="mcp",
            split="train",
            source=claim.source,
            claim_type=claim.type,
            confidence=claim.confidence,
            correct_claimed=None,
            on_target=True,
            verdict=verdict.intrinsic_verdict,
            strength=verdict.strength,
            method="+".join(methods) or "none",
            depends_on=claim.depends_on,
        )
        adjusted = adjust(row, maps, table, parents)
        return {
            **result,
            "calibration": "calibrated",
            "c_adj": adjusted.adjusted,
            "c_prior": adjusted.prior,
            "likelihood": adjusted.likelihood,
            "calibration_sha256": hashlib.sha256(raw).hexdigest(),
        }

    def verify_claim(self, claim: dict[str, Any], config_id: str | None = None):
        result = self.verify_claims([claim], config_id)
        if result.get("status") == "ok":
            return result["results"][0]
        return result

    def verify_claims(self, claims: list[dict[str, Any]], config_id: str | None = None):
        try:
            if len(claims) > 2000:
                raise McpError("budget_exceeded", "At most 2,000 claims per request")
            try:
                parsed = [Claim.intake(ClaimSubmission.model_validate(item)) for item in claims]
            except ValueError as exc:
                raise McpError("invalid_claim", "Claim does not match the current schema") from exc
            if not parsed:
                return response(results=[])
            digest = parsed[0].binary_sha256
            if any(c.run_id != parsed[0].run_id for c in parsed) or len(
                {c.claim_id for c in parsed}
            ) != len(parsed):
                raise McpError("invalid_claim", "Batch requires one run and unique claims")
            if any(c.binary_sha256 != digest for c in parsed):
                raise McpError("invalid_claim", "One batch must refer to one binary")
            with self.lock:
                if digest not in self.binaries:
                    raise McpError("unknown_binary", "Load this binary first")
                if digest not in self.analyses:
                    raise McpError("analysis_pending", "Poll the analysis job before verification")
                binary, analysis = self.binaries[digest], self.analyses[digest]
                known = set(self.claims) | {c.claim_id for c in parsed}
                if any(not set(c.depends_on) <= known for c in parsed):
                    raise McpError("invalid_claim", "Unknown reasoning parent")

                def verify() -> dict[str, Any]:
                    verdicts = self.backend.verify(parsed, binary, analysis)
                    by_id = {c.claim_id: c for c in parsed}
                    verdict_by_id = {v.claim_id: v for v in verdicts}
                    if set(verdict_by_id) != set(by_id) or len(verdicts) != len(parsed):
                        raise ValueError("backend returned an incomplete verification batch")
                    try:
                        order = list(
                            TopologicalSorter(
                                {c.claim_id: c.depends_on for c in parsed}
                            ).static_order()
                        )
                    except CycleError as exc:
                        raise McpError("invalid_claim", "Cyclic reasoning dependency") from exc
                    with self.lock:
                        prior_claims, prior_results = dict(self.claims), dict(self.verdicts)
                    staged: dict[str, dict[str, Any]] = {}
                    for identity in order:
                        if identity not in by_id:
                            continue
                        claim = by_id[identity]
                        parents: list[float] = []
                        for parent in claim.depends_on:
                            parent_claim = by_id.get(parent) or prior_claims[parent]
                            if parent_claim.run_id != claim.run_id:
                                raise McpError(
                                    "invalid_claim", "Reasoning parent belongs to another run"
                                )
                            parent_result = staged.get(parent) or prior_results[parent]
                            parents.append(
                                min(
                                    0.98,
                                    max(
                                        0.02,
                                        float(parent_result.get("c_adj", parent_claim.confidence)),
                                    ),
                                )
                            )
                        verdict = verdict_by_id[identity]
                        staged[identity] = response(
                            verdict=verdict.model_dump(mode="json"),
                            **self.confidence(claim, verdict, config_id, parents),
                        )
                    with self.lock:
                        self.claims.update(by_id)
                        self.verdicts.update(staged)
                    return response(results=[staged[c.claim_id] for c in parsed])

            return self.schedule(
                digest,
                {"claims": [c.model_dump(mode="json") for c in parsed], "config_id": config_id},
                verify,
                True,
            )
        except ValueError as exc:
            return failure(exc)

    def get_evidence(self, artifact: str):
        try:
            if re.fullmatch(r"sha256:[0-9a-f]{64}", artifact) is None:
                raise McpError("invalid_claim", "Malformed evidence artifact ID")
            with self.lock:
                digests = sorted(self.binaries)
            for digest in digests:
                try:
                    data = ArtifactStore(self.root / digest / "artifacts").get(artifact)
                except FileNotFoundError:
                    continue
                if len(data) > 512 * 1024:
                    raise McpError(
                        "budget_exceeded", "Evidence exceeds the 512 KiB response budget"
                    )
                return response(artifact=artifact, evidence=json.loads(data))
            raise McpError("invalid_claim", "Unknown evidence artifact")
        except (ValueError, OSError) as exc:
            return failure(exc)

    def explain_verdict(self, claim_id: str):
        with self.lock:
            found = self.verdicts.get(claim_id)
            if found is None:
                return response("error", "invalid_claim", "Unknown claim ID")
            verdict = found["verdict"]
            return response(
                claim_id=claim_id,
                harness=verdict["harness"],
                methods=verdict["methods_run"],
                aspects=verdict["aspects"],
            )

    def list_supported(self):
        import yaml

        root = Path(__file__).parents[1]
        snippet = (root / "prompts/snippet-v1.md").read_bytes()
        purposes = yaml.safe_load((root / "mappings/purpose_packs.yaml").read_bytes())["map"]
        return response(
            server_version=__version__,
            schema_version="1.0",
            taxonomy_version=Taxonomy.bundled().version,
            claim_types=sorted(REQUIRED_ASPECTS),
            aspects=REQUIRED_ASPECTS,
            families=REGISTRY,
            purpose_packs=purposes,
            snippet_version="1.0",
            snippet_sha256=hashlib.sha256(snippet).hexdigest(),
        )

    def purge(self, binary_sha256: str):
        with self.lock:
            if binary_sha256 not in self.binaries:
                return response("error", "unknown_binary", "Unknown binary")
            if any(d == binary_sha256 and not f.done() for d, f in self.jobs.values()):
                return response("error", "analysis_pending", "Wait for active jobs before purging")
            target = self.root / binary_sha256
            if target.is_symlink() or target.resolve().parent != self.root:
                return response("error", "path_not_allowed", "Invalid binary storage path")
            try:
                shutil.rmtree(target)
            except OSError as exc:
                return failure(exc)
            self.binaries.pop(binary_sha256)
            self.analyses.pop(binary_sha256, None)
            self.jobs = {k: v for k, v in self.jobs.items() if v[0] != binary_sha256}
            for identity in list(self.claims):
                if self.claims[identity].binary_sha256 == binary_sha256:
                    self.claims.pop(identity)
                    self.verdicts.pop(identity, None)
            return response(binary_sha256=binary_sha256)


def make_server(session: VerifierSession):
    from mcp.server.fastmcp import FastMCP

    server = FastMCP("aletheia-verifier")
    for name in (
        "load_binary",
        "get_job",
        "get_evidence",
        "list_supported",
        "explain_verdict",
        "purge",
    ):
        server.add_tool(getattr(session, name), name=name)

    @server.tool(name="verify_claim")
    async def verify_claim(claim: dict[str, Any], config_id: str | None = None):
        return await asyncio.to_thread(session.verify_claim, claim, config_id)

    @server.tool(name="verify_claims")
    async def verify_claims(claims: list[dict[str, Any]], config_id: str | None = None):
        return await asyncio.to_thread(session.verify_claims, claims, config_id)

    return server


def serve(config: Config) -> None:
    session = VerifierSession(config, Path(config.paths.runs) / "mcp")
    server = make_server(session)
    try:
        server.run(transport="stdio")
    finally:
        session.close()

"""Phase 1A audit registry, guarded merging and source-independent verdict caching."""

import hashlib
import json
from dataclasses import dataclass, field, replace
from pathlib import Path
from typing import Literal, cast

from pydantic import Field, JsonValue, TypeAdapter

from aletheia import __version__
from aletheia.analysis.ghidra_session import (
    ConstantMatch,
    GhidraAnalysis,
    GhidraOptions,
    publish_immutable,
    read_public_binary,
)
from aletheia.config import Budgets
from aletheia.sandbox.runner import JobRunner
from aletheia.schema.canonical import canonical_bytes, content_hash
from aletheia.schema.models import (
    Address,
    Algorithm,
    Aspect,
    Budget,
    Claim,
    Digest,
    Evidence,
    Job,
    JobResult,
    Outcome,
    Record,
    Sha256,
    Strength,
    Strict,
    Verdict,
)
from aletheia.sources.base import BinaryRef
from aletheia.store.cache import CacheContext, verdict_cache_key
from aletheia.store.database import Store
from aletheia.verify.emulate.core import BASE, CANARY, HEAP, INPUTS, SENTINEL, STACK, STUBS, TLS
from aletheia.verify.probes.client import ProbeClient
from aletheia.verify.probes.inputs import generate_inputs, inputs_for_shape
from aletheia.verify.probes.pack import HexInput, Pack, load_pack
from aletheia.verify.static.arity import Arity, infer_arity
from aletheia.verify.static.worker import StaticRequest


@dataclass(frozen=True)
class MethodSpec:
    name: str
    claim_type: Literal["algorithm_identity", "call_relation"]
    aspect: Literal["output_match", "edge_exists"] | None
    strength: Strength | None
    decisive_verified: bool
    decisive_contradicted: bool
    cost_class: Literal["static", "emulation"]


@dataclass(frozen=True)
class DynamicProof:
    binding_verified: bool
    state_clean: bool
    widths_valid: bool
    reproduced: bool
    complete_scope: bool
    execution_reason: str | None = None

    def failure(self) -> str | None:
        if not self.state_clean:
            return "state_dependent"
        if self.execution_reason:
            return self.execution_reason
        if not self.binding_verified:
            return "binding_not_verified"
        if not self.widths_valid:
            return "no_matching_call_shape"
        if not self.reproduced:
            return "emulation_fault"
        if not self.complete_scope:
            return "no_pack"
        return None


@dataclass(frozen=True)
class MethodResult:
    spec: MethodSpec
    verdict: Verdict | None
    evidence: tuple[Evidence, ...] = ()
    proof: DynamicProof | None = None
    details: dict[str, JsonValue] = field(default_factory=lambda: dict[str, JsonValue]())


def guarded_result(result: MethodResult) -> MethodResult:
    verdict = result.verdict
    if (
        verdict is None
        or verdict.intrinsic_verdict != "CONTRADICTED"
        or result.spec.cost_class != "emulation"
    ):
        return result
    reason = result.proof.failure() if result.proof else "binding_not_verified"
    if reason is None:
        return result
    aspects = {
        key: Aspect(verdict="INCONCLUSIVE", method=result.spec.name) for key in verdict.aspects
    }
    value = verdict.model_copy(
        update={
            "intrinsic_verdict": "INCONCLUSIVE",
            "strength": None,
            "reason": reason,
            "harness": None,
            "counterexample": None,
            "aspects": aspects,
        }
    )
    return replace(result, verdict=value, details=result.details | {"precondition_failure": reason})


def merge_results(claim: Claim, results: list[MethodResult], env_digest: Digest) -> Verdict:
    results = sorted(
        (guarded_result(result) for result in results), key=lambda result: result.spec.name
    )
    aspect = "output_match" if claim.type == "algorithm_identity" else "edge_exists"
    eligible = [
        result
        for result in results
        if result.spec.claim_type == claim.type
        and result.spec.aspect == aspect
        and (result.spec.decisive_verified or result.spec.decisive_contradicted)
        and result.verdict is not None
    ]
    winner: MethodResult | None = None
    outcome: Outcome = "UNVERIFIABLE"
    reason: str | None = "no_pack"
    invalid = [
        result
        for result in results
        if result.verdict is not None and result.verdict.intrinsic_verdict == "INVALID_CLAIM"
    ]

    def candidates(value: Outcome) -> list[MethodResult]:
        return [
            result
            for result in eligible
            if result.verdict is not None and result.verdict.intrinsic_verdict == value
        ]

    def strongest(values: list[MethodResult]) -> MethodResult:
        return min(
            values,
            key=lambda result: (
                -({"E1": 1, "E2": 2}.get(result.spec.strength or "", 0)),
                result.spec.name,
            ),
        )

    contradicted = [
        result for result in candidates("CONTRADICTED") if result.spec.decisive_contradicted
    ]
    verified = [result for result in candidates("VERIFIED") if result.spec.decisive_verified]
    if invalid:
        winner, outcome = invalid[0], "INVALID_CLAIM"
    elif contradicted:
        winner, outcome = strongest(contradicted), "CONTRADICTED"
    elif verified:
        winner, outcome = strongest(verified), "VERIFIED"
    elif values := candidates("INCONCLUSIVE"):
        priorities = [
            "state_dependent",
            "unsupported_relocation",
            "unsupported_import",
            "emulation_fault",
            "budget_exhausted",
            "binding_not_verified",
            "no_matching_call_shape",
            "no_pack",
        ]

        def order(result: MethodResult) -> tuple[int, str]:
            assert result.verdict is not None
            item = (result.verdict.reason or "").split(":", 1)[0]
            return (
                priorities.index(item) if item in priorities else len(priorities),
                result.spec.name,
            )

        winner, outcome = min(values, key=order), "INCONCLUSIVE"
    elif values := candidates("ERROR"):
        winner, outcome = (
            min(
                values,
                key=lambda result: (
                    result.verdict is None or result.verdict.reason != "wall_timeout",
                    result.spec.name,
                ),
            ),
            "ERROR",
        )
    elif values := candidates("NOT_CHECKED"):
        winner, outcome = values[0], "NOT_CHECKED"
    elif values := candidates("UNVERIFIABLE"):
        winner = values[0]
    value = winner.verdict if winner is not None else None
    decisive = outcome in ("VERIFIED", "CONTRADICTED")
    if value is not None:
        reason = None if decisive else value.reason
    strength = winner.spec.strength if decisive and winner is not None else None
    methods = sorted(
        {
            result.spec.name
            for result in results
            if result.verdict is None
            or result.verdict.intrinsic_verdict not in ("NOT_CHECKED", "INVALID_CLAIM")
        }
    )
    all_evidence = [
        item
        for result in results
        for item in (list(result.evidence) + (result.verdict.evidence if result.verdict else []))
    ]
    evidence = [
        Evidence(kind=kind, artifact=artifact, summary=summary)
        for kind, artifact, summary in sorted(
            {(item.kind, item.artifact, item.summary) for item in all_evidence}
        )
    ]
    aspects: dict[Literal["output_match", "edge_exists"], Aspect] = {}
    if (
        winner is not None
        and winner.spec.aspect is not None
        and outcome not in ("NOT_CHECKED", "INVALID_CLAIM")
    ):
        aspects[aspect] = Aspect(verdict=outcome, strength=strength, method=winner.spec.name)
    return Verdict(
        claim_id=claim.claim_id,
        intrinsic_verdict=outcome,
        strength=strength,
        reason=reason,
        aspects=aspects,
        methods_run=methods,
        harness=value.harness if decisive and value is not None else None,
        counterexample=value.counterexample
        if outcome == "CONTRADICTED" and value is not None
        else None,
        evidence=evidence,
        budget_used=Budget(
            instructions=sum(
                result.verdict.budget_used.instructions
                for result in results
                if result.verdict is not None
            )
        ),
        verifier_version=__version__,
        env_digest=env_digest,
    )


class InputObservation(Strict):
    shape: str
    variant: str
    input_hex: HexInput
    status: Literal[
        "match",
        "mismatch",
        "state_dependent",
        "unsupported_import",
        "unsupported_relocation",
        "emulation_fault",
        "budget_exhausted",
    ]
    expected_hex: HexInput
    actual_hex: HexInput
    instructions: int = Field(ge=0)
    fault: str | None
    uninitialized_state_reads: bool
    imports_called: list[str]


class ProbeEvidence(Record):
    binary_sha256: Sha256
    subject: Address
    family: str
    claimed_variant: str | None
    supported_variants: list[str]
    unsupported_variants: list[str]
    arity: Arity | None
    initial_state: str
    observations: list[InputObservation]
    minimization: list[InputObservation]


def probe_proof(
    claim: Claim, analysis: GhidraAnalysis, pack: Pack, evidence: ProbeEvidence, verdict: Verdict
) -> DynamicProof:
    if not isinstance(claim.body, Algorithm):
        raise ValueError("dynamic proof requires algorithm_identity")
    binding = infer_arity(claim.subject.address, analysis)
    if evidence.arity is not None and evidence.arity != binding:
        raise ValueError("probe/analysis binding evidence mismatch")
    shapes = {shape.id: shape for shape in pack.call_shapes}
    eligible = [
        row
        for row in evidence.observations
        if row.shape in shapes and len(shapes[row.shape].roles) == binding.arity
    ]
    state_clean = all(not row.uninitialized_state_reads for row in eligible)
    execution = None
    for status in (
        "unsupported_relocation",
        "unsupported_import",
        "emulation_fault",
        "budget_exhausted",
    ):
        row = next((row for row in eligible if row.status == status), None)
        if row is not None:
            execution = row.fault if status == "unsupported_import" else status
            break
    widths = bool(eligible) and all(
        (
            len(row.expected_hex) // 2 >= shapes[row.shape].return_width // 8
            and len(row.actual_hex) // 2 >= shapes[row.shape].return_width // 8
            and len(row.actual_hex) // 2
            <= shapes[row.shape].return_width // 8
            + shapes[row.shape].output_size(len(bytes.fromhex(row.input_hex)))
        )
        for row in eligible
    )
    ce = verdict.counterexample
    last = evidence.minimization[-1] if evidence.minimization else None
    reproduced = bool(
        ce is not None
        and last is not None
        and last.status == "mismatch"
        and last.fault is None
        and not last.uninitialized_state_reads
        and (last.shape, last.variant, last.input_hex, last.expected_hex, last.actual_hex)
        == (ce.call_shape, ce.variant, ce.input_hex, ce.expected_hex, ce.actual_hex)
        and last.expected_hex != last.actual_hex
    )
    return DynamicProof(
        binding.decisive,
        state_clean,
        widths,
        reproduced,
        claim.body.variant is not None or not pack.unsupported_variants,
        execution,
    )


def verifier_source_hash() -> str:
    root = Path(__file__).resolve().parents[1]
    files = [root / "__init__.py", root / "config.py"]
    for directory in ("verify", "analysis", "worker", "schema", "store", "sandbox"):
        files.extend((root / directory).rglob("*.py"))
    return content_hash(
        {
            path.relative_to(root).as_posix(): hashlib.sha256(path.read_bytes()).hexdigest()
            for path in sorted(set(files))
        }
    )


@dataclass(frozen=True)
class EngineResult:
    verdict: Verdict
    method_results: dict[str, Aspect]
    cache_key: str
    cache_hit: bool


def methods_for(claim: Claim, pack: Pack | None) -> list[MethodSpec]:
    if claim.type == "call_relation":
        return [
            MethodSpec("static.edges@1", "call_relation", "edge_exists", "E1", True, True, "static")
        ]
    assert isinstance(claim.body, Algorithm)
    return [
        MethodSpec("static.constants@1", "algorithm_identity", None, "E1", False, False, "static"),
        MethodSpec(
            f"probe.{claim.body.family}@{pack.version if pack else 1}",
            "algorithm_identity",
            "output_match",
            "E2",
            True,
            True,
            "emulation",
        ),
    ]


DEFAULT_PACK_DIRECTORY = Path(__file__).resolve().parents[2] / "packs"


class Engine:
    def __init__(
        self,
        runner: JobRunner,
        store: Store,
        budgets: Budgets,
        options: Path,
        pack_directory: Path = DEFAULT_PACK_DIRECTORY,
    ):
        self.runner, self.store = runner, store
        self.budgets = budgets.model_copy(deep=True)
        self.options = GhidraOptions.read(options)
        self.options_hash = hashlib.sha256(options.read_bytes()).hexdigest()
        self.pack_paths: dict[str, Path] = {}
        self.packs: dict[str, Pack] = {}
        self.pack_hashes: dict[str, str] = {}
        for path in sorted(pack_directory.glob("*.yaml")):
            if any(part.is_symlink() for part in (path, *path.parents)):
                raise ValueError("pack cannot be a symlink")
            payload = path.read_bytes()
            digest = hashlib.sha256(payload).hexdigest()
            snapshot = self.runner.input_root / "in" / (digest + ".yaml")
            publish_immutable(snapshot, payload)
            pack = load_pack(snapshot)
            if pack.family in self.packs or pack.family != path.stem:
                raise ValueError("duplicate or mislabeled family pack")
            self.pack_paths[pack.family], self.packs[pack.family] = snapshot, pack
            self.pack_hashes[pack.family] = digest
        self.harness: dict[str, JsonValue] = {
            "mode": "audit",
            "verifier_version": __version__,
            "verifier_source_hash": verifier_source_hash(),
            "sandbox": cast(JsonValue, runner.config.model_dump(mode="json")),
            "budgets": cast(JsonValue, budgets.model_dump(mode="json")),
            "analysis_options_hash": self.options_hash,
            "stub_set": "S1",
            "initializers": "verified_standard_crt",
            "mutable_state": "initial_zero_bytes_bss_data",
            "layout": {
                "base": BASE,
                "stubs": STUBS,
                "sentinel": SENTINEL,
                "tls": TLS,
                "heap": HEAP,
                "inputs": INPUTS,
                "stack": STACK,
                "canary": f"{CANARY:016x}",
            },
        }
        self.env_digest = "sha256:" + content_hash(self.harness)
        self.probes = ProbeClient(runner)

    def cache_context(self, claim: Claim, analysis: GhidraAnalysis) -> CacheContext:
        family = claim.body.family if isinstance(claim.body, Algorithm) else None
        pack = self.packs.get(family) if family is not None else None
        hashes = (
            {family: self.pack_hashes[family]}
            if family is not None and family in self.pack_hashes
            else {}
        )
        return CacheContext(
            verifier_version=__version__,
            method_versions=sorted(spec.name for spec in methods_for(claim, pack)),
            pack_hashes=hashes,
            env_digest=self.env_digest,
            analysis_options_hash=self.options_hash,
            harness=self.harness | {"analysis_result_hash": content_hash(analysis)},
        )

    def _stage(self, payload: bytes, suffix: str) -> str:
        digest = hashlib.sha256(payload).hexdigest()
        publish_immutable(self.runner.input_root / "in" / (digest + suffix), payload)
        return "in/" + digest + suffix

    def _error(
        self, spec: MethodSpec, claim: Claim, code: str, detail: str, artifact: str | None = None
    ) -> MethodResult:
        reason = "wall_timeout" if code == "wall_timeout" else "internal"
        if artifact is None:
            artifact = self.runner.artifacts.put(
                canonical_bytes(
                    {
                        "method": spec.name,
                        "error_code": code,
                        "detail": detail,
                        "budget_known": False,
                    }
                )
            )
        evidence = Evidence(
            kind="method_error", artifact=artifact, summary=code + ": " + detail[:160]
        )
        aspects: dict[Literal["output_match", "edge_exists"], Aspect] = (
            {spec.aspect: Aspect(verdict="ERROR", method=spec.name)} if spec.aspect else {}
        )
        verdict = Verdict(
            claim_id=claim.claim_id,
            intrinsic_verdict="ERROR",
            reason=reason,
            aspects=aspects,
            methods_run=[spec.name],
            evidence=[evidence],
            verifier_version=__version__,
            env_digest=self.env_digest,
        )
        return MethodResult(spec, verdict)

    def _static(self, spec: MethodSpec, claim: Claim, analysis: GhidraAnalysis) -> MethodResult:
        request = StaticRequest(
            claim=claim, env_digest=self.env_digest, analysis_options_sha256=self.options_hash
        )
        job = Job.create(
            "verify_static",
            {
                "request": self._stage(canonical_bytes(request), ".json"),
                "analysis": self._stage(canonical_bytes(analysis), ".json"),
            },
            {"method": spec.name},
        )
        handle = self.runner.submit(job)
        result = self.runner.wait(handle)
        if result.status != "ok":
            return self._error(
                spec,
                claim,
                result.error_code or "internal",
                str(result.output.get("detail", "")),
                handle.result_artifact,
            )
        if spec.name == "static.edges@1":
            verdict = Verdict.model_validate(result.output["verdict"])
            if verdict.claim_id != claim.claim_id or verdict.env_digest != self.env_digest:
                raise ValueError("static verdict identity mismatch")
            return MethodResult(spec, verdict)
        matches = TypeAdapter(list[ConstantMatch]).validate_python(result.output["matches"])
        payload = cast(
            JsonValue,
            {
                "binary_sha256": claim.binary_sha256,
                "subject": claim.subject.address,
                "matches": [match.model_dump(mode="json") for match in matches],
            },
        )
        digest = self.runner.artifacts.put(canonical_bytes(payload))
        evidence = tuple(
            Evidence(
                kind="constant_match",
                artifact=digest,
                summary=f"{match.name} at {match.address} ({match.location})",
            )
            for match in matches
        )
        if not evidence:
            evidence = (
                Evidence(kind="constant_scan", artifact=digest, summary="No matching constants."),
            )
        return MethodResult(spec, None, evidence=evidence)

    def _probe(
        self,
        spec: MethodSpec,
        claim: Claim,
        binary: BinaryRef,
        analysis: GhidraAnalysis,
        pack: Pack | None,
    ) -> MethodResult:
        assert isinstance(claim.body, Algorithm)
        try:
            verdict = self.probes.probe(
                binary,
                claim,
                analysis,
                self.pack_paths.get(claim.body.family),
                self.budgets,
                self.env_digest,
            )
        except RuntimeError:
            if self.probes.last_artifact is None:
                raise
            result = JobResult.model_validate_json(
                self.runner.artifacts.get(self.probes.last_artifact)
            )
            if result.status != "error":
                raise
            return self._error(
                spec,
                claim,
                result.error_code or "internal",
                str(result.output.get("detail", "")),
                self.probes.last_artifact,
            )
        artifact = next(item.artifact for item in verdict.evidence if item.kind == "probe_results")
        evidence = ProbeEvidence.model_validate_json(self.runner.artifacts.get(artifact))
        if (
            evidence.binary_sha256,
            evidence.subject,
            evidence.family,
            evidence.claimed_variant,
        ) != (claim.binary_sha256, claim.subject.address, claim.body.family, claim.body.variant):
            raise ValueError("probe evidence identity mismatch")
        proof = (
            probe_proof(claim, analysis, pack, evidence, verdict)
            if (pack is not None and verdict.intrinsic_verdict == "CONTRADICTED")
            else None
        )
        counts: dict[str, JsonValue] = {}
        if pack is not None:
            values = generate_inputs(pack.inputs)
            for shape in pack.call_shapes:
                eligible = len(inputs_for_shape(values, shape.roles))
                counts[shape.id] = {
                    "generated": len(values),
                    "eligible_per_variant": eligible,
                    "skipped_embedded_nul": len(values) - eligible,
                    "executed_by_variant": {
                        variant: sum(
                            row.shape == shape.id and row.variant == variant
                            for row in evidence.observations
                        )
                        for variant in sorted(pack.variants)
                    },
                }
        return MethodResult(spec, verdict, proof=proof, details={"input_counts": counts})

    def verify(
        self, claim: Claim, binary: BinaryRef, analysis: GhidraAnalysis, *, no_cache: bool = False
    ) -> EngineResult:
        read_public_binary(binary)
        if (
            claim.binary_sha256 != binary.binary_sha256
            or analysis.binary_sha256 != binary.binary_sha256
        ):
            raise ValueError("engine public binary/analysis/claim identity mismatch")
        if analysis.options_sha256 != self.options_hash:
            raise ValueError("engine analysis/options identity mismatch")
        context = self.cache_context(claim, analysis)
        key = verdict_cache_key(claim, context)
        if not no_cache:
            cached = self.store.cached_verdict(key, claim.claim_id)
            if cached is not None:
                refs = [item.artifact for item in cached.evidence if item.kind == "method_results"]
                if len(refs) != 1:
                    raise ValueError("cached verdict lacks unique method audit")
                audit = json.loads(self.runner.artifacts.get(refs[0]))
                observations = TypeAdapter(dict[str, Aspect]).validate_python(audit["observations"])
                if set(observations) != set(cached.methods_run):
                    raise ValueError("cached method audit mismatch")
                return EngineResult(cached, observations, key, True)
        pack = self.packs.get(claim.body.family) if isinstance(claim.body, Algorithm) else None
        results: list[MethodResult] = []
        for spec in methods_for(claim, pack):
            try:
                result = (
                    self._static(spec, claim, analysis)
                    if spec.cost_class == "static"
                    else (self._probe(spec, claim, binary, analysis, pack))
                )
            except Exception as exc:
                result = self._error(
                    spec, claim, "internal", type(exc).__name__ + ": " + str(exc)[:240]
                )
            results.append(guarded_result(result))
        verdict = merge_results(claim, results, self.env_digest)
        observations: dict[str, Aspect] = {}
        records: list[dict[str, JsonValue]] = []
        for result in sorted(results, key=lambda result: result.spec.name):
            value = result.verdict
            if value is None or value.intrinsic_verdict not in ("INVALID_CLAIM", "NOT_CHECKED"):
                # Supporting facts get a non-decision observation, never a claim verdict.
                observations[result.spec.name] = Aspect(
                    verdict=value.intrinsic_verdict if value else "INCONCLUSIVE",
                    strength=value.strength if value else None,
                    method=result.spec.name,
                )
            records.append(
                {
                    "method": result.spec.name,
                    "supporting_only": result.spec.aspect is None,
                    "result": cast(JsonValue, value.model_dump(mode="json", exclude={"claim_id"}))
                    if value
                    else None,
                    "details": cast(JsonValue, result.details),
                }
            )
        decisive = [
            result
            for result in results
            if result.spec.aspect is not None and result.verdict is not None
        ]
        disagreement = any(
            result.verdict is not None
            and result.verdict.intrinsic_verdict == "VERIFIED"
            and result.spec.decisive_verified
            for result in decisive
        ) and any(
            result.verdict is not None
            and result.verdict.intrinsic_verdict == "CONTRADICTED"
            and result.spec.decisive_contradicted
            for result in decisive
        )
        audit = cast(
            JsonValue,
            {
                "schema_version": "1.0",
                "methods": records,
                "observations": {
                    name: value.model_dump(mode="json")
                    for name, value in sorted(observations.items())
                },
                "defects": [{"kind": "method_disagreement"}] if disagreement else [],
            },
        )
        digest = self.runner.artifacts.put(canonical_bytes(audit))
        evidence = sorted(
            [
                *verdict.evidence,
                Evidence(
                    kind="method_results",
                    artifact=digest,
                    summary=f"{len(observations)} methods; {int(disagreement)} disagreements",
                ),
            ],
            key=lambda item: (item.kind, item.artifact, item.summary),
        )
        verdict = verdict.model_copy(update={"evidence": evidence})
        # Wall/resource failures are not deterministic semantic cache entries.
        if all(
            result.verdict is None or result.verdict.intrinsic_verdict != "ERROR"
            for result in results
        ):
            self.store.cache_verdict(key, verdict)
        return EngineResult(verdict, observations, key, False)

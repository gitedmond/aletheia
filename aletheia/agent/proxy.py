"""Allowlisted RE tools and validated claim collection without verifier feedback."""

import re
import time
from pathlib import Path
from typing import Literal, Protocol

import yaml
from pydantic import Field, JsonValue, TypeAdapter

from aletheia.agent.upstream import UpstreamCrash
from aletheia.heldout.guard import PrivateGuard
from aletheia.llm.provider import AgentBudgets, ToolFunction, ToolSpec
from aletheia.schema.canonical import canonical_bytes
from aletheia.schema.models import (
    Address,
    Algorithm,
    Call,
    Claim,
    ClaimId,
    ClaimSubmission,
    FunctionPurpose,
    FunctionSignature,
    RunId,
    Sha256,
    Source,
    Strict,
    Subject,
)


class Upstream(Protocol):
    def call(self, name: str, arguments: dict[str, JsonValue]) -> JsonValue: ...


class ReportClaim(Strict):
    type: Literal["algorithm_identity", "call_relation", "function_signature", "function_purpose"]
    subject_address: Address
    body: Algorithm | Call | FunctionSignature | FunctionPurpose
    confidence: float = Field(ge=0, le=1)
    rationale: str | None = None
    evidence_refs: list[str] = Field(default_factory=list[str])
    depends_on: list[str] = Field(default_factory=list[str])
    client_ref: str | None = None


class ReviseClaim(ReportClaim):
    claim_id: ClaimId | None = None


class Finish(Strict):
    note: str | None = None


class Allowlist(Strict):
    version: Literal["1.0"]
    upstream: Literal["pyghidra-mcp"]
    upstream_version: Literal["0.1.6"]
    tools: list[str]


def canonical_output(value: JsonValue) -> JsonValue:
    if isinstance(value, dict):
        return {
            k: canonical_output(v)
            for k, v in sorted(value.items())
            if k not in {"timestamp", "created_at", "updated_at", "load_time", "duration"}
        }
    if isinstance(value, list):
        return [canonical_output(v) for v in value]
    if isinstance(value, str) and re.fullmatch(r"0[xX][0-9a-fA-F]{1,16}", value):
        return f"0x{int(value, 16):08x}"
    return value


class HarnessProxy:
    def __init__(
        self,
        *,
        run_id: str,
        binary_sha256: str,
        source_id: str,
        upstream: Upstream,
        trajectory: Path,
        guard: PrivateGuard,
        budgets: AgentBudgets,
        allowlist: Path = Path("configs/proxy-allowlist.yaml"),
    ):
        self.run_id = TypeAdapter(RunId).validate_python(run_id)
        self.binary_sha256 = TypeAdapter(Sha256).validate_python(binary_sha256)
        self.source = Source(origin="agent", source_id=source_id)
        self.upstream, self.budgets = upstream, budgets.model_copy(deep=True)
        if any(p.is_symlink() for p in (allowlist, *allowlist.parents)):
            raise ValueError("allowlist cannot be a symlink")
        self.allowlist = Allowlist.model_validate(yaml.safe_load(allowlist.read_bytes()))
        if self.allowlist.tools != sorted(set(self.allowlist.tools)):
            raise ValueError("allowlist must be sorted and unique")
        self.trajectory = (
            guard.private_output(trajectory)
            if guard.split == "heldout"
            else guard.public_path(trajectory)
        )
        if self.trajectory.exists():
            raise ValueError("trajectory already exists")
        self.trajectory.parent.mkdir(parents=True, exist_ok=True)
        self.claims: list[Claim] = []
        self.active: dict[tuple[str, str, str], Claim] = {}
        self.client_refs: dict[str, str] = {}
        self.evidence_ids: set[str] = set()
        self.re_calls = self.harness_calls = self.sequence = 0
        self.finished = False

    @property
    def active_claims(self) -> list[Claim]:
        return sorted(self.active.values(), key=lambda claim: claim.claim_id)

    @property
    def exhausted(self) -> bool:
        return (
            self.re_calls >= self.budgets.re_tool_calls
            or self.harness_calls >= self.budgets.harness_tool_calls
        )

    @staticmethod
    def harness_tools() -> list[ToolSpec]:
        return [
            ToolSpec(
                function=ToolFunction(
                    name=name,
                    description=description,
                    parameters=TypeAdapter(dict[str, JsonValue]).validate_python(
                        model.model_json_schema()
                    ),
                )
            )
            for name, model, description in [
                (
                    "report_claim",
                    ReportClaim,
                    "Submit one claim and your probability it is correct.",
                ),
                (
                    "revise_claim",
                    ReviseClaim,
                    "Replace your active claim using its ID or client_ref.",
                ),
                ("finish", Finish, "End this run; submitted claims will be evaluated later."),
            ]
        ]

    @staticmethod
    def key(claim: Claim) -> tuple[str, str, str]:
        return (
            claim.subject.address,
            claim.type,
            claim.body.callee if isinstance(claim.body, Call) else "",
        )

    def report(self, arguments: dict[str, JsonValue], *, revise: bool) -> dict[str, JsonValue]:
        data = (
            ReviseClaim.model_validate(arguments)
            if revise
            else ReportClaim.model_validate(arguments)
        )
        if any(ref not in self.evidence_ids for ref in data.evidence_refs):
            return {"status": "error", "reason": "invalid_evidence_ref"}
        parents = [self.client_refs.get(ref, ref) for ref in data.depends_on]
        known = {claim.claim_id for claim in self.claims}
        if any(parent not in known for parent in parents):
            return {"status": "error", "reason": "invalid_dependency"}
        previous = None
        if revise:
            assert isinstance(data, ReviseClaim)
            identity = data.claim_id or self.client_refs.get(data.client_ref or "")
            previous = next(
                (claim for claim in self.active.values() if claim.claim_id == identity), None
            )
            if previous is None:
                return {"status": "error", "reason": "unknown_active_claim"}
        elif data.client_ref is not None and data.client_ref in self.client_refs:
            return {"status": "error", "reason": "duplicate_client_ref"}
        submission = ClaimSubmission(
            run_id=self.run_id,
            source=self.source,
            binary_sha256=self.binary_sha256,
            subject=Subject(address=data.subject_address),
            type=data.type,
            body=data.body,
            confidence=data.confidence,
            confidence_source="stated",
            rationale=data.rationale,
            evidence_refs=data.evidence_refs,
            depends_on=parents,
            supersedes=previous.claim_id if previous else None,
            algorithms_version="2.0",
            client_ref=data.client_ref,
        )
        claim = Claim.intake(submission)
        key = self.key(claim)
        if previous and key != self.key(previous):
            return {"status": "error", "reason": "revision_key_mismatch"}
        if key in self.active and previous is None:
            return {"status": "error", "reason": "duplicate_active_claim", "action": "revise_claim"}
        if previous and previous.claim_id in parents:
            return {"status": "error", "reason": "self_dependency"}
        self.claims.append(claim)
        self.active[key] = claim
        for ref, identity in list(self.client_refs.items()):
            if previous and identity == previous.claim_id:
                self.client_refs[ref] = claim.claim_id
        if data.client_ref:
            self.client_refs[data.client_ref] = claim.claim_id
        return {"status": "ok", "claim_id": claim.claim_id}

    def call(self, name: str, arguments: dict[str, JsonValue]) -> dict[str, JsonValue]:
        self.sequence += 1
        call_id, start = f"tc-{self.sequence:04d}", time.monotonic()
        if self.finished:
            result: dict[str, JsonValue] = {"status": "error", "reason": "run_finished"}
        elif name == "finish":
            Finish.model_validate(arguments)
            self.finished = True
            result = {"status": "ok"}
        elif name in {"report_claim", "revise_claim"}:
            if self.harness_calls >= self.budgets.harness_tool_calls:
                result = {"status": "error", "reason": "budget_exhausted", "action": "call finish"}
            else:
                self.harness_calls += 1
                try:
                    result = self.report(arguments, revise=name == "revise_claim")
                except ValueError:
                    result = {"status": "error", "reason": "invalid_claim"}
        elif name not in self.allowlist.tools:
            result = {"status": "error", "reason": "tool_not_allowed"}
        elif self.re_calls >= self.budgets.re_tool_calls:
            result = {"status": "error", "reason": "budget_exhausted", "action": "call finish"}
        else:
            self.re_calls += 1
            result = {"status": "error", "reason": "upstream_timeout"}
            try:
                for attempt in range(2):
                    try:
                        output = self.upstream.call(name, arguments)
                        result = {"status": "ok", "result": canonical_output(output)}
                        self.evidence_ids.add(call_id)
                        break
                    except TimeoutError:
                        if attempt:
                            raise
            except TimeoutError:
                result = {"status": "error", "reason": "upstream_timeout"}
            except ValueError:
                result = {"status": "error", "reason": "upstream_tool_error"}
            except UpstreamCrash:
                result = {"status": "error", "reason": "ghidra_crash"}
        result = {"tool_call_id": call_id, **result}
        with self.trajectory.open("ab") as stream:
            stream.write(
                canonical_bytes(
                    {
                        "tool_call_id": call_id,
                        "tool": name,
                        "arguments": arguments,
                        "response": result,
                        "elapsed_seconds": time.monotonic() - start,
                    }
                )
                + b"\n"
            )
        return result

"""Deterministic test scenarios and public JSONL intake, outside the verifier."""

import random
from dataclasses import dataclass
from pathlib import Path

from aletheia.schema.canonical import canonical_bytes, content_hash
from aletheia.schema.models import (
    REGISTRY,
    REGISTRY_V1,
    Algorithm,
    Call,
    Claim,
    ClaimSubmission,
    GroundTruth,
    Kind,
    ManifestInput,
    RunManifest,
    Source,
    Subject,
    Targets,
)
from aletheia.sources.base import BinaryRef

SOURCE = Source(origin="scripted", source_id="scripted:v1")


def _active_key(claim: ClaimSubmission) -> tuple[str, str, str]:
    # Case allocation omits run identity; call kind is deliberately not an active-key field.
    callee = claim.body.callee if isinstance(claim.body, Call) else ""
    return claim.subject.address, claim.type, callee


def _order(claim: ClaimSubmission) -> tuple[int, str, str, str, bytes]:
    return (
        int(claim.subject.address, 16),
        claim.type,
        claim.body.callee if isinstance(claim.body, Call) else "",
        claim.body.kind if isinstance(claim.body, Call) else "",
        canonical_bytes(claim.body),
    )


@dataclass(frozen=True)
class ScriptedCase:
    manifest: RunManifest
    claims: list[Claim]


@dataclass(frozen=True)
class ScriptedResult:
    cases: list[ScriptedCase]
    exclusions: dict[str, int]


def generate(gt: GroundTruth, manifest: ManifestInput, seed: int = 20261013) -> ScriptedResult:
    """Generate first-fit scenario cases; supplied manifest pins come from the caller."""
    if manifest.binaries != [gt.binary_sha256]:
        raise ValueError("scripted manifest binary identity differs from ground truth")
    functions = sorted(gt.functions, key=lambda f: int(f.address, 16))
    addresses = [function.address for function in functions]
    if len(addresses) != len(set(addresses)):
        raise ValueError("duplicate ground-truth function address")
    rng = random.Random(seed)
    registry = REGISTRY_V1 if gt.algorithms_version == "1.0" else REGISTRY
    families = sorted(registry)
    scenarios: dict[str, list[ClaimSubmission]] = {"correct": [], "family_only": [], "mutated": []}

    def add(scenario: str, address: str, body: Algorithm | Call) -> None:
        scenarios[scenario].append(
            ClaimSubmission(
                run_id="r_" + "0" * 16,
                source=SOURCE,
                binary_sha256=gt.binary_sha256,
                subject=Subject(address=address),
                type="call_relation" if isinstance(body, Call) else "algorithm_identity",
                body=body,
                confidence=0.9,
                confidence_source="scripted",
                derived_from="scripted_mutated" if scenario == "mutated" else "scripted_correct",
                algorithms_version=gt.algorithms_version,
            )
        )

    no_candidate = 0
    for function in functions:
        algorithm = function.algorithm
        if function.scorable:
            if algorithm.family == "none":
                add("mutated", function.address, Algorithm(family=rng.choice(families)))
            else:
                add("correct", function.address, Algorithm.model_validate(algorithm.model_dump()))
                add("family_only", function.address, Algorithm(family=algorithm.family))
                siblings = sorted(v for v in registry[algorithm.family] if v != algorithm.variant)
                mutation = (
                    Algorithm(family=algorithm.family, variant=rng.choice(siblings))
                    if siblings
                    else Algorithm(
                        family=rng.choice(
                            [family for family in families if family != algorithm.family]
                        )
                    )
                )
                add("mutated", function.address, mutation)
        edges: list[tuple[str, Kind]] = sorted(
            {
                (edge.target, edge.kind)
                for edge in function.callees
                if edge.kind in ("direct", "tail")
            }
        )
        for callee, kind in edges:
            add("correct", function.address, Call(callee=callee, kind=kind))
            candidates = [
                address
                for address in addresses
                if address != function.address and (address, kind) not in edges
            ]
            if candidates:
                add("mutated", function.address, Call(callee=rng.choice(candidates), kind=kind))
            else:
                no_candidate += 1

    cases: list[ScriptedCase] = []
    for scenario, submissions in scenarios.items():
        bins: list[list[ClaimSubmission]] = []
        keys: list[set[tuple[str, str, str]]] = []
        for submission in sorted(submissions, key=_order):
            key = _active_key(submission)
            index = next((i for i, used in enumerate(keys) if key not in used), len(bins))
            if index == len(bins):
                bins.append([])
                keys.append(set())
            bins[index].append(submission)
            keys[index].add(key)
        for index, members in enumerate(bins):
            source_config = manifest.source_config | {
                "origin": SOURCE.origin,
                "source_id": SOURCE.source_id,
                "scenario": scenario,
                "case_index": index,
                "seed": seed,
                "claims_hash": content_hash(
                    [member.model_dump(mode="json", exclude={"run_id"}) for member in members]
                ),
            }
            value = ManifestInput.model_validate(
                manifest.model_dump()
                | {"source_config": source_config, "seeds": manifest.seeds | {"scripted": seed}}
            )
            run = RunManifest.create(value)
            claims = [
                Claim.intake(
                    ClaimSubmission.model_validate(member.model_dump() | {"run_id": run.run_id})
                )
                for member in members
            ]
            cases.append(ScriptedCase(run, claims))
    exclusions = {"no_wrong_callee_candidate": no_candidate} if no_candidate else {}
    return ScriptedResult(cases, exclusions)


class ScriptedSource:
    origin = "scripted"
    source_id = "scripted:v1"

    def __init__(self, path: Path, run_id: str):
        self.path = path
        self.run_id = run_id

    def produce(self, binary: BinaryRef, targets: Targets) -> list[Claim]:
        """Read only submissions; reject foreign identities and competing active claims."""
        if (binary.binary_sha256, binary.variant_id) != (targets.binary_sha256, targets.variant_id):
            raise ValueError("scripted public binary/targets identity mismatch")
        claims: list[Claim] = []
        keys: set[tuple[str, str, str]] = set()
        for number, line in enumerate(self.path.read_bytes().splitlines(), 1):
            submission = ClaimSubmission.model_validate_json(line)
            if (
                submission.binary_sha256 != binary.binary_sha256
                or submission.run_id != self.run_id
                or submission.source != SOURCE
                or submission.confidence_source != "scripted"
            ):
                raise ValueError(f"scripted submission identity mismatch on line {number}")
            key = _active_key(submission)
            if key in keys:
                raise ValueError(f"duplicate_active_claim on line {number}")
            keys.add(key)
            claims.append(Claim.intake(submission))
        return claims

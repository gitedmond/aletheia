"""Public claim grouping and independent validation of composite evidence."""

from collections import Counter
from typing import Literal, cast

from pydantic import Field

from aletheia.analysis.ghidra_session import GhidraAnalysis
from aletheia.schema.models import Address, Claim, FunctionPurpose, Record, Sha256, Strict, Verdict
from aletheia.verify.probes.inputs import generate_inputs
from aletheia.verify.probes.oracles import byte_pair
from aletheia.verify.probes.pack import HexInput, Pack
from aletheia.verify.probes.purpose import PurposeMapping
from aletheia.verify.static.arity import Arity, infer_arity

Role = Literal["init", "update", "final", "crypt"]
HASH_ROLES = ("init", "update", "final")
CIPHER_ARITIES = {"init": 3, "crypt": 3}
HASH_ARITIES = {"init": 1, "update": 3, "final": 2}


class GroupMember(Strict):
    role: Role
    subject: Address


class GroupTrial(Strict):
    final_shape: Literal["ctx_out", "out_ctx", "roles_a", "roles_b"]
    input_hex: HexInput
    key_hex: HexInput | None = None
    chunks: list[HexInput]
    expected_hex: HexInput
    actual_hex: HexInput
    status: str
    instructions: int = Field(ge=0)
    imports_called: list[str]


class GroupEvidence(Record):
    binary_sha256: Sha256
    family: str
    members: list[GroupMember]
    arity: dict[Role, Arity]
    observations: list[GroupTrial]
    planned_inputs_per_shape: int = Field(ge=0)
    skipped_inputs: list[dict[str, str | int]]
    minimization: list[GroupTrial]


def collect_groups(claims: list[Claim], mapping: PurposeMapping) -> dict[str, list[Claim]]:
    groups: dict[str, list[Claim]] = {}
    for claim in claims:
        if isinstance(claim.body, FunctionPurpose):
            scope = mapping.map.get(claim.body.category)
            if scope is not None and scope.composite:
                groups.setdefault(scope.pack, []).append(claim)
    return {
        family: sorted(members, key=lambda claim: claim.claim_id)
        for family, members in sorted(groups.items())
    }


def public_members(claims: list[Claim]) -> list[GroupMember]:
    purpose: list[tuple[Claim, str]] = []
    for claim in claims:
        if isinstance(claim.body, FunctionPurpose):
            purpose.append((claim, claim.body.category))
    roles: list[tuple[Claim, Role]] = []
    for claim, category in purpose:
        suffix = category.rsplit(".", 1)[1]
        if suffix in HASH_ROLES:
            roles.append((claim, cast(Role, suffix)))
    if len(roles) != len(purpose):
        ordered = sorted(purpose, key=lambda item: (item[0].subject.address, item[0].claim_id))
        roles = [
            (claim, "init" if index == 0 else "crypt") for index, (claim, _) in enumerate(ordered)
        ]
    return sorted(
        (
            GroupMember.model_validate({"subject": claim.subject.address, "role": role})
            for claim, role in roles
        ),
        key=lambda member: (member.role, member.subject),
    )


def group_preconditions(
    evidence: GroupEvidence,
    members: list[GroupMember],
    analysis: GhidraAnalysis,
    pack: Pack,
    verdict: Verdict,
) -> tuple[bool, bool, bool, bool, bool, str | None]:
    if (
        evidence.binary_sha256 != analysis.binary_sha256
        or evidence.family != pack.family
        or evidence.members != members
    ):
        raise ValueError("composite evidence identity mismatch")
    binding = {member.role: infer_arity(member.subject, analysis) for member in members}
    if evidence.arity != binding:
        raise ValueError("composite binding evidence mismatch")
    cipher = pack.family == "rc4"
    bound = all(
        role in binding and binding[role].decisive and binding[role].arity == count
        for role, count in (CIPHER_ARITIES if cipher else HASH_ARITIES).items()
    )
    shapes = ["roles_a", "roles_b"] if cipher else ["ctx_out", "out_ctx"]
    size = 0 if cipher else {"md5": 16, "sha1": 20, "sha256": 32}[pack.family]
    rows = evidence.observations
    clean = all(row.status != "state_dependent" for row in rows)
    execution = next(
        (row.status for row in rows if row.status not in {"match", "mismatch", "state_dependent"}),
        None,
    )

    def width_ok(row: GroupTrial) -> bool:
        if cipher:
            return (
                row.key_hex is not None
                and len(row.expected_hex) == len(row.actual_hex) == len(row.input_hex)
                and "".join(row.chunks) == row.input_hex
            )
        return (
            row.key_hex is None
            and len(row.expected_hex) == len(row.actual_hex) == size * 2
            and "".join(row.chunks) == row.input_hex
        )

    widths = bool(rows) and all(width_ok(row) and 1 <= len(row.chunks) <= 4 for row in rows)
    inputs = pack.inputs.model_copy(
        update={"random": pack.inputs.random.model_copy(update={"count": 16})}
    )
    messages = generate_inputs(inputs)
    wanted = Counter(
        (byte_pair(value)[0].hex(), byte_pair(value)[1].hex()) if cipher else (value.hex(), None)
        for value in messages
    )
    complete = not evidence.skipped_inputs and evidence.planned_inputs_per_shape == sum(
        wanted.values()
    )
    for shape in shapes:
        complete = (
            complete
            and Counter((row.input_hex, row.key_hex) for row in rows if row.final_shape == shape)
            == wanted
        )
    ce = verdict.counterexample
    last = evidence.minimization[-2:]
    reproduced = (
        ce is not None
        and ce.variant == "std"
        and ce.call_shape == ("composite_rc4" if cipher else "composite_ctx_out+out_ctx")
        and len(last) == 2
        and [row.final_shape for row in last] == shapes
        and all(
            row.input_hex == ce.input_hex
            and row.status == "mismatch"
            and width_ok(row)
            and row.expected_hex != row.actual_hex
            for row in last
        )
        and len({row.key_hex for row in last}) == 1
        and "".join(row.expected_hex for row in last) == ce.expected_hex
        and "".join(row.actual_hex for row in last) == ce.actual_hex
    )
    return bound, clean, widths, reproduced, complete, execution

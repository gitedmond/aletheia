"""Phase 1A records. Optional fields have explicit defaults before hashing."""

import re
from typing import Annotated, Literal, Self

from pydantic import BaseModel, ConfigDict, Field, JsonValue, model_validator

from aletheia.schema.canonical import content_hash

Sha256 = Annotated[str, Field(pattern=r"^[0-9a-f]{64}$")]
ClaimId = Annotated[str, Field(pattern=r"^c_[0-9a-f]{24}$")]
RunId = Annotated[str, Field(pattern=r"^r_[0-9a-f]{16}$")]
JobId = Annotated[str, Field(pattern=r"^j_[0-9a-f]{64}$")]
Address = Annotated[str, Field(pattern=r"^0x(?:[0-9a-f]{8}|[1-9a-f][0-9a-f]{8,15})$")]
Target = Annotated[
    str,
    Field(
        pattern=r"^(?:0x(?:[0-9a-f]{8}|[1-9a-f][0-9a-f]{8,15})|import:[A-Za-z_][A-Za-z0-9_.$@]*)$"
    ),
]
Digest = Annotated[str, Field(pattern=r"^sha256:[0-9a-f]{64}$")]
Nonnegative = Annotated[int, Field(ge=0)]
Positive = Annotated[int, Field(gt=0)]
Kind = Literal["direct", "tail", "indirect"]
Outcome = Literal[
    "VERIFIED",
    "CONTRADICTED",
    "INCONCLUSIVE",
    "UNVERIFIABLE",
    "NOT_CHECKED",
    "ERROR",
    "INVALID_CLAIM",
]
Strength = Literal["E1", "E2"]
JobType = Literal[
    "ghidra_analyze",
    "findcrypt_scan",
    "capa_scan",
    "verify_static",
    "verify_probe",
    "verify_composite",
]
REGISTRY_V1: dict[str, tuple[str, ...]] = {
    "crc32": ("ieee", "jamcrc", "crc32c", "bzip2"),
    "adler32": ("zlib",),
    "fletcher16": ("std",),
    "fnv": ("fnv1a-32", "fnv1-32", "fnv1a-64", "fnv1-64"),
    "djb2": ("add", "xor"),
    "base64": ("std-padded", "url-nopad", "std-padded-decode"),
}
REGISTRY = {
    **REGISTRY_V1,
    "md5": ("std",),
    "sha1": ("std",),
    "sha256": ("std",),
    "hex": ("lower", "upper"),
}
REASONS = {
    "fortify_fail",
    "composite_incomplete",
    "arity_not_decisive",
    "width_ambiguous",
    "unknown_category",
    "state_dependent",
    "unsupported_import",
    "no_matching_call_shape",
    "budget_exhausted",
    "emulation_fault",
    "binding_not_verified",
    "indirect_unresolved",
    "no_pack",
    "subject_not_found",
    "wall_timeout",
    "internal",
    "unknown_family",
    "duplicate_active_claim",
    "unknown_variant",
    "unsupported_relocation",
}


class Strict(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True, allow_inf_nan=False)


class Record(Strict):
    schema_version: Literal["1.0"] = "1.0"


class Source(Strict):
    origin: Literal["scripted", "tool", "agent", "human", "classifier"]
    source_id: str = Field(min_length=1)
    shares_backend: bool = False

    @model_validator(mode="after")
    def shared_findcrypt(self) -> Self:
        if self.source_id.startswith("tool:findcrypt") and not self.shares_backend:
            raise ValueError("FindCrypt source must declare shares_backend")
        return self


class Subject(Strict):
    kind: Literal["function"] = "function"
    address: Address


class Algorithm(Strict):
    family: str
    variant: str | None = None

    @model_validator(mode="after")
    def registered(self) -> Self:
        variants = REGISTRY.get(self.family)
        if variants is None:
            raise ValueError("unknown_family")
        if self.variant is not None and self.variant not in variants:
            raise ValueError("unknown_variant")
        return self


class GroundAlgorithm(Strict):
    family: str
    variant: str | None = None

    @model_validator(mode="after")
    def registered(self) -> Self:
        if self.family == "none":
            if self.variant is not None:
                raise ValueError("none requires null variant")
        else:
            Algorithm(family=self.family, variant=self.variant)
        return self


Role = Literal["seed", "buf", "len", "cstr", "out", "out_len", "ctx", "key", "other"]


class SignatureParam(Strict):
    type: str = Field(min_length=1)
    role: Role | None = None
    name: str | None = None


class FunctionSignature(Strict):
    return_type: str = Field(min_length=1)
    params: list[SignatureParam]


class FunctionPurpose(Strict):
    category: str
    proposed_name: str | None = None
    summary: str | None = None

    @model_validator(mode="after")
    def known_category(self) -> Self:
        from aletheia.schema.taxonomy import Taxonomy

        if self.category not in Taxonomy.bundled().leaves:
            raise ValueError("unknown_category")
        return self


class Call(Strict):
    callee: Target
    kind: Kind


class ClaimSubmission(Record):
    run_id: RunId
    source: Source
    binary_sha256: Sha256
    subject: Subject
    type: Literal["algorithm_identity", "call_relation", "function_signature", "function_purpose"]
    body: Algorithm | Call | FunctionSignature | FunctionPurpose
    confidence: Annotated[float, Field(ge=0, le=1)]
    confidence_source: Literal["stated", "tool_default", "scripted"]
    rationale: str | None = None
    evidence_refs: list[str] = Field(default_factory=list)
    depends_on: list[str] = Field(default_factory=list)
    supersedes: ClaimId | None = None
    derived_from: (
        Literal["capa_rule", "constant_xref", "scripted_correct", "scripted_mutated"] | None
    ) = None
    tool_label: str | None = None
    algorithms_version: Literal["1.0", "2.0"] = "1.0"
    client_ref: str | None = None

    @model_validator(mode="after")
    def correct_body(self) -> Self:
        bodies = {
            "algorithm_identity": Algorithm,
            "call_relation": Call,
            "function_signature": FunctionSignature,
            "function_purpose": FunctionPurpose,
        }
        if type(self.body) is not bodies[self.type]:
            raise ValueError("claim type and body disagree")
        if (
            self.algorithms_version == "1.0"
            and isinstance(self.body, Algorithm)
            and self.body.family not in REGISTRY_V1
        ):
            raise ValueError("algorithm family requires algorithms_version 2.0")
        if self.source.origin == "tool" and self.depends_on:
            raise ValueError("tool sources cannot declare reasoning dependencies")
        return self


class Claim(ClaimSubmission):
    claim_id: ClaimId

    @classmethod
    def intake(cls, submission: ClaimSubmission) -> Self:
        value = submission.model_dump()
        return cls.model_validate(value | {"claim_id": "c_" + content_hash(submission)[:24]})

    @model_validator(mode="after")
    def deterministic_id(self) -> Self:
        expected = "c_" + content_hash(self.model_dump(mode="json", exclude={"claim_id"}))[:24]
        if self.claim_id != expected:
            raise ValueError("claim_id does not match canonical content")
        return self


class Budget(Strict):
    instructions: Nonnegative = 0


class Aspect(Strict):
    verdict: Outcome
    strength: Strength | None = None
    method: str = Field(min_length=1)


class Evidence(Strict):
    kind: str
    artifact: Digest
    summary: str


class Counterexample(Strict):
    call_shape: str
    input_hex: Annotated[str, Field(pattern=r"^(?:[0-9a-f]{2})*$")]
    expected_hex: Annotated[str, Field(pattern=r"^(?:[0-9a-f]{2})*$")]
    actual_hex: Annotated[str, Field(pattern=r"^(?:[0-9a-f]{2})*$")]
    variant: str
    matches_variant: str | None = None


AspectName = Literal[
    "output_match",
    "edge_exists",
    "arity",
    "return_width",
    "param_widths",
    "param_types",
    "category_behavior",
]


class Verdict(Record):
    claim_id: ClaimId
    intrinsic_verdict: Outcome
    strength: Strength | None = None
    aspects: dict[AspectName, Aspect] = Field(default_factory=lambda: dict[AspectName, Aspect]())
    graph_status: Literal["OK"] = "OK"
    methods_run: list[str] = Field(default_factory=list)
    reason: str | None = None
    harness: str | None = None
    evidence: list[Evidence] = Field(default_factory=lambda: list[Evidence]())
    counterexample: Counterexample | None = None
    budget_used: Budget = Field(default_factory=Budget)
    verifier_version: str
    env_digest: Digest

    @model_validator(mode="after")
    def requirements(self) -> Self:
        if self.methods_run != sorted(set(self.methods_run)):
            raise ValueError("methods_run must be sorted and unique")
        if self.intrinsic_verdict in ("INCONCLUSIVE", "UNVERIFIABLE", "ERROR", "INVALID_CLAIM"):
            if not self.reason:
                raise ValueError("non-decisive failure requires a reason")
        if (
            self.reason
            and self.reason not in REASONS
            and not re.fullmatch(r"unsupported_import:[A-Za-z_][A-Za-z0-9_.$@]*", self.reason)
        ):
            raise ValueError("unknown reason code")
        if self.intrinsic_verdict in ("VERIFIED", "CONTRADICTED"):
            if not self.harness or self.strength is None:
                raise ValueError("decisive verdict requires harness and strength")
        return self


class Edge(Strict):
    target: Target
    kind: Kind


class GroundFunction(Strict):
    address: Address
    size: Positive
    name: str
    algorithm: GroundAlgorithm
    clone_of: str | None = None
    scorable: bool
    exclusion_reason: str | None = None
    callees: list[Edge] = Field(default_factory=lambda: list[Edge]())
    source_signature: str | None = None


class AbiType(Strict):
    model_config = ConfigDict(serialize_by_alias=True)
    kind: Literal["void", "int", "ptr", "float", "other"] = Field(alias="class")
    width: Nonnegative | None
    declared: str | None = None

    @model_validator(mode="after")
    def valid_width(self) -> Self:
        widths = {"void": {0}, "int": {8, 16, 32, 64}, "ptr": {64}, "float": {32, 64}}
        if self.kind != "other" and self.width not in widths[self.kind]:
            raise ValueError("invalid ABI class/width pair")
        if self.kind == "other" and not self.declared:
            raise ValueError("complex ABI types require their declared IR type")
        return self


class AbiSignature(Strict):
    model_config = ConfigDict(serialize_by_alias=True)
    return_type: AbiType = Field(alias="return")
    params: list[AbiType]
    abi_complex: bool
    variadic: bool

    @model_validator(mode="after")
    def complex_types(self) -> Self:
        if not self.abi_complex and any(
            value.kind == "other" for value in [self.return_type, *self.params]
        ):
            raise ValueError("complex ABI type requires abi_complex")
        return self


class SourceSignature(Strict):
    return_type: str
    params: list[str]
    variadic: bool


class GroundFunctionV2(GroundFunction):
    category: str | None
    acceptable_categories: list[str]
    abi_signature: AbiSignature | None
    source_types: SourceSignature | None
    roles: list[Role]

    @model_validator(mode="after")
    def category_contract(self) -> Self:
        from aletheia.schema.taxonomy import Taxonomy

        leaves = set(Taxonomy.bundled().leaves)
        if self.category is not None and self.category not in leaves:
            raise ValueError("unknown ground-truth category")
        if (
            self.acceptable_categories != sorted(set(self.acceptable_categories))
            or not set(self.acceptable_categories) <= leaves
        ):
            raise ValueError("invalid acceptable categories")
        if self.category is not None and self.category not in self.acceptable_categories:
            raise ValueError("acceptable categories must include the primary category")
        if self.scorable and (self.category is None or self.abi_signature is None):
            raise ValueError("scorable v2 functions require category and compiler ABI")
        return self


class ExcludedFunction(Strict):
    name: str
    reason: Literal["fully_inlined", "cold_split", "trivial", "abi_unavailable"]


class GroundTruth(Strict):
    schema_version: Literal["1.0", "2.0"] = "1.0"
    binary_sha256: Sha256
    program_id: str
    variant_id: str
    build_flags: str
    algorithms_version: Literal["1.0", "2.0"] = "1.0"
    functions: list[GroundFunction | GroundFunctionV2]
    excluded_functions: list[ExcludedFunction] = Field(
        default_factory=lambda: list[ExcludedFunction]()
    )

    @model_validator(mode="after")
    def registry_version(self) -> Self:
        if any(
            isinstance(fn, GroundFunctionV2) != (self.schema_version == "2.0")
            for fn in self.functions
        ):
            raise ValueError("ground-truth function fields differ from schema version")
        if self.schema_version == "1.0" and any(
            fn.reason == "abi_unavailable" for fn in self.excluded_functions
        ):
            raise ValueError("ABI exclusions require ground-truth schema 2.0")
        if self.algorithms_version == "1.0" and any(
            fn.algorithm.family not in REGISTRY_V1 and fn.algorithm.family != "none"
            for fn in self.functions
        ):
            raise ValueError("algorithm family requires algorithms_version 2.0")
        return self


class Targets(Record):
    binary_sha256: Sha256
    variant_id: str
    targets: list[Address]

    @model_validator(mode="after")
    def ordered(self) -> Self:
        if self.targets != sorted(set(self.targets), key=lambda a: int(a, 16)):
            raise ValueError("targets must be sorted numerically and unique")
        return self


class Grade(Record):
    claim_id: ClaimId
    grader_version: str
    on_target: bool
    phantom: bool
    family_correct: bool | None = None
    variant_correct: bool | None = None
    edge_correct: bool | None = None
    correct_strict: bool | None
    correct_lenient: bool | None
    verdict_correct: bool | None = None
    correct_claimed: bool | None = Field(default=None, exclude_if=lambda value: value is None)
    correct_partial: float | None = Field(
        default=None, ge=0, le=1, exclude_if=lambda value: value is None
    )
    role_correct: bool | None = Field(default=None, exclude_if=lambda value: value is None)
    family_credit_suppressed: bool = Field(default=False, exclude_if=lambda value: not value)
    strict_exclusion_reason: str | None = Field(
        default=None, exclude_if=lambda value: value is None
    )
    lenient_exclusion_reason: str | None = Field(
        default=None, exclude_if=lambda value: value is None
    )
    aspect_correct: dict[AspectName, bool | None] = Field(
        default_factory=lambda: dict[AspectName, bool | None](), exclude_if=lambda value: not value
    )


class ManifestInput(Record):
    source_config: dict[str, JsonValue]
    binaries: list[Sha256] = Field(min_length=1, max_length=1)
    versions: dict[str, JsonValue]
    image_digests: dict[str, Digest]
    analysis_options_hash: Sha256
    pack_hashes: dict[str, Sha256]
    mapping_hashes: dict[str, Sha256]
    algorithms_version: Literal["1.0", "2.0"] = "1.0"
    verifier_version: str
    grader_version: str
    seeds: dict[str, int]


class RunManifest(ManifestInput):
    run_id: RunId
    created_at: str | None = Field(default=None, json_schema_extra={"informational": True})

    @classmethod
    def create(cls, value: ManifestInput, created_at: str | None = None) -> Self:
        return cls.model_validate(
            value.model_dump()
            | {"run_id": "r_" + content_hash(value)[:16], "created_at": created_at}
        )

    @model_validator(mode="after")
    def deterministic_id(self) -> Self:
        value = self.model_dump(mode="json", exclude={"run_id", "created_at"})
        if self.run_id != "r_" + content_hash(value)[:16]:
            raise ValueError("run_id does not match manifest inputs")
        return self


InputPath = Annotated[
    str,
    Field(
        pattern=r"^in/(?:[A-Za-z0-9_-]+/)*[0-9a-f]{64}\.[a-z0-9]+$",
        json_schema_extra={"not": {"pattern": r"(^|/)private(/|$)"}},
    ),
]


class JobInput(Record):
    type: JobType
    inputs: dict[str, InputPath] = Field(default_factory=dict)
    params: dict[str, JsonValue] = Field(default_factory=dict)

    @model_validator(mode="after")
    def input_paths(self) -> Self:
        for path in self.inputs.values():
            if "private" in path.split("/"):
                raise ValueError("job inputs cannot include private/")
        return self


class Job(JobInput):
    job_id: JobId

    @classmethod
    def create(cls, kind: JobType, inputs: dict[str, str], params: dict[str, JsonValue]) -> Self:
        value = JobInput(type=kind, inputs=inputs, params=params)
        return cls.model_validate(value.model_dump() | {"job_id": "j_" + content_hash(value)})

    @model_validator(mode="after")
    def deterministic_id(self) -> Self:
        if self.job_id != "j_" + content_hash(self.model_dump(mode="json", exclude={"job_id"})):
            raise ValueError("job_id does not match job input")
        return self


class JobResult(Record):
    job_id: JobId
    status: Literal["ok", "error"]
    error_code: Literal["wall_timeout", "oom", "internal", "bad_input"] | None = None
    output: dict[str, JsonValue] = Field(default_factory=dict)
    budget_used: Budget = Field(default_factory=Budget)

    @model_validator(mode="after")
    def coherent_status(self) -> Self:
        if (self.status == "error") != (self.error_code is not None):
            raise ValueError("error status requires a code; ok status forbids it")
        return self

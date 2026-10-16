"""Strict Phase 1A pack declarations and safe YAML loading."""

from pathlib import Path
from typing import Annotated, Literal, Protocol, Self, cast

import yaml
from pydantic import Field, model_validator

from aletheia.schema.models import REGISTRY, Strict
from aletheia.verify.probes.oracles import ORACLE_VARIANTS

type Role = Literal["seed", "buf", "len", "cstr", "out"]
Identifier = Annotated[str, Field(pattern=r"^[a-z][a-z0-9_]*$")]
HexInput = Annotated[str, Field(pattern=r"^(?:[0-9a-f]{2})*$")]
SHAPES: dict[str, list[Role]] = {
    "seed_buf_len": ["seed", "buf", "len"],
    "buf_len": ["buf", "len"],
    "buf_len_digest_out": ["buf", "len", "out"],
    "out_buf_len_digest": ["out", "buf", "len"],
    "buf_len16": ["buf", "len"],
    "buf_len_decode_out": ["buf", "len", "out"],
    "cstr": ["cstr"],
    "buf_len_out": ["buf", "len", "out"],
}
FAMILY_SHAPES: dict[str, set[str]] = {
    "crc32": {"seed_buf_len", "buf_len"},
    "adler32": {"seed_buf_len", "buf_len"},
    "fnv": {"buf_len"},
    "djb2": {"buf_len", "cstr"},
    "base64": {"buf_len_out", "buf_len_decode_out"},
    "fletcher16": {"buf_len16"},
    **{name: {"buf_len_digest_out", "out_buf_len_digest"} for name in ("md5", "sha1", "sha256")},
}


class CallShape(Strict):
    id: Identifier
    roles: list[Role]
    return_width: Literal[16, 32, 64]
    comparison: Literal["return_output", "output"] = "return_output"
    out_size: Literal["base64_encode", "base64_decode", "md5", "sha1", "sha256"] | None = None

    @model_validator(mode="after")
    def semantics(self) -> Self:
        digest_shape = self.id in {"buf_len_digest_out", "out_buf_len_digest"}
        if digest_shape != (self.comparison == "output"):
            raise ValueError("digest shapes compare only their fixed output")
        if digest_shape != (self.out_size in {"md5", "sha1", "sha256"}):
            raise ValueError("digest shapes require a fixed digest allocation")
        allocation = {"buf_len_out": "base64_encode", "buf_len_decode_out": "base64_decode"}.get(
            self.id
        )
        if not digest_shape and self.out_size != allocation:
            raise ValueError("call shape output allocation mismatch")
        if self.roles != SHAPES.get(self.id):
            raise ValueError("unknown call shape or role order")
        if ("out" in self.roles) != (self.out_size is not None):
            raise ValueError("output shape must declare its output allocation")
        width = 16 if self.id == "buf_len16" else (64 if "out" in self.roles else 32)
        if self.return_width != width:
            raise ValueError("return width does not match the Phase 1A call shape")
        return self

    def output_size(self, input_len: int) -> int:
        if input_len < 0:
            raise ValueError("negative input length")
        if self.out_size is None:
            return 0
        if self.out_size in {"md5", "sha1", "sha256"}:
            return {"md5": 16, "sha1": 20, "sha256": 32}[self.out_size]
        if self.out_size == "base64_decode":
            return max(1, input_len)
        return 4 * ((input_len + 2) // 3) + 4


def _empty_bindings() -> dict[Literal["seed"], int]:
    return {}


class VariantProbe(Strict):
    oracle: Identifier
    input_encoding: Literal["raw", "base64"] = "raw"
    call_shapes: list[Identifier] | None = None
    bind: dict[Literal["seed"], Annotated[int, Field(ge=0, le=0xFFFFFFFF)]] = Field(
        default_factory=_empty_bindings
    )


class RandomInputs(Strict):
    count: int = Field(ge=0)
    max_len: int = Field(ge=0)
    seed: int


class Inputs(Strict):
    fixed: list[str]
    boundary_lengths: bool = False
    fixed_hex: list[HexInput] = Field(default_factory=list)
    random: RandomInputs

    @model_validator(mode="after")
    def nonempty(self) -> Self:
        if not self.fixed and not self.fixed_hex and not self.random.count:
            raise ValueError("pack must declare at least one input")
        return self


class Pack(Strict):
    family: str
    version: int = Field(gt=0)
    call_shapes: list[CallShape] = Field(min_length=1)
    variants: dict[str, VariantProbe] = Field(min_length=1)
    inputs: Inputs
    near_miss: list[Identifier]

    @model_validator(mode="after")
    def relationships(self) -> Self:
        if self.family not in REGISTRY or self.family not in FAMILY_SHAPES:
            raise ValueError("family has no Phase 1A pack support")
        ids = [shape.id for shape in self.call_shapes]
        if len(ids) != len(set(ids)):
            raise ValueError("duplicate call shape")
        if not set(ids) <= FAMILY_SHAPES[self.family]:
            raise ValueError("call shape is not supported for this family")
        if self.family in {"md5", "sha1", "sha256"} and any(
            shape.out_size != self.family for shape in self.call_shapes
        ):
            raise ValueError("digest allocation must match the pack family")
        needs_seed = "seed_buf_len" in ids
        for variant, probe in self.variants.items():
            if probe.call_shapes is not None and (
                not probe.call_shapes or not set(probe.call_shapes) <= set(ids)
            ):
                raise ValueError("variant call shapes must select declared shapes")
            if (probe.input_encoding == "base64") != (probe.oracle == "base64_decode"):
                raise ValueError("base64 decode requires canonical encoded inputs")
            if self.family == "base64":
                expected = (
                    "buf_len_decode_out" if probe.oracle == "base64_decode" else "buf_len_out"
                )
                if set(probe.call_shapes or ids) != {expected}:
                    raise ValueError("base64 oracle requires its matching call shape")
            if variant not in REGISTRY[self.family]:
                raise ValueError("unknown variant for family")
            if ORACLE_VARIANTS.get(probe.oracle) != (self.family, variant):
                raise ValueError("oracle does not implement the declared family/variant")
            if needs_seed and "seed" not in probe.bind:
                raise ValueError("seed call shape requires an explicit variant binding")
            if probe.bind and self.family not in {"crc32", "adler32"}:
                raise ValueError("family does not accept seed bindings")
        if len(self.near_miss) != len(set(self.near_miss)):
            raise ValueError("duplicate near-miss identifier")
        return self

    @property
    def unsupported_variants(self) -> tuple[str, ...]:
        return tuple(sorted(set(REGISTRY[self.family]) - self.variants.keys()))


class _UniqueLoader(yaml.SafeLoader):
    """Reject ambiguous duplicate keys instead of silently using the last value."""


class _Constructor(Protocol):
    def construct_object(self, node: yaml.Node, deep: bool = False) -> object: ...


def _mapping(loader: _UniqueLoader, node: yaml.MappingNode) -> dict[object, object]:
    loader.flatten_mapping(node)
    result: dict[object, object] = {}
    for key_node, value_node in node.value:
        constructor = cast(_Constructor, loader)
        key = constructor.construct_object(key_node, deep=True)
        try:
            if key in result:
                raise ValueError(f"duplicate YAML key: {key}")
            result[key] = constructor.construct_object(value_node, deep=True)
        except TypeError as error:
            raise ValueError("invalid YAML mapping key") from error
    return result


_UniqueLoader.add_constructor(yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG, _mapping)


def load_pack(path: Path) -> Pack:
    try:
        raw: object = yaml.load(path.read_text(encoding="utf-8"), Loader=_UniqueLoader)
    except yaml.YAMLError as error:
        raise ValueError(f"invalid pack YAML: {path}") from error
    return Pack.model_validate(raw)

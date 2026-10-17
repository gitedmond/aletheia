"""Public Ghidra observations for conservative signature decisions."""

from typing import Literal, Self

from pydantic import Field, model_validator

from aletheia.schema.models import Strict

ArgumentRegister = Literal["rdi", "rsi", "rdx", "rcx", "r8", "r9"]
ARGUMENT_REGISTERS = ("rdi", "rsi", "rdx", "rcx", "r8", "r9")
ParameterRegister = Literal[
    "rdi",
    "rsi",
    "rdx",
    "rcx",
    "r8",
    "r9",
    "xmm0",
    "xmm1",
    "xmm2",
    "xmm3",
    "xmm4",
    "xmm5",
    "xmm6",
    "xmm7",
]
PARAMETER_REGISTERS = (
    *ARGUMENT_REGISTERS,
    "xmm0",
    "xmm1",
    "xmm2",
    "xmm3",
    "xmm4",
    "xmm5",
    "xmm6",
    "xmm7",
)
Width = Literal[8, 16, 32, 64]


class WidthFact(Strict):
    kind: Literal["int_or_ptr", "float", "none", "unknown"]
    width: Width | None = None

    @model_validator(mode="after")
    def known_width(self) -> Self:
        if (self.kind in {"int_or_ptr", "float"}) != (self.width is not None):
            raise ValueError("known register classes require a width")
        if self.kind == "float" and self.width not in (32, 64):
            raise ValueError("scalar floating widths must be 32 or 64")
        return self


class ReturnFact(Strict):
    integer: WidthFact
    floating: WidthFact

    @model_validator(mode="after")
    def register_banks(self) -> Self:
        if self.integer.kind == "float" or self.floating.kind == "int_or_ptr":
            raise ValueError("return fact register bank mismatch")
        return self


class CallSignatureUse(Strict):
    return_read: ReturnFact
    argument_writes: dict[ParameterRegister, Width | None]


class SignatureFacts(Strict):
    return_paths: list[ReturnFact] = Field(min_length=1)
    param_reads: dict[ParameterRegister, Width | None]
    pointer_params: list[ArgumentRegister]
    exclusion_reason: str | None = None

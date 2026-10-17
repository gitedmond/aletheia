"""Shared C spelling canonicalization for the pinned x86-64 SysV target."""

import re
from dataclasses import dataclass
from typing import Literal


@dataclass(frozen=True)
class CanonicalType:
    kind: Literal["int", "float", "ptr", "void", "unknown"]
    width: int | None


INTEGERS = {
    **dict.fromkeys(
        ("char", "signed char", "unsigned char", "int8_t", "uint8_t", "bool", "_Bool"), 8
    ),
    **dict.fromkeys(
        (
            "short",
            "short int",
            "signed short",
            "unsigned short",
            "unsigned short int",
            "int16_t",
            "uint16_t",
        ),
        16,
    ),
    **dict.fromkeys(
        ("int", "signed", "signed int", "unsigned", "unsigned int", "int32_t", "uint32_t"), 32
    ),
    **dict.fromkeys(
        (
            "long",
            "long int",
            "signed long",
            "unsigned long",
            "unsigned long int",
            "long long",
            "long long int",
            "signed long long",
            "unsigned long long",
            "unsigned long long int",
            "size_t",
            "ssize_t",
            "ptrdiff_t",
            "intptr_t",
            "uintptr_t",
            "int64_t",
            "uint64_t",
            "off_t",
        ),
        64,
    ),
}


def canonical_type(spelling: str, *, return_type: bool = False) -> CanonicalType:
    text = " ".join(re.sub(r"\b(?:const|volatile)\b", "", spelling).split())
    if "*" in text or re.search(r"\[[^\]]*\]", text):
        return CanonicalType("ptr", 64)
    if text in INTEGERS:
        return CanonicalType("int", INTEGERS[text])
    if re.fullmatch(r"enum(?:\s+[A-Za-z_]\w*)?", text):
        return CanonicalType("int", 32)
    if text in {"float", "double"}:
        return CanonicalType("float", 32 if text == "float" else 64)
    if text == "void" and return_type:
        return CanonicalType("void", 0)
    return CanonicalType("unknown", None)

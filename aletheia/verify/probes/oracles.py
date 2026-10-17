"""Pack-owned reference algorithms; never read corpus sources or native tests."""

import base64
import hashlib
import re
import zlib
from dataclasses import dataclass

MASK32 = 0xFFFFFFFF

PURPOSE_VARIANTS: dict[str, tuple[str, ...]] = {
    "strlen": ("std",),
    "strcmp": ("std",),
    "memcpy": ("std",),
    "hex": ("lower", "upper"),
    "parse-int": ("decimal-signed", "decimal-unsigned"),
}


def string_pair(data: bytes) -> tuple[bytes, bytes]:
    if len(data) < 2:
        raise ValueError("string pair requires a length prefix")
    size = int.from_bytes(data[:2], "little")
    if size > len(data) - 2:
        raise ValueError("string pair length exceeds payload")
    left, right = data[2 : 2 + size], data[2 + size :]
    if b"\0" in left or b"\0" in right:
        raise ValueError("string pair cannot contain embedded NULs")
    return left, right


# Registry membership alone does not imply probe support.
ORACLE_VARIANTS: dict[str, tuple[str, str]] = {
    **{name + "_std": (name, "std") for name in ("strlen", "strcmp", "memcpy")},
    "hex_lower": ("hex", "lower"),
    "hex_upper": ("hex", "upper"),
    "parse_int_signed": ("parse-int", "decimal-signed"),
    "parse_int_unsigned": ("parse-int", "decimal-unsigned"),
    "crc32_ieee": ("crc32", "ieee"),
    "crc32_jamcrc": ("crc32", "jamcrc"),
    "crc32c": ("crc32", "crc32c"),
    "crc32_bzip2": ("crc32", "bzip2"),
    "adler32_zlib": ("adler32", "zlib"),
    "fnv1a_32": ("fnv", "fnv1a-32"),
    "fnv1_32": ("fnv", "fnv1-32"),
    "djb2_add": ("djb2", "add"),
    "djb2_xor": ("djb2", "xor"),
    **{name + "_std": (name, "std") for name in ("md5", "sha1", "sha256")},
    "fletcher16_std": ("fletcher16", "std"),
    "base64_decode": ("base64", "std-padded-decode"),
    "base64_std": ("base64", "std-padded"),
    "base64_url": ("base64", "url-nopad"),
}


@dataclass(frozen=True)
class OracleResult:
    return_value: int
    output: bytes | None = None


def _crc(data: bytes, seed: int, polynomial: int, *, reflected: bool) -> int:
    state = seed ^ MASK32
    for byte in data:
        state ^= byte if reflected else byte << 24
        for _ in range(8):
            if reflected:
                state = (state >> 1) ^ (polynomial if state & 1 else 0)
            else:
                state = ((state << 1) ^ (polynomial if state & 0x80000000 else 0)) & MASK32
    return state ^ MASK32


def evaluate(name: str, data: bytes, *, seed: int | None = None) -> OracleResult:
    """Return the declared output, with 32-bit arithmetic at each algorithm step.

    CRC seeds use the finalized running-CRC convention; JAMCRC complements the
    IEEE result. Adler uses its usual running state (default 1). No implicit
    coercion or unsupported-oracle fallback is allowed.
    """
    if name not in ORACLE_VARIANTS:
        raise ValueError(f"unknown oracle: {name}")
    if seed is not None and (type(seed) is not int or not 0 <= seed <= MASK32):
        raise ValueError("oracle seed must be an unsigned 32-bit integer")
    family, _ = ORACLE_VARIANTS[name]
    if seed is not None and family not in {"crc32", "adler32"}:
        raise ValueError(f"oracle does not accept a seed: {name}")
    if family == "strlen":
        if b"\0" in data:
            raise ValueError("strlen input contains embedded NUL")
        return OracleResult(len(data))
    if family == "strcmp":
        left, right = string_pair(data)
        return OracleResult((left > right) - (left < right))
    if family == "memcpy":
        return OracleResult(0, data + b"\xa5" * 16)
    if family == "hex":
        output = data.hex().encode("ascii")
        return OracleResult(0, output.upper() if name == "hex_upper" else output)
    if family == "parse-int":
        pattern = (
            rb"(?:0|-[1-9][0-9]*|[1-9][0-9]*)"
            if name == "parse_int_signed"
            else rb"(?:0|[1-9][0-9]*)"
        )
        if re.fullmatch(pattern, data) is None or len(data) > 20:
            raise ValueError("parse-int input must be canonical decimal")
        return OracleResult(int(data))
    if name in {"crc32_ieee", "crc32_jamcrc"}:
        value = zlib.crc32(data, 0 if seed is None else seed) & MASK32
        return OracleResult(value ^ MASK32 if name == "crc32_jamcrc" else value)
    if name == "crc32c":
        return OracleResult(_crc(data, seed or 0, 0x82F63B78, reflected=True))
    if name == "crc32_bzip2":
        return OracleResult(_crc(data, seed or 0, 0x04C11DB7, reflected=False))
    if name == "adler32_zlib":
        return OracleResult(zlib.adler32(data, 1 if seed is None else seed) & MASK32)
    if family == "fnv":
        value = 0x811C9DC5
        for byte in data:
            if name == "fnv1a_32":
                value ^= byte
            value = (value * 0x01000193) & MASK32
            if name == "fnv1_32":
                value ^= byte
        return OracleResult(value)
    if family == "djb2":
        value = 5381
        for byte in data:
            value = (value * 33) + byte if name == "djb2_add" else (value * 33) ^ byte
            value &= MASK32
        return OracleResult(value)
    if family in {"md5", "sha1", "sha256"}:
        return OracleResult(0, hashlib.new(family, data).digest())
    if name == "fletcher16_std":
        first = second = 0
        for byte in data:
            first = (first + byte) % 255
            second = (second + first) % 255
        return OracleResult((second << 8) | first)
    if name == "base64_decode":
        output = base64.b64decode(data, validate=True)
        if base64.b64encode(output) != data:
            raise ValueError("decode input must be canonical padded base64")
    elif name == "base64_std":
        output = base64.b64encode(data)
    else:
        output = base64.urlsafe_b64encode(data).rstrip(b"=")
    return OracleResult(len(output), output)

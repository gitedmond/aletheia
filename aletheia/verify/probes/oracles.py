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
    "memset": ("std",),
    "memcmp": ("std",),
    "xor": ("std",),
    "rc4": ("std",),
    "file-read": ("std",),
    "print": ("bytes", "hex32"),
    "sha1_transform": ("std",),
    "sha256_transform": ("std",),
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


def byte_pair(data: bytes) -> tuple[bytes, bytes]:
    """Length-prefixed pair for raw byte buffers; NUL bytes are ordinary data."""
    if len(data) < 2:
        raise ValueError("byte pair requires a length prefix")
    size = int.from_bytes(data[:2], "little")
    if size > len(data) - 2:
        raise ValueError("byte pair length exceeds payload")
    return data[2 : 2 + size], data[2 + size :]


# Registry membership alone does not imply probe support.
ORACLE_VARIANTS: dict[str, tuple[str, str]] = {
    **{name + "_std": (name, "std") for name in ("strlen", "strcmp", "memcpy")},
    "memset_std": ("memset", "std"),
    "memcmp_std": ("memcmp", "std"),
    "xor_std": ("xor", "std"),
    "rc4_std": ("rc4", "std"),
    "read_std": ("file-read", "std"),
    "print_bytes_std": ("print", "bytes"),
    "hex_print32_std": ("print", "hex32"),
    "sha1_transform_std": ("sha1_transform", "std"),
    "sha256_transform_std": ("sha256_transform", "std"),
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


def _rol32(value: int, count: int) -> int:
    return ((value << count) | (value >> (32 - count))) & MASK32


def _ror32(value: int, count: int) -> int:
    return ((value >> count) | (value << (32 - count))) & MASK32


# FIPS 180-4 block compression; state words are native little-endian, blocks
# are big-endian, matching the corpus' `uint32_t state[]` / byte-block layout.
def _sha1_block(state: bytes, block: bytes) -> bytes:
    h = [int.from_bytes(state[index : index + 4], "little") for index in range(0, 20, 4)]
    words = [int.from_bytes(block[index : index + 4], "big") for index in range(0, 64, 4)]
    for step in range(16, 80):
        words.append(
            _rol32(words[step - 3] ^ words[step - 8] ^ words[step - 14] ^ words[step - 16], 1)
        )
    a, b, c, d, e = h
    for step in range(80):
        if step < 20:
            choice, constant = (b & c) | (~b & d), 0x5A827999
        elif step < 40:
            choice, constant = b ^ c ^ d, 0x6ED9EBA1
        elif step < 60:
            choice, constant = (b & c) | (b & d) | (c & d), 0x8F1BBCDC
        else:
            choice, constant = b ^ c ^ d, 0xCA62C1D6
        a, b, c, d, e = (
            (_rol32(a, 5) + choice + e + constant + words[step]) & MASK32,
            a,
            _rol32(b, 30),
            c,
            d,
        )
    return b"".join(
        ((first + second) & MASK32).to_bytes(4, "little")
        for first, second in zip(h, (a, b, c, d, e), strict=True)
    )


_SHA256_CONSTANTS = (
    0x428A2F98, 0x71374491, 0xB5C0FBCF, 0xE9B5DBA5, 0x3956C25B, 0x59F111F1, 0x923F82A4, 0xAB1C5ED5,
    0xD807AA98, 0x12835B01, 0x243185BE, 0x550C7DC3, 0x72BE5D74, 0x80DEB1FE, 0x9BDC06A7, 0xC19BF174,
    0xE49B69C1, 0xEFBE4786, 0x0FC19DC6, 0x240CA1CC, 0x2DE92C6F, 0x4A7484AA, 0x5CB0A9DC, 0x76F988DA,
    0x983E5152, 0xA831C66D, 0xB00327C8, 0xBF597FC7, 0xC6E00BF3, 0xD5A79147, 0x06CA6351, 0x14292967,
    0x27B70A85, 0x2E1B2138, 0x4D2C6DFC, 0x53380D13, 0x650A7354, 0x766A0ABB, 0x81C2C92E, 0x92722C85,
    0xA2BFE8A1, 0xA81A664B, 0xC24B8B70, 0xC76C51A3, 0xD192E819, 0xD6990624, 0xF40E3585, 0x106AA070,
    0x19A4C116, 0x1E376C08, 0x2748774C, 0x34B0BCB5, 0x391C0CB3, 0x4ED8AA4A, 0x5B9CCA4F, 0x682E6FF3,
    0x748F82EE, 0x78A5636F, 0x84C87814, 0x8CC70208, 0x90BEFFFA, 0xA4506CEB, 0xBEF9A3F7, 0xC67178F2,
)


def _sha256_block(state: bytes, block: bytes) -> bytes:
    h = [int.from_bytes(state[index : index + 4], "little") for index in range(0, 32, 4)]
    words = [int.from_bytes(block[index : index + 4], "big") for index in range(0, 64, 4)]
    for step in range(16, 64):
        first = (
            _ror32(words[step - 15], 7) ^ _ror32(words[step - 15], 18) ^ (words[step - 15] >> 3)
        )
        second = (
            _ror32(words[step - 2], 17) ^ _ror32(words[step - 2], 19) ^ (words[step - 2] >> 10)
        )
        words.append((words[step - 16] + first + words[step - 7] + second) & MASK32)
    a, b, c, d, e, f, g, last = h
    for step in range(64):
        upper = _ror32(e, 6) ^ _ror32(e, 11) ^ _ror32(e, 25)
        choose = (e & f) ^ (~e & g)
        first = (last + upper + choose + _SHA256_CONSTANTS[step] + words[step]) & MASK32
        lower = _ror32(a, 2) ^ _ror32(a, 13) ^ _ror32(a, 22)
        majority = (a & b) ^ (a & c) ^ (b & c)
        second = (lower + majority) & MASK32
        a, b, c, d, e, f, g, last = (
            (first + second) & MASK32,
            a,
            b,
            c,
            (d + first) & MASK32,
            e,
            f,
            g,
        )
    return b"".join(
        ((first + second) & MASK32).to_bytes(4, "little")
        for first, second in zip(h, (a, b, c, d, e, f, g, last), strict=True)
    )


def _rc4_keyed(payload: bytes, key: bytes) -> bytes:
    # Empty key mirrors the corpus guard (init fails, state stays zero) -> no-op.
    if not key:
        return payload
    box = list(range(256))
    j = 0
    for i in range(256):
        j = (j + box[i] + key[i % len(key)]) & 0xFF
        box[i], box[j] = box[j], box[i]
    i = j = 0
    output = bytearray()
    for byte in payload:
        i = (i + 1) & 0xFF
        j = (j + box[i]) & 0xFF
        box[i], box[j] = box[j], box[i]
        output.append(byte ^ box[(box[i] + box[j]) & 0xFF])
    return bytes(output)


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
    if family == "memset":
        value = data[0] if data else 0
        return OracleResult(0, bytes([value]) * len(data) + b"\xa5" * 16)
    if family == "memcmp":
        left, right = byte_pair(data)
        size = min(len(left), len(right))
        return OracleResult((left[:size] > right[:size]) - (left[:size] < right[:size]))
    if family == "xor":
        payload, key = byte_pair(data)
        output = (
            payload if not key else bytes(p ^ key[i % len(key)] for i, p in enumerate(payload))
        )
        return OracleResult(0, output)
    if family == "rc4":
        payload, key = byte_pair(data)
        return OracleResult(0, _rc4_keyed(payload, key))
    if family == "file-read":
        return OracleResult(0, len(data).to_bytes(8, "little") + data + b"\0")
    if name == "print_bytes_std":
        return OracleResult(0, data.hex().encode("ascii") + b"\n")
    if name == "hex_print32_std":
        value = int.from_bytes(data[:4].ljust(4, b"\0"), "little")
        return OracleResult(0, format(value, "08x").encode("ascii") + b"\n")
    if family in {"sha1_transform", "sha256_transform"}:
        width = 20 if family == "sha1_transform" else 32
        if len(data) != width + 64:
            raise ValueError("transform input must be a state word block plus one 64-byte block")
        compress = _sha1_block if family == "sha1_transform" else _sha256_block
        return OracleResult(0, compress(data[:width], data[width:]))
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

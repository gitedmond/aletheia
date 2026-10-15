"""Supporting constants never produce a verifier verdict."""

import struct

from aletheia.analysis.ghidra_session import ConstantMatch, GhidraAnalysis
from aletheia.schema.models import Algorithm, Claim

IMMEDIATES = {
    "crc32": {
        "ieee_polynomial": 0xEDB88320,
        "crc32c_polynomial": 0x82F63B78,
        "bzip2_polynomial": 0x04C11DB7,
    },
    "fnv": {
        "fnv1a32_basis": 0x811C9DC5,
        "fnv32_prime": 0x01000193,
        "fnv64_basis": 0xCBF29CE484222325,
        "fnv64_prime": 0x100000001B3,
    },
    "djb2": {"djb2_seed": 5381},
    "adler32": {"adler32_modulus": 65521},
}
TABLES = {
    "crc32": {"ieee_table_prefix": struct.pack("<4I", 0, 0x77073096, 0xEE0E612C, 0x990951BA)},
    "base64": {
        "standard_alphabet": b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/",
        "url_alphabet": b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_",
    },
}


def constant_evidence(claim: Claim, analysis: GhidraAnalysis) -> list[ConstantMatch]:
    """Return only support for this subject/family; the engine owns all decisions."""
    if claim.binary_sha256 != analysis.binary_sha256:
        raise ValueError("constant evidence binary identity mismatch")
    if not isinstance(claim.body, Algorithm):
        raise ValueError("constant evidence requires an algorithm claim")
    function = next((fn for fn in analysis.functions if fn.entry == claim.subject.address), None)
    if function is None:
        raise ValueError("subject_not_found")
    return [match for match in function.constants if match.family == claim.body.family]

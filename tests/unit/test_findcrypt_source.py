"""FindCrypt preserves tool provenance, deduplicates xrefs and counts unmapped labels."""

import pytest

from aletheia.sources.findcrypt import FindcryptAdapter, FindcryptMapping, FindcryptReport


def report():
    return FindcryptReport.model_validate(
        {
            "binary_sha256": "a" * 64,
            "labels": [
                {"name": "CRYPT_CRC32", "address": "0x00000800", "xrefs_to": ["0x00001000"]},
                {"name": "CRYPT_CRC32_ALT", "address": "0x00000900", "xrefs_to": ["0x00001000"]},
                {"name": "CRYPT_UNKNOWN", "address": "0x00000a00", "xrefs_to": ["0x00002000"]},
            ],
        }
    )


def test_deduplication_provenance_and_unmapped_labels():
    mapping = FindcryptMapping.model_validate(
        {
            "findcrypt_version": "3.1.10",
            "ghidra_version": "11.4.3",
            "map": {"CRYPT_CRC32": {"family": "crc32"}, "CRYPT_CRC32_ALT": {"family": "crc32"}},
        }
    )
    result = FindcryptAdapter(mapping, "r_" + "1" * 16).adapt(report(), "a" * 64)
    assert len(result.claims) == 1
    claim = result.claims[0]
    assert claim.subject.address == "0x00001000" and claim.body.family == "crc32"
    assert claim.source.shares_backend and claim.derived_from == "constant_xref"
    assert claim.tool_label == "CRYPT_CRC32" and claim.confidence == 1.0
    assert result.unmapped_label == {"CRYPT_UNKNOWN": 1}
    assert result.deduplicated_label == {"CRYPT_CRC32_ALT": 1}
    with pytest.raises(ValueError, match="identity"):
        FindcryptAdapter(mapping, "r_" + "1" * 16).adapt(report(), "b" * 64)


def test_report_rejects_unordered_addresses_and_conflicting_family_variants():
    raw = report().model_dump()
    raw["labels"][0]["xrefs_to"] = ["0x00002000", "0x00001000"]
    with pytest.raises(ValueError, match="sorted"):
        FindcryptReport.model_validate(raw)
    mapping = FindcryptMapping.model_validate(
        {
            "findcrypt_version": "3.1.10",
            "ghidra_version": "11.4.3",
            "map": {
                "CRYPT_CRC32": {"family": "crc32", "variant": "ieee"},
                "CRYPT_CRC32_ALT": {"family": "crc32", "variant": "crc32c"},
            },
        }
    )
    with pytest.raises(ValueError, match="conflicting"):
        FindcryptAdapter(mapping, "r_" + "1" * 16).adapt(report(), "a" * 64)

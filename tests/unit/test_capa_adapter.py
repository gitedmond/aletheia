"""T18: normalize the observed pinned capa format and count every unmapped match."""

import copy

import pytest

from aletheia.schema.models import Algorithm, Claim
from aletheia.sources.capa import CapaAdapter, CapaMapping

SHA = "a" * 64
RUN = "r_" + "1" * 16


def mapping():
    return CapaMapping(
        capa_version="9.4.0",
        rules_tag="9.4.0",
        address_base_field="meta.analysis.base_address.value",
        map={
            "hash data with CRC32": Algorithm(family="crc32"),
            "hash data using fnv": Algorithm(family="fnv"),
        },
    )


def report():
    def rule(scope, *addresses):
        return {
            "meta": {"scopes": {"static": scope}},
            "matches": [[{"type": "absolute", "value": a}, {"success": True}] for a in addresses],
        }

    return {
        "meta": {
            "version": "9.4.0",
            "sample": {"sha256": SHA},
            "analysis": {
                "format": "elf",
                "arch": "amd64",
                "base_address": {"type": "absolute", "value": 0x2000000},
            },
            "timestamp": "informational",
        },
        "rules": {
            "hash data with CRC32": rule("function", 0x2001EB0),
            "contain loop": rule("function", 0x2001EB0, 0x2001F30),
            "encode data using XOR": rule("basic block", 0x2001F40),
        },
    }


def test_observed_base_field_scope_and_unmapped_counts():
    result = CapaAdapter(mapping(), RUN).adapt(report(), SHA)
    assert len(result.claims) == 1
    claim = result.claims[0]
    assert isinstance(claim, Claim)
    assert claim.subject.address == "0x00001eb0"
    assert claim.body == Algorithm(family="crc32")
    assert claim.confidence == 1.0 and claim.confidence_source == "tool_default"
    assert claim.derived_from == "capa_rule" and claim.tool_label == "hash data with CRC32"
    assert claim.source.origin == "tool" and not claim.source.shares_backend
    assert claim.source.source_id == "tool:capa@9.4.0+rules@9.4.0"
    assert claim.depends_on == []
    assert result.unmapped_scope == 1
    assert result.unmapped_label == {"contain loop": 2}


def test_timestamp_and_rule_iteration_do_not_change_claims():
    first = report()
    second = copy.deepcopy(first)
    second["meta"]["timestamp"] = "different"
    second["rules"] = dict(reversed(list(second["rules"].items())))
    adapter = CapaAdapter(mapping(), RUN)
    assert adapter.adapt(first, SHA) == adapter.adapt(second, SHA)


@pytest.mark.parametrize("change", ["version", "sha", "base", "relative", "below_base", "boolean"])
def test_invalid_pinned_report_fails_explicitly(change):
    raw = report()
    if change == "version":
        raw["meta"]["version"] = "9.3.0"
    if change == "sha":
        raw["meta"]["sample"]["sha256"] = "b" * 64
    if change == "base":
        del raw["meta"]["analysis"]["base_address"]
    if change == "relative":
        raw["rules"]["hash data with CRC32"]["matches"][0][0]["type"] = "relative"
    if change == "below_base":
        raw["rules"]["hash data with CRC32"]["matches"][0][0]["value"] = 1
    if change == "boolean":
        raw["rules"]["hash data with CRC32"]["matches"][0][0]["value"] = True
    with pytest.raises(ValueError):
        CapaAdapter(mapping(), RUN).adapt(raw, SHA)


def test_duplicate_matches_are_counted_without_duplicate_active_claims():
    raw = report()
    matches = raw["rules"]["hash data with CRC32"]["matches"]
    matches.append(copy.deepcopy(matches[0]))
    result = CapaAdapter(mapping(), RUN).adapt(raw, SHA)
    assert len(result.claims) == 1
    assert result.deduplicated_label == {"hash data with CRC32": 1}


def test_conflicting_algorithms_at_one_subject_fail_instead_of_dropping_a_claim():
    raw = report()
    raw["rules"]["hash data using fnv"] = copy.deepcopy(raw["rules"]["hash data with CRC32"])
    with pytest.raises(ValueError, match="conflicting_algorithm_labels"):
        CapaAdapter(mapping(), RUN).adapt(raw, SHA)


def test_mapping_rejects_unknown_algorithms_versions_and_fields():
    value = mapping().model_dump()
    for field, new in [
        ("capa_version", "9.3.0"),
        ("rules_tag", "mutable-main"),
        ("address_base_field", "guess"),
    ]:
        bad = value | {field: new}
        with pytest.raises(ValueError):
            CapaMapping.model_validate(bad)
    with pytest.raises(ValueError):
        CapaMapping.model_validate(value | {"unexpected": True})


def test_mapping_yaml_rejects_duplicate_and_unsafe_tags(tmp_path):
    import yaml

    path = tmp_path / "mapping.yaml"
    path.write_text('capa_version: "9.4.0"\ncapa_version: "9.3.0"\n')
    with pytest.raises(ValueError, match="unique"):
        CapaMapping.read(path)
    path.write_text('!!python/object/apply:os.system ["exit 0"]')
    with pytest.raises(yaml.YAMLError):
        CapaMapping.read(path)

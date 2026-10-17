import json
from pathlib import Path

import pytest

from aletheia.verify.probes.inputs import generate_inputs, inputs_for_call
from aletheia.verify.probes.oracles import evaluate, string_pair
from aletheia.verify.probes.pack import load_pack


def test_protected_purpose_vectors():
    vectors = json.loads(Path("tests/golden/purpose-vectors-phase1b.json").read_bytes())
    for row in vectors["vectors"]:
        result = evaluate(row["oracle"], bytes.fromhex(row["input_hex"]))
        assert result.return_value == row["return_value"]
        assert (result.output.hex() if result.output is not None else None) == row["output_hex"]


@pytest.mark.parametrize("data", [b"", b"+1", b"01", b"-0", b"1x", b"-1"])
def test_unsigned_decimal_rejects_noncanonical_or_negative_inputs(data):
    with pytest.raises(ValueError):
        evaluate("parse_int_unsigned", data)


def test_generated_pairs_and_numeric_domains_are_deterministic_and_valid():
    pair = load_pack(Path("packs/strcmp.yaml"))
    values = generate_inputs(pair.inputs)
    assert values == generate_inputs(pair.inputs)
    assert any(a > b for a, b in map(string_pair, values))
    assert any(a < b for a, b in map(string_pair, values))
    assert any(a == b for a, b in map(string_pair, values))
    decimal = load_pack(Path("packs/parse-int.yaml"))
    for shape in decimal.call_shapes:
        for variant in decimal.variants.values():
            inputs = inputs_for_call(generate_inputs(decimal.inputs), variant, shape)
            assert inputs and inputs == inputs_for_call(
                generate_inputs(decimal.inputs), variant, shape
            )
            for value in inputs:
                actual = evaluate(variant.oracle, value).return_value
                signed = variant.input_encoding == "decimal_signed"
                assert actual >= (-(1 << (shape.return_width - 1)) if signed else 0)
                assert actual < 1 << (shape.return_width - int(signed))


def test_string_generation_preserves_fixed_bytes_and_rejects_ignored_pair_inputs():
    from aletheia.verify.probes.pack import Inputs

    data = {"fixed": ["a\0b"], "string_data": True, "random": {"count": 1, "max_len": 8, "seed": 7}}
    assert generate_inputs(Inputs.model_validate(data))[0] == b"a\0b"
    with pytest.raises(ValueError, match="pair generation"):
        Inputs.model_validate(data | {"string_pairs": True})
    with pytest.raises(ValueError, match="requires string_pairs"):
        Inputs.model_validate(data | {"fixed_pairs": [["61", "62"]]})

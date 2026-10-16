"""Every declared fixed input is independently protected by a cited F2 vector."""

import json
from pathlib import Path

import yaml

from aletheia.verify.probes.inputs import inputs_for_variant
from aletheia.verify.probes.oracles import evaluate
from aletheia.verify.probes.pack import load_pack


def test_pack_fixed_inputs_equal_published_vector_table():
    table = yaml.safe_load(Path("tests/golden/vectors.yaml").read_text())
    table["vectors"] += json.loads(Path("tests/golden/vectors-phase1b.json").read_bytes())[
        "vectors"
    ]
    protected = {(row["family"], row["variant"], row["input_hex"]) for row in table["vectors"]}
    declared = set()
    for path in sorted(Path("packs").glob("*.yaml")):
        pack = load_pack(path)
        assert pack.inputs.random.count == 64 and pack.inputs.random.max_len == 4096
        inputs = [value.encode() for value in pack.inputs.fixed]
        inputs += [bytes.fromhex(value) for value in pack.inputs.fixed_hex]
        for variant, probe in pack.variants.items():
            declared.update(
                (pack.family, variant, value.hex()) for value in inputs_for_variant(inputs, probe)
            )
    assert declared == protected
    for row in table["vectors"]:
        pack = load_pack(Path("packs") / (row["family"] + ".yaml"))
        variant = pack.variants[row["variant"]]
        actual = evaluate(variant.oracle, bytes.fromhex(row["input_hex"]), **variant.bind)
        assert actual.return_value == row["expected_return"]
        assert (actual.output.hex() if actual.output is not None else None) == row[
            "expected_output_hex"
        ]
        assert row["references"] and row["independent_check"]

import base64
from pathlib import Path

import pytest

from aletheia.verify.probes.inputs import inputs_for_variant
from aletheia.verify.probes.oracles import evaluate
from aletheia.verify.probes.pack import load_pack


def test_fletcher_vectors_and_decode_input_domain():
    assert evaluate("fletcher16_std", b"abcde").return_value == 0xC8F0
    assert evaluate("fletcher16_std", b"abcdef").return_value == 0x2057
    pack = load_pack(Path("packs/base64.yaml"))
    probe = pack.variants["std-padded-decode"]
    values = inputs_for_variant([b"Man", b"M", b"\xfb\xff"], probe)
    assert values == [b"TWFu", b"TQ==", b"+/8="]
    for raw, encoded in zip([b"Man", b"M", b"\xfb\xff"], values, strict=True):
        result = evaluate(probe.oracle, encoded)
        assert result.output == raw and result.return_value == len(raw)
        assert base64.b64encode(result.output) == encoded
    with pytest.raises(ValueError):
        evaluate(probe.oracle, b"TQ=")
    shape = next(s for s in pack.call_shapes if s.id in probe.call_shapes)
    assert shape.output_size(4) == 4
    fletcher = load_pack(Path("packs/fletcher16.yaml"))
    assert fletcher.call_shapes[0].return_width == 16

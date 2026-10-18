import json
import random

import pytest
from jsonschema import validate
from pydantic import ValidationError

from aletheia.verify.probes.inputs import generate_inputs, inputs_for_shape
from aletheia.verify.probes.minimize import minimize_counterexample
from aletheia.verify.probes.oracles import evaluate
from aletheia.verify.probes.pack import Pack, load_pack


def crc_pack():
    return {
        "family": "crc32",
        "version": 1,
        "call_shapes": [
            {"id": "seed_buf_len", "roles": ["seed", "buf", "len"], "return_width": 32},
            {"id": "buf_len", "roles": ["buf", "len"], "return_width": 32},
        ],
        "variants": {"ieee": {"oracle": "crc32_ieee", "bind": {"seed": 0}}},
        "inputs": {
            "fixed": ["", "a", "123456789"],
            "fixed_hex": ["00ff"],
            "random": {"count": 8, "max_len": 16, "seed": 4411},
        },
        "near_miss": ["crc32_no_final_xor"],
    }


def test_yaml_loader_and_schema_roundtrip(tmp_path):
    path = tmp_path / "pack.yaml"
    path.write_text(json.dumps(crc_pack()))  # JSON is a YAML subset.
    pack = load_pack(path)
    validate(pack.model_dump(mode="json"), Pack.model_json_schema())
    assert Pack.model_validate_json(pack.model_dump_json()) == pack
    assert pack.family == "crc32"
    assert [shape.id for shape in pack.call_shapes] == ["seed_buf_len", "buf_len"]


@pytest.mark.parametrize(
    "mutation",
    [
        lambda p: p.update(extra=True),
        lambda p: p.update(family="unknown"),
        lambda p: p.update(version=0),
        lambda p: p.update(version=True),
        lambda p: p.update(call_shapes=[]),
        lambda p: p["call_shapes"].append(p["call_shapes"][0]),
        lambda p: p["call_shapes"][0].update(roles=["len", "buf"]),
        lambda p: p["call_shapes"][0].update(return_width=17),
        lambda p: p["variants"].update(unknown={"oracle": "crc32_ieee"}),
        lambda p: p["variants"]["ieee"].update(oracle="fnv1a_32"),
        lambda p: p["variants"]["ieee"].update(bind={}),
        lambda p: p["variants"]["ieee"].update(bind={"seed": -1}),
        lambda p: p["variants"]["ieee"].update(bind={"seed": 2**32}),
        lambda p: p["variants"]["ieee"].update(bind={"len": 3}),
        lambda p: p["inputs"].update(fixed_hex=["f"]),
        lambda p: p["inputs"].update(fixed_hex=["GG"]),
        lambda p: p["inputs"]["random"].update(count=-1),
        lambda p: p["inputs"]["random"].update(max_len=-1),
        lambda p: p["inputs"]["random"].update(seed=None),
        lambda p: p.update(near_miss=["../escape"]),
    ],
)
def test_invalid_packs_fail_explicitly(mutation):
    raw = crc_pack()
    mutation(raw)
    with pytest.raises(ValidationError):
        Pack.model_validate(raw)


def test_yaml_duplicate_keys_and_unsafe_tags_fail(tmp_path):
    path = tmp_path / "bad.yaml"
    for source in ["family: crc32\nfamily: fnv\n", "!!python/object/apply:os.system ['false']"]:
        path.write_text(source)
        with pytest.raises(ValueError):
            load_pack(path)


def test_inputs_reproduce_without_using_global_rng():
    pack = Pack.model_validate(crc_pack())
    before = random.getstate()
    first = generate_inputs(pack.inputs)
    assert random.getstate() == before
    assert first == generate_inputs(pack.inputs)
    assert first[:4] == [b"", b"a", b"123456789", b"\0\xff"]
    assert len(first) == 12
    assert all(len(value) <= 16 for value in first[4:])
    pack.inputs.random.seed += 1
    assert generate_inputs(pack.inputs)[4:] != first[4:]


def test_cstr_skips_only_inputs_containing_nul():
    assert inputs_for_shape([b"", b"a", b"\0", b"a\0b", b"\xff"], ["cstr"]) == [b"", b"a", b"\xff"]
    assert inputs_for_shape([b"\0"], ["buf", "len"]) == [b"\0"]


def test_zero_random_bound_and_empty_pack_rejection():
    raw = crc_pack()
    raw["inputs"]["random"].update(count=2, max_len=0)
    assert generate_inputs(Pack.model_validate(raw).inputs)[-2:] == [b"", b""]
    raw["inputs"].update(fixed=[], fixed_hex=[])
    raw["inputs"]["random"]["count"] = 0
    with pytest.raises(ValidationError):
        Pack.model_validate(raw)


@pytest.mark.parametrize(
    "name,data,expected",
    [
        ("crc32_ieee", b"123456789", 0xCBF43926),
        ("crc32_jamcrc", b"123456789", 0x340BC6D9),
        ("crc32c", b"123456789", 0xE3069283),
        ("crc32_bzip2", b"123456789", 0xFC891918),
        ("adler32_zlib", b"Wikipedia", 0x11E60398),
        ("fnv1a_32", b"a", 0xE40C292C),
        ("fnv1_32", b"a", 0x050C5D7E),
        ("fnv1a_32", b"", 0x811C9DC5),
        ("fnv1_32", b"", 0x811C9DC5),
        ("djb2_add", b"a", 0x0002B606),
        ("djb2_xor", b"a", 0x0002B5C4),
        ("djb2_add", b"", 0x1505),
        ("djb2_xor", b"", 0x1505),
    ],
)
def test_published_spec_vectors(name, data, expected):
    result = evaluate(name, data)
    assert result.return_value == expected
    assert result.output is None


@pytest.mark.parametrize(
    "name,data,expected",
    [
        ("base64_std", b"Man", b"TWFu"),
        ("base64_std", b"M", b"TQ=="),
        ("base64_url", b"M", b"TQ"),
        ("base64_std", bytes.fromhex("fbff"), b"+/8="),
        ("base64_url", bytes.fromhex("fbff"), b"-_8"),
        ("base64_std", b"", b""),
    ],
)
def test_base64_compares_count_and_bytes(name, data, expected):
    result = evaluate(name, data)
    assert result.return_value == len(expected)
    assert result.output == expected


def test_seeded_oracle_streaming_and_width():
    for name in ["crc32_ieee", "crc32c", "crc32_bzip2", "adler32_zlib"]:
        first = evaluate(name, b"abc").return_value
        assert evaluate(name, b"def", seed=first) == evaluate(name, b"abcdef")
    for name in ["fnv1a_32", "fnv1_32", "djb2_add", "djb2_xor"]:
        assert 0 <= evaluate(name, bytes(range(256)) * 20).return_value <= 0xFFFFFFFF


def test_unknown_oracle_and_unprobed_variants_are_not_fallbacks():
    with pytest.raises(ValueError, match="unknown oracle"):
        evaluate("fnv1a_64", b"a")
    raw = crc_pack()
    raw.update(family="fnv", call_shapes=[raw["call_shapes"][1]])
    raw["variants"] = {"fnv1a-64": {"oracle": "fnv1a_32"}}
    with pytest.raises(ValidationError):
        Pack.model_validate(raw)


def test_minimization_order_and_suffix_only():
    visited = []

    def mismatch(data):
        visited.append(data)
        return data.startswith(b"a")

    assert minimize_counterexample([b"azz", b"aa", b"ab"], mismatch) == b"a"
    assert visited == [b"aa", b"a", b""]
    assert minimize_counterexample([b"ab", b"aa", b"azz"], mismatch) == b"a"
    assert minimize_counterexample([b"abc"], lambda data: len(data) >= 2) == b"ab"


def test_minimization_rejects_nonreproducing_input_and_accepts_empty():
    with pytest.raises(ValueError, match="does not reproduce"):
        minimize_counterexample([b"a"], lambda _: False)
    with pytest.raises(ValueError, match="no failing inputs"):
        minimize_counterexample([], lambda _: True)
    assert minimize_counterexample([b"a", b""], lambda _: True) == b""


def test_random_generator_pinned_sequence():
    raw = crc_pack()
    raw["inputs"]["random"]["count"] = 4
    assert [value.hex() for value in generate_inputs(Pack.model_validate(raw).inputs)[4:]] == [
        "63b8bc8c",
        "23c668795cb7eebd26",
        "5613812efd14335a51e3f4db63",
        "",
    ]


@pytest.mark.parametrize(
    "family,variants,shapes",
    [
        (
            "crc32",
            {
                "ieee": "crc32_ieee",
                "jamcrc": "crc32_jamcrc",
                "crc32c": "crc32c",
                "bzip2": "crc32_bzip2",
            },
            ["seed_buf_len", "buf_len"],
        ),
        ("adler32", {"zlib": "adler32_zlib"}, ["seed_buf_len", "buf_len"]),
        ("fnv", {"fnv1a-32": "fnv1a_32", "fnv1-32": "fnv1_32"}, ["buf_len"]),
        ("djb2", {"add": "djb2_add", "xor": "djb2_xor"}, ["buf_len", "cstr"]),
        ("base64", {"std-padded": "base64_std", "url-nopad": "base64_url"}, ["buf_len_out"]),
    ],
)
def test_every_supported_family_declares_its_scope(family, variants, shapes):
    roles = {
        "seed_buf_len": ["seed", "buf", "len"],
        "buf_len": ["buf", "len"],
        "cstr": ["cstr"],
        "buf_len_out": ["buf", "len", "out"],
    }
    raw = crc_pack()
    raw.update(family=family)
    raw["variants"] = {
        variant: {
            "oracle": oracle,
            "bind": ({"seed": 1 if family == "adler32" else 0} if "seed_buf_len" in shapes else {}),
        }
        for variant, oracle in variants.items()
    }
    raw["call_shapes"] = [
        {"id": shape, "roles": roles[shape], "return_width": 64, "out_size": "base64_encode"}
        if shape == "buf_len_out"
        else {"id": shape, "roles": roles[shape], "return_width": 32}
        for shape in shapes
    ]
    pack = Pack.model_validate(raw)
    validate(pack.model_dump(mode="json"), Pack.model_json_schema())
    unsupported = {"fnv": ("fnv1-64", "fnv1a-64"), "base64": ("std-padded-decode",)}
    assert pack.unsupported_variants == unsupported.get(family, ())
    if family == "base64":
        assert [pack.call_shapes[0].output_size(n) for n in range(5)] == [4, 8, 8, 8, 12]
        with pytest.raises(ValueError):
            pack.call_shapes[0].output_size(-1)


def test_json_schema_rejects_structural_errors():
    from jsonschema import ValidationError as SchemaError

    for field, value in [("version", "1"), ("variants", {}), ("unexpected", True)]:
        raw = crc_pack()
        raw[field] = value
        with pytest.raises(SchemaError):
            validate(raw, Pack.model_json_schema())


@pytest.mark.parametrize("seed", [-1, 2**32, True])
def test_oracle_invalid_seeds_fail(seed):
    with pytest.raises(ValueError):
        evaluate("crc32_ieee", b"a", seed=seed)
    with pytest.raises(ValueError):
        evaluate("fnv1a_32", b"a", seed=0)

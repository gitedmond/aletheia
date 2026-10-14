"""T08: private extraction, O0 counts and leakage checks execute in a sandbox."""

import hashlib
import json
from pathlib import Path

import pytest

from aletheia.config import Config
from aletheia.corpus.build import Variant, build_program
from aletheia.corpus.ground_truth import check_leakage, extract_ground_truth
from aletheia.schema.canonical import canonical_bytes

pytestmark = pytest.mark.integration


@pytest.mark.parametrize(
    "program", ["crc32tool", "adlerfletch", "hashtable", "b64", "cmd-dispatch"]
)
def test_extraction_is_canonical_and_targets_are_public(tmp_path, program):
    image = Config.read(Path("aletheia.toml")).sandbox.image_build
    source = Path("corpus/tierA") / program
    build = build_program(source, Variant(image=image, output_root=tmp_path / "build"))
    first = extract_ground_truth(build, source)
    second = extract_ground_truth(build, source)
    assert canonical_bytes(first) == canonical_bytes(second)
    assert first.binary_sha256 == hashlib.sha256(build.stripped.read_bytes()).hexdigest()
    assert first.program_id == "tierA/" + program
    assert len(first.functions) > 5
    assert [f.address for f in first.functions] == sorted(
        {f.address for f in first.functions}, key=lambda a: int(a, 16)
    )
    targets = json.loads((build.metadata.parent / "targets.json").read_bytes())
    assert set(targets) == {"schema_version", "binary_sha256", "variant_id", "targets"}
    assert targets["targets"] == [f.address for f in first.functions if f.scorable]
    assert check_leakage(build.stripped, first, source) == []
    assert (build.unstripped.parent / "ground_truth.json").read_bytes() == canonical_bytes(first)
    authored = {f.name: f for f in first.functions}
    assert authored["main"].algorithm.family == "none"
    if program == "crc32tool":
        for name in ["crc32_update", "crc32_bitwise", "crc32_update_rt"]:
            assert authored[name].algorithm.family == "crc32"
            assert authored[name].algorithm.variant == "ieee"
            assert authored[name].scorable
        assert authored["jamcrc"].algorithm.variant == "jamcrc"
        assert any(e.target == authored["crc32_update"].address for e in authored["main"].callees)
        assert any(e.target.startswith("import:") for f in first.functions for e in f.callees)
        assert authored["crc32_update"].source_signature is not None
    if program == "cmd-dispatch":
        edges = {e.target for f in first.functions for e in f.callees if e.kind == "indirect"}
        assert {authored[n].address for n in ("cmd_hash", "cmd_sum", "cmd_help")} <= edges


def test_planted_name_annotation_file_and_root_leaks_are_detected(tmp_path):
    image = Config.read(Path("aletheia.toml")).sandbox.image_build
    source = Path("corpus/tierA/crc32tool")
    build = build_program(source, Variant(image=image, output_root=tmp_path / "build"))
    gt = extract_ground_truth(build, source)
    for token in (
        b"crc32_update",
        b"@algorithm crc32/ieee",
        b"algorithms.c",
        str(source.resolve()).encode(),
    ):
        planted = tmp_path / "planted.bin"
        planted.write_bytes(build.stripped.read_bytes() + b"\x00" + token + b"\x00")
        hits = check_leakage(planted, gt, source)
        assert any(token.decode() in h.token for h in hits)


def test_private_build_hash_mismatch_fails_explicitly(tmp_path):
    from aletheia.corpus.ground_truth import GroundTruthError

    image = Config.read(Path("aletheia.toml")).sandbox.image_build
    source = Path("corpus/tierA/crc32tool")
    build = build_program(source, Variant(image=image, output_root=tmp_path / "build"))
    build.o0.write_bytes(build.o0.read_bytes() + b"changed")
    with pytest.raises(GroundTruthError, match="hash"):
        extract_ground_truth(build, source)


def test_leak_failure_preserves_entire_previous_bundle(tmp_path):
    import shutil

    from aletheia.corpus.build import BuildError

    copied = tmp_path / "corpus"
    shutil.copytree("corpus", copied)
    source = copied / "tierA/crc32tool"
    image = Config.read(Path("aletheia.toml")).sandbox.image_build
    variant = Variant(image=image, output_root=tmp_path / "build")
    built = build_program(source, variant)
    before = {
        p.relative_to(built.metadata.parent): p.read_bytes()
        for p in built.metadata.parent.rglob("*")
        if p.is_file()
    }
    main = source / "src/main.c"
    main.write_text(
        main.read_text().replace(
            "int main(int argc, char **argv) {",
            'int main(int argc, char **argv) {\n    fputs("@algorithm none", stdout);',
        )
    )
    with pytest.raises(BuildError, match="leakage"):
        build_program(source, variant)
    after = {
        p.relative_to(built.metadata.parent): p.read_bytes()
        for p in built.metadata.parent.rglob("*")
        if p.is_file()
    }
    assert after == before

"""T07: emitted binaries and LLVM parsing stay inside the compiler sandbox."""

import hashlib
import json
import shutil
from pathlib import Path

import pytest

from aletheia.config import Config
from aletheia.corpus.build import BuildError, Variant, build_program

pytestmark = pytest.mark.integration
PROGRAMS = ("crc32tool", "adlerfletch", "hashtable", "b64", "cmd-dispatch")


@pytest.mark.parametrize("program", PROGRAMS)
def test_two_builds_are_identical_and_private_outputs_exist(tmp_path, program):
    image = Config.read(Path("aletheia.toml")).sandbox.image_build
    variant = Variant(image=image, output_root=tmp_path / "build")
    source = Path("corpus/tierA") / program
    first = build_program(source, variant)
    original = {p.name: p.read_bytes() for p in (first.stripped, first.unstripped, first.o0)}
    metadata = first.metadata.read_bytes()
    second = build_program(source, variant)
    assert second.binary_sha256 == first.binary_sha256
    assert {
        p.name: p.read_bytes() for p in (second.stripped, second.unstripped, second.o0)
    } == original
    assert second.metadata.read_bytes() == metadata
    assert second.stripped.name == hashlib.sha256(second.stripped.read_bytes()).hexdigest() + ".bin"
    assert second.stripped.parent.name == "stripped"
    assert second.unstripped.parent.name == second.o0.parent.name == "private"
    assert second.unstripped.name == "unstripped.bin"
    assert second.o0.name == "o0.bin"
    record = json.loads(metadata)
    assert record["variant_id"] == "clang23-O2-x64-pie-hardoff"
    assert record["image"] == image
    assert record["source_date_epoch"] == 0
    assert record["hashes"]["stripped"] == second.binary_sha256
    assert record["compiler_version"] == "23.1.3"
    assert record["build_flags"][1] == "-O2"
    assert record["o0_flags"][1] == "-O0"
    assert "-march=x86-64" in record["build_flags"]
    assert "-ffile-prefix-map=/corpus=." in record["build_flags"]
    assert "-Wl,--build-id=none" in record["build_flags"]
    assert record["inspection"]["stripped_has_symtab"] is False
    assert record["inspection"]["private_has_debug_info"] is True
    assert record["inspection"]["machine"] == "EM_X86_64"
    assert record["inspection"]["type"] == "SharedObject"


def test_compile_failure_preserves_previous_build(tmp_path):
    corpus = tmp_path / "corpus"
    shutil.copytree("corpus", corpus)
    image = Config.read(Path("aletheia.toml")).sandbox.image_build
    variant = Variant(image=image, output_root=tmp_path / "build")
    source = corpus / "tierA/crc32tool"
    first = build_program(source, variant)
    previous = first.metadata.read_bytes()
    main = source / "src/main.c"
    main.write_text(main.read_text() + "\n#error acceptance_compile_failure\n")
    with pytest.raises(BuildError, match="compiler"):
        build_program(source, variant)
    assert first.metadata.read_bytes() == previous
    assert first.stripped.is_file()


def test_hardened_build_preserves_real_import_edges_and_reproduces(tmp_path):
    image = Config.read(Path("aletheia.toml")).sandbox.image_build
    variant = Variant(image=image, output_root=tmp_path / "build", hardening="hardened")
    first = build_program(Path("corpus/tierA/cmd-dispatch"), variant)
    original = [p.read_bytes() for p in (first.stripped, first.unstripped, first.o0)]
    second = build_program(Path("corpus/tierA/cmd-dispatch"), variant)
    assert [p.read_bytes() for p in (second.stripped, second.unstripped, second.o0)] == original
    record = json.loads(second.metadata.read_bytes())
    assert record["variant_id"] == "clang23-O2-x64-pie-hardened"
    assert "-fstack-protector-strong" in record["build_flags"]
    assert "-D_FORTIFY_SOURCE=2" in record["build_flags"]
    assert "-fcf-protection=full" in record["build_flags"]
    truth = json.loads((second.o0.parent / "ground_truth.json").read_bytes())
    imports = {
        f["name"]: {e["target"] for e in f["callees"] if e["target"].startswith("import:")}
        for f in truth["functions"]
    }
    assert "import:__printf_chk" in imports["cmd_hash"]
    assert "import:puts" in imports["cmd_help"]
    assert "import:__vfprintf_chk" in imports["log_msg"]

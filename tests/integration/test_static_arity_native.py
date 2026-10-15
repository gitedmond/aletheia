"""T11: production Ghidra arity matches independently reviewed F7, including varargs."""

from pathlib import Path

import pytest
import yaml

from aletheia.analysis.ghidra_session import GhidraAnalysisCache
from aletheia.config import Config
from aletheia.corpus.build import Variant, build_program
from aletheia.sandbox.runner import JobRunner
from aletheia.sources.base import BinaryRef
from aletheia.store.artifacts import ArtifactStore
from aletheia.verify.static.arity import infer_arity

pytestmark = pytest.mark.integration


def test_golden_arity_and_variadic_rejection(tmp_path):
    cfg = Config.read(Path("aletheia.toml"))
    golden = yaml.safe_load(Path("tests/golden/arity.yaml").read_text())
    cache = GhidraAnalysisCache(
        JobRunner(
            cfg.sandbox,
            tmp_path / "public",
            tmp_path / "jobs",
            ArtifactStore(tmp_path / "artifacts"),
        ),
        tmp_path / "cache",
    )
    for program in golden["programs"]:
        built = build_program(
            Path("corpus/tierA") / program["program"],
            Variant(image=cfg.sandbox.image_build, output_root=tmp_path / "build"),
        )
        assert built.binary_sha256 == program["binary_sha256"]
        analysis = cache.analyze(
            BinaryRef(built.binary_sha256, built.stripped, built.variant_id),
            Path("configs/ghidra-analysis.json"),
        )
        for case in program["cases"]:
            result = infer_arity(case["address"], analysis)
            assert result.model_dump() == {
                key: case[key] for key in ("arity", "decisive", "reason")
            }, (program["program"], case["name"], result)


def test_implicit_register_definitions_prepare_real_sysv_arguments(tmp_path):
    import hashlib
    import json

    from test_emulator import run_container

    cfg = Config.read(Path("aletheia.toml"))
    inputs, outputs = tmp_path / "compile/in", tmp_path / "compile/out"
    inputs.mkdir(parents=True)
    outputs.mkdir()
    (inputs / "caller.S").write_text("""
.text
.globl arity3
.hidden arity3
.type arity3,@function
arity3:
 leaq (%rdi,%rsi),%rax
 addq %rdx,%rax
 ret
.size arity3,.-arity3
.globl caller_cqo
.type caller_cqo,@function
caller_cqo:
 movl $1,%edi
 movl $2,%esi
 movq $-1,%rax
 cqo
 call arity3
 addq $1,%rax
 ret
.size caller_cqo,.-caller_cqo
.globl caller_rdtsc
.type caller_rdtsc,@function
caller_rdtsc:
 movl $1,%edi
 movl $2,%esi
 rdtsc
 call arity3
 addq $1,%rax
 ret
.size caller_rdtsc,.-caller_rdtsc
.section .note.GNU-stack,"",@progbits
""")
    (inputs / "driver.c").write_text(
        "extern long caller_cqo(void),caller_rdtsc(void);"
        "int main(void) { return (int)(caller_cqo()+caller_rdtsc()); }"
    )
    compile_script = """
import json,subprocess
from pathlib import Path
binary='/job/out/callers.bin'
subprocess.run(['clang','-O2','-fPIE','-pie','-fno-stack-protector','-march=x86-64',
 '-Wl,--build-id=none','/job/in/caller.S','/job/in/driver.c','-o',binary],check=True)
text=subprocess.check_output(['llvm-nm','--defined-only',binary],text=True)
Path('/job/out/symbols.json').write_text(json.dumps({line.split()[2]:int(line.split()[0],16)
 for line in text.splitlines() if len(line.split())==3}))
subprocess.run(['llvm-strip','--strip-all',binary],check=True)
"""
    run_container(cfg.sandbox.image_build, inputs, outputs, ["python", "-c", compile_script])
    symbols = json.loads((outputs / "symbols.json").read_bytes())
    payload = (outputs / "callers.bin").read_bytes()
    digest = hashlib.sha256(payload).hexdigest()
    public = tmp_path / "stripped" / (digest + ".bin")
    public.parent.mkdir()
    public.write_bytes(payload)
    cache = GhidraAnalysisCache(
        JobRunner(
            cfg.sandbox,
            tmp_path / "public",
            tmp_path / "jobs",
            ArtifactStore(tmp_path / "artifacts"),
        ),
        tmp_path / "cache",
    )
    record = cache.analyze(
        BinaryRef(digest, public, "implicit-argument-definitions"),
        Path("configs/ghidra-analysis.json"),
    )
    subject = f"0x{symbols['arity3']:08x}"
    sites = [site for fn in record.functions for site in fn.call_sites if site.target == subject]
    assert len(sites) == 2
    assert all(site.argument_registers == ["rdi", "rsi", "rdx"] for site in sites)
    assert infer_arity(subject, record).model_dump() == {
        "arity": 3,
        "decisive": True,
        "reason": None,
    }

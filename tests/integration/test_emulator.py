"""T12 real stripped code: checksum, bounded execution, state tracking and reset."""

import hashlib
import json
import os
import subprocess
from pathlib import Path

import pytest

from aletheia.config import Config
from aletheia.corpus.build import Variant, build_program
from aletheia.sandbox.policy import container_args

pytestmark = pytest.mark.integration

NATIVE = """
volatile unsigned bss;
volatile unsigned zero __attribute__((section(".data"))) = 0;
volatile unsigned initialized = 7;
volatile unsigned nonzero_bytes = 0x07070707;
const volatile unsigned constant = 11;
extern unsigned foreign(void);
unsigned read_bss(void) { return bss; }
unsigned read_zero(void) { return zero; }
unsigned read_initialized(void) { return initialized; }
unsigned read_nonzero_bytes(void) { return nonzero_bytes; }
unsigned read_constant(void) { return constant; }
unsigned write_then_read(void) { bss = 9; return bss; }
unsigned write_zero_then_read(void) { zero = 13; return zero; }
unsigned null_read(void) { return *(volatile unsigned *)0; }
unsigned long canary(void) {
    unsigned long value;
    __asm__ volatile("movq %%fs:0x28, %0" : "=r"(value));
    return value;
}
unsigned unknown(void) { return foreign(); }
unsigned write_code(void) { *(volatile unsigned char *)(unsigned long)&read_bss = 0; return 0; }
unsigned system_call(void) { __asm__ volatile("syscall" ::: "rcx", "r11", "memory"); return 0; }
unsigned spin(void) { for (;;) { __asm__ volatile(""); } }
"""


def run_container(image, inputs, outputs, argv):
    cfg = Config.read(Path("aletheia.toml")).sandbox.model_copy(update={"image_analysis": image})
    result = subprocess.run(
        [
            "docker",
            "run",
            "--rm",
            *container_args(cfg, inputs, outputs, os.getuid(), os.getgid()),
            "--entrypoint",
            argv[0],
            image,
            *argv[1:],
        ],
        capture_output=True,
        text=True,
        timeout=90,
    )
    assert result.returncode == 0, result.stdout + result.stderr
    return result.stdout


def emulate(tmp_path, binary, calls, instructions=100000):
    cfg = Config.read(Path("aletheia.toml"))
    inputs, outputs = tmp_path / "in", tmp_path / "out"
    inputs.mkdir(parents=True)
    outputs.mkdir()
    payload = binary.read_bytes()
    name = hashlib.sha256(payload).hexdigest() + ".bin"
    (inputs / name).write_bytes(payload)
    script = (
        """
import dataclasses,json
from pathlib import Path
from aletheia.config import Budgets
from aletheia.verify.emulate.core import Buffer,Emulator
calls = CALLS
emulator=Emulator(Path('/job/in/NAME'),Budgets(instructions_per_invocation=LIMIT))
results=[]
for entry,args,width in calls:
 args=[Buffer(bytes.fromhex(arg)) if isinstance(arg,str) else arg for arg in args]
 result=dataclasses.asdict(emulator.call(entry,args,width))
 result['out_buffers']=[value.hex() for value in result['out_buffers']]
 results.append(result)
print(json.dumps({'calls':results,'data_imports':emulator.data_imports}))
""".replace("CALLS", repr(calls))
        .replace("NAME", name)
        .replace("LIMIT", str(instructions))
    )
    return json.loads(
        run_container(cfg.sandbox.image_analysis, inputs, outputs, ["python", "-c", script])
    )


def test_real_crc32_budget_and_runtime_table_reset(tmp_path):
    cfg = Config.read(Path("aletheia.toml"))
    built = build_program(
        Path("corpus/tierA/crc32tool"),
        Variant(image=cfg.sandbox.image_build, output_root=tmp_path / "build"),
    )
    gt = json.loads((built.unstripped.parent / "ground_truth.json").read_bytes())
    entries = {fn["name"]: int(fn["address"], 16) for fn in gt["functions"]}
    vector = b"123456789".hex()
    result = emulate(
        tmp_path / "normal",
        built.stripped,
        [
            (entries["crc32_bitwise"], [vector, 9], 32),
            (entries["crc32_update_rt"], [0, vector, 9], 32),
            (entries["crc32_table_init"], [], 32),
            (entries["crc32_update_rt"], [0, vector, 9], 32),
        ],
    )
    first, uninitialized, initializer, reset = result["calls"]
    assert first["ret"] == 0xCBF43926 and first["fault"] is None
    assert not first["uninitialized_state_reads"]
    assert uninitialized["uninitialized_state_reads"] and reset["uninitialized_state_reads"]
    assert initializer["fault"] is None
    assert result["data_imports"] == ["data_import:stderr", "data_import:stdin"]
    limited = emulate(
        tmp_path / "limited",
        built.stripped,
        [
            (entries["crc32_bitwise"], [vector, 9], 32),
        ],
        instructions=32,
    )["calls"][0]
    assert limited["fault"] == "budget_exhausted" and limited["instructions"] == 32


def test_mutable_zero_bytes_constants_tls_faults_and_unknown_import(tmp_path):
    cfg = Config.read(Path("aletheia.toml"))
    inputs, outputs = tmp_path / "compile/in", tmp_path / "compile/out"
    inputs.mkdir(parents=True)
    outputs.mkdir()
    (inputs / "state.c").write_text(NATIVE)
    (inputs / "tls.c").write_text("__thread int state; int read_tls(void) { return state; }")
    compile_script = """
import json,subprocess
from pathlib import Path
symbols={}
for name in ('state','tls'):
 output='/job/out/'+name+'.bin'
 subprocess.run(['clang','-O2','-fPIC','-shared','-nostdlib','-march=x86-64',
                 '-fno-stack-protector','-Wl,--build-id=none','/job/in/'+name+'.c','-o',output],check=True)
 text=subprocess.check_output(['llvm-nm','--defined-only',output],text=True)
 symbols[name]={line.split()[2]:int(line.split()[0],16) for line in text.splitlines()
                if len(line.split())==3}
 subprocess.run(['llvm-strip','--strip-all',output],check=True)
Path('/job/out/symbols.json').write_text(json.dumps(symbols))
"""
    run_container(cfg.sandbox.image_build, inputs, outputs, ["python", "-c", compile_script])
    symbols = json.loads((outputs / "symbols.json").read_bytes())
    names = [
        "read_bss",
        "read_zero",
        "read_initialized",
        "read_constant",
        "write_then_read",
        "read_bss",
        "write_zero_then_read",
        "read_zero",
        "canary",
        "null_read",
        "unknown",
        "spin",
        "write_code",
        "system_call",
        "read_nonzero_bytes",
    ]
    result = emulate(
        tmp_path / "run",
        outputs / "state.bin",
        [(symbols["state"][name], [], 64 if name == "canary" else 32) for name in names],
        instructions=32,
    )["calls"]
    assert [row["uninitialized_state_reads"] for row in result[:8]] == [
        True,
        True,
        True,  # Author-selected byte policy: high zero bytes of uint32_t7 remain tracked.
        False,
        False,
        True,
        False,
        True,
    ]
    assert [result[index]["ret"] for index in (2, 3, 4, 6, 8)] == [
        7,
        11,
        9,
        13,
        0x2F8A5C11D3E07B46,
    ]
    assert [result[index]["fault"] for index in (9, 10, 11)] == [
        "emulation_fault",
        "unsupported_import:foreign",
        "budget_exhausted",
    ]
    assert result[12]["fault"] == result[13]["fault"] == "emulation_fault"
    assert result[14]["ret"] == 0x07070707 and not result[14]["uninitialized_state_reads"]
    unsupported = emulate(
        tmp_path / "tls",
        outputs / "tls.bin",
        [
            (symbols["tls"]["read_tls"], [], 32),
        ],
    )["calls"][0]
    assert unsupported["fault"] == "unsupported_relocation"

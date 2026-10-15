"""T13: execute every specified libc stub through real imported machine-code calls."""

import json
from pathlib import Path

import pytest
from test_emulator import emulate, run_container

from aletheia.config import Config

pytestmark = pytest.mark.integration

SOURCE = r"""
#include <stddef.h>
extern void *memcpy(void *, const void *, size_t);
extern void *memmove(void *, const void *, size_t);
extern void *memset(void *, int, size_t);
extern int memcmp(const void *, const void *, size_t);
extern size_t strlen(const char *);
extern int strcmp(const char *, const char *);
extern int strncmp(const char *, const char *, size_t);
extern void *malloc(size_t);
extern void *calloc(size_t, size_t);
extern void *realloc(void *, size_t);
extern void free(void *);
extern void __stack_chk_fail(void);
volatile unsigned state;
void *copy(void *a, const void *b, size_t n) { return memcpy(a,b,n); }
void *move(char *a, size_t n) { return memmove(a+1,a,n); }
void *set(void *a, size_t n) { return memset(a,0x1ab,n); }
int compare(const void *a,const void *b,size_t n) { int v=memcmp(a,b,n); return (v>0)-(v<0); }
size_t length(const char *a) { return strlen(a); }
int strings(const char *a,const char *b) { int v=strcmp(a,b); return (v>0)-(v<0); }
int prefix(const char *a,const char *b,size_t n) { int v=strncmp(a,b,n); return (v>0)-(v<0); }
unsigned allocate(size_t n) { unsigned char *p=malloc(n); if(!p)return 42; p[0]=17; return p[0]; }
unsigned zero_allocate(size_t n,size_t m) { unsigned char *p=calloc(n,m); if(!p)return 42;
 return p[0]|p[n*m-1]; }
unsigned grow(void) { unsigned char *p=malloc(2); p[0]=37;p[1]=19; p=realloc(p,8);
 return p[0]+p[1]; }
unsigned release(void) { unsigned char *p=malloc(1); p[0]=23; free(p); return p[0]; }
unsigned fail(void) { __stack_chk_fail(); return 0; }
int read_state(const void *p) { return memcmp((const void *)&state,p,4); }
unsigned write_state(void) { memset((void *)&state,7,4); return state; }
void *write_ro(void) { return memset((void *)"literal",1,2); }
"""


@pytest.fixture(scope="module")
def stub_binary(tmp_path_factory):
    root = tmp_path_factory.mktemp("stubs")
    inputs, outputs = root / "in", root / "out"
    inputs.mkdir()
    outputs.mkdir()
    (inputs / "stubs.c").write_text(SOURCE)
    cfg = Config.read(Path("aletheia.toml"))
    script = """
import json,subprocess
from pathlib import Path
output='/job/out/stubs.bin'
subprocess.run(['clang','-shared','-nostdlib','-O2','-fPIC','-fno-builtin',
 '-fno-stack-protector','-march=x86-64','-Wl,--build-id=none','/job/in/stubs.c','-o',output],check=True)
text=subprocess.check_output(['llvm-nm','--defined-only',output],text=True)
Path('/job/out/symbols.json').write_text(json.dumps({line.split()[2]:int(line.split()[0],16)
 for line in text.splitlines() if len(line.split())==3}))
subprocess.run(['llvm-strip','--strip-all',output],check=True)
"""
    run_container(cfg.sandbox.image_build, inputs, outputs, ["python", "-c", script])
    return outputs / "stubs.bin", json.loads((outputs / "symbols.json").read_bytes())


@pytest.mark.parametrize(
    "stub,name,args,expected,out",
    [
        ("memcpy", "copy", ["00000000", "61626364", 4], 0x78000000, "61626364"),
        ("memmove", "move", ["6162636400", 4], 0x78000001, "6161626364"),
        ("memset", "set", ["000000", 3], 0x78000000, "ababab"),
        ("memcmp", "compare", ["ff", "01", 1], 1, None),
        ("strlen", "length", ["6162630064"], 3, None),
        ("strcmp", "strings", ["ff00", "0100"], 1, None),
        ("strncmp", "prefix", ["61620063", "61620064", 4], 0, None),
        ("malloc", "allocate", [8], 17, None),
        ("calloc", "zero_allocate", [2, 4], 0, None),
        ("realloc", "grow", [], 56, None),
        ("free", "release", [], 23, None),
        ("__stack_chk_fail", "fail", [], None, None),
    ],
)
def test_native_import_stub(stub_binary, tmp_path, stub, name, args, expected, out):
    binary, symbols = stub_binary
    result = emulate(tmp_path, binary, [(symbols[name], args, 64)])["calls"][0]
    assert result["ret"] == expected, result
    assert result["fault"] == ("emulation_fault" if name == "fail" else None), result
    assert stub in result["imports_called"]
    if out is not None:
        assert result["out_buffers"][0] == out


def test_stub_memory_permissions_initialization_and_allocator_bounds(stub_binary, tmp_path):
    binary, symbols = stub_binary
    calls = [
        (symbols[name], args, 64)
        for name, args in [
            ("read_state", ["00000000"]),
            ("write_state", []),
            ("read_state", ["00000000"]),
            ("write_ro", []),
            ("allocate", [2**64 - 1]),
            ("zero_allocate", [2**63, 2]),
            ("copy", [0, 0, 0]),
            ("allocate", [8]),
            ("allocate", [8]),
        ]
    ]
    results = emulate(tmp_path, binary, calls)["calls"]
    assert results[0]["uninitialized_state_reads"] and results[2]["uninitialized_state_reads"]
    assert results[1]["ret"] == 0x07070707 and not results[1]["uninitialized_state_reads"]
    assert results[3]["fault"] == "emulation_fault"
    assert [row["ret"] for row in results[4:]] == [42, 42, 0, 17, 17]
    assert all(row["fault"] is None for row in results[4:])

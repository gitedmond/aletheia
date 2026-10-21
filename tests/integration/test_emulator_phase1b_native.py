"""Real hardened code, F17 table layout, fortified faults and persistent sequences."""

import hashlib
import json
from pathlib import Path

import pytest
from test_emulator import run_container

from aletheia.config import Config

pytestmark = pytest.mark.integration

SOURCE = r"""
#include <stddef.h>
#include <stdint.h>
extern void *__memcpy_chk(void *, const void *, size_t, size_t);
extern void *__memmove_chk(void *, const void *, size_t, size_t);
extern void *__memset_chk(void *, int, size_t, size_t);
extern char *__strcpy_chk(char *, const char *, size_t);
extern const unsigned short **__ctype_b_loc(void);
extern const int **__ctype_tolower_loc(void), **__ctype_toupper_loc(void);
extern int *__errno_location(void);
int copy_checked(char *d, const char *s, size_t n) {__memcpy_chk(d,s,n,4);return (int)n;}
int move_checked(char *d, const char *s, size_t n) {__memmove_chk(d,s,n,4);return (int)n;}
int set_checked(char *d, const char *s, size_t n) {__memset_chk(d,*s,n,4);return (int)n;}
int string_checked(char *d, const char *s, size_t n) {(void)n;__strcpy_chk(d,s,4);return 0;}
int classify(int c) {return (*__ctype_b_loc())[c];}
int lower_case(int c) {return (*__ctype_tolower_loc())[c];}
int upper_case(int c) {return (*__ctype_toupper_loc())[c];}
int errno_previous(void) {int *p=__errno_location();int old=*p;*p=19;return old;}
volatile uint32_t persistent;
void initialize_state(void) {persistent=0x01020304;}
uint32_t read_state(void) {return persistent;}
void initialize_context(uint32_t *p) {*p=0x01020304;}
uint32_t update_context(uint32_t *p, const uint8_t *b, size_t n) {*p+=n?b[0]:0;return *p;}
"""


def test_hardened_stubs_tables_sequences_and_faults(tmp_path):
    cfg = Config.read(Path("aletheia.toml"))
    inputs, output = tmp_path / "compile/in", tmp_path / "compile/out"
    inputs.mkdir(parents=True)
    output.mkdir()
    (inputs / "subject.c").write_text(SOURCE)
    compile_script = """
import json,subprocess
from pathlib import Path
p='/job/out/subject.bin'
subprocess.run(['clang','-O2','-fPIC','-shared','-nostdlib','-march=x86-64',
 '-fcf-protection=full','-fstack-protector-strong','-fno-builtin','-Wl,--build-id=none',
 '/job/in/subject.c','-o',p],check=True)
text=subprocess.check_output(['llvm-nm','--defined-only',p],text=True)
symbols={x.split()[2]:int(x.split()[0],16) for x in text.splitlines() if len(x.split())==3}
assert 'endbr64' in subprocess.check_output(['llvm-objdump','-d',p],text=True)
Path('/job/out/symbols.json').write_text(json.dumps(symbols))
subprocess.run(['llvm-strip','--strip-all',p],check=True)
"""
    run_container(cfg.sandbox.image_build, inputs, output, ["python", "-c", compile_script])
    symbols = json.loads((output / "symbols.json").read_bytes())
    job_in, job_out = tmp_path / "job/in", tmp_path / "job/out"
    job_in.mkdir(parents=True)
    job_out.mkdir()
    payload = (output / "subject.bin").read_bytes()
    name = hashlib.sha256(payload).hexdigest() + ".bin"
    (job_in / name).write_bytes(payload)
    script = """
import dataclasses,json,struct
from pathlib import Path
from aletheia.config import Budgets
from aletheia.verify.emulate.core import Buffer,Emulator
s=SYMBOLS
emu=Emulator(Path('/job/in/NAME'),Budgets())
def record(result):
 value=dataclasses.asdict(result)
 value['out_buffers']=[b.hex() for b in result.out_buffers]
 value['stdout']=result.stdout.hex()
 value['stderr']=result.stderr.hex()
 return value
copies=[]
for fn in ['copy_checked','move_checked','set_checked','string_checked']:
 copies.append(record(emu.call(s[fn],[Buffer(bytes(16)),Buffer(b'hi\\0'),3])))
 copies.append(record(emu.call(s[fn],[Buffer(bytes(16)),Buffer(b'hello\\0'),5])))
tables={}
for key,code,width in [('b','H',2),('tolower','i',4),('toupper','i',4)]:
 pivot=struct.unpack('<Q',emu.read_memory(emu.libc_objects['__ctype_'+key+'_loc'],8))[0]
 tables[key]=list(struct.unpack('<384'+code,emu.read_memory(pivot-128*width,384*width)))
seq=emu.call_sequence([(s['initialize_state'],[],32),(s['read_state'],[],32)])
reset=emu.call(s['read_state'],[],32)
context=Buffer(bytes(4))
shared=emu.call_sequence([(s['initialize_context'],[context],32),
 (s['update_context'],[context,Buffer(b'\\x05'),1],32)])
errno=emu.call_sequence([(s['errno_previous'],[],32),(s['errno_previous'],[],32)])
print(json.dumps({'copies':copies,'tables':tables,'sequence':[record(x) for x in seq],
 'reset':record(reset),'shared':[record(x) for x in shared],'errno':[record(x) for x in errno]}))
""".replace("SYMBOLS", repr(symbols)).replace("NAME", name)
    result = json.loads(
        run_container(cfg.sandbox.image_analysis, job_in, job_out, ["python", "-c", script])
    )
    for index, call in enumerate(result["copies"]):
        assert call["fault"] == ("fortify_fail" if index % 2 else None)
        if index % 2 == 0:
            assert call["out_buffers"][0].startswith("686900" if index != 4 else "686868")
    tables = json.loads(Path("aletheia/verify/emulate/ctype_tables.json").read_bytes())
    assert result["tables"] == {key: tables[key] for key in ["b", "tolower", "toupper"]}
    assert result["sequence"][1]["ret"] == 0x01020304
    assert not result["sequence"][1]["uninitialized_state_reads"]
    assert result["reset"]["ret"] == 0 and result["reset"]["uninitialized_state_reads"]
    assert result["shared"][1]["ret"] == 0x01020309
    assert result["shared"][1]["out_buffers"][0] == "09030201"
    assert [call["ret"] for call in result["errno"]] == [0, 0]

from types import SimpleNamespace

import pytest

from aletheia.verify.emulate.stubs import FortifyFault, emulate_import


class Guest:
    def __init__(self, args):
        self.registers = SimpleNamespace(
            UC_X86_REG_RDI=0, UC_X86_REG_RSI=1, UC_X86_REG_RDX=2, UC_X86_REG_RCX=3
        )
        self.uc = SimpleNamespace(reg_read=lambda register: args[register])
        self.memory = bytearray(256)
        self.libc_objects = {
            "__ctype_b_loc": 100,
            "__ctype_tolower_loc": 108,
            "__ctype_toupper_loc": 116,
            "__errno_location": 124,
        }

    def check_memory(self, address, size, write=False):
        assert 0 <= address <= address + size <= len(self.memory)

    def read_memory(self, address, size):
        self.check_memory(address, size)
        return bytes(self.memory[address : address + size])

    def write_memory(self, address, payload):
        self.check_memory(address, len(payload))
        self.memory[address : address + len(payload)] = payload

    def charge_work(self, units):
        assert units >= 0


@pytest.mark.parametrize("name", ["__memcpy_chk", "__memmove_chk", "__memset_chk", "__strcpy_chk"])
def test_each_fortified_stub_copies_and_refuses_overflow(name):
    args = [32, 65 if name == "__memset_chk" else 0, 3, 3]
    if name == "__strcpy_chk":
        args[2] = 3
    guest = Guest(args)
    guest.memory[:3] = b"hi\0"
    assert emulate_import(guest, name) == 32
    assert guest.memory[32:35] == (b"AAA" if name == "__memset_chk" else b"hi\0")
    if name == "__strcpy_chk":
        args[2] = 2
    else:
        args[3] = 2
    with pytest.raises(FortifyFault):
        emulate_import(guest, name)


@pytest.mark.parametrize(
    "name", ["__ctype_b_loc", "__ctype_tolower_loc", "__ctype_toupper_loc", "__errno_location"]
)
def test_each_tls_pointer_stub_returns_its_initialized_object(name):
    guest = Guest([0, 0, 0, 0])
    assert emulate_import(guest, name) == guest.libc_objects[name]


def test_probe_retains_fortify_fault_as_a_non_mismatch_status():
    from aletheia.verify.emulate.core import CallResult
    from aletheia.verify.probes.pack import CallShape, VariantProbe
    from aletheia.verify.probes.runner import run_input

    emu = SimpleNamespace(call=lambda *args: CallResult(None, [], 1, "fortify_fail", False, []))
    shape = CallShape(id="buf_len", roles=["buf", "len"], return_width=32)
    probe = VariantProbe(oracle="crc32_ieee", bind={"seed": 0})
    result = run_input(emu, 4096, shape, "ieee", probe, b"abc")
    assert result.status == "fortify_fail" and result.result.ret is None


def test_packaged_ctype_tables_equal_the_reviewed_native_fixture():
    import json
    from pathlib import Path

    assert json.loads(Path("aletheia/verify/emulate/ctype_tables.json").read_bytes()) == json.loads(
        Path("tests/golden/ctype_tables.json").read_bytes()
    )

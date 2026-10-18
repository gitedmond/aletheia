from types import SimpleNamespace

import pytest

from aletheia.verify.emulate.core import MemoryFault
from aletheia.verify.emulate.stubs import FortifyFault, emulate_import


class Guest:
    def __init__(self, args):
        self.args = args
        self.registers = SimpleNamespace(
            UC_X86_REG_RDI=0,
            UC_X86_REG_RSI=1,
            UC_X86_REG_RDX=2,
            UC_X86_REG_RCX=3,
            UC_X86_REG_R8=4,
            UC_X86_REG_R9=5,
        )
        self.uc = SimpleNamespace(reg_read=lambda register: self.args[register])
        self.memory = bytearray(256)
        self.libc_objects = {
            "__ctype_b_loc": 100,
            "__ctype_tolower_loc": 108,
            "__ctype_toupper_loc": 116,
            "__errno_location": 124,
        }
        self.virtual_files = {b"probe.dat": b"hi\x00there"}
        self.file_handles = {}
        self.stdout = bytearray()
        self.heap = 200

    def allocate(self, size):
        address, self.heap = self.heap, self.heap + size
        assert self.heap <= len(self.memory)
        return address

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


def _write_cstring(guest, address, value):
    guest.memory[address : address + len(value) + 1] = value + b"\0"


def test_virtual_file_cursor_stubs_read_only_declared_files():
    guest = Guest([32, 64, 0, 0, 0, 0])
    _write_cstring(guest, 64, b"rb")
    _write_cstring(guest, 32, b"probe.dat")
    handle = emulate_import(guest, "fopen")
    assert handle and emulate_import(guest, "fopen") != handle
    guest.args[0] = handle
    assert [emulate_import(guest, "fgetc") for _ in range(9)] == [
        104,
        105,
        0,
        116,
        104,
        101,
        114,
        101,
        -1,
    ]
    assert emulate_import(guest, "ferror") == 0
    assert emulate_import(guest, "fclose") == 0
    assert emulate_import(guest, "fgetc") == -1
    guest.args[0] = 32
    _write_cstring(guest, 32, b"missing.dat")
    assert emulate_import(guest, "fopen") == 0


def test_putchar_and_printf_render_the_declared_subset_into_stdout():
    guest = Guest([32, 255, 0xDEADBEEF, 16, 0xEF, 0])
    _write_cstring(guest, 32, b"%02x|%08x|%s|%c|%%\n")
    _write_cstring(guest, 16, b"ok")
    written = emulate_import(guest, "printf")
    assert bytes(guest.stdout) == b"ff|deadbeef|ok|\xef|%\n"
    assert written == len(guest.stdout)
    guest.stdout.clear()
    _write_cstring(guest, 32, b"%X|0x%x\n")
    guest.args[1], guest.args[2] = 0xDEADBEEF, 0xABC
    emulate_import(guest, "printf")
    assert bytes(guest.stdout) == b"DEADBEEF|0xabc\n"
    guest = Guest([65, 0, 0, 0, 0, 0])
    assert emulate_import(guest, "putchar") == 65 and bytes(guest.stdout) == b"A"


def test_printf_rejects_conversions_outside_the_declared_subset():
    guest = Guest([16, 1, 0, 0, 0, 0])
    _write_cstring(guest, 16, b"%p")
    with pytest.raises(MemoryFault):
        emulate_import(guest, "printf")
    guest = Guest([16, 1, 2, 3, 4, 5])
    _write_cstring(guest, 16, b"%x%x%x%x%x%x")
    with pytest.raises(MemoryFault):
        emulate_import(guest, "printf")


@pytest.mark.parametrize("fmt", [b"%lx", b"%#x", b"%-8x", b"%+d", b"%05s"])
def test_printf_abstains_on_unsupported_flags_and_lengths(fmt):
    guest = Guest([32, 1, 0, 0, 0, 0])
    _write_cstring(guest, 32, fmt)
    with pytest.raises(MemoryFault):
        emulate_import(guest, "printf")


def test_printf_padding_preserves_the_sign_and_charges_before_allocating():
    from aletheia.verify.emulate.core import BudgetExhausted

    guest = Guest([32, (-12) & 0xFFFFFFFF, 0, 0, 0, 0])
    _write_cstring(guest, 32, b"%05d")
    emulate_import(guest, "printf")
    assert bytes(guest.stdout) == b"-0012"
    guest.stdout.clear()
    _write_cstring(guest, 32, b"%999999999x")

    def bounded(units):
        if units > 64:
            raise BudgetExhausted

    guest.charge_work = bounded
    with pytest.raises(BudgetExhausted):
        emulate_import(guest, "printf")
    assert not guest.stdout


def test_fortified_printf_skips_flag_and_format_registers():
    guest = Guest([1, 32, 0xABC, 0, 0, 0])
    _write_cstring(guest, 32, b"%08x\n")
    assert emulate_import(guest, "__printf_chk") == 9
    assert bytes(guest.stdout) == b"00000abc\n"


def test_virtual_files_reject_writing_modes():
    guest = Guest([32, 64, 0, 0, 0, 0])
    _write_cstring(guest, 32, b"probe.dat")
    _write_cstring(guest, 64, b"wb")
    with pytest.raises(MemoryFault):
        emulate_import(guest, "fopen")


def test_indirect_file_output_preserves_post_call_state_reads():
    from aletheia.verify.emulate.core import CallResult
    from aletheia.verify.probes.pack import CallShape, VariantProbe
    from aletheia.verify.probes.runner import run_input

    emu = SimpleNamespace(virtual_files={}, uninitialized=False)
    emu.call = lambda *args: CallResult(
        0, [b"probe.dat\0", (32).to_bytes(8, "little"), bytes(8)], 1, None, False, []
    )

    def read_global(address, size):
        assert (address, size) == (32, 1)
        emu.uninitialized = True
        return b"\0"

    emu.read_memory = read_global
    shape = CallShape(
        id="path_out_len",
        roles=["path", "out_ptr", "len_ptr"],
        return_width=32,
        comparison="return_output",
    )
    result = run_input(emu, 4096, shape, "std", VariantProbe(oracle="read_std"), b"")
    assert result.status == "state_dependent"
    assert result.result.uninitialized_state_reads

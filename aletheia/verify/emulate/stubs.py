"""S1: deterministic libc primitives operating only on checked guest memory."""

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from aletheia.verify.emulate.core import Emulator


class BudgetExhausted(Exception):
    pass


class MemoryFault(Exception):
    pass


class FortifyFault(MemoryFault):
    pass


def emulate_import(emu: "Emulator", name: str) -> int | None:
    """None identifies an unsupported import; all supported stubs return an integer."""
    regs = emu.registers
    a, b, n = (
        int(emu.uc.reg_read(register))
        for register in (regs.UC_X86_REG_RDI, regs.UC_X86_REG_RSI, regs.UC_X86_REG_RDX)
    )
    if name in emu.libc_objects:
        return emu.libc_objects[name]
    if name in ("__memcpy_chk", "__memmove_chk", "__memset_chk"):
        if n > int(emu.uc.reg_read(regs.UC_X86_REG_RCX)):
            raise FortifyFault("copy exceeds declared destination size")
        name = name.removeprefix("__").removesuffix("_chk")
    if name == "__strcpy_chk":
        output = bytearray()
        while True:
            if len(output) >= n:
                raise FortifyFault("string exceeds declared destination size")
            emu.charge_work(1)
            value = emu.read_memory(b + len(output), 1)
            output.extend(value)
            if value == b"\0":
                emu.write_memory(a, bytes(output))
                return a
    if name in ("memcpy", "memmove"):
        emu.check_memory(a, n, write=True)
        emu.write_memory(a, emu.read_memory(b, n))
        return a
    if name == "memset":
        emu.check_memory(a, n, write=True)
        emu.write_memory(a, bytes([b & 255]) * n)
        return a
    if name == "memcmp":
        left, right = emu.read_memory(a, n), emu.read_memory(b, n)
        return (left > right) - (left < right)
    if name == "strlen":
        length = 0
        while True:
            emu.charge_work(1)
            if emu.read_memory(a + length, 1) == b"\0":
                return length
            length += 1
    if name in ("strcmp", "strncmp"):
        index = 0
        while name == "strcmp" or index < n:
            emu.charge_work(1)
            left, right = emu.read_memory(a + index, 1)[0], emu.read_memory(b + index, 1)[0]
            if left != right or left == 0:
                return left - right
            index += 1
        return 0
    if name == "malloc":
        return emu.allocate(a)
    if name == "calloc":
        if a * b >= 2**64:
            return 0
        address = emu.allocate(a * b)
        if address:
            emu.write_memory(address, bytes(a * b))
        return address
    if name == "realloc":
        if a == 0:
            return emu.allocate(b)
        if a not in emu.allocations:
            raise MemoryFault("realloc of unknown allocation")
        if b == 0:
            return 0
        address = emu.allocate(b)
        if address:
            emu.write_memory(address, emu.read_memory(a, min(emu.allocations[a], b)))
        return address
    if name == "free":
        return 0
    if name == "__stack_chk_fail":
        raise MemoryFault("stack canary check failed")
    return None

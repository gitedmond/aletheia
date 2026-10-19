"""S1: deterministic libc primitives operating only on checked guest memory."""

from collections.abc import Callable
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
    if name == "strchr":
        index = 0
        target = b & 0xFF
        while True:
            emu.charge_work(1)
            value = emu.read_memory(a + index, 1)[0]
            if value == target:
                return a + index
            if value == 0:
                return 0
            index += 1
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
    if name == "fopen":
        path = _cstring(emu, a)
        if _cstring(emu, b) not in {b"r", b"rb"}:
            raise MemoryFault("unsupported virtual-file mode")
        if path not in emu.virtual_files:
            return 0
        handle = emu.allocate(16)
        if not handle:
            raise MemoryFault("file handle allocation failed")
        emu.file_handles[handle] = (path, [0])
        return handle
    if name == "fgetc":
        entry = emu.file_handles.get(a)
        emu.charge_work(1)
        if entry is None:
            return -1
        content = emu.virtual_files[entry[0]]
        position = entry[1][0]
        if position >= len(content):
            return -1
        entry[1][0] = position + 1
        return int(content[position])
    if name == "ferror":
        return 0
    if name == "fclose":
        emu.file_handles.pop(a, None)
        return 0
    if name == "puts":
        output = _cstring(emu, a)
        emu.charge_work(1)
        emu.stdout.extend(output + b"\n")
        return 0
    if name == "fwrite":
        size, count = b, n
        stream = int(emu.uc.reg_read(regs.UC_X86_REG_RCX))
        if not _is_stdout(emu, stream):
            return None
        length = size * count
        if length >= 2**64:
            raise MemoryFault("fwrite size overflow")
        emu.charge_work(length)
        if length:
            emu.stdout.extend(emu.read_memory(a, length))
        return count if size else 0
    if name in {"vfprintf", "__vfprintf_chk"}:
        stream = a
        if name == "vfprintf":
            format_address, va_list = b, n
        else:
            if b not in (0, 1):
                return None
            format_address, va_list = n, int(emu.uc.reg_read(regs.UC_X86_REG_RCX))
        if not _is_stdout(emu, stream):
            return None
        return _printf(emu, format_address, argument_reader=_va_list_reader(emu, va_list))
    if name in ("putchar", "putc", "_IO_putc"):
        emu.stdout.append(a & 0xFF)
        return a & 0xFF
    if name in {"printf", "__printf_chk"}:
        emu.charge_work(1)
        return _printf(emu, b if name == "__printf_chk" else a, name == "__printf_chk")
    return None


def _cstring(emu: "Emulator", address: int) -> bytes:
    output = bytearray()
    while True:
        emu.charge_work(1)
        value = emu.read_memory(address + len(output), 1)
        if value == b"\0":
            return bytes(output)
        output.extend(value)


def _is_stdout(emu: "Emulator", stream: int) -> bool:
    return getattr(emu, "stdout_handle", None) == stream


def _va_list_reader(emu: "Emulator", address: int) -> Callable[[], int]:
    emu.charge_work(3)
    state = emu.read_memory(address, 24)
    gp_offset = int.from_bytes(state[:4], "little")
    overflow_area = int.from_bytes(state[8:16], "little")
    register_save_area = int.from_bytes(state[16:24], "little")
    if gp_offset > 48 or gp_offset % 8:
        raise MemoryFault("invalid x86-64 va_list register offset")

    def read_argument() -> int:
        nonlocal gp_offset, overflow_area
        emu.charge_work(1)
        if gp_offset < 48:
            value = int.from_bytes(
                emu.read_memory(register_save_area + gp_offset, 8), "little"
            )
            gp_offset += 8
            return value
        if overflow_area > 2**64 - 8:
            raise MemoryFault("invalid x86-64 va_list overflow pointer")
        value = int.from_bytes(emu.read_memory(overflow_area, 8), "little")
        overflow_area += 8
        return value

    return read_argument


# shortcut: printf handles the literal/%x/%X/%d/%u/%c/%s subset with 0 flags and
# widths the corpus writers use; extend only when a pack needs more.
def _printf(
    emu: "Emulator",
    format_address: int,
    fortified: bool = False,
    argument_reader: Callable[[], int] | None = None,
) -> int | None:
    registers = emu.registers
    arguments = (
        []
        if argument_reader is not None
        else [
            int(emu.uc.reg_read(register))
            for register in (
                registers.UC_X86_REG_RSI,
                registers.UC_X86_REG_RDX,
                registers.UC_X86_REG_RCX,
                registers.UC_X86_REG_R8,
                registers.UC_X86_REG_R9,
            )[1 if fortified else 0 :]
        ]
    )
    fmt = _cstring(emu, format_address)
    output = bytearray()
    index = 0

    def next_argument() -> int:
        nonlocal index
        if argument_reader is not None:
            return argument_reader()
        if index >= len(arguments):
            raise MemoryFault("printf varargs exceed registers")
        value = arguments[index]
        index += 1
        return value

    position = 0
    while position < len(fmt):
        character = fmt[position]
        if character != 0x25:
            output.append(character)
            position += 1
            continue
        position += 1
        if position < len(fmt) and fmt[position] == 0x25:
            output.append(0x25)
            position += 1
            continue
        zero = position < len(fmt) and fmt[position] == 0x30
        width = 0
        while position < len(fmt) and 0x30 <= fmt[position] <= 0x39:
            width = width * 10 + (fmt[position] - 0x30)
            position += 1
        if position >= len(fmt) or fmt[position] not in b"xXducs":
            return None
        conversion = chr(fmt[position])
        if zero and conversion in "sc":
            return None
        emu.charge_work(width)
        position += 1
        if conversion == "s":
            rendered = _cstring(emu, next_argument())
        else:
            value = next_argument()
            if conversion == "c":
                rendered = bytes([value & 0xFF])
            elif conversion in "xX":
                digits = format(value & 0xFFFFFFFF, "x")
                rendered = (digits if conversion == "x" else digits.upper()).encode("ascii")
            elif conversion == "u":
                rendered = str(value & 0xFFFFFFFF).encode("ascii")
            else:
                signed = value & 0xFFFFFFFF
                if signed >= 2**31:
                    signed -= 2**32
                rendered = str(signed).encode("ascii")
        if width > len(rendered):
            filler = b"0" if zero and conversion != "s" else b" "
            padding = filler * (width - len(rendered))
            rendered = (
                b"-" + padding + rendered[1:]
                if zero and rendered.startswith(b"-")
                else padding + rendered
            )
        output.extend(rendered)
    emu.stdout.extend(output)
    return len(output)

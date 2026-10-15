"""Bounded x86-64 emulation of stripped public ELFs inside the job sandbox."""

import hashlib
import importlib
import io
import struct
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, cast

from aletheia.config import Budgets
from aletheia.verify.emulate.stubs import MemoryFault, emulate_import
from aletheia.worker.containment import require_job_sandbox
from aletheia.worker.main import guarded_input

BASE = 0x10000000
STUBS = 0x70000000
SENTINEL = 0x71000000
TLS = 0x72000000
HEAP = 0x73000000
INPUTS = 0x78000000
STACK = 0x7F000000
PAGE = 4096


@dataclass(frozen=True)
class Region:
    name: str
    start: int
    end: int


def memory_regions(image: list[tuple[int, int]], budget: Budgets) -> list[Region]:
    """Validate the complete map before allocating; adjacent image pages form one region."""
    merged: list[Region] = []
    for start, end in sorted(image):
        if start < 0 or end <= start or end > 2**64 - BASE:
            raise ValueError("invalid image region")
        low, high = BASE + start // PAGE * PAGE, BASE + (end + PAGE - 1) // PAGE * PAGE
        if merged and low <= merged[-1].end:
            merged[-1] = Region("image", merged[-1].start, max(high, merged[-1].end))
        else:
            merged.append(Region("image", low, high))
    regions = sorted(
        [
            *merged,
            Region("stubs", STUBS, STUBS + 65536),
            Region("sentinel", SENTINEL, SENTINEL + PAGE),
            Region("tls", TLS, TLS + 65536),
            Region("heap", HEAP, HEAP + budget.heap_mb * 1024**2),
            Region("inputs", INPUTS, INPUTS + 16 * 1024**2),
            Region("stack", STACK, STACK + budget.stack_mb * 1024**2),
        ],
        key=lambda region: region.start,
    )
    if any(r.start % PAGE or r.end % PAGE or r.end <= r.start or r.end >= 2**64 for r in regions):
        raise ValueError("regions must be positive page-aligned intervals")
    if any(
        right.start - left.end < PAGE for left, right in zip(regions, regions[1:], strict=False)
    ):
        raise ValueError("memory overlap or missing guard page")
    if sum(r.end - r.start for r in merged) > 256 * 1024**2:
        raise ValueError("image exceeds the memory limit")
    return regions


@dataclass(frozen=True)
class Buffer:
    data: bytes
    size: int | None = None


@dataclass(frozen=True)
class CallResult:
    ret: int | None
    out_buffers: list[bytes]
    instructions: int
    fault: str | None
    uninitialized_state_reads: bool
    imports_called: list[str]


@dataclass
class Tracked:
    start: int
    written: bytearray
    initial: bytes = field(default=b"")


class Emulator:
    def __init__(self, stripped: Path, budget: Budgets):
        require_job_sandbox(Path("/job"))
        path = guarded_input(Path("/job"), "in/" + stripped.name)
        if path != stripped:
            raise ValueError("emulator input must be in /job/in")
        with path.open("rb") as stream:
            payload = stream.read(20 * 1024**2 + 1)
        if len(payload) > 20 * 1024**2 or hashlib.sha256(payload).hexdigest() != path.stem:
            raise ValueError("invalid public binary size/hash")
        self.budget = budget
        self.native = cast(Any, importlib.import_module("unicorn"))
        self.registers = cast(Any, importlib.import_module("unicorn.x86_const"))
        self.uc = self.native.Uc(self.native.UC_ARCH_X86, self.native.UC_MODE_64)
        self.tracked: list[Tracked] = []
        self.imports: dict[int, str] = {}
        self.data_imports: list[str] = []
        self.heap_next = HEAP
        self.allocations: dict[int, int] = {}
        self.total_instructions = 0
        self.instructions = 0
        self.fault: str | None = None
        self.uninitialized = False
        self.called: list[str] = []
        self.unsupported = False
        parser = cast(Any, importlib.import_module("elftools.elf.elffile"))
        errors = cast(Any, importlib.import_module("elftools.common.exceptions"))
        try:
            self._load(parser.ELFFile(io.BytesIO(payload)))
        except (errors.ELFError, struct.error, OverflowError) as exc:
            raise ValueError("malformed ELF") from exc
        self.snapshot = [
            (region.start, bytes(self.uc.mem_read(region.start, region.end - region.start)))
            for region in self.regions
        ]
        for tracked in self.tracked:
            tracked.initial = bytes(tracked.written)
        self.context = self.uc.context_save()
        self.initial_heap = self.heap_next

    def _mark(self, address: int, size: int, *, write: bool) -> None:
        for tracked in self.tracked:
            low = max(address, tracked.start) - tracked.start
            high = min(address + size, tracked.start + len(tracked.written)) - tracked.start
            if low < high:
                if write:
                    tracked.written[low:high] = b"\1" * (high - low)
                elif 0 in tracked.written[low:high]:
                    self.uninitialized = True

    def _memory(self, uc: Any, access: int, address: int, size: int, value: int, user: Any) -> None:
        self._mark(address, size, write=access == self.native.UC_MEM_WRITE)

    def _instruction(self, uc: Any, address: int, size: int, user: Any) -> None:
        self.instructions += 1
        self.total_instructions += 1
        if address in self.imports:
            name = self.imports[address]
            self.called.append(name)
            try:
                value = emulate_import(self, name)
                if value is None:
                    self.fault = "unsupported_import:" + name
                else:
                    uc.reg_write(self.registers.UC_X86_REG_RAX, value & (2**64 - 1))
            except (MemoryFault, self.native.UcError):
                self.fault = "emulation_fault"
            if self.fault:
                uc.emu_stop()

    def _system_call(self, uc: Any, user: Any) -> None:
        self.fault = "emulation_fault"
        uc.emu_stop()

    def check_memory(self, address: int, size: int, *, write: bool = False) -> None:
        if size < 0 or address < 0 or address + size > 2**64:
            raise MemoryFault("invalid memory interval")
        if size == 0:
            return
        required = self.native.UC_PROT_WRITE if write else self.native.UC_PROT_READ
        for page in range(address // PAGE * PAGE, (address + size - 1) // PAGE * PAGE + 1, PAGE):
            if not self.permissions.get(page, 0) & required:
                raise MemoryFault("unmapped or protected memory")

    def read_memory(self, address: int, size: int) -> bytes:
        self.check_memory(address, size)
        self._mark(address, size, write=False)
        return bytes(self.uc.mem_read(address, size)) if size else b""

    def write_memory(self, address: int, data: bytes) -> None:
        self.check_memory(address, len(data), write=True)
        if data:
            self.uc.mem_write(address, data)
            self._mark(address, len(data), write=True)

    def allocate(self, size: int) -> int:
        size = max(1, size)
        end = self.heap_next + (size + 15) // 16 * 16
        if end > HEAP + self.budget.heap_mb * 1024**2:
            return 0
        address, self.heap_next = self.heap_next, end
        self.allocations[address] = size
        return address

    def _allocate_heap(self, size: int) -> int:
        address = self.heap_next
        self.heap_next += (size + 15) // 16 * 16
        if self.heap_next > HEAP + self.budget.heap_mb * 1024**2:
            raise ValueError("data imports exceed heap capacity")
        return address

    def _load(self, elf: Any) -> None:
        if (
            elf.elfclass != 64
            or not elf.little_endian
            or elf["e_machine"] != "EM_X86_64"
            or elf["e_type"] != "ET_DYN"
        ):
            raise ValueError("emulator requires a little-endian x86-64 PIE")
        if elf.num_sections() > 4096 or elf.num_segments() > 128:
            raise ValueError("ELF table exceeds Phase 1A bounds")
        sections = list(elf.iter_sections())
        if any(
            section.name == ".symtab" or section.name.startswith((".debug", ".zdebug"))
            for section in sections
        ):
            raise ValueError("emulator requires a stripped public binary")
        segments = [
            segment
            for segment in elf.iter_segments()
            if segment["p_type"] == "PT_LOAD" and segment["p_memsz"]
        ]
        if not segments:
            raise ValueError("ELF has no loadable image")
        for segment in segments:
            if (
                segment["p_filesz"] > segment["p_memsz"]
                or len(segment.data()) != segment["p_filesz"]
            ):
                raise ValueError("invalid load segment")
        self.regions = memory_regions(
            [(int(s["p_vaddr"]), int(s["p_vaddr"] + s["p_memsz"])) for s in segments], self.budget
        )
        for region in self.regions:
            self.uc.mem_map(region.start, region.end - region.start, self.native.UC_PROT_ALL)
        permissions: dict[int, int] = {}
        self.executable: list[tuple[int, int]] = []
        for segment in segments:
            start, end = (
                BASE + int(segment["p_vaddr"]),
                BASE + int(segment["p_vaddr"] + segment["p_memsz"]),
            )
            flags = int(segment["p_flags"])
            permission = (1 if flags & 4 else 0) | (2 if flags & 2 else 0) | (4 if flags & 1 else 0)
            for page in range(start // PAGE * PAGE, (end + PAGE - 1) // PAGE * PAGE, PAGE):
                permissions[page] = permissions.get(page, 0) | permission
            if flags & 1:
                self.executable.append((start, end))
            self.uc.mem_write(start, segment.data())
        for section in sections:
            if section["sh_flags"] & 3 == 3 and section["sh_size"]:
                nobits = section["sh_type"] == "SHT_NOBITS"
                if not nobits and not (
                    section.name == ".data" or section.name.startswith(".data.")
                ):
                    continue
                start, size = BASE + int(section["sh_addr"]), int(section["sh_size"])
                if not self._image_contains(start, size):
                    raise ValueError("mutable section lies outside the loaded image")
                mask = (
                    bytearray(size)
                    if nobits
                    else bytearray(byte != 0 for byte in self.uc.mem_read(start, size))
                )
                self.tracked.append(Tracked(start, mask))
        self._relocate(elf)
        self.uc.mem_write(STUBS, (b"\xc3" + b"\xcc" * 15) * 4096)
        self.uc.mem_write(TLS + 0x28, struct.pack("<Q", 0x2F8A5C11D3E07B46))
        regs = self.registers
        self.uc.reg_write(regs.UC_X86_REG_FS_BASE, TLS)
        self.uc.reg_write(regs.UC_X86_REG_CR0, (self.uc.reg_read(regs.UC_X86_REG_CR0) & ~4) | 2)
        self.uc.reg_write(
            regs.UC_X86_REG_CR4, self.uc.reg_read(regs.UC_X86_REG_CR4) | (1 << 9) | (1 << 10)
        )
        self.uc.reg_write(regs.UC_X86_REG_MXCSR, 0x1F80)
        self.permissions = permissions
        for page, permission in sorted(permissions.items()):
            self.uc.mem_protect(page, PAGE, permission)
        for region in self.regions:
            if region.name != "image":
                permission = self.native.UC_PROT_READ | (
                    self.native.UC_PROT_EXEC
                    if region.name in ("stubs", "sentinel")
                    else self.native.UC_PROT_WRITE
                )
                self.uc.mem_protect(region.start, region.end - region.start, permission)
                self.permissions.update(
                    {page: int(permission) for page in range(region.start, region.end, PAGE)}
                )
        self.uc.hook_add(self.native.UC_HOOK_MEM_READ | self.native.UC_HOOK_MEM_WRITE, self._memory)
        self.uc.hook_add(self.native.UC_HOOK_CODE, self._instruction)
        self.uc.hook_add(
            self.native.UC_HOOK_INSN,
            self._system_call,
            None,
            1,
            0,
            self.registers.UC_X86_INS_SYSCALL,
        )
        if any(s.name == ".preinit_array" and s["sh_size"] for s in sections):
            raise ValueError("project initialization entries are forbidden")
        if not self.unsupported:
            for section in sections:
                if section.name == ".init_array":
                    if section["sh_size"] % 8 or section["sh_size"] > 256:
                        raise ValueError("invalid initialization array")
                    start, size = BASE + int(section["sh_addr"]), int(section["sh_size"])
                    if size == 0:
                        continue
                    if not self._image_contains(start, size):
                        raise ValueError("initialization array lies outside the loaded image")
                    data = bytes(self.uc.mem_read(start, size))
                    for (entry,) in struct.iter_unpack("<Q", data):
                        if not self._verified_crt(entry):
                            raise ValueError("unverified initialization entry")
                        result = self._invoke(entry - BASE, [], 64)
                        if result.fault or result.uninitialized_state_reads:
                            raise ValueError("CRT initialization failed: " + str(result.fault))

    def _image_contains(self, start: int, size: int) -> bool:
        return size >= 0 and any(
            region.name == "image" and region.start <= start and start + size <= region.end
            for region in self.regions
        )

    def _relocate(self, elf: Any) -> None:
        relocations: list[tuple[int, int, int, Any]] = []
        names: set[str] = set()
        for name in (".rela.dyn", ".rela.plt"):
            section = elf.get_section_by_name(name)
            if section is None:
                continue
            symbols = elf.get_section(section["sh_link"])
            for relocation in section.iter_relocations():
                kind = int(relocation["r_info_type"])
                symbol = symbols.get_symbol(relocation["r_info_sym"])
                relocations.append(
                    (int(relocation["r_offset"]), kind, int(relocation["r_addend"]), symbol)
                )
                if (
                    kind == 7 or (kind == 6 and symbol["st_info"]["type"] == "STT_FUNC")
                ) and symbol["st_shndx"] == "SHN_UNDEF":
                    names.add(str(symbol.name))
        if len(names) > 4096 or len(relocations) > 65536:
            raise ValueError("relocation/import table exceeds Phase 1A limits")
        slots = {name: STUBS + index * 16 for index, name in enumerate(sorted(names))}
        self.imports = {address: name for name, address in slots.items()}
        data_objects: dict[str, int] = {}
        for offset, kind, addend, symbol in sorted(relocations, key=lambda item: item[:3]):
            address = BASE + offset
            if not self._image_contains(address, 8):
                raise ValueError("relocation destination outside image")
            symbol_type, binding = symbol["st_info"]["type"], symbol["st_info"]["bind"]
            if kind == 8:
                value = BASE + addend
            elif kind in (6, 7) and symbol.name in slots:
                value = slots[symbol.name]
            elif isinstance(symbol["st_shndx"], int) and (
                (kind in (6, 7) and symbol_type in ("STT_FUNC", "STT_OBJECT"))
                or (kind == 1 and symbol_type == "STT_OBJECT")
            ):
                value = BASE + int(symbol["st_value"]) + (addend if kind == 1 else 0)
            elif (
                kind in (1, 6) and symbol_type == "STT_OBJECT" and symbol["st_shndx"] == "SHN_UNDEF"
            ):
                if symbol.name not in data_objects:
                    data_objects[symbol.name] = self._allocate_heap(256)
                value = data_objects[symbol.name] + (addend if kind == 1 else 0)
            elif (
                kind == 6
                and symbol_type == "STT_NOTYPE"
                and binding == "STB_WEAK"
                and symbol["st_shndx"] == "SHN_UNDEF"
            ):
                # Undefined optional CRT references have no implementation to import.
                value = 0
            else:
                self.unsupported = True
                continue
            if not 0 <= value < 2**64:
                raise ValueError("relocation value outside x86-64 address space")
            self.uc.mem_write(address, struct.pack("<Q", value))
            self._mark(address, 8, write=True)
        self.data_imports = ["data_import:" + name for name in sorted(data_objects)]

    def _verified_crt(self, entry: int) -> bool:
        # shortcut: pinned empty-TM-clone CRT only; review new templates on toolchain changes.
        if not any(start <= entry and entry + 9 <= end for start, end in self.executable):
            return False
        prefix = bytes(self.uc.mem_read(entry, 9))
        if prefix[:5] != bytes.fromhex("f30f1efae9"):
            return False
        target = entry + 9 + struct.unpack("<i", prefix[5:])[0]
        if not any(start <= target and target + 57 <= end for start, end in self.executable):
            return False
        body = bytes(self.uc.mem_read(target, 57))
        if body[:3] != bytes.fromhex("488d3d") or body[7:10] != bytes.fromhex("488d35"):
            return False
        first = target + 7 + struct.unpack("<i", body[3:7])[0]
        second = target + 14 + struct.unpack("<i", body[10:14])[0]
        return (
            first == second
            and body[14:36] == bytes.fromhex("4829fe4889f048c1ee3f48c1f8034801c648d1fe7414")
            and body[56] == 0xC3
        )

    def _invoke(self, entry: int, args: list[int | Buffer], ret_width: int) -> CallResult:
        self.instructions, self.fault, self.uninitialized, self.called = 0, None, False, []
        if self.unsupported:
            self.fault = "unsupported_relocation"
        if len(args) > 6 or ret_width not in (8, 16, 32, 64):
            raise ValueError("unsupported SysV arguments/return width")
        if entry < 0 or not any(start <= BASE + entry < end for start, end in self.executable):
            raise ValueError("entry is not in an executable image segment")
        registers = [
            self.registers.UC_X86_REG_RDI,
            self.registers.UC_X86_REG_RSI,
            self.registers.UC_X86_REG_RDX,
            self.registers.UC_X86_REG_RCX,
            self.registers.UC_X86_REG_R8,
            self.registers.UC_X86_REG_R9,
        ]
        cursor = INPUTS
        buffers: list[tuple[int, int]] = []
        for register, argument in zip(registers, args, strict=False):
            if isinstance(argument, Buffer):
                size = len(argument.data) if argument.size is None else argument.size
                if (
                    size < len(argument.data)
                    or size < 0
                    or cursor + max(1, size) > INPUTS + 16 * 1024**2
                ):
                    raise ValueError("argument buffers exceed input region")
                self.uc.mem_write(cursor, argument.data)
                buffers.append((cursor, size))
                value = cursor
                cursor += (max(1, size) + 15) // 16 * 16
            else:
                value = argument & ((1 << 64) - 1)
            self.uc.reg_write(register, value)
        stack = STACK + self.budget.stack_mb * 1024**2 - 8
        self.uc.mem_write(stack, struct.pack("<Q", SENTINEL))
        self.uc.reg_write(self.registers.UC_X86_REG_RSP, stack)
        limit = min(
            self.budget.instructions_per_invocation,
            self.budget.instructions_per_claim - self.total_instructions,
        )
        if not self.fault:
            if limit <= 0:
                self.fault = "budget_exhausted"
            else:
                try:
                    self.uc.emu_start(BASE + entry, SENTINEL, count=limit)
                except self.native.UcError:
                    self.fault = "emulation_fault"
                if not self.fault and self.uc.reg_read(self.registers.UC_X86_REG_RIP) != SENTINEL:
                    self.fault = "budget_exhausted"
        return CallResult(
            None
            if self.fault
            else int(self.uc.reg_read(self.registers.UC_X86_REG_RAX)) & ((1 << ret_width) - 1),
            [bytes(self.uc.mem_read(address, size)) for address, size in buffers],
            self.instructions,
            self.fault,
            self.uninitialized,
            sorted(set(self.called)),
        )

    def call(self, entry: int, args: list[int | Buffer], ret_width: int = 32) -> CallResult:
        """Restore initializer state for each invocation; the claim instruction total persists."""
        self.uc.context_restore(self.context)
        for address, data in self.snapshot:
            self.uc.mem_write(address, data)
        for tracked in self.tracked:
            tracked.written[:] = tracked.initial
        self.heap_next = self.initial_heap
        self.allocations.clear()
        return self._invoke(entry, args, ret_width)

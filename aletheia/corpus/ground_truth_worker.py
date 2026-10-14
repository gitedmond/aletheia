"""Private Capstone/symbol extraction. Entry points reject execution outside Docker.

The pyelftools/Capstone dynamic boundary is confined to this sandbox module.
No verifier imports it or receives its private inputs.
"""

import hashlib
import importlib
import importlib.metadata
import json
import os
import re
import subprocess
import sys
from pathlib import Path
from typing import Any, cast

from aletheia.corpus.lint import lint_program, source_functions
from aletheia.schema.canonical import canonical_bytes
from aletheia.schema.models import (
    Edge,
    ExcludedFunction,
    GroundAlgorithm,
    GroundFunction,
    GroundTruth,
    Targets,
)


def require_sandbox() -> None:
    mounts: dict[str, set[str]] = {}
    for line in Path("/proc/self/mountinfo").read_text().splitlines():
        fields = line.split()
        mounts[fields[4]] = set(fields[5].split(","))
    readonly = ("/", "/in", "/corpus", "/code/aletheia")
    if (
        not Path("/.dockerenv").is_file()
        or os.getuid() == 0
        or any("ro" not in mounts.get(path, set[str]()) for path in readonly)
        or "rw" not in mounts.get("/out", set[str]())
    ):
        raise ValueError("ground truth requires a non-root Docker sandbox with protected mounts")


def annotations(program: Path) -> dict[str, tuple[GroundAlgorithm, list[str]]]:
    errors = lint_program(program)
    if errors:
        raise ValueError("invalid annotations: " + "; ".join(e.rule for e in errors))
    result: dict[str, tuple[GroundAlgorithm, list[str]]] = {}
    for path in sorted((program / "src").rglob("*.c")):
        text = path.read_text()
        for fn in source_functions(text, path):
            lines = text.splitlines()
            i = fn.line - 2
            block: list[str] = []
            while i >= 0 and lines[i].strip().startswith("// @"):
                block.append(lines[i].strip())
                i -= 1
            algorithm = next(
                s.removeprefix("// @algorithm ") for s in block if s.startswith("// @algorithm ")
            )
            family, _, variant = algorithm.partition("/")
            targets = next(
                (
                    s.removeprefix("// @indirect-targets ").split(",")
                    for s in block
                    if s.startswith("// @indirect-targets ")
                ),
                list[str](),
            )
            result[fn.name] = (
                GroundAlgorithm(family=family, variant=variant or None),
                [n.strip() for n in targets],
            )
    return result


def elf(path: Path) -> Any:
    # Imports and ELF decoding occur only after the worker's sandbox check.
    if importlib.metadata.version("pyelftools") != "0.33":
        raise ValueError("pyelftools pin mismatch")
    parser = cast(Any, importlib.import_module("elftools.elf.elffile"))
    return parser.ELFFile(path.open("rb"))


def verify_crt(binary: Any, annotated: dict[str, tuple[GroundAlgorithm, list[str]]]) -> list[int]:
    """Allow only the pinned local CRT frame_dummy initialization entry."""
    section = binary.get_section_by_name(".init_array")
    if section is None or section["sh_size"] == 0:
        return []
    if int(section["sh_size"]) != 8 or "frame_dummy" in annotated:
        raise ValueError("authored or unsupported initialization entries")
    symtab = binary.get_section_by_name(".symtab")
    frames = [
        s
        for s in symtab.iter_symbols()
        if s.name == "frame_dummy"
        and s["st_info"]["bind"] == "STB_LOCAL"
        and s["st_info"]["type"] == "STT_FUNC"
    ]
    entries = [
        s
        for s in symtab.iter_symbols()
        if s.name == "__frame_dummy_init_array_entry" and s["st_info"]["bind"] == "STB_LOCAL"
    ]
    if (
        len(frames) != 1
        or len(entries) != 1
        or int(entries[0]["st_value"]) != int(section["sh_addr"])
    ):
        raise ValueError("unverified CRT initialization entry")
    relocations = [
        r
        for sec in binary.iter_sections()
        if sec["sh_type"] == "SHT_RELA"
        for r in sec.iter_relocations()
        if int(r["r_offset"]) == int(section["sh_addr"])
    ]
    if (
        len(relocations) != 1
        or relocations[0]["r_info_type"] != 8
        or int(relocations[0]["r_addend"]) != int(frames[0]["st_value"])
    ):
        raise ValueError("unverified CRT initialization relocation")
    return [int(frames[0]["st_value"])]


def symbols(binary: Any) -> dict[str, tuple[int, int, bytes]]:
    if (
        binary["e_machine"] != "EM_X86_64"
        or binary["e_type"] != "ET_DYN"
        or not binary.little_endian
        or binary.elfclass != 64
    ):
        raise ValueError("ground truth supports only little-endian x86-64 PIE")
    symtab = binary.get_section_by_name(".symtab")
    if symtab is None:
        raise ValueError("private symbol table missing")
    result: dict[str, tuple[int, int, bytes]] = {}
    for symbol in symtab.iter_symbols():
        if (
            symbol["st_info"]["type"] != "STT_FUNC"
            or symbol["st_size"] <= 0
            or not isinstance(symbol["st_shndx"], int)
        ):
            continue
        section = binary.get_section(symbol["st_shndx"])
        if not section["sh_flags"] & 4:
            continue
        address, size = int(symbol["st_value"]), int(symbol["st_size"])
        offset = address - int(section["sh_addr"])
        data = bytes(section.data()[offset : offset + size])
        if offset < 0 or len(data) != size:
            raise ValueError("invalid function range: " + symbol.name)
        if symbol.name in result:
            raise ValueError("duplicate symbol name: " + symbol.name)
        result[symbol.name] = (address, size, data)
    return result


def disassembler() -> Any:
    capstone = cast(Any, importlib.import_module("capstone"))
    if importlib.metadata.version("capstone") != "5.0.9":
        raise ValueError("Capstone pin mismatch")
    engine = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
    engine.detail = True
    return engine


def instructions(engine: Any, data: bytes, address: int) -> list[Any]:
    decoded = list(engine.disasm(data, address))
    if sum(i.size for i in decoded) != len(data):
        raise ValueError(f"incomplete disassembly at {address:#x}")
    return decoded


def imports(binary: Any, engine: Any) -> tuple[dict[int, str], dict[int, str]]:
    slots: dict[int, str] = {}
    for section in binary.iter_sections():
        if section["sh_type"] != "SHT_RELA":
            continue
        symtab = binary.get_section(section["sh_link"])
        for relocation in section.iter_relocations():
            if relocation["r_info_type"] in (6, 7):  # x86-64 GLOB_DAT / JUMP_SLOT
                symbol = symtab.get_symbol(relocation["r_info_sym"])
                if symbol.name:
                    slots[int(relocation["r_offset"])] = "import:" + symbol.name
    stubs: dict[int, str] = {}
    for name in (".plt", ".plt.sec", ".plt.got"):
        section = binary.get_section_by_name(name)
        if section is None:
            continue
        base = int(section["sh_addr"])
        width = int(section["sh_entsize"]) or (8 if name == ".plt.got" else 16)
        for insn in instructions(engine, bytes(section.data()), base):
            if insn.mnemonic == "jmp" and len(insn.operands) == 1:
                op = insn.operands[0]
                # Capstone X86_OP_MEM=3, X86_REG_RIP=41.
                if op.type == 3 and op.mem.base == 41 and op.mem.index == 0:
                    target = slots.get(insn.address + insn.size + op.mem.disp)
                    if target:
                        stubs[base + (insn.address - base) // width * width] = target
    return slots, stubs


def signatures(binary: Any) -> dict[str, str]:
    if not binary.has_dwarf_info():
        raise ValueError("private DWARF missing")
    dwarf = binary.get_dwarf_info()

    def type_name(die: Any, depth: int = 0) -> str:
        if depth > 30:
            raise ValueError("recursive DWARF type")
        if die is None:
            return "void"
        name = die.attributes.get("DW_AT_name")
        if name is not None:
            return bytes(name.value).decode("utf-8")
        target = (
            die.get_DIE_from_attribute("DW_AT_type") if "DW_AT_type" in die.attributes else None
        )
        inner = type_name(target, depth + 1)
        if die.tag == "DW_TAG_pointer_type":
            return inner + " *"
        if die.tag == "DW_TAG_const_type":
            return "const " + inner
        if die.tag == "DW_TAG_volatile_type":
            return "volatile " + inner
        if die.tag == "DW_TAG_array_type":
            return inner + "[]"
        return inner

    result: dict[str, str] = {}
    for cu in dwarf.iter_CUs():
        for die in cu.iter_DIEs():
            if (
                die.tag != "DW_TAG_subprogram"
                or "DW_AT_name" not in die.attributes
                or "DW_AT_low_pc" not in die.attributes
            ):
                continue
            name = bytes(die.attributes["DW_AT_name"].value).decode("utf-8")
            return_type = type_name(
                die.get_DIE_from_attribute("DW_AT_type") if "DW_AT_type" in die.attributes else None
            )
            parameters: list[str] = []
            for child in die.iter_children():
                if child.tag == "DW_TAG_formal_parameter":
                    parameters.append(type_name(child.get_DIE_from_attribute("DW_AT_type")))
                elif child.tag == "DW_TAG_unspecified_parameters":
                    parameters.append("...")
            result[name] = return_type + " (" + ", ".join(parameters or ["void"]) + ")"
    return result


def extract(directory: Path, program: Path) -> GroundTruth:
    require_sandbox()
    metadata = json.loads((directory / "build.json").read_bytes())
    for kind, path in [
        ("unstripped", directory / "private/unstripped.bin"),
        ("o0", directory / "private/o0.bin"),
        ("stripped", directory / "stripped" / (metadata["hashes"]["stripped"] + ".bin")),
    ]:
        if hashlib.sha256(path.read_bytes()).hexdigest() != metadata["hashes"][kind]:
            raise ValueError("build hash mismatch: " + kind)
    for name, digest in metadata["source_hashes"].items():
        if hashlib.sha256((program.parent.parent / name).read_bytes()).hexdigest() != digest:
            raise ValueError("source hash mismatch: " + name)
    annotated = annotations(program)
    binary = elf(directory / "private/unstripped.bin")
    o0_binary = elf(directory / "private/o0.bin")
    try:
        verify_crt(binary, annotated)
        verify_crt(o0_binary, annotated)
        current, original = symbols(binary), symbols(o0_binary)
        engine = disassembler()
        slots, stubs = imports(binary, engine)
        signature = signatures(binary)
        # Stable collapse of linker aliases; two authored aliases are ambiguous.
        addresses: dict[int, str] = {}
        for name, (address, _, _) in sorted(
            current.items(), key=lambda item: (item[0] not in annotated, item[0])
        ):
            if address in addresses:
                if name in annotated and addresses[address] in annotated:
                    raise ValueError("ambiguous authored symbol aliases")
                continue
            addresses[address] = name
        functions: list[GroundFunction] = []
        excluded: list[ExcludedFunction] = []
        for name in sorted(annotated.keys() - current.keys()):
            excluded.append(ExcludedFunction(name=name, reason="fully_inlined"))
        for address, name in sorted(addresses.items()):
            _, size, data = current[name]
            clone = re.fullmatch(r"(.+)\.(?:constprop|isra|part)\.\d+", name)
            cold = re.fullmatch(r"(.+)\.cold(?:\.\d+)?", name)
            base = clone[1] if clone else cold[1] if cold else name
            algorithm, indirect = annotated.get(base, (GroundAlgorithm(family="none"), []))
            if base not in original:
                raise ValueError("O0 symbol missing: " + base)
            original_addr, _, original_data = original[base]
            nontrivial = len(instructions(engine, original_data, original_addr)) > 10
            reason = "cold_split" if cold else None if nontrivial else "trivial"
            if reason:
                excluded.append(ExcludedFunction(name=name, reason=reason))
            edges: set[tuple[str, str]] = set()
            for insn in instructions(engine, data, address):
                if insn.mnemonic not in ("call", "jmp") or len(insn.operands) != 1:
                    continue
                kind = "direct" if insn.mnemonic == "call" else "tail"
                op = insn.operands[0]
                target: str | None = None
                if op.type == 2:  # immediate direct branch
                    destination = int(op.imm)
                    if insn.mnemonic == "jmp" and address <= destination < address + size:
                        continue
                    target = (
                        f"0x{destination:08x}"
                        if destination in addresses
                        else stubs.get(destination)
                    )
                elif op.type == 3 and op.mem.base == 41 and op.mem.index == 0:
                    target = slots.get(insn.address + insn.size + op.mem.disp)
                if target:
                    edges.add((target, kind))
                elif op.type != 2:
                    for indirect_name in indirect:
                        if indirect_name not in current:
                            raise ValueError("indirect target missing: " + indirect_name)
                        edges.add((f"0x{current[indirect_name][0]:08x}", "indirect"))
            functions.append(
                GroundFunction(
                    address=f"0x{address:08x}",
                    size=size,
                    name=name,
                    algorithm=algorithm,
                    clone_of=clone[1] if clone else None,
                    scorable=reason is None,
                    exclusion_reason=reason,
                    callees=[Edge(target=t, kind=cast(Any, k)) for t, k in sorted(edges)],
                    source_signature=signature.get(base),
                )
            )
        return GroundTruth(
            binary_sha256=metadata["hashes"]["stripped"],
            program_id=metadata["program_id"],
            variant_id=metadata["variant_id"],
            build_flags=" ".join(metadata["build_flags"]),
            functions=functions,
            excluded_functions=sorted(excluded, key=lambda f: (f.name, f.reason)),
        )
    finally:
        binary.stream.close()
        o0_binary.stream.close()


def leakage(
    binary: Path, gt: GroundTruth, program: Path, original_root: str
) -> list[dict[str, str]]:
    require_sandbox()
    needles: set[tuple[str, str]] = {(f.name, "function") for f in gt.functions if len(f.name) >= 4}
    for path in sorted((program / "src").rglob("*")):
        if path.suffix not in (".c", ".h"):
            continue
        needles.add((path.name, "filename"))
        for line in path.read_text().splitlines():
            if line.strip().startswith("// @"):
                needles.add((line.strip().removeprefix("// "), "annotation"))
    for path in (program.parent.parent / "include").glob("*.h"):
        needles.add((path.name, "filename"))
    needles.add((original_root, "source_root"))
    needles.add(("/corpus", "source_root"))
    payload = binary.read_bytes()
    hits: list[dict[str, str]] = []
    for token, kind in sorted(needles):
        if kind == "function":
            # Match complete C identifiers; required imports such as
            # __libc_start_main contain neither an identifier main nor _start.
            pattern = rb"(?<![A-Za-z0-9_$])" + re.escape(token.encode()) + rb"(?![A-Za-z0-9_$])"
            found = re.search(pattern, payload) is not None
        else:
            found = token.encode() in payload
        if found:
            hits.append({"token": token, "kind": kind})
    return hits


def main() -> None:
    require_sandbox()
    request = json.loads(Path("/in/request.json").read_bytes())
    program = Path("/corpus/tierA") / request["program"]
    if request["action"] == "extract":
        gt = extract(Path("/in/build"), program)
        hits = leakage(
            Path("/in/build/stripped") / (gt.binary_sha256 + ".bin"),
            gt,
            program,
            request["source_root"],
        )
        if hits:
            raise ValueError("stripped leakage: " + json.dumps(hits, sort_keys=True))
        targets = Targets(
            binary_sha256=gt.binary_sha256,
            variant_id=gt.variant_id,
            targets=[f.address for f in gt.functions if f.scorable],
        )
        Path("/out/ground_truth.json").write_bytes(canonical_bytes(gt))
        Path("/out/targets.json").write_bytes(canonical_bytes(targets))
    elif request["action"] == "review":
        directory = Path("/in/build")
        gt = extract(directory, program)
        Path("/out/ground_truth.json").write_bytes(canonical_bytes(gt))
        listing = subprocess.run(
            ["llvm-objdump", "-d", str(directory / "private/unstripped.bin")],
            capture_output=True,
            text=True,
            check=True,
            timeout=30,
        )
        Path("/out/disassembly.txt").write_text(listing.stdout)
        binary, original = (
            elf(directory / "private/unstripped.bin"),
            elf(directory / "private/o0.bin"),
        )
        try:
            engine = disassembler()
            counts = {
                name: len(instructions(engine, data, address))
                for name, (address, _, data) in sorted(symbols(original).items())
            }
            report = {
                "o0_instruction_counts": counts,
                "crt_initializers": verify_crt(binary, annotations(program)),
                "tool_versions": {
                    name: importlib.metadata.version(name) for name in ("capstone", "pyelftools")
                },
                "python": sys.version.split()[0],
            }
            Path("/out/review.json").write_text(
                json.dumps(report, sort_keys=True, separators=(",", ":"))
            )
        finally:
            binary.stream.close()
            original.stream.close()
    elif request["action"] == "leakage":
        gt = GroundTruth.model_validate_json(Path("/in/ground_truth.json").read_bytes())
        Path("/out/leakage.json").write_bytes(
            json.dumps(
                leakage(Path("/in/binary.bin"), gt, program, request["source_root"]),
                sort_keys=True,
                separators=(",", ":"),
            ).encode()
        )
    else:
        raise ValueError("unknown ground truth action")


if __name__ == "__main__":
    try:
        main()
    except Exception as error:
        print(f"ground truth failed: {type(error).__name__}: {error}", file=sys.stderr)
        raise SystemExit(1) from error

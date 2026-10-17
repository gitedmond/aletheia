"""Bounded register observations from the pinned Ghidra listing, inside its sandbox."""

import re
from collections.abc import Iterable, Iterator
from itertools import islice
from typing import Any, cast

from aletheia.schema.signature_facts import (
    ARGUMENT_REGISTERS,
    PARAMETER_REGISTERS,
    ArgumentRegister,
    CallSignatureUse,
    ParameterRegister,
    ReturnFact,
    SignatureFacts,
    Width,
    WidthFact,
)


def _registers(instruction: Any, *, writes: bool) -> dict[str, int]:
    values: dict[str, int] = {}
    objects = instruction.getResultObjects() if writes else instruction.getInputObjects()
    for value in objects:
        if hasattr(value, "getBaseRegister"):
            base = str(value.getBaseRegister().getName()).lower()
            if base.startswith(("ymm", "zmm")):
                base = "xmm" + base[3:]
            values[base] = max(values.get(base, 0), int(value.getBitLength()))
    for operand in range(instruction.getNumOperands()):
        register = instruction.getRegister(operand)
        reference = instruction.getOperandRefType(operand)
        if (
            register is not None
            and reference is not None
            and (reference.isWrite() if writes else reference.isRead())
        ):
            base = str(register.getBaseRegister().getName()).lower()
            if base.startswith(("ymm", "zmm")):
                base = "xmm" + base[3:]
            if base in values:
                values[base] = int(register.getBitLength())
    mnemonic = str(instruction.getMnemonicString()).upper()
    if (
        not writes
        and mnemonic in {"XOR", "SUB", "PXOR", "XORPS", "XORPD"}
        and instruction.getNumOperands() == 2
        and str(instruction.getDefaultOperandRepresentation(0))
        == str(instruction.getDefaultOperandRepresentation(1))
    ):
        for base in _registers(instruction, writes=True):
            values.pop(base, None)
    return values


def _value(instruction: Any, width: int, bank: str) -> WidthFact:
    if bank.startswith("xmm"):
        mnemonic = str(instruction.getMnemonicString()).upper()
        size = (
            32
            if mnemonic.endswith(("SS", "MOVD"))
            else 64
            if mnemonic.endswith(("SD", "MOVQ"))
            else None
        )
        return WidthFact(kind="float", width=size) if size else WidthFact(kind="unknown")
    return (
        WidthFact(kind="int_or_ptr", width=width)
        if width in (8, 16, 32, 64)
        else WidthFact(kind="unknown")
    )


def _unknown() -> ReturnFact:
    return ReturnFact(integer=WidthFact(kind="unknown"), floating=WidthFact(kind="unknown"))


def _source_blocks(block: Any, monitor: Any) -> Iterator[Any]:
    references = block.getSources(monitor)
    while references.hasNext():
        reference = references.next()
        source = reference.getSourceBlock()
        if not reference.getFlowType().isCall() and source is not None:
            yield source


def _return_path(
    program: Any, function: Any, terminal: Any, blocks: Any, monitor: Any, bank: str
) -> WidthFact:
    at: Any = terminal.getAddress()
    block: Any = blocks.getFirstCodeBlockContaining(at, monitor)
    visited: set[int] = set()
    for _ in range(4):
        if block is None:
            return WidthFact(kind="unknown")
        key = int(block.getMinAddress().getOffset())
        if key in visited:
            return WidthFact(kind="unknown")
        visited.add(key)
        for instruction in program.getListing().getInstructions(block, False):
            if instruction.getAddress().compareTo(at) >= 0:
                continue
            writes = _registers(instruction, writes=True)
            if bank in writes:
                return _value(instruction, writes[bank], bank)
            if str(instruction.getMnemonicString()).upper() == "CALL":
                return WidthFact(kind="unknown")
        if block.contains(function.getEntryPoint()):
            return WidthFact(kind="none")
        predecessors: list[Any] = [
            source
            for source in _source_blocks(block, monitor)
            if function.getBody().contains(source.getMinAddress())
        ]
        if len(predecessors) != 1:
            return WidthFact(kind="unknown")
        block = predecessors[0]
        at = block.getMaxAddress().add(1)
    return WidthFact(kind="unknown")


def caller_signature_use(
    program: Any, instruction: Any, blocks: Any, monitor: Any
) -> CallSignatureUse:
    block = blocks.getFirstCodeBlockContaining(instruction.getAddress(), monitor)
    if block is None:
        return CallSignatureUse(return_read=_unknown(), argument_writes={})
    arguments: dict[ParameterRegister, Width | None] = {}
    before = program.getListing().getInstructions(block, True)
    for previous in before:
        if previous.getAddress().compareTo(instruction.getAddress()) >= 0:
            break
        if str(previous.getMnemonicString()).upper() == "CALL":
            arguments.clear()
        else:
            for base, width in _registers(previous, writes=True).items():
                if base in PARAMETER_REGISTERS:
                    observed = _value(previous, width, base).width
                    arguments[base] = observed
    result = {"rax": WidthFact(kind="none"), "xmm0": WidthFact(kind="none")}
    pending = set(result)
    following = instruction.getNext()
    for _ in range(8):
        if following is None or not block.contains(following.getAddress()):
            break
        reads, writes = _registers(following, writes=False), _registers(following, writes=True)
        for bank in sorted(pending):
            if bank in reads:
                result[bank] = _value(following, reads[bank], bank)
                pending.remove(bank)
            elif bank in writes:
                pending.remove(bank)
        if str(following.getMnemonicString()).upper() == "CALL":
            break
        following = following.getNext()
    return CallSignatureUse(
        return_read=ReturnFact(integer=result["rax"], floating=result["xmm0"]),
        argument_writes=arguments,
    )


def _pointer_bases(instruction: Any) -> set[str]:
    if not any(str(op.getMnemonic()) in {"LOAD", "STORE"} for op in instruction.getPcode()):
        return set()
    names = {
        str(value.getName()).lower(): str(value.getBaseRegister().getName()).lower()
        for value in instruction.getInputObjects()
        if hasattr(value, "getBaseRegister")
    }
    pointers: set[str] = set()
    for operand in range(instruction.getNumOperands()):
        match = re.search(
            r"\[\s*([a-z0-9]+)\s*(?:\+|-|\])",
            str(instruction.getDefaultOperandRepresentation(operand)).lower(),
        )
        if match and names.get(match[1]) in ARGUMENT_REGISTERS:
            pointers.add(names[match[1]])
    return pointers


def signature_facts(
    program: Any, function: Any, blocks: Any, monitor: Any, *, complete: bool, tail: bool
) -> SignatureFacts:
    body = function.getBody()
    instructions = list(
        islice(cast(Iterable[Any], program.getListing().getInstructions(body, True)), 4097)
    )
    nodes = list(islice(cast(Iterable[Any], blocks.getCodeBlocksContaining(body, monitor)), 257))
    if len(instructions) > 4096 or len(nodes) > 256 or not complete:
        return SignatureFacts(
            return_paths=[_unknown()],
            param_reads={},
            pointer_params=[],
            exclusion_reason="signature_budget" if complete else "incomplete_body",
        )
    returns = [
        ReturnFact(
            integer=_return_path(program, function, instruction, blocks, monitor, "rax"),
            floating=_return_path(program, function, instruction, blocks, monitor, "xmm0"),
        )
        for instruction in instructions
        if str(instruction.getMnemonicString()).upper() == "RET"
    ]
    if tail or not returns:
        returns.append(_unknown())
    by_key: dict[int, Any] = {int(block.getMinAddress().getOffset()): block for block in nodes}
    predecessors = {
        key: {
            int(source.getMinAddress().getOffset())
            for source in _source_blocks(block, monitor)
            if int(source.getMinAddress().getOffset()) in by_key
        }
        for key, block in by_key.items()
    }
    entry = next(
        (key for key, block in by_key.items() if block.contains(function.getEntryPoint())), None
    )
    if entry is None:
        return SignatureFacts(
            return_paths=returns,
            param_reads={},
            pointer_params=[],
            exclusion_reason="entry_block_missing",
        )
    reachable = {entry}
    for _ in nodes:
        reachable.update(key for key, preds in predecessors.items() if preds & reachable)
    rows = {
        key: [
            ins
            for ins in program.getListing().getInstructions(by_key[key], True)
            if body.contains(ins.getAddress())
        ]
        for key in sorted(reachable)
    }
    killed = {
        key: {
            register
            for ins in values
            for register in (
                PARAMETER_REGISTERS
                if str(ins.getMnemonicString()).upper() == "CALL"
                else _registers(ins, writes=True)
            )
        }
        for key, values in rows.items()
    }
    incoming: dict[int, set[str]] = {key: set[str](PARAMETER_REGISTERS) for key in rows}
    outgoing: dict[int, set[str]] = {
        key: set[str](PARAMETER_REGISTERS) - killed[key] for key in rows
    }
    changed = True
    while changed:
        changed = False
        for key in rows:
            parents = [outgoing[parent] for parent in predecessors[key] if parent in outgoing]
            before: set[str] = (
                set[str](PARAMETER_REGISTERS)
                if key == entry
                else set[str].intersection(*parents)
                if parents
                else set()
            )
            after = before - killed[key]
            if before != incoming[key] or after != outgoing[key]:
                incoming[key], outgoing[key] = before, after
                changed = True
    reads: dict[ParameterRegister, Width | None] = {}
    pointers: set[ArgumentRegister] = set()
    for key, values in rows.items():
        available = set(incoming[key])
        for ins in values:
            for register, width in _registers(ins, writes=False).items():
                observed = _value(ins, width, register).width
                if register in PARAMETER_REGISTERS and register in available:
                    prior = reads.get(register)
                    if observed is None or (register in reads and prior is None):
                        reads[register] = None
                    else:
                        reads[register] = cast(Width, max(prior or 0, observed))
            pointers.update(
                name
                for name in _pointer_bases(ins)
                if name in ARGUMENT_REGISTERS and name in available
            )
            available.difference_update(
                PARAMETER_REGISTERS
                if str(ins.getMnemonicString()).upper() == "CALL"
                else _registers(ins, writes=True)
            )
    return SignatureFacts(
        return_paths=returns,
        param_reads=reads,
        pointer_params=[name for name in ARGUMENT_REGISTERS if name in pointers],
    )

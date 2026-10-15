"""Internal SysV binding proof from independent callee and caller observations."""

from aletheia.analysis.ghidra_session import GhidraAnalysis
from aletheia.schema.models import Address, Strict

ARGUMENT_REGISTERS = ("rdi", "rsi", "rdx", "rcx", "r8", "r9")


class Arity(Strict):
    arity: int | None
    decisive: bool
    reason: str | None


def infer_arity(subject: Address, analysis: GhidraAnalysis) -> Arity:
    function = next((fn for fn in analysis.functions if fn.entry == subject), None)
    sites = [site for fn in analysis.functions for site in fn.call_sites if site.target == subject]
    reason = None
    count = function.decompiler_param_count if function is not None else None
    callers: list[int] = []
    for site in sites:
        registers = set(site.argument_registers or [])
        n = len(registers)
        if site.kind == "direct" and n and registers == set(ARGUMENT_REGISTERS[:n]):
            callers.append(n)
    if function is None:
        reason = "subject_not_found"
    elif function.is_variadic_like:
        reason = "variadic_like"
    elif any(site.kind == "tail" for site in sites):
        reason = "tail_target"
    elif count is None:
        reason = "decompiler_failed"
    elif count > 6:
        reason = "too_many_arguments"
    elif not callers:
        reason = "no_determinable_caller"
    elif any(caller != count for caller in callers):
        reason = "caller_count_mismatch"
    return Arity(arity=count if reason is None else None, decisive=reason is None, reason=reason)

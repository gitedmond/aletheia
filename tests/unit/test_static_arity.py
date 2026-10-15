"""Arity binds only when independent callee and determinable callers agree."""

import pytest

from aletheia.analysis.ghidra_session import GhidraAnalysis
from aletheia.verify.static.arity import infer_arity


def analysis(count=2, registers=("rdi", "rsi"), kind="direct", variadic=False):
    return GhidraAnalysis.model_validate(
        {
            "binary_sha256": "a" * 64,
            "options_sha256": "b" * 64,
            "functions": [
                {
                    "entry": "0x00001000",
                    "body_ranges": [{"start": "0x00001000", "end": "0x00001020"}],
                    "is_thunk": False,
                    "decompiler_param_count": count,
                    "is_variadic_like": variadic,
                },
                {
                    "entry": "0x00002000",
                    "body_ranges": [{"start": "0x00002000", "end": "0x00002020"}],
                    "is_thunk": False,
                    "call_sites": [
                        {
                            "address": "0x00002010",
                            "target": "0x00001000",
                            "kind": kind,
                            "argument_registers": list(registers),
                        }
                    ],
                },
            ],
        }
    )


@pytest.mark.parametrize(
    "count,registers,kind,variadic,arity,reason",
    [
        (2, ("rdi", "rsi"), "direct", False, 2, None),
        (2, (), "direct", False, None, "no_determinable_caller"),
        (2, ("rsi",), "direct", False, None, "no_determinable_caller"),
        (2, ("rdi",), "direct", False, None, "caller_count_mismatch"),
        (2, ("rdi", "rsi"), "tail", False, None, "tail_target"),
        (2, ("rdi", "rsi"), "direct", True, None, "variadic_like"),
        (None, ("rdi", "rsi"), "direct", False, None, "decompiler_failed"),
        (7, ("rdi", "rsi"), "direct", False, None, "too_many_arguments"),
    ],
)
def test_binding_preconditions(count, registers, kind, variadic, arity, reason):
    result = infer_arity("0x00001000", analysis(count, registers, kind, variadic))
    assert result.arity == arity and result.decisive == (arity is not None)
    assert result.reason == reason


def test_all_determinable_callers_must_agree_and_missing_subject():
    record = analysis()
    caller = record.functions[1]
    caller.call_sites.append(
        caller.call_sites[0].model_copy(
            update={"address": "0x00002011", "argument_registers": ["rdi"]}
        )
    )
    assert infer_arity("0x00001000", record).reason == "caller_count_mismatch"
    assert infer_arity("0x00000001", record).reason == "subject_not_found"

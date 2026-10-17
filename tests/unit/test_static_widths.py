import pytest

from aletheia.schema.signature_facts import ReturnFact, WidthFact
from aletheia.schema.types import canonical_type
from aletheia.verify.static.signatures import decide_return


def fact(kind, width=None):
    return ReturnFact(
        integer=WidthFact(kind=kind, width=width) if kind != "float" else WidthFact(kind="none"),
        floating=WidthFact(kind=kind, width=width) if kind == "float" else WidthFact(kind="none"),
    )


@pytest.mark.parametrize(
    "callee,callers,spelling,expected",
    [
        ([fact("int_or_ptr", 32)], [fact("int_or_ptr", 32)], "uint32_t", "VERIFIED"),
        ([fact("int_or_ptr", 64)], [fact("int_or_ptr", 64)], "size_t", "VERIFIED"),
        ([fact("float", 64)], [fact("float", 64)], "double", "VERIFIED"),
        ([fact("int_or_ptr", 32)], [fact("int_or_ptr", 64)], "size_t", "INCONCLUSIVE"),
        ([fact("int_or_ptr", 64)], [fact("int_or_ptr", 32)], "uint32_t", "INCONCLUSIVE"),
        ([fact("int_or_ptr", 32)], [fact("int_or_ptr", 32)], "void", "CONTRADICTED"),
        ([fact("none")], [fact("none")], "int", "CONTRADICTED"),
        ([fact("unknown")], [fact("int_or_ptr", 32)], "int", "INCONCLUSIVE"),
        (
            [fact("int_or_ptr", 32), fact("int_or_ptr", 64)],
            [fact("int_or_ptr", 32)],
            "int",
            "INCONCLUSIVE",
        ),
        ([fact("float", 32)], [fact("float", 32)], "float", "VERIFIED"),
        ([fact("float", 64)], [fact("float", 32)], "float", "INCONCLUSIVE"),
        ([fact("int_or_ptr", 8)], [fact("int_or_ptr", 8)], "char", "VERIFIED"),
        ([fact("int_or_ptr", 16)], [fact("int_or_ptr", 16)], "uint16_t", "VERIFIED"),
        ([fact("int_or_ptr", 32)], [fact("none")], "int", "INCONCLUSIVE"),
        ([fact("none")], [fact("none")], "void", "INCONCLUSIVE"),
    ],
)
def test_return_width_decisions(callee, callers, spelling, expected):
    assert decide_return(canonical_type(spelling, return_type=True), callee, callers) == expected


def test_movzx_destination_width_is_not_replaced_by_its_source_width():
    from types import SimpleNamespace

    from aletheia.analysis.signature_worker import _registers

    base = SimpleNamespace(getName=lambda: "RAX")
    eax = SimpleNamespace(getBaseRegister=lambda: base, getBitLength=lambda: 32)
    al = SimpleNamespace(getBaseRegister=lambda: base, getBitLength=lambda: 8)
    instruction = SimpleNamespace(
        getInputObjects=lambda: [al],
        getResultObjects=lambda: [eax],
        getNumOperands=lambda: 2,
        getRegister=lambda index: [eax, al][index],
        getMnemonicString=lambda: "MOVZX",
        getOperandRefType=lambda index: SimpleNamespace(
            isWrite=lambda: index == 0, isRead=lambda: index == 1
        ),
    )
    assert _registers(instruction, writes=True) == {"rax": 32}
    assert _registers(instruction, writes=False) == {"rax": 8}


@pytest.mark.parametrize(
    "address_type,expected",
    [
        ("const char *", "VERIFIED"),
        ("uintptr_t", "INCONCLUSIVE"),
        ("uint64_t", "INCONCLUSIVE"),
        ("uint32_t", "CONTRADICTED"),
    ],
)
def test_mixed_register_banks_and_integer_address_ambiguity(address_type, expected):
    from aletheia.analysis.ghidra_session import GhidraAnalysis
    from aletheia.schema.models import Claim, ClaimSubmission
    from aletheia.verify.static.signatures import verify_widths

    returned = fact("int_or_ptr", 32).model_dump()
    analysis = GhidraAnalysis.model_validate(
        {
            "binary_sha256": "a" * 64,
            "options_sha256": "b" * 64,
            "functions": [
                {
                    "entry": "0x00001000",
                    "body_ranges": [{"start": "0x00001000", "end": "0x00001010"}],
                    "is_thunk": False,
                    "signature_facts": {
                        "return_paths": [returned],
                        "param_reads": {"rdi": 64, "xmm0": 64},
                        "pointer_params": ["rdi"],
                    },
                },
                {
                    "entry": "0x00002000",
                    "body_ranges": [{"start": "0x00002000", "end": "0x00002010"}],
                    "is_thunk": False,
                    "call_sites": [
                        {
                            "address": "0x00002005",
                            "kind": "direct",
                            "target": "0x00001000",
                            "signature_use": {
                                "return_read": returned,
                                "argument_writes": {"rdi": 64, "xmm0": 64},
                            },
                        }
                    ],
                },
            ],
        }
    )
    claim = Claim.intake(
        ClaimSubmission.model_validate(
            {
                "run_id": "r_" + "a" * 16,
                "source": {"origin": "human", "source_id": "human:synthetic"},
                "binary_sha256": "a" * 64,
                "subject": {"address": "0x00001000"},
                "type": "function_signature",
                "body": {
                    "return_type": "uint32_t",
                    "params": [{"type": "double"}, {"type": address_type}],
                },
                "confidence": 0.8,
                "confidence_source": "stated",
            }
        )
    )
    result = verify_widths(claim, analysis, "sha256:" + "c" * 64)
    assert result.verdict.aspects["param_widths"].verdict == expected
    assert result.verdict.aspects["param_types"].verdict == "INCONCLUSIVE"
    assert any(item.kind == "pointer_use" for item in result.verdict.evidence)

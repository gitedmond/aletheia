"""A malformed or incomplete sequence record cannot establish contradiction."""

from pathlib import Path

import pytest

from aletheia.analysis.ghidra_session import GhidraAnalysis
from aletheia.schema.models import Counterexample, Verdict
from aletheia.verify.engine import DynamicProof
from aletheia.verify.groups import GroupEvidence, group_preconditions
from aletheia.verify.probes.inputs import generate_inputs
from aletheia.verify.probes.pack import load_pack


@pytest.mark.parametrize(
    "damage,failed",
    [
        (None, None),
        ("truncated", "complete_scope"),
        ("replay", "reproduced"),
        ("fault", "execution_reason"),
    ],
)
def test_composite_proof_requires_complete_clean_reproduced_sequences(damage, failed):
    pack = load_pack(Path("packs/md5.yaml"))
    members = [
        {"subject": f"0x0000{index}000", "role": role}
        for index, role in [(1, "final"), (2, "init"), (3, "update")]
    ]
    counts = {"init": 1, "update": 3, "final": 2}
    functions = [
        {
            "entry": m["subject"],
            "body_ranges": [{"start": m["subject"], "end": f"0x{int(m['subject'], 16) + 1:08x}"}],
            "is_thunk": False,
            "decompiler_param_count": counts[m["role"]],
        }
        for m in members
    ]
    functions.append(
        {
            "entry": "0x00004000",
            "body_ranges": [{"start": "0x00004000", "end": "0x000040ff"}],
            "is_thunk": False,
            "call_sites": [
                {
                    "address": f"0x0000400{i}",
                    "kind": "direct",
                    "target": m["subject"],
                    "argument_registers": ["rdi", "rsi", "rdx"][: counts[m["role"]]],
                }
                for i, m in enumerate(members)
            ],
        }
    )
    analysis = GhidraAnalysis.model_validate(
        {"binary_sha256": "a" * 64, "options_sha256": "b" * 64, "functions": functions}
    )
    inputs = pack.inputs.model_copy(
        update={"random": pack.inputs.random.model_copy(update={"count": 16})}
    )
    values = generate_inputs(inputs)
    rows = [
        {
            "final_shape": shape,
            "input_hex": data.hex(),
            "chunks": [data.hex()],
            "expected_hex": "00" * 16,
            "actual_hex": "01" * 16,
            "status": "mismatch",
            "instructions": 1,
            "imports_called": [],
        }
        for shape in ["ctx_out", "out_ctx"]
        for data in values
    ]
    replay = [
        next(row.copy() for row in rows if row["input_hex"] == "" and row["final_shape"] == shape)
        for shape in ["ctx_out", "out_ctx"]
    ]
    assert len(replay) == 2
    ce = Counterexample(
        call_shape="composite_ctx_out+out_ctx",
        input_hex="",
        expected_hex="00" * 32,
        actual_hex="01" * 32,
        variant="std",
    )
    verdict = Verdict(
        claim_id="c_" + "a" * 24,
        intrinsic_verdict="CONTRADICTED",
        strength="E2",
        counterexample=ce,
        harness="Controlled public sequence evidence.",
        verifier_version="0.1.0",
        env_digest="sha256:" + "e" * 64,
    )
    if damage == "truncated":
        rows.pop()
    if damage == "replay":
        replay[-1]["actual_hex"] = "00" * 16
    if damage == "fault":
        rows[0]["status"] = "emulation_fault"
    evidence = GroupEvidence.model_validate(
        {
            "binary_sha256": "a" * 64,
            "family": "md5",
            "members": members,
            "arity": {
                role: {"arity": n, "decisive": True, "reason": None} for role, n in counts.items()
            },
            "observations": rows,
            "planned_inputs_per_shape": len(values),
            "skipped_inputs": [],
            "minimization": replay,
        }
    )
    proof = DynamicProof(*group_preconditions(evidence, evidence.members, analysis, pack, verdict))
    if failed:
        assert proof.failure() is not None
        assert (
            not getattr(proof, failed)
            if failed != "execution_reason"
            else proof.execution_reason == "emulation_fault"
        )
    else:
        assert proof.failure() is None

import hashlib
from pathlib import Path

from aletheia.analysis.ghidra_session import GhidraAnalysis
from aletheia.config import Budgets
from aletheia.verify.composite import CompositeMember, CompositeRequest, verify_composite
from aletheia.verify.emulate.core import CallResult
from aletheia.verify.probes.pack import load_pack
from aletheia.verify.static.arity import Arity


def request():
    return CompositeRequest(
        binary_sha256="a" * 64,
        family="md5",
        budgets=Budgets(),
        env_digest="sha256:" + "b" * 64,
        members=[
            CompositeMember(claim_id="c_" + str(i) * 24, subject=f"0x0000100{i}", role=role)
            for i, role in enumerate(["init", "update", "final"], 1)
        ],
    )


def test_missing_role_never_executes_and_complete_group_shares_evidence(monkeypatch):
    import aletheia.verify.composite as module

    req = request()
    analysis = GhidraAnalysis(
        binary_sha256="a" * 64,
        options_sha256="c" * 64,
        functions=[
            {
                "entry": member.subject,
                "body_ranges": [
                    {"start": member.subject, "end": f"0x{int(member.subject, 16) + 1:08x}"}
                ],
                "is_thunk": False,
            }
            for member in req.members
        ],
    )
    pack = load_pack(Path("packs/md5.yaml"))
    binary = Path("a" * 64 + ".bin")
    incomplete = req.model_copy(update={"members": req.members[:2]})
    outcome = verify_composite(incomplete, analysis, binary, pack)
    assert all(v.reason == "composite_incomplete" for v in outcome.verdicts)

    class Emulator:
        mode = 0
        instances = 0

        def __init__(self, binary, budgets):
            self.total_instructions = 0
            Emulator.instances += 1

        def call_sequence(self, steps):
            if self.mode == 2 or (self.mode == 3 and self.instances > 1):
                return [CallResult(None, [], 1, "fortify_fail", False, [])]
            context = steps[0][1][0]
            assert all(args[0] is context for _, args, _ in steps[1:-1])
            message = b"".join(args[1].data for _, args, _ in steps[1:-1])
            self.total_instructions += len(steps)
            results = [CallResult(0, [], 1, None, False, []) for _ in steps]
            if steps[-1][1][0] is context:
                output = [b"", hashlib.md5(message).digest() if self.mode == 0 else b"x" * 16]
            else:
                output = [b"incorrect", b""]
            results[-1] = CallResult(0, output, 1, None, False, [])
            return results

    monkeypatch.setattr(module, "Emulator", Emulator)
    monkeypatch.setattr(
        module, "infer_arity", lambda *args: Arity(arity=3, decisive=False, reason="test")
    )
    outcome = verify_composite(req, analysis, binary, pack)
    assert len(outcome.verdicts) == 3
    assert all(v.intrinsic_verdict == "VERIFIED" for v in outcome.verdicts)
    assert len({v.evidence[0].artifact for v in outcome.verdicts}) == 1
    assert outcome.verdicts[0].evidence[0].artifact in outcome.artifacts

    changed = req.model_copy(
        update={
            "members": [
                member.model_copy(update={"claim_id": "c_" + str(i) * 24})
                for i, member in enumerate(req.members, 4)
            ]
        }
    )
    other = verify_composite(changed, analysis, binary, pack)
    assert other.verdicts[0].evidence[0].artifact == outcome.verdicts[0].evidence[0].artifact
    Emulator.mode = 2
    failed = verify_composite(req, analysis, binary, pack)
    assert all(
        v.intrinsic_verdict == "INCONCLUSIVE" and v.reason == "fortify_fail"
        for v in failed.verdicts
    )
    Emulator.mode = 1
    monkeypatch.setattr(
        module,
        "infer_arity",
        lambda subject, analysis: Arity(
            arity={"0x00001001": 1, "0x00001002": 3, "0x00001003": 2}[subject],
            decisive=True,
            reason=None,
        ),
    )
    wrong = verify_composite(req, analysis, binary, pack)
    assert all(v.intrinsic_verdict == "CONTRADICTED" and v.counterexample for v in wrong.verdicts)
    assert all(v.counterexample.input_hex == "" for v in wrong.verdicts)

    Emulator.mode = 3
    Emulator.instances = 0
    failed_minimization = verify_composite(req, analysis, binary, pack)
    assert all(
        v.intrinsic_verdict == "INCONCLUSIVE" and v.reason == "fortify_fail"
        for v in failed_minimization.verdicts
    )

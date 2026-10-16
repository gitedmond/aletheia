import hashlib
from pathlib import Path

from aletheia.verify.emulate.core import Buffer, CallResult
from aletheia.verify.probes.inputs import generate_inputs
from aletheia.verify.probes.pack import load_pack
from aletheia.verify.probes.runner import run_input


def test_hash_shapes_compare_the_output_role_and_ignore_return():
    for family in ["md5", "sha1", "sha256"]:
        pack = load_pack(Path("packs") / (family + ".yaml"))
        data = b"abc"
        digest = getattr(hashlib, family)(data).digest()
        lengths = {len(value) for value in generate_inputs(pack.inputs)}
        assert {0, 1, 55, 56, 57, 63, 64, 65, 119, 120, 127, 128, 129, 1000} <= lengths
        for shape in pack.call_shapes:

            class Reference:
                def call(self, entry, args, width, digest=digest):
                    buffers = [arg for arg in args if isinstance(arg, Buffer)]
                    output = [digest if arg.size == len(digest) else arg.data for arg in buffers]
                    return CallResult(123456789, output, 1, None, False, [])

            trial = run_input(Reference(), 0, shape, "std", pack.variants["std"], data)
            assert trial.status == "match"
            assert trial.expected == digest.hex()


def test_faulted_hash_order_is_counted_and_other_order_can_verify(monkeypatch, tmp_path):
    from aletheia.analysis.ghidra_session import GhidraAnalysis
    from aletheia.config import Budgets
    from aletheia.selftest import _claim
    from aletheia.sources.base import BinaryRef
    from aletheia.verify.probes import runner
    from aletheia.verify.static.arity import Arity

    pack = load_pack(Path("packs/md5.yaml"))
    values = generate_inputs(pack.inputs)
    binary = BinaryRef("a" * 64, tmp_path / "stripped" / ("a" * 64 + ".bin"), "test")
    analysis = GhidraAnalysis(
        binary_sha256=binary.binary_sha256,
        options_sha256="b" * 64,
        functions=[
            {
                "entry": "0x00001000",
                "body_ranges": [{"start": "0x00001000", "end": "0x00001010"}],
                "is_thunk": False,
            }
        ],
    )

    class Emulator:
        def __init__(self, binary, budgets):
            self.total_instructions = 0

        def call(self, entry, args, width):
            self.total_instructions += 1
            if args[0].size is None:
                return CallResult(None, [], 1, "emulation_fault", False, [])
            data = args[1].data
            return CallResult(999, [hashlib.md5(data).digest(), data], 1, None, False, [])

    monkeypatch.setattr(runner, "Emulator", Emulator)
    monkeypatch.setattr(
        runner, "infer_arity", lambda *args: Arity(arity=3, decisive=True, reason=None)
    )
    result = runner.verify_algorithm(
        _claim(binary, "0x00001000", "md5", "std"),
        analysis,
        pack,
        binary.stripped,
        Budgets(),
        "sha256:" + "c" * 64,
    )
    assert result.verdict.intrinsic_verdict == "VERIFIED"
    payload = next(iter(result.artifacts.values()))
    assert len(payload["observations"]) == len(values) + 1
    assert payload["skipped_inputs"] == [
        {
            "shape": "buf_len_digest_out",
            "variant": "std",
            "count": len(values) - 1,
            "reason": "emulation_fault",
        }
    ]

"""Purpose self-test uses stripped binaries and production worker verdicts."""

from pathlib import Path

import pytest

from aletheia.analysis.ghidra_session import GhidraAnalysisCache
from aletheia.config import Config
from aletheia.sandbox.runner import JobRunner
from aletheia.selftest import purpose_cases
from aletheia.store.artifacts import ArtifactStore

pytestmark = pytest.mark.integration


def test_purpose_calibration_in_production_worker(tmp_path):
    cfg = Config.read(Path("aletheia.toml"))
    runner = JobRunner(
        cfg.sandbox, tmp_path / "public", tmp_path / "jobs", ArtifactStore(tmp_path / "artifacts")
    )
    rows = purpose_cases(
        cfg,
        tmp_path,
        runner,
        GhidraAnalysisCache(runner, tmp_path / "cache"),
        {"strlen", "strcmp", "memcpy", "hex", "parse-int"},
    )
    assert len(rows) == 25
    assert all(row["passed"] for row in rows), [row for row in rows if not row["passed"]]


def test_declared_variants_match_references_and_reject_near_misses(tmp_path):
    import json
    import shutil

    from test_emulator import run_container

    from aletheia.selftest import compile_fixture

    cfg = Config.read(Path("aletheia.toml"))
    source = Path("tests/fixtures/purpose/calibration")
    fixture = json.loads((source / "cases.json").read_bytes())
    binary, symbols = compile_fixture(source, cfg, tmp_path, fixture["binary_sha256"])
    inputs, outputs = tmp_path / "in", tmp_path / "out"
    inputs.mkdir()
    outputs.mkdir()
    shutil.copyfile(binary.stripped, inputs / binary.stripped.name)
    for family in {case["family"] for case in fixture["variant_checks"]}:
        shutil.copyfile(Path("packs") / (family + ".yaml"), inputs / (family + ".yaml"))
    checks = [case | {"address": symbols[case["name"]]} for case in fixture["variant_checks"]]
    script = """
import json
from pathlib import Path
from aletheia.config import Budgets
from aletheia.verify.emulate.core import Emulator
from aletheia.verify.probes.inputs import generate_inputs,inputs_for_call
from aletheia.verify.probes.pack import load_pack
from aletheia.verify.probes.runner import run_input
checks=CHECKS
binary=next(Path('/job/in').glob('*.bin'))
for case in checks:
 pack=load_pack(Path('/job/in')/(case['family']+'.yaml'))
 pack.inputs.random.count=0
 shape=next(s for s in pack.call_shapes if s.id==case['shape'])
 probe=pack.variants[case['variant']]
 emu=Emulator(binary,Budgets())
 statuses=[run_input(emu,int(case['address'],16),shape,case['variant'],probe,data).status
           for data in inputs_for_call(generate_inputs(pack.inputs),probe,shape)]
 assert statuses and all(s in {'match','mismatch'} for s in statuses),(case,statuses)
 assert all(s=='match' for s in statuses)==case['matches'],(case,statuses)
print(json.dumps({'checked':len(checks)}))
""".replace("CHECKS", repr(checks))
    result = run_container(cfg.sandbox.image_analysis, inputs, outputs, ["python", "-c", script])
    assert json.loads(result)["checked"] == len(checks)

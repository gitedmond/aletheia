"""Typed initializer exhaustion during minimization/reproduction remains a budget outcome."""

import hashlib
import json
from pathlib import Path

import pytest
from test_emulator import run_container

from aletheia.analysis.ghidra_session import GhidraAnalysisCache
from aletheia.config import Config
from aletheia.sandbox.runner import JobRunner
from aletheia.schema.canonical import canonical_bytes
from aletheia.schema.models import Claim, ClaimSubmission
from aletheia.selftest import build_fixture
from aletheia.store.artifacts import ArtifactStore

pytestmark = pytest.mark.integration


def test_fresh_initializer_budget_exhaustion_uses_real_production_binding(tmp_path):
    cfg = Config.read(Path("aletheia.toml"))
    root = tmp_path / "fixtures"
    root.mkdir()
    binary, symbols, _ = build_fixture("fnv", cfg, root)
    runner = JobRunner(
        cfg.sandbox, tmp_path / "public", tmp_path / "jobs", ArtifactStore(tmp_path / "artifacts")
    )
    analysis = GhidraAnalysisCache(runner, tmp_path / "analysis-cache").analyze(
        binary, Path(cfg.ghidra.analysis_options), subjects=[symbols["wrong_offset_basis"]]
    )
    claim = Claim.intake(
        ClaimSubmission.model_validate(
            {
                "run_id": "r_" + "2" * 16,
                "source": {"origin": "human", "source_id": "human:fresh-budget"},
                "binary_sha256": binary.binary_sha256,
                "subject": {"address": symbols["wrong_offset_basis"]},
                "type": "algorithm_identity",
                "body": {"family": "fnv", "variant": "fnv1a-32"},
                "confidence": 1.0,
                "confidence_source": "stated",
            }
        )
    )
    inputs, outputs = tmp_path / "faults/in", tmp_path / "faults/out"
    inputs.mkdir(parents=True)
    outputs.mkdir()
    (inputs / binary.stripped.name).write_bytes(binary.stripped.read_bytes())
    names = {}
    for key, payload, suffix in [
        ("analysis", canonical_bytes(analysis), "json"),
        ("claim", canonical_bytes(claim), "json"),
        ("pack", Path("packs/fnv.yaml").read_bytes(), "yaml"),
    ]:
        names[key] = hashlib.sha256(payload).hexdigest() + "." + suffix
        (inputs / names[key]).write_bytes(payload)
    script = """
import json
from pathlib import Path
from aletheia.analysis.ghidra_session import GhidraAnalysis
from aletheia.config import Budgets
from aletheia.schema.models import Claim
from aletheia.verify.emulate.core import Emulator,InitializationBudgetExhausted
from aletheia.verify.probes.pack import load_pack
import aletheia.verify.probes.runner as module
analysis=GhidraAnalysis.model_validate_json(Path('/job/in/ANALYSIS').read_bytes())
claim=Claim.model_validate_json(Path('/job/in/CLAIM').read_bytes())
pack=load_pack(Path('/job/in/PACK'))
rows=[]
for fail_at in (2,3):
 count=0
 instances=[]
 class BudgetOnFresh(Emulator):
  def __init__(self,*args,**kwargs):
   global count
   count+=1
   if count==fail_at:
    raise InitializationBudgetExhausted(1)
   super().__init__(*args,**kwargs)
   instances.append(self)
 module.Emulator=BudgetOnFresh
 try:
  result=module.verify_algorithm(claim,analysis,pack,Path('/job/in/BINARY'),Budgets(),'sha256:'+'c'*64)
  rows.append({'outcome':result.verdict.intrinsic_verdict,'reason':result.verdict.reason,
   'instructions':result.verdict.budget_used.instructions,
   'expected_instructions':sum(instance.total_instructions for instance in instances)+1})
 except Exception as exc:
  rows.append({'exception':type(exc).__name__})
print(json.dumps(rows))
"""
    for key, name in {**names, "binary": binary.stripped.name}.items():
        script = script.replace(key.upper(), name)
    rows = json.loads(
        run_container(cfg.sandbox.image_analysis, inputs, outputs, ["python", "-c", script])
    )
    assert all(
        row.get("outcome") == "INCONCLUSIVE" and row.get("reason") == "budget_exhausted"
        for row in rows
    ), rows
    assert all(row["instructions"] == row["expected_instructions"] for row in rows)

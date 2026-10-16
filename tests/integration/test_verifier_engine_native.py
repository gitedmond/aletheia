"""T16: real arity/probes, audit isolation, cross-source reuse and cache invalidation."""

import json
from pathlib import Path

import pytest
import yaml

from aletheia.analysis.ghidra_session import GhidraAnalysisCache
from aletheia.config import Config
from aletheia.sandbox.runner import JobRunner
from aletheia.schema.models import Claim, ClaimSubmission, Verdict
from aletheia.selftest import build_fixture
from aletheia.store.artifacts import ArtifactStore
from aletheia.store.cache import verdict_cache_key
from aletheia.store.database import Store
from aletheia.verify.engine import (
    Engine,
    MethodResult,
    ProbeEvidence,
    merge_results,
    methods_for,
    probe_proof,
)

pytestmark = pytest.mark.integration


def test_real_audit_cache_identity_preconditions_and_configuration(tmp_path):
    cfg = Config.read(Path("aletheia.toml"))
    root = tmp_path / "fixtures"
    root.mkdir()
    binary, symbols, _ = build_fixture("fnv", cfg, root)
    artifacts = ArtifactStore(tmp_path / "artifacts")
    runner = JobRunner(cfg.sandbox, tmp_path / "public", tmp_path / "jobs", artifacts)
    cache = GhidraAnalysisCache(runner, tmp_path / "analysis-cache")
    analysis = cache.analyze(
        binary, Path(cfg.ghidra.analysis_options), subjects=[symbols["wrong_prime"]]
    )
    original = Claim.intake(
        ClaimSubmission.model_validate(
            {
                "run_id": "r_" + "2" * 16,
                "source": {"origin": "human", "source_id": "human:native-engine"},
                "binary_sha256": binary.binary_sha256,
                "subject": {"address": symbols["wrong_prime"]},
                "type": "algorithm_identity",
                "body": {"family": "fnv", "variant": "fnv1a-32"},
                "confidence": 1.0,
                "confidence_source": "stated",
            }
        )
    )
    with Store(tmp_path / "metadata.sqlite") as store:
        engine = Engine(runner, store, cfg.budgets, Path(cfg.ghidra.analysis_options))
        original_budget = cfg.budgets.instructions_per_claim
        cfg.budgets.instructions_per_claim += 1
        assert engine.budgets.instructions_per_claim == original_budget
        cfg.budgets.instructions_per_claim = original_budget
        first = engine.verify(original, binary, analysis)
        assert (first.verdict.intrinsic_verdict, first.verdict.strength) == (
            "CONTRADICTED",
            "E2",
        ), first
        assert not first.cache_hit
        assert set(first.method_results) == {"probe.fnv@1", "static.constants@1"}
        assert first.method_results["static.constants@1"].verdict == "INCONCLUSIVE"
        count = len(list(runner.jobs_root.iterdir()))
        changed = original.model_dump(mode="json", exclude={"claim_id"})
        changed.update(
            source={"origin": "scripted", "source_id": "scripted:v1"},
            confidence=0.1,
            confidence_source="scripted",
            rationale="Ignored metadata",
            derived_from="scripted_mutated",
            run_id="r_" + "3" * 16,
        )
        second_claim = Claim.intake(ClaimSubmission.model_validate(changed))
        second = engine.verify(second_claim, binary, analysis)
        assert second.cache_hit and second.cache_key == first.cache_key
        assert second.verdict.claim_id == second_claim.claim_id != original.claim_id
        assert len(list(runner.jobs_root.iterdir())) == count
        assert second.method_results == first.method_results
        for field in (
            "instructions_per_invocation",
            "instructions_per_claim",
            "heap_mb",
            "stack_mb",
        ):
            budget = cfg.budgets.model_copy(update={field: getattr(cfg.budgets, field) + 1})
            altered = Engine(runner, store, budget, Path(cfg.ghidra.analysis_options))
            assert (
                verdict_cache_key(original, altered.cache_context(original, analysis))
                != first.cache_key
            )
        pack_dir = tmp_path / "packs"
        pack_dir.mkdir()
        raw = yaml.safe_load(Path("packs/fnv.yaml").read_text())
        raw["inputs"]["random"]["seed"] += 1
        (pack_dir / "fnv.yaml").write_text(yaml.safe_dump(raw, sort_keys=False))
        altered = Engine(runner, store, cfg.budgets, Path(cfg.ghidra.analysis_options), pack_dir)
        assert (
            verdict_cache_key(original, altered.cache_context(original, analysis))
            != first.cache_key
        )
        options = json.loads(Path(cfg.ghidra.analysis_options).read_bytes())
        option = next(
            item for item in options["options"] if item["name"] == "Aggressive Instruction Finder"
        )
        option["value"] = not option["value"]
        option_path = tmp_path / "options.json"
        option_path.write_text(json.dumps(options))
        altered = Engine(runner, store, cfg.budgets, option_path)
        assert (
            verdict_cache_key(original, altered.cache_context(original, analysis))
            != first.cache_key
        )
        with pytest.raises(ValueError, match="analysis/options"):
            altered.verify(original, binary, analysis)
        ref = next(
            item.artifact for item in first.verdict.evidence if item.kind == "method_results"
        )
        audit = json.loads(artifacts.get(ref))
        assert not audit["defects"]
        record = next(row for row in audit["methods"] if row["method"] == "probe.fnv@1")
        assert "claim_id" not in record["result"]
        counts = record["details"]["input_counts"]["buf_len"]
        assert counts["generated"] == counts["eligible_per_variant"] == 66
        assert counts["skipped_embedded_nul"] == 0
        assert counts["executed_by_variant"]["fnv1a-32"] == 66
        raw_verdict = Verdict.model_validate(record["result"] | {"claim_id": original.claim_id})
        ref = next(item.artifact for item in raw_verdict.evidence if item.kind == "probe_results")
        proof_data = ProbeEvidence.model_validate_json(artifacts.get(ref))
        pack = engine.packs["fnv"]
        spec = next(spec for spec in methods_for(original, pack) if spec.cost_class == "emulation")
        for change, reason in [
            ("state", "state_dependent"),
            ("width", "no_matching_call_shape"),
            ("reproduction", "emulation_fault"),
        ]:
            damaged = proof_data.model_copy(deep=True)
            if change == "state":
                damaged.observations[0].uninitialized_state_reads = True
            elif change == "width":
                damaged.observations[0].actual_hex = ""
            else:
                damaged.minimization = []
            proof = probe_proof(original, analysis, pack, damaged, raw_verdict)
            guarded = merge_results(
                original, [MethodResult(spec, raw_verdict, proof=proof)], engine.env_digest
            )
            assert (guarded.intrinsic_verdict, guarded.reason) == ("INCONCLUSIVE", reason)
        missing_callers = analysis.model_copy(deep=True)
        for function in missing_callers.functions:
            function.call_sites = []
        with pytest.raises(ValueError, match="binding evidence mismatch"):
            probe_proof(original, missing_callers, pack, proof_data, raw_verdict)
        changed_analysis = engine.verify(second_claim, binary, missing_callers)
        assert not changed_analysis.cache_hit
        assert (changed_analysis.verdict.intrinsic_verdict, changed_analysis.verdict.reason) == (
            "INCONCLUSIVE",
            "binding_not_verified",
        )
        binary.stripped.write_bytes(b"tampered")
        with pytest.raises(ValueError, match="content/hash mismatch"):
            engine.verify(original, binary, analysis)

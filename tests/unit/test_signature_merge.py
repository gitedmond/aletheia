"""Required aspect combinations, with optional contradictions kept separate."""

from itertools import product

import pytest

from aletheia.schema.models import Aspect, Claim, ClaimSubmission, Verdict
from aletheia.verify.engine import MethodResult, MethodSpec, merge_results

ENV = "sha256:" + "e" * 64
VALUES = ["VERIFIED", "CONTRADICTED", "INCONCLUSIVE", "ERROR", "NOT_CHECKED", "UNVERIFIABLE"]


def signature():
    return Claim.intake(
        ClaimSubmission.model_validate(
            {
                "run_id": "r_" + "2" * 16,
                "source": {"origin": "human", "source_id": "human:aspect-table"},
                "binary_sha256": "a" * 64,
                "subject": {"address": "0x00001000"},
                "type": "function_signature",
                "body": {"return_type": "uint32_t", "params": []},
                "confidence": 1.0,
                "confidence_source": "stated",
            }
        )
    )


def observation(claim, aspect, outcome, optional):
    method = "static.arity@2" if aspect == "arity" else "static.widths@1"
    decisive = outcome in {"VERIFIED", "CONTRADICTED"}
    aspects = {aspect: Aspect(verdict=outcome, strength="E1" if decisive else None, method=method)}
    if aspect == "return_width":
        aspects["param_widths"] = Aspect(verdict=optional, strength="E1", method=method)
        aspects["param_types"] = Aspect(verdict="INCONCLUSIVE", method=method)
    return MethodResult(
        MethodSpec(method, "function_signature", aspect, "E1", True, True, "static"),
        Verdict(
            claim_id=claim.claim_id,
            intrinsic_verdict=outcome,
            strength="E1" if decisive else None,
            aspects=aspects,
            methods_run=[method],
            reason=None if decisive else "no_pack",
            harness="Controlled public facts." if decisive else None,
            verifier_version="0.1.0",
            env_digest=ENV,
        ),
    )


@pytest.mark.parametrize(
    "arity,width,optional", list(product(VALUES, VALUES, ["VERIFIED", "CONTRADICTED"]))
)
def test_required_aspects_and_optional_decisions(arity, width, optional):
    claim = signature()
    results = [
        observation(claim, "arity", arity, optional),
        observation(claim, "return_width", width, optional),
    ]
    outcomes = {arity, width}
    expected = (
        "CONTRADICTED"
        if "CONTRADICTED" in outcomes
        else "VERIFIED"
        if outcomes == {"VERIFIED"}
        else "INCONCLUSIVE"
        if outcomes & {"VERIFIED", "INCONCLUSIVE"}
        else "ERROR"
        if "ERROR" in outcomes
        else "NOT_CHECKED"
        if "NOT_CHECKED" in outcomes
        else "UNVERIFIABLE"
    )
    verdict = merge_results(claim, results, ENV)
    assert verdict.intrinsic_verdict == expected
    assert verdict.aspects["arity"].verdict == arity
    assert verdict.aspects["return_width"].verdict == width
    assert verdict.aspects["param_widths"].verdict == optional
    assert verdict.aspects["param_types"].verdict == "INCONCLUSIVE"
    if expected == "VERIFIED":
        assert verdict.strength == "E1"


@pytest.mark.parametrize(
    "mode,first_width,expected_calls",
    [
        ("audit", "VERIFIED", 3),
        ("runtime", "VERIFIED", 2),
        ("runtime", "INCONCLUSIVE", 3),
    ],
)
def test_runtime_waits_for_all_required_aspects(
    tmp_path, monkeypatch, mode, first_width, expected_calls
):
    import hashlib
    from pathlib import Path

    from aletheia.analysis.ghidra_session import GhidraAnalysis
    from aletheia.config import Config
    from aletheia.sandbox.runner import JobRunner
    from aletheia.sources.base import BinaryRef
    from aletheia.store.artifacts import ArtifactStore
    from aletheia.store.database import Store
    from aletheia.verify import engine as module

    cfg = Config()
    payload = b"opaque coordinator input, never parsed by this unit test"
    digest = hashlib.sha256(payload).hexdigest()
    path = tmp_path / "stripped" / (digest + ".bin")
    path.parent.mkdir()
    path.write_bytes(payload)
    data = signature().model_dump(mode="json", exclude={"claim_id"})
    data["binary_sha256"] = digest
    claim = Claim.intake(ClaimSubmission.model_validate(data))
    runner = JobRunner(
        cfg.sandbox, tmp_path / "public", tmp_path / "jobs", ArtifactStore(tmp_path / "artifacts")
    )
    methods = module.methods_for(claim, None)
    methods.append(
        MethodSpec(
            "static.z_extra@1", "function_signature", "return_width", "E1", True, True, "static"
        )
    )
    monkeypatch.setattr(module, "methods_for", lambda claim, pack: methods)
    calls = []
    with Store(tmp_path / "db.sqlite") as store:
        engine = module.Engine(
            runner, store, cfg.budgets, Path("configs/ghidra-analysis.json"), mode=mode
        )
        analysis = GhidraAnalysis(
            binary_sha256=digest, options_sha256=engine.options_hash, functions=[]
        )
        from aletheia.store.cache import verdict_cache_key

        context = engine.cache_context(claim, analysis)
        key = verdict_cache_key(claim, context)
        assert key != verdict_cache_key(
            claim, context.model_copy(update={"taxonomy_version": "2.0"})
        )
        assert key != verdict_cache_key(
            claim, context.model_copy(update={"purpose_packs_hash": "f" * 64})
        )
        assert context.harness["mode"] == mode

        def static(spec, current, analysis):
            calls.append(spec.name)
            outcome = (
                "CONTRADICTED"
                if spec.aspect == "arity"
                else first_width
                if len(calls) == 2
                else "VERIFIED"
            )
            value = observation(current, spec.aspect, outcome, "CONTRADICTED")
            verdict = value.verdict.model_copy(
                update={
                    "methods_run": [spec.name],
                    "aspects": {
                        spec.aspect: Aspect(
                            verdict=outcome,
                            strength="E1" if outcome != "INCONCLUSIVE" else None,
                            method=spec.name,
                        )
                    },
                }
            )
            return MethodResult(spec, verdict)

        monkeypatch.setattr(engine, "_static", static)
        result = engine.verify(claim, BinaryRef(digest, path, "synthetic"), analysis)
        assert result.verdict.intrinsic_verdict == "CONTRADICTED"
        assert len(calls) == expected_calls

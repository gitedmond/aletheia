"""Local claim acquisition, then independent verification/grading and dev-only fits."""

import json
from pathlib import Path
from typing import Any

from aletheia.agent.loop import AgentResult
from aletheia.agent.run import collect
from aletheia.confidence import Sample, fit_calibration, fit_likelihoods, sample
from aletheia.llm.provider import AgentConfig, OpenAICompatibleProvider, Provider
from aletheia.llm.windows_loopback import WindowsLoopbackProvider
from aletheia.orchestrate import Benchmark, file_hash, write_json
from aletheia.schema.canonical import content_hash
from aletheia.schema.models import Claim, RunManifest


def provider_for(config: AgentConfig) -> Provider:
    if config.transport == "windows-loopback":
        return WindowsLoopbackProvider(config)
    return OpenAICompatibleProvider(config)


def run_agent(
    benchmark: Benchmark,
    agent: AgentConfig,
    provider: Provider,
    program: str,
    sample_index: int,
    *,
    seed: int = 20261013,
) -> tuple[str, AgentResult]:
    if agent.hosted:
        raise ValueError("hosted_cost_cap")
    if sample_index < 0:
        raise ValueError("sample index cannot be negative")
    binary, targets, _ = benchmark.bundle(program)
    manifest_input = benchmark.manifest_input(program, "agent")
    manifest_input.algorithms_version = "2.0"
    effective_seed = seed + sample_index
    manifest_input.source_config.update(
        {
            "origin": "agent",
            "source_id": "agent:" + agent.config_id,
            "agent_config": agent.model_dump(mode="json"),
            "sample_index": sample_index,
            "prompt_hash": file_hash(Path(agent.prompt)),
            "context_hash": file_hash(Path(__file__).parents[2] / "prompts/context-v1.md"),
            "provider_transport": provider.id,
        }
    )
    manifest_input.seeds["agent"] = effective_seed
    manifest = RunManifest.create(manifest_input)
    root = benchmark.directory(manifest.run_id) / "agent"
    if (root / "agent.json").exists():
        record = json.loads((root / "agent.json").read_bytes())
        if record["run_id"] != manifest.run_id or record["config"] != agent.model_dump(mode="json"):
            raise ValueError("agent run provenance differs")
        result = AgentResult.model_validate(record["result"])
        claims = [Claim.model_validate(c) for c in json.loads((root / "claims.json").read_bytes())]
    else:
        result, claims = collect(
            benchmark.config,
            agent,
            provider,
            binary,
            targets,
            manifest.run_id,
            root,
            seed=effective_seed,
        )
    run = benchmark.ingest(program, manifest, claims)
    path = benchmark.directory(run) / "run.json"
    metadata = json.loads(path.read_bytes())
    metadata["agent_result"] = result.model_dump(mode="json")
    metadata["sample_index"] = sample_index
    write_json(path, metadata)
    benchmark.verify(run)
    benchmark.score([run])
    return run, result


def fit_dev(benchmark: Benchmark, runs: list[str] | None = None) -> dict[str, Any]:
    if benchmark.config.guard.split != "dev":
        raise ValueError("confidence fitting accepts dev runs only")
    selected = sorted(set(runs if runs is not None else benchmark.run_ids()))
    rows: list[Sample] = []
    manifests: dict[str, str] = {}
    source_scopes: dict[str, str] = {}
    with benchmark.store() as store:
        for run in selected:
            root = benchmark.directory(run)
            manifest = RunManifest.model_validate_json((root / "manifest.json").read_bytes())
            if manifest.source_config.get("split", "dev") != "dev":
                raise ValueError("held-out run cannot enter dev fitting")
            metadata = json.loads((root / "run.json").read_bytes())
            source_id = str(manifest.source_config["source_id"])
            scope_data: dict[str, Any] = {
                "agent": manifest.source_config.get("agent_config"),
                "prompt": manifest.source_config.get("prompt_hash"),
                "context": manifest.source_config.get("context_hash"),
                "mappings": manifest.mapping_hashes,
                "versions": manifest.versions,
                "images": manifest.image_digests,
                "analysis_options": manifest.analysis_options_hash,
                "packs": manifest.pack_hashes,
                "verifier": manifest.verifier_version,
                "grader": manifest.grader_version,
                "run_config": manifest.source_config.get("run_config"),
            }
            scope = content_hash(scope_data)
            if source_id in source_scopes and source_scopes[source_id] != scope:
                raise ValueError("configuration drift within a fitting source")
            source_scopes[source_id] = scope
            claims = benchmark.claims(store, run)
            for claim in claims:
                binary = store.connection.execute(
                    "SELECT split FROM binaries WHERE sha256=?", (claim.binary_sha256,)
                ).fetchone()
                if binary is None or binary[0] != "dev":
                    raise ValueError("non-dev binary cannot enter fitting")
                rows.append(
                    sample(
                        claim,
                        store.get_grade(claim.claim_id),
                        store.get_verdict(claim.claim_id),
                        program=metadata["program"],
                        split="dev",
                    )
                )
            manifests[run] = file_hash(root / "manifest.json")
    calibration, likelihoods = fit_calibration(rows), fit_likelihoods(rows)
    destination = benchmark.root / "confidence"
    write_json(destination / "calibration.json", calibration)
    write_json(destination / "likelihoods.json", likelihoods)
    receipt = {
        "status": "ok",
        "input_run_ids": selected,
        "manifest_digests": manifests,
        "eligible_rows": sum(r.on_target and r.correct_claimed is not None for r in rows),
        "calibration_hash": file_hash(destination / "calibration.json"),
        "likelihoods_hash": file_hash(destination / "likelihoods.json"),
        "calibrated_sources": len(calibration.maps),
        "unfitted": len(calibration.unfitted),
    }
    write_json(destination / "fit.json", receipt)
    return receipt

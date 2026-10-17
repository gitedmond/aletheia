"""Collect a local agent run from public stripped input; grade only afterward."""

from pathlib import Path

from aletheia.agent.loop import AgentLoop, AgentResult, build_messages
from aletheia.agent.proxy import HarnessProxy
from aletheia.agent.replay import RecordingProvider
from aletheia.agent.upstream import GhidraUpstream
from aletheia.config import Config
from aletheia.llm.provider import AgentConfig, CachedProvider, Provider
from aletheia.orchestrate import write_json
from aletheia.schema.models import Claim, Targets
from aletheia.sources.base import BinaryRef


def collect(
    config: Config,
    agent: AgentConfig,
    provider: Provider,
    binary: BinaryRef,
    targets: Targets,
    run_id: str,
    root: Path,
    *,
    seed: int = 20261013,
) -> tuple[AgentResult, list[Claim]]:
    if agent.hosted:
        raise ValueError("hosted_cost_cap")
    if targets.binary_sha256 != binary.binary_sha256 or targets.variant_id != binary.variant_id:
        raise ValueError("agent target identity mismatch")
    root = (
        config.guard.private_output(root)
        if config.guard.split == "heldout"
        else config.guard.public_path(root)
    )
    if any(
        (root / name).exists()
        for name in ("trajectory.jsonl", "agent.json", "claims-history.json", "claims.json")
    ):
        raise ValueError("run artifacts already exist")
    cached = CachedProvider(agent, provider, root / "responses", config.guard)
    upstream = GhidraUpstream(
        config.sandbox,
        binary,
        Path(config.ghidra.analysis_options),
        root / "ghidra",
        guard=config.guard,
    )
    try:
        proxy = HarnessProxy(
            run_id=run_id,
            binary_sha256=binary.binary_sha256,
            source_id="agent:" + agent.config_id,
            upstream=upstream,
            trajectory=root / "trajectory.jsonl",
            guard=config.guard,
            budgets=agent.budgets,
        )
        tools = upstream.tools()
        if sorted(tool.function.name for tool in tools) != proxy.allowlist.tools:
            raise ValueError("upstream tool schema drift")
        messages, prompt_hash, context_hash = build_messages(Path(agent.prompt), targets)
        recording = RecordingProvider(cached)
        loop = AgentLoop(agent, recording, proxy, tools, seed=seed)
        result = loop.run(messages)
        write_json(
            root / "agent.json",
            {
                "run_id": run_id,
                "binary_sha256": binary.binary_sha256,
                "messages": [m.model_dump(mode="json") for m in messages],
                "provider_events": recording.events,
                "clock_trace": [repr(value) for value in loop.clock_trace],
                "config": agent.model_dump(mode="json"),
                "provider_transport": provider.id,
                "prompt_hash": prompt_hash,
                "context_hash": context_hash,
                "tool_schemas": [tool.model_dump(mode="json") for tool in tools],
                "seed": seed,
                "result": result.model_dump(mode="json"),
            },
        )
        write_json(
            root / "claims-history.json", [claim.model_dump(mode="json") for claim in proxy.claims]
        )
        write_json(
            root / "claims.json", [claim.model_dump(mode="json") for claim in proxy.active_claims]
        )
        return result, proxy.active_claims
    finally:
        upstream.close()

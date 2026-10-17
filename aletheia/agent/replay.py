"""Agent replay requires cached responses and the recorded public tool transcript."""

import json
from pathlib import Path
from typing import Any

from pydantic import JsonValue

from aletheia.agent.loop import AgentLoop
from aletheia.agent.proxy import HarnessProxy
from aletheia.agent.upstream import UpstreamCrash
from aletheia.heldout.guard import PrivateGuard
from aletheia.llm.provider import (
    AgentConfig,
    CachedProvider,
    ChatRequest,
    ChatResponse,
    FakeProvider,
    Message,
    Provider,
    ProviderRejected,
    ProviderUnavailable,
    ToolSpec,
)
from aletheia.schema.canonical import canonical_bytes, content_hash


class RecordingProvider:
    id = "recording"

    def __init__(self, provider: Provider):
        self.provider = provider
        self.events: list[dict[str, Any]] = []

    def send(self, req: ChatRequest) -> ChatResponse:
        event: dict[str, Any] = {"request_hash": content_hash(req)}
        try:
            result = self.provider.send(req)
        except ProviderUnavailable:
            self.events.append(event | {"outcome": "unavailable"})
            raise
        except ProviderRejected as exc:
            self.events.append(event | {"outcome": "rejected", "reason": exc.reason})
            raise
        except ValueError:
            self.events.append(event | {"outcome": "malformed"})
            raise
        self.events.append(event | {"outcome": "response"})
        return result


class ReplayProvider:
    id = "replay"

    def __init__(self, cached: CachedProvider, events: list[dict[str, Any]]):
        self.cached, self.events, self.position = cached, events, 0
        self.hits = self.errors = self.misses = 0

    def send(self, req: ChatRequest) -> ChatResponse:
        if self.position >= len(self.events):
            raise ValueError("agent_replay_script_exhausted")
        event = self.events[self.position]
        self.position += 1
        if event["request_hash"] != content_hash(req):
            raise ValueError("agent_replay_request_drift")
        if event["outcome"] == "response":
            try:
                response = self.cached.send(req)
            except ValueError:
                self.misses += 1
                raise
            self.hits += 1
            return response
        self.errors += 1
        if event["outcome"] == "unavailable":
            raise ProviderUnavailable("recorded transport failure")
        if event["outcome"] == "rejected":
            raise ProviderRejected(event["reason"])
        raise ValueError("recorded malformed response")


class RecordedUpstream:
    def __init__(self, records: list[dict[str, Any]], allowed: list[str]):
        self.records = [r for r in records if r["tool"] in allowed]
        self.position = self.attempt = 0

    def start(self) -> None:
        pass

    def call(self, name: str, arguments: dict[str, JsonValue]) -> JsonValue:
        if self.position >= len(self.records):
            raise ValueError("agent_replay_tools_exhausted")
        item = self.records[self.position]
        if item["tool"] != name or canonical_bytes(item["arguments"]) != canonical_bytes(arguments):
            raise ValueError("agent_replay_tool_drift")
        result = item["response"]
        if result["status"] == "ok":
            self.position += 1
            return result["result"]
        if result.get("reason") == "upstream_timeout":
            self.attempt += 1
            if self.attempt == 2:
                self.attempt = 0
                self.position += 1
            raise TimeoutError("recorded upstream timeout")
        self.position += 1
        if result.get("reason") == "ghidra_crash":
            raise UpstreamCrash("recorded upstream crash")
        raise ValueError("recorded upstream error")


def replay_agent(root: Path, destination: Path, guard: PrivateGuard) -> dict[str, Any]:
    record = json.loads(guard.access(root / "agent.json").read_bytes())
    if guard.split == "heldout":
        guard.private_output(destination)
    else:
        guard.public_path(destination)
    config = AgentConfig.model_validate(record["config"])
    cached = CachedProvider(config, FakeProvider([]), root / "responses", guard, replay=True)
    provider = ReplayProvider(cached, record["provider_events"])
    transcript = (
        [json.loads(line) for line in (root / "trajectory.jsonl").read_text().splitlines()]
        if (root / "trajectory.jsonl").exists()
        else []
    )
    upstream = RecordedUpstream(
        transcript, [tool["function"]["name"] for tool in record["tool_schemas"]]
    )
    proxy = HarnessProxy(
        run_id=record["run_id"],
        binary_sha256=record["binary_sha256"],
        source_id="agent:" + config.config_id,
        upstream=upstream,
        trajectory=destination / "trajectory.jsonl",
        guard=guard,
        budgets=config.budgets,
    )
    ticks = iter(float(value) for value in record["clock_trace"])
    loop = AgentLoop(
        config,
        provider,
        proxy,
        [ToolSpec.model_validate(t) for t in record["tool_schemas"]],
        seed=record["seed"],
        sleep=lambda _: None,
        clock=lambda: next(ticks),
    )
    try:
        result = loop.run([Message.model_validate(m) for m in record["messages"]])
    except (StopIteration, ValueError, RuntimeError) as exc:
        return {
            "status": "failed",
            "differences": ["agent replay drift: " + type(exc).__name__],
            "provider_cache_hits": provider.hits,
            "provider_errors_replayed": provider.errors,
            "provider_cache_misses": provider.misses,
        }

    claims: list[JsonValue] = [c.model_dump(mode="json") for c in proxy.active_claims]
    expected = json.loads((root / "claims.json").read_bytes())
    history = json.loads((root / "claims-history.json").read_bytes())
    differences: list[str] = []
    actual_transcript = (
        [json.loads(line) for line in (destination / "trajectory.jsonl").read_text().splitlines()]
        if (destination / "trajectory.jsonl").exists()
        else []
    )

    def deterministic(records: list[dict[str, Any]]) -> list[Any]:
        return [
            {key: value for key, value in row.items() if key != "elapsed_seconds"}
            for row in records
        ]

    if canonical_bytes(deterministic(actual_transcript)) != canonical_bytes(
        deterministic(transcript)
    ):
        differences.append("trajectory")
    if list(ticks):
        differences.append("unused-clock-decisions")
    if canonical_bytes(claims) != canonical_bytes(expected):
        differences.append("claims")
    if canonical_bytes([c.model_dump(mode="json") for c in proxy.claims]) != canonical_bytes(
        history
    ):
        differences.append("claims-history")
    if result.model_dump(mode="json") != record["result"]:
        differences.append("agent-result")
    if (
        provider.position != len(provider.events)
        or upstream.position != len(upstream.records)
        or provider.misses
    ):
        differences.append("unconsumed-or-missing-cache")
    return {
        "status": "passed" if not differences else "failed",
        "differences": differences,
        "provider_cache_hits": provider.hits,
        "provider_errors_replayed": provider.errors,
        "provider_cache_misses": provider.misses,
    }

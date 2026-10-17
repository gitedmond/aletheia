"""Scripted protocol, retry and exhaustion behavior without a model or real sleep."""

from pathlib import Path

from aletheia.agent.loop import AgentLoop
from aletheia.agent.proxy import HarnessProxy
from aletheia.agent.upstream import UpstreamCrash
from aletheia.heldout.guard import PrivateGuard
from aletheia.llm.provider import (
    AgentBudgets,
    AgentConfig,
    ChatResponse,
    FakeProvider,
    FunctionCall,
    Message,
    ProviderUnavailable,
    ToolCall,
    Usage,
)


class Upstream:
    def __init__(self, crashes=0):
        self.crashes, self.starts = crashes, 0

    def start(self):
        self.starts += 1

    def call(self, name, arguments):
        if self.crashes:
            self.crashes -= 1
            raise UpstreamCrash("crash")
        return {"code": "return 7;"}


def response(name="finish", arguments="{}"):
    return ChatResponse(
        message=Message(
            role="assistant",
            tool_calls=[
                ToolCall(id="call-1", function=FunctionCall(name=name, arguments=arguments))
            ],
        ),
        usage=Usage(input_tokens=10, output_tokens=5),
        raw_hash="a" * 64,
    )


def loop(tmp_path, script, upstream=None, **budget):
    cfg = AgentConfig(
        config_id="local-a",
        base_url="http://127.0.0.1:11434/v1",
        model="fake",
        model_file_sha256="a" * 64,
        budgets=AgentBudgets(**budget),
    )
    proxy = HarnessProxy(
        run_id="r_" + "1" * 16,
        binary_sha256="a" * 64,
        source_id="agent:local-a",
        upstream=upstream or Upstream(),
        trajectory=tmp_path / "trajectory.jsonl",
        guard=PrivateGuard(None),
        budgets=cfg.budgets,
    )
    sleeps = []
    runner = AgentLoop(cfg, FakeProvider(script), proxy, [], sleep=sleeps.append)
    return runner, sleeps


def test_finish_and_exhaustion_final_turn(tmp_path):
    runner, _ = loop(tmp_path, [response("decompile_function"), response()], re_tool_calls=1)
    result = runner.run([Message(role="system", content="fixture")])
    assert result.status == "budget_exhausted" and result.reason == "re_tool_calls"
    assert runner.proxy.finished
    assert runner.messages[-3].role == "user"
    assert runner.messages[-3].content == "budget exhausted, call finish"
    other, _ = loop(tmp_path / "other", [response()])
    assert other.run([]).status == "completed"


def test_provider_retry_delays_and_unavailability(tmp_path):
    runner, sleeps = loop(
        tmp_path, [ProviderUnavailable("5xx"), ProviderUnavailable("timeout"), response()]
    )
    assert runner.run([]).status == "completed" and sleeps == [5, 20]
    failed, sleeps = loop(tmp_path / "failed", [ProviderUnavailable("timeout")] * 3)
    result = failed.run([])
    assert result.status == "failed" and result.reason == "provider_unavailable"
    assert sleeps == [5, 20]


def test_three_malformed_calls_fail_and_valid_calls_reset_streak(tmp_path):
    malformed = response("report_claim", "not JSON")
    runner, _ = loop(
        tmp_path,
        [malformed, malformed, response("decompile_function"), malformed, malformed, malformed],
    )
    result = runner.run([])
    assert result.status == "failed" and result.reason == "model_protocol"
    assert result.malformed_calls == 5


def test_upstream_restarts_once_and_second_crash_fails(tmp_path):
    upstream = Upstream(crashes=2)
    runner, _ = loop(
        tmp_path, [response("decompile_function"), response("decompile_function")], upstream
    )
    result = runner.run([])
    assert result.status == "failed" and result.reason == "ghidra_crash"
    assert result.upstream_restarts == 1 and upstream.starts == 1


def test_prompt_is_frozen_appendix_with_public_inputs_only():
    from aletheia.agent.loop import build_messages
    from aletheia.schema.models import Targets

    messages, digest, context_hash = build_messages(
        Path("prompts/agent-v1.md"),
        Targets(binary_sha256="a" * 64, variant_id="baseline", targets=[]),
    )
    assert len(digest) == 64 and messages[0].role == "system" and messages[1].role == "user"
    assert "Algorithm registry" in messages[0].content
    assert "{taxonomy}" not in messages[0].content
    assert 'binary_name is "input"' in messages[1].content
    import hashlib

    assert hashlib.sha256(messages[1].content.encode()).hexdigest() == context_hash


def test_missing_claim_field_is_reported_without_echoing_input(tmp_path):
    runner, _ = loop(tmp_path, [])
    output = runner.proxy.call("report_claim", {"rationale": "private marker"})
    assert output["reason"] == "invalid_claim"
    assert "type: missing" in output["message"]
    assert "private marker" not in output["message"]


def test_permanent_provider_failure_stops_without_retry_or_malformed_count(tmp_path):
    from aletheia.llm.provider import ProviderRejected

    runner, sleeps = loop(tmp_path, [ProviderRejected("model_pin_mismatch")])
    result = runner.run([])
    assert result.reason == "model_pin_mismatch" and result.provider_requests == 1
    assert result.malformed_calls == 0 and sleeps == []

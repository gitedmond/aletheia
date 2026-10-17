"""Agent wall cap permits exactly the documented final finish request."""

from aletheia.agent.loop import AgentLoop
from aletheia.agent.proxy import HarnessProxy
from aletheia.heldout.guard import PrivateGuard
from aletheia.llm.provider import (
    AgentBudgets,
    AgentConfig,
    ChatResponse,
    FakeProvider,
    FunctionCall,
    Message,
    ToolCall,
    Usage,
)


def test_wall_cap_returns_budget_state_with_one_final_request(tmp_path):
    config = AgentConfig(
        config_id="local-a",
        base_url="http://127.0.0.1:11434/v1",
        model="fake",
        model_file_sha256="a" * 64,
        budgets=AgentBudgets(wall_minutes=1),
    )

    class Upstream:
        def call(self, *args):
            raise AssertionError("No RE call expected")

    proxy = HarnessProxy(
        run_id="r_" + "7" * 16,
        binary_sha256="a" * 64,
        source_id="agent:local-a",
        upstream=Upstream(),
        trajectory=tmp_path / "trajectory.jsonl",
        guard=PrivateGuard(None),
        budgets=config.budgets,
    )
    finish = ChatResponse(
        message=Message(
            role="assistant",
            tool_calls=[
                ToolCall(id="finish", function=FunctionCall(name="finish", arguments="{}"))
            ],
        ),
        usage=Usage(input_tokens=1, output_tokens=1),
        raw_hash="a" * 64,
    )
    clock = iter([0.0, 61.0])
    loop = AgentLoop(config, FakeProvider([finish]), proxy, [], clock=lambda: next(clock))
    result = loop.run([])
    assert result.status == "budget_exhausted" and result.reason == "wall_time"
    assert result.provider_requests == 1 and proxy.finished

"""Bounded claim-source conversation; no verifier or private truth access."""

import hashlib
import time
from collections.abc import Callable
from pathlib import Path
from typing import Literal

from pydantic import Field, JsonValue, TypeAdapter

from aletheia.agent.proxy import HarnessProxy
from aletheia.llm.provider import (
    AgentConfig,
    ChatRequest,
    Message,
    Provider,
    ProviderRejected,
    ProviderUnavailable,
    ToolSpec,
)
from aletheia.schema.canonical import canonical_bytes
from aletheia.schema.models import Strict, Targets
from aletheia.schema.taxonomy import Taxonomy


def build_messages(prompt: Path, targets: Targets) -> tuple[list[Message], str, str]:
    if any(p.is_symlink() for p in (prompt, *prompt.parents)):
        raise ValueError("agent prompt cannot be a symlink")
    raw = prompt.read_bytes()
    algorithms = (Path(__file__).parents[2] / "algorithms.yaml").read_bytes().decode()
    content = raw.decode()
    for key, value in {
        "targets": canonical_bytes(targets).decode(),
        "algorithms": algorithms,
        "taxonomy": canonical_bytes(Taxonomy.bundled()).decode(),
    }.items():
        content = content.replace("{" + key + "}", value)
    context = (Path(__file__).parents[2] / "prompts/context-v1.md").read_bytes()
    return (
        [
            Message(role="system", content=content),
            Message(role="user", content=context.decode()),
        ],
        hashlib.sha256(raw).hexdigest(),
        hashlib.sha256(context).hexdigest(),
    )


class AgentResult(Strict):
    status: Literal["completed", "failed", "budget_exhausted"]
    reason: str | None = None
    input_tokens: int = Field(ge=0)
    output_tokens: int = Field(ge=0)
    malformed_calls: int = Field(ge=0)
    upstream_restarts: int = Field(ge=0)
    provider_requests: int = Field(ge=0)


class AgentLoop:
    def __init__(
        self,
        config: AgentConfig,
        provider: Provider,
        proxy: HarnessProxy,
        tools: list[ToolSpec],
        *,
        seed: int = 20261013,
        sleep: Callable[[float], None] = time.sleep,
        clock: Callable[[], float] = time.monotonic,
    ):
        self.config, self.provider, self.proxy = config.model_copy(deep=True), provider, proxy
        allowed = set(proxy.allowlist.tools)
        self.tools = (
            sorted(
                [tool for tool in tools if tool.function.name in allowed],
                key=lambda tool: tool.function.name,
            )
            + proxy.harness_tools()
        )
        self.seed, self.sleep, self.clock = seed, sleep, clock
        self.messages: list[Message] = []

    def run(self, messages: list[Message]) -> AgentResult:
        self.messages = [message.model_copy(deep=True) for message in messages]
        self.clock_trace: list[float] = []

        def tick() -> float:
            value = self.clock()
            self.clock_trace.append(value)
            return value

        start = tick()
        inputs = outputs = malformed = streak = restarts = requests = 0
        final_turn = False
        exhaustion: str | None = None

        def result(status: Literal["completed", "failed", "budget_exhausted"], reason: str | None):
            return AgentResult(
                status=status,
                reason=reason,
                input_tokens=inputs,
                output_tokens=outputs,
                malformed_calls=malformed,
                upstream_restarts=restarts,
                provider_requests=requests,
            )

        # Current author policy caps hosted spending at zero, before any request.
        if self.config.hosted:
            return result("budget_exhausted", "hosted_cost_cap")
        while not self.proxy.finished:
            if tick() - start >= self.config.budgets.wall_minutes * 60:
                exhaustion = exhaustion or "wall_time"
            elif inputs >= self.config.budgets.input_tokens:
                exhaustion = exhaustion or "input_tokens"
            elif self.proxy.exhausted:
                exhaustion = exhaustion or (
                    "re_tool_calls"
                    if self.proxy.re_calls >= self.config.budgets.re_tool_calls
                    else "harness_tool_calls"
                )
            if exhaustion and not final_turn:
                self.messages.append(Message(role="user", content="budget exhausted, call finish"))
                final_turn = True
            request = ChatRequest(
                model=self.config.model,
                messages=self.messages,
                tools=self.tools,
                temperature=self.config.temperature,
                seed=self.seed if self.config.seed_supported else None,
                max_output_tokens=self.config.max_output_tokens,
                reasoning_effort=self.config.reasoning_effort,
            )
            response = None
            for attempt in range(3):
                try:
                    requests += 1
                    response = self.provider.send(request)
                    break
                except ProviderRejected as exc:
                    return result("failed", exc.reason)
                except ProviderUnavailable:
                    if attempt == 2:
                        return result("failed", "provider_unavailable")
                    self.sleep([5, 20][attempt])
                except ValueError:
                    malformed += 1
                    streak += 1
                    self.messages.append(
                        Message(
                            role="user", content="Malformed response; use the advertised tools."
                        )
                    )
                    break
            if response is None:
                if streak >= 3:
                    return result("failed", "model_protocol")
                if final_turn:
                    return result("budget_exhausted", exhaustion)
                continue
            inputs += response.usage.input_tokens
            outputs += response.usage.output_tokens
            self.messages.append(response.message)
            calls = response.message.tool_calls
            if not calls:
                streak += 1
                malformed += 1
                self.messages.append(
                    Message(role="user", content="Use report_claim, revise_claim or finish.")
                )
            ids: set[str] = set()
            for call in calls:
                output: dict[str, JsonValue]
                try:
                    if call.id in ids:
                        raise ValueError("duplicate tool call ID")
                    ids.add(call.id)
                    arguments = TypeAdapter(dict[str, JsonValue]).validate_json(
                        call.function.arguments
                    )
                    output = self.proxy.call(call.function.name, arguments)
                    protocol_error = output.get("reason") in {"invalid_claim", "tool_not_allowed"}
                except ValueError:
                    output = {"status": "error", "reason": "malformed_tool_call"}
                    protocol_error = True
                self.messages.append(
                    Message(
                        role="tool", tool_call_id=call.id, content=canonical_bytes(output).decode()
                    )
                )
                if protocol_error:
                    malformed += 1
                    streak += 1
                else:
                    streak = 0
                if output.get("reason") == "ghidra_crash":
                    if restarts:
                        return result("failed", "ghidra_crash")
                    restarts += 1
                    restart = getattr(self.proxy.upstream, "start", None)
                    if not callable(restart):
                        return result("failed", "ghidra_crash")
                    try:
                        restart()
                    except (RuntimeError, ValueError, OSError, TimeoutError):
                        return result("failed", "ghidra_crash")
                if streak >= 3:
                    return result("failed", "model_protocol")
            if streak >= 3:
                return result("failed", "model_protocol")
            if final_turn:
                return result("budget_exhausted", exhaustion)
        return result("budget_exhausted" if exhaustion else "completed", exhaustion)

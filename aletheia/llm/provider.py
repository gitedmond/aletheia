"""Strict chat-completion boundary, recorded fake and immutable response cache."""

import hashlib
import json
import os
from pathlib import Path
from typing import Any, Literal, Protocol
from urllib.error import HTTPError, URLError
from urllib.parse import urlsplit
from urllib.request import HTTPRedirectHandler, Request, build_opener

from pydantic import Field, JsonValue, model_validator

from aletheia.analysis.ghidra_session import publish_immutable
from aletheia.heldout.guard import PrivateGuard
from aletheia.schema.canonical import canonical_bytes, content_hash
from aletheia.schema.models import Sha256, Strict


class FunctionCall(Strict):
    name: str = Field(min_length=1)
    arguments: str


class ToolCall(Strict):
    id: str = Field(min_length=1)
    type: Literal["function"] = "function"
    function: FunctionCall


class Message(Strict):
    role: Literal["system", "user", "assistant", "tool"]
    content: str | None = None
    tool_calls: list[ToolCall] = Field(default_factory=list[ToolCall])
    tool_call_id: str | None = None


class ToolFunction(Strict):
    name: str = Field(min_length=1)
    description: str
    parameters: dict[str, JsonValue]


class ToolSpec(Strict):
    type: Literal["function"] = "function"
    function: ToolFunction


class ChatRequest(Strict):
    model: str = Field(min_length=1)
    messages: list[Message]
    tools: list[ToolSpec] = Field(default_factory=list[ToolSpec])
    temperature: float | None = None
    seed: int | None = None
    max_output_tokens: int = Field(default=2048, gt=0)


class Usage(Strict):
    input_tokens: int = Field(ge=0)
    output_tokens: int = Field(ge=0)


class ChatResponse(Strict):
    message: Message
    usage: Usage
    provider_request_id: str | None = None
    raw_hash: Sha256


class AgentBudgets(Strict):
    re_tool_calls: int = Field(default=150, ge=0)
    harness_tool_calls: int = Field(default=200, ge=0)
    input_tokens: int = Field(default=2_000_000, gt=0)
    wall_minutes: int = Field(default=30, gt=0, le=30)


class Price(Strict):
    input_per_mtok: float = Field(default=0.0, ge=0, allow_inf_nan=False)
    output_per_mtok: float = Field(default=0.0, ge=0, allow_inf_nan=False)


class AgentConfig(Strict):
    config_id: str = Field(pattern=r"^[a-z][a-z0-9-]*$")
    provider: Literal["openai-compatible"] = "openai-compatible"
    base_url: str
    api_key_env: str | None = Field(default=None, pattern=r"^[A-Za-z_][A-Za-z0-9_]*$")
    model: str = Field(min_length=1)
    model_file_sha256: Sha256 | None = None
    hosted: bool = False
    retention_setting: str = "local"
    prompt: str = "prompts/agent-v1.md"
    temperature: float | None = 0.0
    seed_supported: bool = True
    max_output_tokens: int = Field(default=2048, gt=0)
    budgets: AgentBudgets = Field(default_factory=AgentBudgets)
    price: Price = Field(default_factory=Price)

    @model_validator(mode="after")
    def endpoint(self):
        url = urlsplit(self.base_url)
        if url.username or url.password or url.query or url.fragment:
            raise ValueError("provider URL cannot contain credentials, query or fragment")
        if self.hosted:
            if url.scheme != "https" or not url.hostname or self.retention_setting == "local":
                raise ValueError("hosted provider requires HTTPS and recorded retention")
        elif (
            url.scheme != "http"
            or url.hostname not in {"127.0.0.1", "localhost", "::1"}
            or self.model_file_sha256 is None
            or self.retention_setting != "local"
            or self.price.input_per_mtok != 0
            or self.price.output_per_mtok != 0
        ):
            raise ValueError("local provider requires loopback, pinned weights and zero price")
        return self


class Provider(Protocol):
    id: str

    def send(self, req: ChatRequest) -> ChatResponse: ...


class ProviderUnavailable(RuntimeError):
    """Only retryable transport failures, without credentials or response content."""


class FakeProvider:
    id = "fake"

    def __init__(self, script: list[ChatResponse | Exception]):
        self.script = iter(script)
        self.calls = 0

    def send(self, req: ChatRequest) -> ChatResponse:
        self.calls += 1
        try:
            item = next(self.script)
        except StopIteration as exc:
            raise ValueError("fake script exhausted") from exc
        if isinstance(item, Exception):
            raise item
        return item.model_copy(deep=True)


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(
        self, req: Request, fp: Any, code: int, msg: str, headers: Any, newurl: str
    ) -> None:
        raise ValueError("provider_redirect")


class OpenAICompatibleProvider:
    id = "openai-compatible"

    def __init__(self, config: AgentConfig):
        self.config = config

    def payload(self, req: ChatRequest) -> dict[str, JsonValue]:
        if req.model != self.config.model:
            raise ValueError("provider model identity mismatch")
        data: dict[str, JsonValue] = {
            "model": req.model,
            "messages": [
                {
                    k: v
                    for k, v in message.model_dump(mode="json").items()
                    if v is not None and v != []
                }
                for message in req.messages
            ],
            "max_tokens": req.max_output_tokens,
            "stream": False,
        }
        if req.tools:
            data["tools"] = [tool.model_dump(mode="json") for tool in req.tools]
        if req.temperature is not None:
            data["temperature"] = req.temperature
        if req.seed is not None and self.config.seed_supported:
            data["seed"] = req.seed
        return data

    @staticmethod
    def parse(raw: bytes) -> ChatResponse:
        try:
            data = json.loads(raw)
            message = data["choices"][0]["message"]
            # Some compatible servers include informational assistant fields.
            message = {key: message[key] for key in Message.model_fields if key in message}
            if isinstance(message.get("tool_calls"), list):
                message["tool_calls"] = [
                    {key: value for key, value in call.items() if key != "index"}
                    for call in message["tool_calls"]
                ]
            result = ChatResponse(
                message=Message.model_validate(message),
                usage=Usage(
                    input_tokens=data["usage"]["prompt_tokens"],
                    output_tokens=data["usage"]["completion_tokens"],
                ),
                provider_request_id=data.get("id"),
                raw_hash=hashlib.sha256(raw).hexdigest(),
            )
            if result.message.role != "assistant":
                raise ValueError("unexpected response role")
            return result
        except (ValueError, TypeError, KeyError, IndexError) as exc:
            raise ValueError("malformed provider response") from exc

    def send(self, req: ChatRequest) -> ChatResponse:
        if self.config.hosted:
            raise ValueError("budget_exhausted: hosted calls disabled by the Phase 1B zero cap")
        headers = {"Content-Type": "application/json"}
        if self.config.api_key_env:
            headers["Authorization"] = "Bearer " + os.environ[self.config.api_key_env]
        request = Request(
            self.config.base_url.rstrip("/") + "/chat/completions",
            data=canonical_bytes(self.payload(req)),
            headers=headers,
            method="POST",
        )
        try:
            with build_opener(NoRedirect).open(request, timeout=120) as response:
                raw = response.read(32 * 1024 * 1024 + 1)
        except HTTPError as exc:
            if exc.code >= 500:
                raise ProviderUnavailable(f"provider HTTP {exc.code}") from None
            raise ValueError(f"provider HTTP {exc.code}") from None
        except (URLError, TimeoutError) as exc:
            raise ProviderUnavailable("provider transport unavailable") from exc
        if len(raw) > 32 * 1024 * 1024:
            raise ValueError("provider response too large")
        return self.parse(raw)


class CachedProvider:
    """Cache snapshots are split-scoped by their caller's private guard."""

    id = "cached"

    def __init__(
        self,
        config: AgentConfig,
        provider: Provider,
        root: Path,
        guard: PrivateGuard,
        *,
        replay: bool = False,
    ):
        self.config, self.provider, self.replay = config, provider, replay
        self.root = (
            guard.private_output(root) if guard.split == "heldout" else guard.public_path(root)
        )
        self.root.mkdir(parents=True, exist_ok=True)

    def send(self, req: ChatRequest) -> ChatResponse:
        key = content_hash(
            {"config": self.config.model_dump(mode="json"), "request": req.model_dump(mode="json")}
        )
        path = self.root / (key + ".json")
        if path.is_symlink():
            raise ValueError("response cache cannot be a symlink")
        if path.exists():
            return ChatResponse.model_validate_json(path.read_bytes())
        if self.replay:
            raise ValueError("provider_cache_miss")
        response = self.provider.send(req)
        publish_immutable(path, canonical_bytes(response))
        return response

"""Recorded responses exercise the provider boundary without network or spending."""

import hashlib
import json

import pytest

from aletheia.heldout.guard import PrivateGuard
from aletheia.llm.cost import CostGuard, ExposureLog
from aletheia.llm.provider import (
    AgentConfig,
    CachedProvider,
    ChatRequest,
    ChatResponse,
    FakeProvider,
    Message,
    OpenAICompatibleProvider,
    ProviderUnavailable,
    Usage,
)


def config(**changes):
    return AgentConfig.model_validate(
        {
            "config_id": "local-a",
            "base_url": "http://127.0.0.1:11434/v1",
            "model": "fixture",
            "model_file_sha256": "a" * 64,
            **changes,
        }
    )


def request():
    return ChatRequest(model="fixture", messages=[Message(role="user", content="hello")])


def response():
    return ChatResponse(
        message=Message(role="assistant", content="done"),
        usage=Usage(input_tokens=10, output_tokens=2),
        raw_hash="b" * 64,
    )


def test_response_cache_is_config_scoped_and_replay_never_calls_provider(tmp_path):
    fake = FakeProvider([response()])
    cached = CachedProvider(config(), fake, tmp_path, PrivateGuard(None))
    assert cached.send(request()) == response()
    assert cached.send(request()) == response() and fake.calls == 1
    replay = CachedProvider(config(), FakeProvider([]), tmp_path, PrivateGuard(None), replay=True)
    assert replay.send(request()) == response()
    other = CachedProvider(
        config(config_id="local-b"), FakeProvider([]), tmp_path, PrivateGuard(None), replay=True
    )
    with pytest.raises(ValueError, match="cache_miss"):
        other.send(request())


def test_compatible_payload_tools_and_usage_are_preserved():
    req = request().model_copy(update={"temperature": 0.0, "seed": 7})
    payload = OpenAICompatibleProvider(config()).payload(req)
    assert payload["seed"] == 7 and payload["temperature"] == 0
    raw = json.dumps(
        {
            "id": "request-1",
            "choices": [
                {
                    "message": {
                        "role": "assistant",
                        "content": None,
                        "tool_calls": [
                            {
                                "id": "tool-1",
                                "type": "function",
                                "function": {"name": "finish", "arguments": "{}"},
                            }
                        ],
                    }
                }
            ],
            "usage": {"prompt_tokens": 12, "completion_tokens": 3},
        }
    ).encode()
    parsed = OpenAICompatibleProvider.parse(raw)
    assert parsed.usage == Usage(input_tokens=12, output_tokens=3)
    assert parsed.message.tool_calls[0].function.name == "finish"
    assert parsed.raw_hash == hashlib.sha256(raw).hexdigest()
    with pytest.raises(ValueError, match="provider response"):
        OpenAICompatibleProvider.parse(b"{}")
    with pytest.raises(ValueError, match="local provider"):
        config(base_url="https://example.com/v1")
    with pytest.raises(ProviderUnavailable):
        FakeProvider([ProviderUnavailable("timeout")]).send(request())


def test_cost_guard_requires_three_dev_pilots_and_refuses_projected_overrun(tmp_path):
    guard = CostGuard(tmp_path / "cost.jsonl", cap_usd=0.0)
    hosted = config(
        hosted=True,
        model_file_sha256=None,
        base_url="https://example.com/v1",
        retention_setting="recorded-policy",
        price={"input_per_mtok": 1.0},
    )
    with pytest.raises(ValueError, match="budget_exhausted"):
        guard.authorize(hosted, pilot=True)
    paid = CostGuard(tmp_path / "paid.jsonl", cap_usd=10.0)
    with pytest.raises(ValueError, match="three dev pilots"):
        paid.project(hosted, [1.0, 1.0], 4)
    pilots = ["r_" + f"{i:016x}" for i in range(3)]
    for run in pilots:
        paid.record(hosted, Usage(input_tokens=1_000_000, output_tokens=0), run)
    assert paid.project(hosted, pilots, 4)
    assert not paid.project(hosted, pilots, 100)
    with pytest.raises(ValueError, match="projection"):
        paid.authorize(hosted)
    assert paid.project(hosted, pilots, 4)
    paid.record(hosted, Usage(input_tokens=8_000_000, output_tokens=0), "r_" + "1" * 16)
    assert not paid.project(hosted, pilots, 4)
    assert not guard.authorize(config())  # Local calls consume no hosted budget.
    assert json.loads((tmp_path / "paid.jsonl").read_text().splitlines()[-1])["allowed"] is False


def test_exposure_lines_only_for_hosted_heldout_and_limit_is_per_binary(tmp_path):
    private = tmp_path / "private"
    private.mkdir(mode=0o700)
    log = ExposureLog(PrivateGuard(private, "heldout"))
    digest = "c" * 64
    assert log.record(config(), digest, "r_" + "1" * 16, split="heldout") == 0
    hosted = config(
        hosted=True,
        model_file_sha256=None,
        base_url="https://example.com/v1",
        retention_setting="recorded-policy",
    )
    assert log.record(hosted, digest, "r_" + "1" * 16, split="dev") == 0
    for i in range(30):
        count = log.record(hosted, digest, "r_" + f"{i:016x}", split="heldout")
    assert count == 30 and log.count(digest) == 30
    assert log.record(hosted, digest, "r_" + f"{29:016x}", split="heldout") == 30
    with pytest.raises(ValueError, match="exposure_limit"):
        log.record(hosted, digest, "r_" + f"{30:016x}", split="heldout")
    assert log.count("d" * 64) == 0
    assert log.warning(digest)

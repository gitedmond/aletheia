"""Windows loopback bridge boundary without a runtime or network."""

import json
import subprocess

import pytest

from aletheia.llm.provider import AgentConfig, ChatRequest, Message, ProviderUnavailable
from aletheia.llm.windows_loopback import WindowsLoopbackProvider


def test_bridge_encodes_request_as_data_and_preserves_compatible_settings(monkeypatch):
    config = AgentConfig(
        config_id="local-a",
        base_url="http://127.0.0.1:11434/v1",
        model="fixture",
        model_file_sha256="a" * 64,
    )
    provider = WindowsLoopbackProvider(config)
    request = ChatRequest(
        model="fixture",
        messages=[Message(role="user", content="$(must not execute)")],
        reasoning_effort="none",
    )

    def run(argv, **kwargs):
        assert argv[0] == "powershell.exe" and "Hidden" in argv
        envelope = json.loads(kwargs["input"])
        assert envelope["request"]["messages"][0]["content"] == "$(must not execute)"
        assert envelope["request"]["reasoning_effort"] == "none"
        assert envelope["model_file_sha256"] == "a" * 64
        raw = {
            "choices": [{"message": {"role": "assistant", "content": "done"}}],
            "usage": {"prompt_tokens": 10, "completion_tokens": 2},
        }
        return subprocess.CompletedProcess(argv, 0, json.dumps(raw).encode(), b"")

    monkeypatch.setattr(subprocess, "run", run)
    assert provider.send(request).message.content == "done"
    config.base_url = "http://localhost:11434/v1"
    with pytest.raises(ValueError, match="fixed local"):
        provider.send(request)


def test_bridge_transport_failure_is_countable_and_does_not_echo_request(monkeypatch):
    config = AgentConfig(
        config_id="local-a",
        base_url="http://127.0.0.1:11434/v1",
        model="fixture",
        model_file_sha256="a" * 64,
    )

    def run(*args, **kwargs):
        raise subprocess.TimeoutExpired("private request marker", 120)

    monkeypatch.setattr(subprocess, "run", run)
    with pytest.raises(ProviderUnavailable, match="local runtime transport unavailable"):
        WindowsLoopbackProvider(config).send(ChatRequest(model="fixture", messages=[]))

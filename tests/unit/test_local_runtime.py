"""Windows loopback bridge boundary without a runtime or network."""

import json
import shutil
import subprocess
from pathlib import Path

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

    monkeypatch.setattr(shutil, "which", lambda name: "/windows/System32/powershell.exe")

    def run(argv, **kwargs):
        assert kwargs.get("cwd") == Path("/windows/System32")
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


@pytest.mark.parametrize(
    "code,reason", [(3, "model_pin_mismatch"), (4, "provider_request_rejected")]
)
def test_permanent_bridge_failures_are_not_retryable(monkeypatch, code, reason):
    from aletheia.llm.provider import ProviderRejected

    config = AgentConfig(
        config_id="local-a",
        base_url="http://127.0.0.1:11434/v1",
        model="fixture",
        model_file_sha256="a" * 64,
    )
    monkeypatch.setattr(
        subprocess, "run", lambda *args, **kwargs: subprocess.CompletedProcess(args, code, b"", b"")
    )
    with pytest.raises(ProviderRejected, match=reason):
        WindowsLoopbackProvider(config).send(ChatRequest(model="fixture", messages=[]))


def test_existing_run_metadata_is_preserved_before_any_provider_call(tmp_path):
    from aletheia.agent.run import collect
    from aletheia.config import Config
    from aletheia.llm.provider import FakeProvider
    from aletheia.schema.models import Targets
    from aletheia.sources.base import BinaryRef

    config = AgentConfig(
        config_id="local-a",
        base_url="http://127.0.0.1:11434/v1",
        model="fixture",
        model_file_sha256="a" * 64,
    )
    root = tmp_path / "run"
    root.mkdir()
    (root / "agent.json").write_text("original")
    fake = FakeProvider([])
    binary = BinaryRef("a" * 64, tmp_path / "stripped" / ("a" * 64 + ".bin"), "fixture")
    targets = Targets(binary_sha256="a" * 64, variant_id="fixture", targets=[])
    with pytest.raises(ValueError, match="run artifacts already exist"):
        collect(Config(), config, fake, binary, targets, "r_" + "1" * 16, root)
    assert (root / "agent.json").read_text() == "original" and fake.calls == 0

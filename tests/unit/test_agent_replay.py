"""Agent cassette replay performs no provider calls and requires cached responses."""

import json
from pathlib import Path

from aletheia.agent.replay import replay_agent
from aletheia.agent.run import collect
from aletheia.config import Config
from aletheia.heldout.guard import PrivateGuard
from aletheia.llm.provider import (
    AgentConfig,
    ChatResponse,
    FakeProvider,
    FunctionCall,
    Message,
    ProviderUnavailable,
    ToolCall,
    Usage,
)
from aletheia.schema.models import Targets
from aletheia.sources.base import BinaryRef


def response(name, arguments):
    return ChatResponse(
        message=Message(
            role="assistant",
            tool_calls=[
                ToolCall(
                    id="call", function=FunctionCall(name=name, arguments=json.dumps(arguments))
                )
            ],
        ),
        usage=Usage(input_tokens=10, output_tokens=2),
        raw_hash="a" * 64,
    )


def test_real_collector_cassette_replays_retry_and_claims_without_provider(tmp_path, monkeypatch):
    import yaml

    from aletheia.llm.provider import ToolFunction, ToolSpec

    class Upstream:
        def __init__(self, *args, **kwargs):
            pass

        def tools(self):
            return [
                ToolSpec(
                    function=ToolFunction(
                        name=name, description="fixture", parameters={"type": "object"}
                    )
                )
                for name in yaml.safe_load(Path("configs/proxy-allowlist.yaml").read_text())[
                    "tools"
                ]
            ]

        def close(self):
            pass

        def call(self, *args):
            raise AssertionError("No native tool needed in this cassette")

    monkeypatch.setattr("aletheia.agent.run.GhidraUpstream", Upstream)
    config = AgentConfig(
        config_id="local-a",
        base_url="http://127.0.0.1:11434/v1",
        model="fake",
        model_file_sha256="a" * 64,
    )
    binary = BinaryRef("a" * 64, tmp_path / "stripped" / ("a" * 64 + ".bin"), "fixture")
    targets = Targets(binary_sha256="a" * 64, variant_id="fixture", targets=["0x00001000"])
    fake = FakeProvider(
        [
            ProviderUnavailable("timeout"),
            response(
                "report_claim",
                {
                    "type": "algorithm_identity",
                    "subject_address": "0x00001000",
                    "body": {"family": "crc32", "variant": None},
                    "confidence": 0.8,
                },
            ),
            response("finish", {}),
        ]
    )
    monkeypatch.setattr("aletheia.agent.loop.time.sleep", lambda _: None)
    root = tmp_path / "original"
    result, claims = collect(Config(), config, fake, binary, targets, "r_" + "4" * 16, root)
    assert result.status == "completed" and len(claims) == 1
    replayed = replay_agent(root, tmp_path / "replayed", PrivateGuard(None))
    assert replayed["status"] == "passed", replayed
    assert replayed["provider_cache_hits"] == 2 and replayed["provider_errors_replayed"] == 1
    assert fake.calls == 3

    next((root / "responses").glob("*.json")).unlink()
    missing = replay_agent(root, tmp_path / "missing-cache", PrivateGuard(None))
    assert missing["status"] == "failed" and missing["provider_cache_misses"] > 0
    assert fake.calls == 3

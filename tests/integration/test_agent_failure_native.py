"""Kill this run's actual upstream container twice; never target another job."""

import json
import subprocess
from pathlib import Path

import pytest

from aletheia.agent.loop import AgentLoop
from aletheia.agent.proxy import HarnessProxy
from aletheia.agent.upstream import GhidraUpstream
from aletheia.config import Config
from aletheia.heldout.guard import PrivateGuard
from aletheia.llm.provider import (
    AgentConfig,
    ChatResponse,
    FakeProvider,
    FunctionCall,
    Message,
    ToolCall,
    Usage,
)
from aletheia.selftest import compile_fixture

pytestmark = pytest.mark.integration


def test_two_actual_upstream_kills_restart_once_then_fail_with_reason(tmp_path):
    cfg = Config.read(Path("aletheia.toml"))
    source = Path("tests/fixtures/static/signature")
    fixture = json.loads((source / "cases.json").read_bytes())
    binary, symbols = compile_fixture(source, cfg, tmp_path, fixture["binary_sha256"])
    upstream = GhidraUpstream(
        cfg.sandbox,
        binary,
        Path(cfg.ghidra.analysis_options),
        tmp_path / "upstream",
        guard=PrivateGuard(None),
    )

    class KillingUpstream:
        kills = 0

        def call(self, name, arguments):
            ids = subprocess.check_output(
                ["docker", "ps", "-q", "--filter", "ancestor=" + cfg.sandbox.image_analysis],
                text=True,
            ).split()
            assert ids
            inspected = json.loads(subprocess.check_output(["docker", "inspect", *ids], text=True))
            own = [
                item["Id"]
                for item in inspected
                if any(
                    mount["Source"] == str(upstream.inputs.resolve()) for mount in item["Mounts"]
                )
            ]
            assert len(own) == 1
            subprocess.run(
                ["docker", "kill", "--signal", "KILL", own[0]], check=True, capture_output=True
            )
            self.kills += 1
            return upstream.call(name, arguments)

        def start(self):
            upstream.start()

    killer = KillingUpstream()
    try:
        agent = AgentConfig(
            config_id="local-a",
            base_url="http://127.0.0.1:11434/v1",
            model="fake",
            model_file_sha256="a" * 64,
        )
        proxy = HarnessProxy(
            run_id="r_" + "7" * 16,
            binary_sha256=binary.binary_sha256,
            source_id="agent:local-a",
            upstream=killer,
            trajectory=tmp_path / "trajectory.jsonl",
            guard=PrivateGuard(None),
            budgets=agent.budgets,
        )
        call = ChatResponse(
            message=Message(
                role="assistant",
                tool_calls=[
                    ToolCall(
                        id="call",
                        function=FunctionCall(
                            name="decompile_function",
                            arguments=json.dumps(
                                {"binary_name": "input", "name": "FUN_" + symbols["sig_ret32"][2:]}
                            ),
                        ),
                    )
                ],
            ),
            usage=Usage(input_tokens=1, output_tokens=1),
            raw_hash="a" * 64,
        )
        loop = AgentLoop(agent, FakeProvider([call, call]), proxy, [], sleep=lambda _: None)
        result = loop.run([])
        assert result.status == "failed" and result.reason == "ghidra_crash"
        assert result.upstream_restarts == 1 and killer.kills == 2
        assert result.provider_requests == 2
    finally:
        upstream.close()

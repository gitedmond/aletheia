"""Pinned native acquisition, selected variant, scoring, dev fit and cache-only replay."""

import json
from pathlib import Path

import pytest

from aletheia.agent.batch import fit_dev, run_agent
from aletheia.agent.replay import replay_agent
from aletheia.config import Config
from aletheia.corpus.build import Variant, build_program
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
from aletheia.orchestrate import Benchmark
from aletheia.replay import replay

pytestmark = pytest.mark.integration


def test_agent_batch_native_verification_fit_and_fresh_replay(tmp_path):
    cfg = Config.read(Path("aletheia.toml"))
    cfg.paths.build = str(tmp_path / "build")
    cfg.paths.runs = str(tmp_path / "runs")
    cfg.paths.artifacts = str(tmp_path / "artifacts")
    for mode in ["hardoff", "hardened"]:
        build_program(
            Path("corpus/tierA/crc32tool"),
            Variant(
                cfg.sandbox.image_build,
                Path(cfg.paths.build),
                hardening=mode,
                ground_truth_version="2.0",
            ),
        )
    variant = Variant(cfg.sandbox.image_build).id
    benchmark = Benchmark(cfg, variant=variant, algorithms_version="2.0")
    _, targets, _ = benchmark.bundle("crc32tool")
    agent = AgentConfig(
        config_id="local-fixture",
        base_url="http://127.0.0.1:11434/v1",
        model="fake",
        model_file_sha256="a" * 64,
    )

    def response(name, args):
        return ChatResponse(
            message=Message(
                role="assistant",
                tool_calls=[
                    ToolCall(
                        id="call", function=FunctionCall(name=name, arguments=json.dumps(args))
                    )
                ],
            ),
            usage=Usage(input_tokens=10, output_tokens=2),
            raw_hash="a" * 64,
        )

    fake = FakeProvider(
        [
            response(
                "report_claim",
                {
                    "type": "algorithm_identity",
                    "subject_address": targets.targets[0],
                    "body": {"family": "crc32", "variant": None},
                    "confidence": 0.8,
                },
            ),
            response("finish", {}),
        ]
    )
    run, result = run_agent(benchmark, agent, fake, "crc32tool", 0)
    assert result.status == "completed" and fake.calls == 2
    fit = fit_dev(benchmark, [run])
    assert fit["input_run_ids"] == [run] and fit["eligible_rows"] == 1
    assert fit_dev(benchmark, [run]) == fit
    assert (
        replay_agent(
            benchmark.directory(run) / "agent", tmp_path / "agent-replay", PrivateGuard(None)
        )["status"]
        == "passed"
    )
    replayed = replay(benchmark, run)
    assert replayed["exit_code"] == 0, replayed
    # Repeated scheduling reuses immutable acquisition and never asks the empty provider.
    assert run_agent(benchmark, agent, FakeProvider([]), "crc32tool", 0)[0] == run

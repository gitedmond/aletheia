"""Real stdio MCP load, sandbox analysis, runtime verdict, evidence and purge."""

import asyncio
import base64
import json
from pathlib import Path

import pytest
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

from aletheia.config import Config
from aletheia.selftest import compile_fixture

pytestmark = pytest.mark.integration


def test_stdio_verifier_uses_real_sandbox_and_returns_signature_evidence(tmp_path):
    cfg = Config.read(Path("aletheia.toml"))
    source = Path("tests/fixtures/static/signature")
    fixture = json.loads((source / "cases.json").read_bytes())
    binary, symbols = compile_fixture(source, cfg, tmp_path, fixture["binary_sha256"])
    config = tmp_path / "mcp.toml"
    config.write_text(
        f'[paths]\nruns = "{tmp_path}/runtime"\n[sandbox]\n'
        f'image_analysis = "{cfg.sandbox.image_analysis}"\n'
        f'image_build = "{cfg.sandbox.image_build}"\n'
    )

    async def scenario():
        params = StdioServerParameters(
            command=str(Path(".venv/bin/alth").resolve()),
            args=["--config", str(config), "serve-mcp"],
        )
        async with stdio_client(params) as (read, write):
            async with ClientSession(read, write) as session:
                await session.initialize()
                listing = await session.list_tools()
                assert sorted(t.name for t in listing.tools) == sorted(
                    [
                        "load_binary",
                        "get_job",
                        "verify_claim",
                        "verify_claims",
                        "get_evidence",
                        "list_supported",
                        "explain_verdict",
                        "purge",
                    ]
                )

                async def call(name, args):
                    result = await session.call_tool(name, args)
                    assert not result.isError, result
                    return json.loads(result.content[0].text)

                loaded = await call(
                    "load_binary",
                    {"bytes_b64": base64.b64encode(binary.stripped.read_bytes()).decode()},
                )
                assert loaded["status"] == "pending"
                for _ in range(1200):
                    job = await call("get_job", {"job_id": loaded["job_id"]})
                    if job["status"] != "pending":
                        break
                    await asyncio.sleep(0.05)
                assert job["job_status"] == "done", job
                claim = {
                    "run_id": "r_" + "4" * 16,
                    "source": {"origin": "human", "source_id": "mcp-client"},
                    "binary_sha256": binary.binary_sha256,
                    "subject": {"address": symbols["sig_ret32"]},
                    "type": "function_signature",
                    "body": fixture["cases"][0]["body"],
                    "confidence": 0.8,
                    "confidence_source": "stated",
                }
                result = await call("verify_claim", {"claim": claim})
                if result["status"] == "pending":
                    for _ in range(1200):
                        job = await call("get_job", {"job_id": result["job_id"]})
                        if job["status"] != "pending":
                            break
                        await asyncio.sleep(0.05)
                    assert job["job_status"] == "done", job
                    result = job["result"]["results"][0]
                assert result["status"] == "ok", result
                verdict = result["verdict"]
                assert verdict["intrinsic_verdict"] == "VERIFIED", verdict
                assert result["calibration"] == "uncalibrated" and "c_adj" not in result
                explained = await call("explain_verdict", {"claim_id": verdict["claim_id"]})
                assert explained["methods"] == verdict["methods_run"]
                assert verdict["evidence"]
                evidence = await call(
                    "get_evidence", {"artifact": verdict["evidence"][0]["artifact"]}
                )
                assert evidence["status"] == "ok", evidence
                assert (await call("purge", {"binary_sha256": binary.binary_sha256}))[
                    "status"
                ] == "ok"
                assert not (tmp_path / "runtime/mcp" / binary.binary_sha256).exists()

    asyncio.run(scenario())

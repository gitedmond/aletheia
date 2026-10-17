"""Real stdio tool discovery and decompilation inside the isolated Ghidra upstream."""

import json
from pathlib import Path

import pytest

from aletheia.agent.proxy import Allowlist
from aletheia.agent.upstream import GhidraUpstream
from aletheia.config import Config
from aletheia.heldout.guard import PrivateGuard
from aletheia.selftest import compile_fixture

pytestmark = pytest.mark.integration


def test_pinned_upstream_exposes_only_expected_read_tools_and_decompiles(tmp_path):
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
    try:
        import yaml

        allowed = Allowlist.model_validate(
            yaml.safe_load(Path("configs/proxy-allowlist.yaml").read_bytes())
        )
        tools = upstream.tools()
        assert sorted(t.function.name for t in tools) == allowed.tools
        result = upstream.call(
            "decompile_function",
            {
                "binary_name": "input",
                "name": "FUN_" + symbols["sig_ret32"][2:],
            },
        )
        assert isinstance(result, dict) and not result.get("isError"), result
        assert "uint" in json.dumps(result) or "int" in json.dumps(result)
    finally:
        upstream.close()

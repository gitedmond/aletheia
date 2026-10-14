import json
from pathlib import Path

import pytest
from pydantic import ValidationError
from typer.testing import CliRunner

from aletheia.cli import app
from aletheia.config import Config
from aletheia.doctor import diagnose, read_lock


def test_config_defaults_disable_llm():
    config = Config()
    assert config.llm.enabled is False
    assert config.llm.cost_cap_usd == 0
    assert config.sandbox.concurrency == 4


@pytest.mark.parametrize(
    "data",
    [
        {"extra": 1},
        {"sandbox": {"concurrency": 0}},
        {"llm": {"enabled": True}},
        {"llm": {"cost_cap_usd": 1}},
    ],
)
def test_invalid_config_is_rejected(data):
    with pytest.raises(ValidationError):
        Config.model_validate(data)


def test_lock_requires_exactly_one_toml_block(tmp_path: Path):
    path = tmp_path / "versions.lock.md"
    path.write_text("# No lock")
    with pytest.raises(ValueError):
        read_lock(path)


def test_doctor_missing_config_is_explicit(tmp_path: Path):
    result = CliRunner().invoke(app, ["--config", str(tmp_path / "missing"), "--json", "doctor"])
    assert result.exit_code == 2
    assert '"status":"error"' in result.output
    assert "config" in result.output


@pytest.mark.parametrize("version,status", [("29.1.3", "ok"), ("28.4.0", "error")])
def test_doctor_reports_docker_pin_mismatch(monkeypatch, version, status):
    def command(args):
        if args[:2] == ["docker", "version"]:
            return json.dumps({"Server": {"Version": version}})
        if args == ["uv", "--version"]:
            return "uv 0.13.0"
        if args[:3] == ["docker", "image", "inspect"]:
            return args[3]
        raise AssertionError(args)

    monkeypatch.setattr("aletheia.doctor.command", command)
    checks = diagnose(Path("aletheia.toml"))["checks"]
    docker = next(check for check in checks if check["name"] == "docker")
    assert docker["status"] == status
    assert version in docker["detail"]
    if status == "error":
        assert "expected 29.1.3" in docker["detail"]

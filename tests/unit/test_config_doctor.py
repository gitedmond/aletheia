from pathlib import Path

import pytest
from pydantic import ValidationError
from typer.testing import CliRunner

from aletheia.cli import app
from aletheia.config import Config
from aletheia.doctor import read_lock


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

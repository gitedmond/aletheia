from importlib.metadata import entry_points

from typer.testing import CliRunner

from aletheia.cli import app


def test_help():
    result = CliRunner().invoke(app, ["--help"])
    assert result.exit_code == 0
    assert "--config" in result.output
    assert "--json" in result.output


def test_aliases_target_the_same_entrypoint():
    scripts = {ep.name: ep.value for ep in entry_points(group="console_scripts")}
    assert scripts["alth"] == scripts["aletheia"] == "aletheia.cli:main"

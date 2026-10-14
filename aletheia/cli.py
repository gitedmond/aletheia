"""Phase 1A command-line entry points."""
from dataclasses import dataclass
from pathlib import Path
from typing import Annotated

import typer

app = typer.Typer(no_args_is_help=True, help="Evidence-backed reverse engineering verification.")


@dataclass(frozen=True)
class CliOptions:
    config: Path
    json_output: bool


@app.callback(invoke_without_command=True)
def configure(
    ctx: typer.Context,
    config: Annotated[Path, typer.Option("--config")] = Path("aletheia.toml"),
    json_output: Annotated[bool, typer.Option("--json")] = False,
) -> None:
    """Global options precede the subcommand."""
    ctx.obj = CliOptions(config, json_output)


def options(ctx: typer.Context) -> CliOptions:
    value = ctx.obj
    if not isinstance(value, CliOptions):
        raise RuntimeError("CLI context was not initialized")
    return value


def main() -> None:
    app()


if __name__ == "__main__":
    main()

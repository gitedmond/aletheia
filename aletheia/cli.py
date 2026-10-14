"""Phase 1A command-line entry points."""

import json
from dataclasses import asdict, dataclass
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


@app.command()
def doctor(ctx: typer.Context) -> None:
    """Check configuration, pinned tools, and local Docker images without changing them."""
    from aletheia.doctor import diagnose

    cfg = options(ctx)
    result = diagnose(cfg.config)
    if cfg.json_output:
        typer.echo(json.dumps(result, sort_keys=True, separators=(",", ":")))
    else:
        for check in result["checks"]:
            typer.echo(f"{check['name']}: {check['status']} - {check['detail']}")
    raise typer.Exit(0 if result["status"] == "ok" else 2)


schema_app = typer.Typer(help="Export Phase 1A JSON Schemas.")
app.add_typer(schema_app, name="schema")


@schema_app.command("export")
def schema_export(directory: Path = Path("spec/claims-v1")) -> None:
    from aletheia.schema.export import export_schemas

    export_schemas(directory)
    typer.echo(str(directory))


corpus_app = typer.Typer(help="Lint and prepare the Phase 1A C corpus.")
app.add_typer(corpus_app, name="corpus")


@corpus_app.command("lint")
def corpus_lint(
    ctx: typer.Context,
    directory: Annotated[Path, typer.Argument()] = Path("corpus/tierA"),
    program: Annotated[str | None, typer.Option("--program")] = None,
) -> None:
    """Check a program directory or all programs below a corpus root."""
    from aletheia.corpus.lint import LintError, lint_program

    if program is not None:
        directory = directory / program
    if program is not None or (directory / "src").is_dir():
        programs = [directory] if (directory / "src").is_dir() else []
    else:
        programs = sorted(p for p in directory.glob("*") if p.is_dir() and (p / "src").is_dir())
    errors = [error for program in programs for error in lint_program(program)]
    if not programs:
        errors = [LintError(str(directory), 0, "program_missing", "no corpus programs found")]
    if options(ctx).json_output:
        typer.echo(
            json.dumps(
                {"programs": len(programs), "errors": [asdict(e) for e in errors]},
                sort_keys=True,
                separators=(",", ":"),
            )
        )
    else:
        for error in errors:
            typer.echo(f"{error.path}:{error.line}: {error.rule}: {error.message}")
        typer.echo(f"{len(programs)} programs, {len(errors)} errors")
    raise typer.Exit(1 if errors else 0)


def main() -> None:
    app()


if __name__ == "__main__":
    main()

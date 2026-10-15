"""Phase 1A command-line entry points."""

import json
import subprocess
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


@corpus_app.command("build")
def corpus_build(
    ctx: typer.Context,
    directory: Annotated[Path, typer.Argument()] = Path("corpus/tierA"),
    program: Annotated[str | None, typer.Option("--program")] = None,
) -> None:
    """Build reproducible binaries, private truth, public targets and check leakage."""
    from aletheia.config import Config
    from aletheia.corpus.build import BuildError, Variant, build_program

    cfg = options(ctx)
    selected = directory / program if program is not None else directory
    programs = (
        ([selected] if (selected / "src").is_dir() else [])
        if (program is not None or (selected / "src").is_dir())
        else sorted(p for p in selected.iterdir() if (p / "src").is_dir())
        if (selected.is_dir())
        else []
    )
    try:
        if not programs:
            raise BuildError("program_missing: no selected corpus programs")
        config = Config.read(cfg.config)
        variant = Variant(image=config.sandbox.image_build, output_root=Path(config.paths.build))
        built = [build_program(path, variant) for path in programs]
        result = {
            "status": "ok",
            "programs": [
                {
                    "program_id": output.program_id,
                    "binary_sha256": output.binary_sha256,
                    "build_json": str(output.metadata),
                }
                for output in built
            ],
        }
    except (BuildError, OSError, ValueError, subprocess.SubprocessError) as error:
        result = {"status": "error", "error": str(error)}
    typer.echo(json.dumps(result, sort_keys=True) if cfg.json_output else str(result))
    raise typer.Exit(0 if result["status"] == "ok" else 1)


claims_app = typer.Typer(help="Generate deterministic scripted claim scenarios.")
app.add_typer(claims_app, name="claims")


@claims_app.command("scripted")
def claims_scripted(
    ctx: typer.Context,
    program: Annotated[str, typer.Option("--program")],
    manifest: Annotated[Path, typer.Option("--manifest")],
    seed: Annotated[int, typer.Option("--seed")] = 20261013,
) -> None:
    """Generate JSONL case runs using private truth and a complete manifest input."""
    import re

    from aletheia.config import Config
    from aletheia.schema.canonical import canonical_bytes
    from aletheia.schema.models import GroundTruth, ManifestInput
    from aletheia.sources.scripted import generate

    cfg = options(ctx)
    try:
        if re.fullmatch(r"[a-z][a-z0-9-]*", program) is None:
            raise ValueError("invalid program name")
        config = Config.read(cfg.config)
        paths = sorted((Path(config.paths.build) / program).glob("*/private/ground_truth.json"))
        if len(paths) != 1:
            raise ValueError("program requires exactly one built ground-truth variant")
        gt = GroundTruth.model_validate_json(paths[0].read_bytes())
        if gt.program_id != "tierA/" + program:
            raise ValueError("ground-truth program identity mismatch")
        result = generate(gt, ManifestInput.model_validate_json(manifest.read_bytes()), seed)
        destination = Path(config.paths.runs) / "scripted" / program
        files: dict[Path, bytes] = {}
        records: list[dict[str, str]] = []
        for case in result.cases:
            stem = destination / case.manifest.run_id
            claim_path = stem.with_suffix(".jsonl")
            manifest_path = stem.with_suffix(".manifest.json")
            files[manifest_path] = canonical_bytes(case.manifest) + b"\n"
            files[claim_path] = b"".join(
                canonical_bytes(claim.model_dump(mode="json", exclude={"claim_id"})) + b"\n"
                for claim in case.claims
            )
            records.append(
                {
                    "run_id": case.manifest.run_id,
                    "claims_file": str(claim_path),
                    "manifest_file": str(manifest_path),
                }
            )
        for path, payload in files.items():
            if path.exists() and path.read_bytes() != payload:
                raise ValueError(f"preserving different existing output: {path}")
        for path, payload in files.items():
            path.parent.mkdir(parents=True, exist_ok=True)
            try:
                with path.open("xb") as stream:
                    stream.write(payload)
            except FileExistsError:
                if path.read_bytes() != payload:
                    raise ValueError(f"preserving different existing output: {path}") from None
        output = {
            "status": "ok",
            "claims": sum(len(case.claims) for case in result.cases),
            "cases": records,
            "exclusions": result.exclusions,
        }
    except (OSError, ValueError) as error:
        output = {"status": "error", "error": str(error)}
    typer.echo(json.dumps(output, sort_keys=True) if cfg.json_output else str(output))
    raise typer.Exit(0 if output["status"] == "ok" else 1)


@app.command()
def verifiability(
    ctx: typer.Context,
    program: Annotated[str | None, typer.Option("--program")] = None,
) -> None:
    """Show declared E2 coverage for built programs and currently installed packs."""
    import re
    from typing import cast

    from pydantic import JsonValue

    from aletheia.config import Config
    from aletheia.corpus.verifiability import markdown, table
    from aletheia.schema.canonical import canonical_bytes
    from aletheia.schema.models import GroundTruth
    from aletheia.verify.probes.pack import load_pack

    cfg = options(ctx)
    try:
        if program is not None and re.fullmatch(r"[a-z][a-z0-9-]*", program) is None:
            raise ValueError("invalid program name")
        config = Config.read(cfg.config)
        root = Path(config.paths.build)
        paths = sorted(
            (root / program).glob("*/private/ground_truth.json")
            if program
            else root.glob("*/*/private/ground_truth.json")
        )
        if not paths:
            raise ValueError("program_missing: no built ground truth found")
        truths = [GroundTruth.model_validate_json(path.read_bytes()) for path in paths]
        if program and any(gt.program_id != "tierA/" + program for gt in truths):
            raise ValueError("ground-truth program identity mismatch")
        report = table(truths, [load_pack(path) for path in sorted(Path("packs").glob("*.yaml"))])
        typer.echo(
            canonical_bytes(cast(JsonValue, report)).decode()
            if cfg.json_output
            else markdown(report)
        )
    except (OSError, ValueError) as error:
        result = {"status": "error", "error": str(error)}
        typer.echo(json.dumps(result, sort_keys=True) if cfg.json_output else str(result))
        raise typer.Exit(1) from None


def main() -> None:
    app()


if __name__ == "__main__":
    main()

"""Phase 1A command-line entry points."""

import json
import subprocess
from collections.abc import Callable
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Annotated, Any

if TYPE_CHECKING:
    from aletheia.orchestrate import Benchmark

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


@app.command()
def selftest(
    ctx: typer.Context, family: Annotated[str | None, typer.Option("--family")] = None
) -> None:
    """Calibrate references and near misses using production Ghidra arity and sandbox probes."""
    from pydantic import JsonValue

    from aletheia.config import Config
    from aletheia.selftest import run_selftest

    result: dict[str, JsonValue]
    try:
        result = run_selftest(Config.read(options(ctx).config), family)
    except (ValueError, OSError, RuntimeError, subprocess.SubprocessError) as exc:
        result = {"status": "error", "detail": str(exc)}
    if options(ctx).json_output:
        from aletheia.schema.canonical import canonical_bytes

        typer.echo(canonical_bytes(result).decode())
    else:
        typer.echo(json.dumps(result, sort_keys=True))
    raise typer.Exit(0 if result["status"] == "ok" else 1)


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
    manifest: Annotated[Path | None, typer.Option("--manifest")] = None,
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
        if manifest is None:
            from aletheia.orchestrate import Benchmark

            inputs = Benchmark(config).manifest_input(program, "scripted")
        else:
            inputs = ManifestInput.model_validate_json(manifest.read_bytes())
        result = generate(gt, inputs, seed)
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
        if any(
            gt.program_id != "tierA/" + path.parents[2].name
            or gt.variant_id != path.parents[1].name
            for gt, path in zip(truths, paths, strict=True)
        ):
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


def _benchmark_action(ctx: typer.Context, action: "Callable[[Benchmark], Any]") -> None:
    from aletheia.config import Config
    from aletheia.orchestrate import Benchmark
    from aletheia.schema.canonical import canonical_bytes

    try:
        result = action(Benchmark(Config.read(options(ctx).config)))
        typer.echo(canonical_bytes(result).decode())
    except (OSError, ValueError, RuntimeError, KeyError) as error:
        typer.echo(json.dumps({"status": "error", "error": str(error)}, sort_keys=True))
        raise typer.Exit(1) from None


@app.command()
def run(
    ctx: typer.Context,
    source: Annotated[str, typer.Option("--source")],
    program: Annotated[str | None, typer.Option("--program")] = None,
    no_cache: Annotated[bool, typer.Option("--no-cache")] = False,
) -> None:
    """Produce claims, verify every applicable method, and score built programs."""
    if source == "agent":
        typer.echo(json.dumps({"status": "disabled", "reason": "llm.enabled=false"}))
        raise typer.Exit(3)

    def action(benchmark: "Benchmark") -> dict[str, Any]:
        programs = [program] if program is not None else benchmark.programs()
        if not programs:
            raise ValueError("no built programs")
        runs = [
            run
            for selected in programs
            for run in benchmark.run(selected, source, no_cache=no_cache)
        ]
        return {"status": "ok", "runs": runs, "accounting": benchmark.accounting(runs)}

    _benchmark_action(ctx, action)


tools_app = typer.Typer(help="Run pinned tool adapters and ingest their claims.")
app.add_typer(tools_app, name="tools")


@tools_app.command("run")
def tools_run(
    ctx: typer.Context,
    tool: Annotated[str, typer.Option("--tool")],
    program: Annotated[str | None, typer.Option("--program")] = None,
    no_cache: Annotated[bool, typer.Option("--no-cache")] = False,
) -> None:
    def action(benchmark: "Benchmark") -> dict[str, Any]:
        selected = tool.split(",")
        if not selected or set(selected) - {"capa", "findcrypt"}:
            raise ValueError("--tool must select capa,findcrypt")
        programs = [program] if program is not None else benchmark.programs()
        if not programs:
            raise ValueError("no built programs")
        return {
            "status": "ok",
            "runs": [
                run
                for name in sorted(set(selected))
                for current in programs
                for run in benchmark.create(current, name, no_cache=no_cache)
            ],
        }

    _benchmark_action(ctx, action)


@app.command()
def verify(
    ctx: typer.Context,
    run: Annotated[str | None, typer.Option("--run")] = None,
    no_cache: Annotated[bool, typer.Option("--no-cache")] = False,
) -> None:
    """Verify active claims; existing verdicts are preserved unless --no-cache is given."""

    def action(benchmark: "Benchmark") -> dict[str, Any]:
        runs = benchmark.run_ids(run)
        for current in runs:
            benchmark.verify(current, no_cache=no_cache)
        return {"status": "ok", "runs": runs}

    _benchmark_action(ctx, action)


@app.command()
def score(ctx: typer.Context, run: Annotated[str | None, typer.Option("--run")] = None) -> None:
    """Grade verified claims and emit reproducible metrics."""
    _benchmark_action(ctx, lambda benchmark: benchmark.score(benchmark.run_ids(run)))


@claims_app.command("submit")
def claims_submit(
    ctx: typer.Context,
    file: Annotated[Path, typer.Option("--file")],
    source: Annotated[str, typer.Option("--source")],
    manifest: Annotated[Path | None, typer.Option("--manifest")] = None,
) -> None:
    """Ingest JSONL submissions with their complete pinned run manifest."""
    from aletheia.schema.models import Claim, ClaimSubmission, RunManifest

    def action(benchmark: "Benchmark") -> dict[str, Any]:
        value = RunManifest.model_validate_json(
            (manifest or file.with_suffix(".manifest.json")).read_bytes()
        )
        claims = [
            Claim.intake(ClaimSubmission.model_validate_json(line))
            for line in file.read_bytes().splitlines()
        ]
        if value.source_config.get("source_id") != source:
            raise ValueError("manifest source differs from --source")
        program = value.source_config.get("program")
        if not isinstance(program, str):
            raise ValueError("manifest requires a built program")
        run = benchmark.ingest(program, value, claims)
        return {"status": "ok", "run": run, "claims": len(claims)}

    _benchmark_action(ctx, action)


@app.command()
def replay(ctx: typer.Context, run: Annotated[str, typer.Option("--run")]) -> None:
    """Rerun every verifier method, refuse pin drift or missing source-job cache."""
    from aletheia.config import Config
    from aletheia.orchestrate import Benchmark
    from aletheia.replay import replay as replay_run
    from aletheia.schema.canonical import canonical_bytes

    try:
        result = replay_run(Benchmark(Config.read(options(ctx).config)), run)
    except (OSError, ValueError, KeyError) as exc:
        typer.echo(json.dumps({"status": "error", "error": str(exc)}, sort_keys=True))
        raise typer.Exit(1) from None
    typer.echo(canonical_bytes(result).decode())
    raise typer.Exit(result["exit_code"])


@app.command()
def report(
    ctx: typer.Context,
    runs: Annotated[str, typer.Option("--runs")],
    out: Annotated[Path, typer.Option("--out")],
) -> None:
    """Write benchmark metrics, counterexamples, misses and population disclosures."""
    from aletheia.report import collect, render

    def action(benchmark: "Benchmark") -> dict[str, Any]:
        payload = render(collect(benchmark, runs.split(",")))
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(payload)
        return {"status": "ok", "out": str(out), "runs": sorted(set(runs.split(",")))}

    _benchmark_action(ctx, action)


def main() -> None:
    app()


if __name__ == "__main__":
    main()

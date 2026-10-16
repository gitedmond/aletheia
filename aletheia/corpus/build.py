"""Reproducible corpus compilation and LLVM inspection in the build image."""

import fcntl
import hashlib
import json
import os
import re
import shlex
import shutil
import subprocess
import tempfile
import uuid
import warnings
from dataclasses import dataclass
from pathlib import Path
from typing import Literal, cast

from pydantic import JsonValue

from aletheia.corpus.lint import lint_program
from aletheia.doctor import read_lock
from aletheia.schema.canonical import canonical_bytes

ROOT = Path(__file__).resolve().parents[2]
FLAGS = (
    "-std=c17",
    "-O2",
    "-g",
    "-march=x86-64",
    "-mtune=generic",
    "-fPIE",
    "-pie",
    "-fno-stack-protector",
    "-U_FORTIFY_SOURCE",
    "-D_FORTIFY_SOURCE=0",
    "-fcf-protection=none",
    "-fno-ident",
    "-ffile-prefix-map=/corpus=.",
    "-DNDEBUG",
    "-Wl,--build-id=none",
)


class BuildError(ValueError):
    """An explicit build, input, toolchain, inspection or publication failure."""


@dataclass(frozen=True)
class Variant:
    image: str
    output_root: Path = Path("build")
    compiler_major: int = 23
    hardening: Literal["hardoff", "hardened"] = "hardoff"

    def __post_init__(self) -> None:
        if self.hardening not in {"hardoff", "hardened"}:
            raise ValueError("unknown hardening variant")
        if re.fullmatch(r"sha256:[0-9a-f]{64}", self.image) is None:
            raise ValueError("build image must be a full immutable local image ID")
        expected = str(read_lock(ROOT / "versions.lock.md")["pins"]["clang"]["version"])
        if self.compiler_major != int(expected.split(".")[0]):
            raise ValueError("only the pinned compiler major is supported")

    @property
    def id(self) -> str:
        return f"clang{self.compiler_major}-O2-x64-pie-{self.hardening}"

    @property
    def flags(self) -> tuple[str, ...]:
        if self.hardening == "hardoff":
            return FLAGS
        replacements = {
            "-fno-stack-protector": "-fstack-protector-strong",
            "-D_FORTIFY_SOURCE=0": "-D_FORTIFY_SOURCE=2",
            "-fcf-protection=none": "-fcf-protection=full",
        }
        return tuple(replacements.get(flag, flag) for flag in FLAGS)


@dataclass(frozen=True)
class BuildOutput:
    program_id: str
    variant_id: str
    binary_sha256: str
    stripped: Path
    unstripped: Path
    o0: Path
    metadata: Path


def _no_symlinks(path: Path) -> None:
    for component in (path, *path.parents):
        if component.is_symlink():
            raise BuildError(f"symlink is not a build input/output: {component}")


def _snapshot(program: Path, destination: Path) -> dict[str, str]:
    _no_symlinks(program)
    if program.parent.name != "tierA" or re.fullmatch(r"[a-z][a-z0-9-]*", program.name) is None:
        raise BuildError("program must be a named directory below tierA")
    sources = sorted((program / "src").rglob("*.c"))
    if not sources:
        raise BuildError("program_missing: no C sources")
    root = program.parent.parent
    for path in (program / "src").rglob("*"):
        _no_symlinks(path)
        if path.is_file() and path.suffix not in {".c", ".h"}:
            raise BuildError(f"c17_only: unsupported source input: {path}")
    files = sorted(
        set(
            sources
            + list((program / "src").rglob("*.h"))
            + list((root / "include").glob("*.h"))
            + [program / "Makefile"]
            + list((program / "tests").glob("*.c"))
        )
    )
    hashes: dict[str, str] = {}
    for source in files:
        _no_symlinks(source)
        if not source.is_file():
            raise BuildError(f"non-regular source: {source}")
        relative = source.relative_to(root)
        payload = source.read_bytes()
        target = destination / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(payload)
        target.chmod(0o644)
        hashes[relative.as_posix()] = hashlib.sha256(payload).hexdigest()
    errors = lint_program(destination / "tierA" / program.name)
    if errors:
        raise BuildError(
            "source lint failed: " + "; ".join(f"{e.rule}: {e.message}" for e in errors)
        )
    return hashes


def _execute(
    image: str, snapshot: Path, output: Path, program: str, build_flags: tuple[str, ...] = FLAGS
) -> None:
    if os.getuid() == 0:
        raise BuildError("compiler jobs require a non-root task identity")
    sources = [
        p.relative_to(snapshot / "tierA" / program).as_posix()
        for p in sorted((snapshot / "tierA" / program / "src").rglob("*.c"))
    ]
    commands = ["mkdir -p /out/private /out/stripped", "clang --version > /out/compiler.txt"]
    for optimization, name in (("-O2", "unstripped"), ("-O0", "o0")):
        flags = [optimization if flag == "-O2" else flag for flag in build_flags]
        commands.append(
            shlex.join(
                [
                    "clang",
                    *flags,
                    "-I/corpus/include",
                    "-Isrc",
                    *sources,
                    "-o",
                    f"/out/private/{name}.bin",
                ]
            )
        )
    for index, source in enumerate(sources):
        commands.append(
            shlex.join(
                [
                    "clang",
                    *build_flags,
                    "-I/corpus/include",
                    "-Isrc",
                    "-S",
                    "-emit-llvm",
                    source,
                    "-o",
                    f"/out/private/abi-{index:04}.ll",
                ]
            )
        )
    commands.append(
        "llvm-strip --strip-all /out/private/unstripped.bin -o /out/stripped/output.bin"
    )
    commands.append(
        "llvm-readobj --file-headers --sections --elf-output-style=JSON "
        "/out/private/unstripped.bin /out/private/o0.bin /out/stripped/output.bin "
        "> /out/inspection.json"
    )
    name = "aletheia-build-" + uuid.uuid4().hex
    command = [
        "docker",
        "run",
        "--name",
        name,
        "--pull",
        "never",
        "--network",
        "none",
        "--read-only",
        "--user",
        f"{os.getuid()}:{os.getgid()}",
        "--cap-drop",
        "ALL",
        "--security-opt",
        "no-new-privileges",
        "--cpus",
        "2",
        "--memory",
        "1g",
        "--memory-swap",
        "1g",
        "--pids-limit",
        "64",
        "--env",
        "SOURCE_DATE_EPOCH=0",
        "--env",
        "LC_ALL=C.UTF-8",
        "--env",
        "TZ=UTC",
        "--tmpfs",
        "/scratch:rw,nosuid,nodev,noexec,size=256m,mode=1777",
        "--mount",
        f"type=bind,src={snapshot},dst=/corpus,readonly",
        "--mount",
        f"type=bind,src={output},dst=/out",
        "--workdir",
        f"/corpus/tierA/{program}",
        image,
        "sh",
        "-ec",
        "; ".join(commands),
    ]
    failure: BuildError | None = None
    try:
        result = subprocess.run(command, capture_output=True, text=True, timeout=60)
        if result.returncode:
            failure = BuildError("compiler sandbox failed: " + result.stdout + result.stderr)
    except subprocess.TimeoutExpired:
        failure = BuildError("compiler sandbox wall_timeout")
    except OSError as error:
        failure = BuildError(f"compiler sandbox unavailable: {error}")
    finally:
        detail = ""
        try:
            cleanup = subprocess.run(
                ["docker", "rm", "--force", name], capture_output=True, text=True, timeout=15
            )
            if cleanup.returncode and "No such container" not in cleanup.stderr:
                detail = "compiler container cleanup failed: " + cleanup.stderr
        except (OSError, subprocess.TimeoutExpired) as error:
            detail = f"compiler container cleanup failed: {error}"
        if detail:
            failure = BuildError(f"{failure}; {detail}" if failure else detail)
    if failure:
        raise failure


def _inspection(path: Path) -> dict[str, JsonValue]:
    """Parse LLVM's JSON report, never an ELF on the host."""
    reports = cast(list[dict[str, JsonValue]], json.loads(path.read_text()))
    extracted: dict[str, dict[str, JsonValue]] = {}
    for report in reports:
        summary = cast(dict[str, str], report["FileSummary"])
        extracted[summary["File"]] = report
    if set(extracted) != {
        "/out/private/unstripped.bin",
        "/out/private/o0.bin",
        "/out/stripped/output.bin",
    }:
        raise BuildError("invalid LLVM inspection report file set")
    private = extracted["/out/private/unstripped.bin"]
    stripped = extracted["/out/stripped/output.bin"]
    sections = cast(list[dict[str, dict[str, JsonValue]]], stripped["Sections"])
    stripped_names = {cast(dict[str, str], x["Section"]["Name"])["Name"] for x in sections}
    sections = cast(list[dict[str, dict[str, JsonValue]]], private["Sections"])
    private_names = {cast(dict[str, str], x["Section"]["Name"])["Name"] for x in sections}
    header = cast(dict[str, JsonValue], stripped["ElfHeader"])
    machine = cast(dict[str, JsonValue], header["Machine"])
    ident = cast(dict[str, dict[str, JsonValue]], header["Ident"])
    if (
        header["Type"] != "SharedObject (0x3)"
        or machine["Value"] != 62
        or ident["Class"]["Value"] != 2
        or ident["DataEncoding"]["Value"] != 1
    ):
        raise BuildError("emitted binary is not a little-endian x86-64 PIE")
    result: dict[str, JsonValue] = {
        "machine": machine["Name"],
        "type": "SharedObject",
        "stripped_has_symtab": ".symtab" in stripped_names,
        "private_has_debug_info": ".debug_info" in private_names,
    }
    if result != {
        "machine": "EM_X86_64",
        "type": "SharedObject",
        "stripped_has_symtab": False,
        "private_has_debug_info": True,
    }:
        raise BuildError("emitted binary failed ELF/strip/debug inspection")
    return result


def _publish(staging: Path, destination: Path) -> None:
    backup = destination.with_name(".previous-" + uuid.uuid4().hex)
    if destination.exists():
        if not (destination / "build.json").is_file():
            raise BuildError("refusing to replace an unrecognized output directory")
        for path in destination.rglob("*"):
            _no_symlinks(path)
            if path.is_file():
                relative = path.relative_to(destination).as_posix()
                if (
                    relative
                    not in {
                        "build.json",
                        "targets.json",
                        "private/unstripped.bin",
                        "private/o0.bin",
                        "private/ground_truth.json",
                        "private/abi.json",
                    }
                    and re.fullmatch(r"stripped/[0-9a-f]{64}\.bin", relative) is None
                    and re.fullmatch(r"private/abi-[0-9]{4}\.ll", relative) is None
                ):
                    raise BuildError(f"refusing to delete an unknown build output: {relative}")
        os.replace(destination, backup)
    try:
        os.replace(staging, destination)
    except OSError:
        if backup.exists():
            os.replace(backup, destination)
        raise
    if backup.exists():
        try:
            shutil.rmtree(backup)
        except OSError as error:
            warnings.warn(
                f"backup_cleanup_failed: retained superseded bundle {backup}: {error}",
                RuntimeWarning,
                stacklevel=2,
            )


def build_program(program_dir: Path, variant: Variant) -> BuildOutput:
    """Publish a complete bundle only after compilation, inspection and hashing succeed."""
    _no_symlinks(program_dir.absolute())
    program = program_dir.resolve()
    output_root = variant.output_root.absolute()
    _no_symlinks(output_root)
    output_root = output_root.resolve()
    if output_root.is_relative_to(program.parent.parent):
        raise BuildError("output directory cannot be inside source inputs")
    if any(
        output_root.is_relative_to(ROOT / p)
        for p in (
            "tests/golden",
            "tests/fixtures",
            "mappings",
            "configs",
            "aletheia",
        )
    ):
        raise BuildError("output directory is protected")
    output_root.mkdir(parents=True, exist_ok=True)
    destination = output_root / program.name / variant.id
    _no_symlinks(destination)
    destination.parent.mkdir(parents=True, exist_ok=True)
    with (output_root / ".build.lock").open("a") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        with tempfile.TemporaryDirectory(prefix=".build-", dir=output_root) as directory:
            temporary = Path(directory)
            snapshot, output = temporary / "corpus", temporary / "out"
            snapshot.mkdir()
            output.mkdir()
            hashes = _snapshot(program, snapshot)
            _execute(variant.image, snapshot, output, program.name, variant.flags)
            compiler = re.search(r"clang version ([0-9.]+)", (output / "compiler.txt").read_text())
            expected = str(read_lock(ROOT / "versions.lock.md")["pins"]["clang"]["version"])
            if compiler is None or compiler.group(1) != expected:
                raise BuildError("compiler version does not match the lock")
            inspection = _inspection(output / "inspection.json")
            names = {
                "stripped": "stripped/output.bin",
                "unstripped": "private/unstripped.bin",
                "o0": "private/o0.bin",
            }
            binary_hashes: dict[str, str] = {}
            for kind, relative in names.items():
                path = output / relative
                _no_symlinks(path)
                binary_hashes[kind] = hashlib.sha256(path.read_bytes()).hexdigest()
            binary_hash = binary_hashes["stripped"]
            (output / names["stripped"]).rename(output / "stripped" / (binary_hash + ".bin"))
            record: dict[str, JsonValue] = {
                "schema_version": "1.0",
                "program_id": "tierA/" + program.name,
                "variant_id": variant.id,
                "image": variant.image,
                "compiler_version": expected,
                "source_date_epoch": 0,
                "build_flags": list(variant.flags),
                "o0_flags": ["-O0" if x == "-O2" else x for x in variant.flags],
                "include_flags": ["-I/corpus/include", "-Isrc"],
                "source_files": [
                    p.relative_to(snapshot / "tierA" / program.name).as_posix()
                    for p in sorted((snapshot / "tierA" / program.name / "src").rglob("*.c"))
                ],
                "source_hashes": dict(hashes),
                "ir_hashes": {
                    path.relative_to(output).as_posix(): hashlib.sha256(
                        path.read_bytes()
                    ).hexdigest()
                    for path in sorted((output / "private").glob("abi-*.ll"))
                },
                "hashes": dict(binary_hashes),
                "inspection": inspection,
            }
            (output / "build.json").write_bytes(canonical_bytes(record))
            (output / "compiler.txt").unlink()
            (output / "inspection.json").unlink()
            from aletheia.corpus.ground_truth import GroundTruthError, complete_staged_build

            try:
                complete_staged_build(output, variant.image, snapshot, program.name, str(program))
            except GroundTruthError as error:
                raise BuildError(str(error)) from error
            _publish(output, destination)
    return BuildOutput(
        "tierA/" + program.name,
        variant.id,
        binary_hash,
        destination / "stripped" / (binary_hash + ".bin"),
        destination / "private/unstripped.bin",
        destination / "private/o0.bin",
        destination / "build.json",
    )


# Private corpus stages share snapshot/publication policy, never verifier helpers.
snapshot_program = _snapshot
check_no_symlinks = _no_symlinks
publish_bundle = _publish

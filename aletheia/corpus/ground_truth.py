"""Host coordination of private extraction. ELF decoding is sandbox-only."""

import fcntl
import json
import os
import re
import shutil
import subprocess
import tempfile
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import cast

from aletheia.corpus.build import (
    ROOT,
    BuildOutput,
    check_no_symlinks,
    publish_bundle,
    snapshot_program,
)
from aletheia.schema.canonical import canonical_bytes
from aletheia.schema.models import GroundTruth, Targets


class GroundTruthError(ValueError):
    """Explicit private extraction, leakage or sandbox failure."""


@dataclass(frozen=True)
class LeakHit:
    token: str
    kind: str


def _run(image: str, inputs: Path, corpus: Path, output: Path) -> None:
    if re.fullmatch(r"sha256:[0-9a-f]{64}", image) is None:
        raise GroundTruthError("ground truth requires a full immutable image ID")
    if os.getuid() == 0:
        raise GroundTruthError("ground truth jobs require a non-root task identity")
    name = "aletheia-truth-" + uuid.uuid4().hex
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
        "--tmpfs",
        "/scratch:rw,nosuid,nodev,noexec,size=128m,mode=1777",
        "--env",
        "PYTHONDONTWRITEBYTECODE=1",
        "--env",
        "PYTHONPATH=/code",
        "--env",
        "LC_ALL=C.UTF-8",
        "--env",
        "TZ=UTC",
        "--workdir",
        "/scratch",
    ]
    for source, target, readonly in [
        (inputs, "/in", True),
        (corpus, "/corpus", True),
        (output, "/out", False),
        (ROOT / "aletheia", "/code/aletheia", True),
    ]:
        command += [
            "--mount",
            f"type=bind,src={source},dst={target}" + (",readonly" if readonly else ""),
        ]
    command += [
        "--entrypoint",
        "/opt/venv/bin/python",
        image,
        "-B",
        "-m",
        "aletheia.corpus.ground_truth_worker",
    ]
    failure = ""
    try:
        result = subprocess.run(command, capture_output=True, text=True, timeout=60)
        if result.returncode:
            failure = "ground truth sandbox failed: " + result.stdout + result.stderr
    except (OSError, subprocess.TimeoutExpired) as error:
        failure = "ground truth sandbox unavailable or wall_timeout: " + str(error)
    finally:
        try:
            cleanup = subprocess.run(
                ["docker", "rm", "--force", name], capture_output=True, text=True, timeout=15
            )
            if cleanup.returncode and "No such container" not in cleanup.stderr:
                failure += "; cleanup failed: " + cleanup.stderr
        except (OSError, subprocess.TimeoutExpired) as error:
            failure += "; cleanup failed: " + str(error)
    if failure:
        raise GroundTruthError(failure)


def complete_staged_build(
    directory: Path, image: str, corpus: Path, program: str, source_root: str
) -> GroundTruth:
    """Finish a private staged bundle before its atomic publication."""
    with tempfile.TemporaryDirectory(prefix=".extract-", dir=directory.parent) as temp:
        work = Path(temp)
        inputs, output = work / "inputs", work / "output"
        inputs.mkdir()
        output.mkdir()
        shutil.copytree(directory, inputs / "build")
        metadata = json.loads((inputs / "build/build.json").read_bytes())
        (inputs / "request.json").write_text(
            json.dumps({"action": "extract", "program": program, "source_root": source_root})
        )
        _run(image, inputs, corpus, output)
        gt = GroundTruth.model_validate_json((output / "ground_truth.json").read_bytes())
        targets = Targets.model_validate_json((output / "targets.json").read_bytes())
        if (
            gt.binary_sha256 != metadata["hashes"]["stripped"]
            or targets.binary_sha256 != gt.binary_sha256
            or gt.program_id != metadata["program_id"]
            or gt.variant_id != metadata["variant_id"]
            or targets.variant_id != gt.variant_id
            or targets.targets != [f.address for f in gt.functions if f.scorable]
        ):
            raise GroundTruthError("worker output identity or target mismatch")
        if "ir_hashes" in metadata:
            payload = (output / "abi.json").read_bytes()
            abi = json.loads(payload)
            if abi["binary_sha256"] != gt.binary_sha256 or abi["variant_id"] != gt.variant_id:
                raise GroundTruthError("worker ABI output identity mismatch")
            (directory / "private/abi.json").write_bytes(payload)
        (directory / "private/ground_truth.json").write_bytes(canonical_bytes(gt))
        (directory / "targets.json").write_bytes(canonical_bytes(targets))
        return gt


def extract_ground_truth(build: BuildOutput, program_dir: Path) -> GroundTruth:
    """Validate immutable inputs in Docker, then publish truth and targets atomically."""
    destination = build.metadata.parent
    check_no_symlinks(destination)
    if any(
        destination.resolve().is_relative_to(ROOT / p)
        for p in ("tests/golden", "tests/fixtures", "mappings", "configs", "aletheia", "corpus")
    ):
        raise GroundTruthError("ground truth output directory is protected")
    if (
        build.unstripped != destination / "private/unstripped.bin"
        or build.o0 != destination / "private/o0.bin"
        or build.stripped != destination / "stripped" / (build.binary_sha256 + ".bin")
    ):
        raise GroundTruthError("build paths do not match the private bundle")
    with (destination.parent.parent / ".build.lock").open("a") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        with tempfile.TemporaryDirectory(prefix=".truth-", dir=destination.parent) as temp:
            work = Path(temp)
            corpus, bundle = work / "corpus", work / "bundle"
            corpus.mkdir()
            for path in destination.rglob("*"):
                check_no_symlinks(path)
            shutil.copytree(destination, bundle)
            snapshot_program(program_dir.absolute(), corpus)
            metadata = json.loads((bundle / "build.json").read_bytes())
            if (
                metadata["hashes"]["stripped"] != build.binary_sha256
                or metadata["variant_id"] != build.variant_id
                or metadata["program_id"] != build.program_id
            ):
                raise GroundTruthError("build metadata identity mismatch")
            gt = complete_staged_build(
                bundle, metadata["image"], corpus, program_dir.name, str(program_dir.resolve())
            )
            publish_bundle(bundle, destination)
            return gt


def check_leakage(stripped: Path, gt: GroundTruth, program_dir: Path) -> list[LeakHit]:
    """Scan opaque bytes for forbidden labels inside the pinned compiler sandbox."""
    check_no_symlinks(stripped.absolute())
    from aletheia.config import Config

    image = Config.read(ROOT / "aletheia.toml").sandbox.image_build
    with tempfile.TemporaryDirectory(prefix="aletheia-leak-") as temp:
        work = Path(temp)
        inputs, output, corpus = work / "inputs", work / "output", work / "corpus"
        inputs.mkdir()
        output.mkdir()
        corpus.mkdir()
        snapshot_program(program_dir.absolute(), corpus)
        shutil.copyfile(stripped, inputs / "binary.bin")
        (inputs / "ground_truth.json").write_bytes(canonical_bytes(gt))
        (inputs / "request.json").write_text(
            json.dumps(
                {
                    "action": "leakage",
                    "program": program_dir.name,
                    "source_root": str(program_dir.resolve()),
                }
            )
        )
        _run(image, inputs, corpus, output)
        return [
            LeakHit(**record)
            for record in cast(
                list[dict[str, str]], json.loads((output / "leakage.json").read_bytes())
            )
        ]

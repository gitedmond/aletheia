"""WSL validation: one summary, durable logs, and recoverable temporary image bindings."""

import argparse
import base64
import fcntl
import json
import os
import re
import subprocess
import sys
from contextlib import contextmanager
from pathlib import Path


def run_logged(command, repo, path):
    with path.open("w") as log:
        result = subprocess.run(command, cwd=repo, stdout=log, stderr=subprocess.STDOUT)
    lines = path.read_text(errors="replace").splitlines()
    summary = lines[-3:] if result.returncode == 0 else lines[-25:]
    if result.returncode == 0 and len(lines) == 1:
        try:
            record = json.loads(lines[0])
            if isinstance(record, dict) and "status" in record:
                summary = ["status: " + str(record["status"])]
        except ValueError:
            pass
    print(
        json.dumps(
            {
                "command": command,
                "exit_code": result.returncode,
                "log": str(path),
                "summary": [line[:240] for line in summary],
            }
        ),
        flush=True,
    )
    return result.returncode


@contextmanager
def image_bindings(repo, state, images):
    receipt = state / "image-bindings.json"
    if receipt.exists():
        prior = json.loads(receipt.read_bytes())
        if prior["active"]:
            if prior["repo"] != str(repo):
                raise ValueError("Image recovery belongs to another checkout")
            for name, item in prior["files"].items():
                target = repo / name
                original, temporary = (
                    base64.b64decode(item[key]) for key in ("original", "temporary")
                )
                if target.read_bytes() not in (original, temporary):
                    raise ValueError("Preserving unexpected edit: " + str(target))
                target.write_bytes(original)
            prior["active"] = False
            receipt.write_text(json.dumps(prior))
    if not images:
        yield
        return
    resolved = {}
    for kind, ref in images.items():
        digest = subprocess.check_output(
            ["docker", "image", "inspect", ref, "--format", "{{.Id}}"], text=True
        ).strip()
        if re.fullmatch(r"sha256:[0-9a-f]{64}", digest) is None:
            raise ValueError("Image must resolve to an immutable local ID")
        resolved[kind] = digest
    files = {}
    for name in ("aletheia.toml", "versions.lock.md"):
        original = (repo / name).read_bytes()
        text = original.decode()
        for kind, digest in resolved.items():
            key = "image_" + kind if name == "aletheia.toml" else kind
            text, count = re.subn(
                r"^" + key + r' = "[^"]*"', key + ' = "' + digest + '"', text, flags=re.M
            )
            if count != 1:
                raise ValueError("Expected exactly one image binding: " + name + "/" + key)
        files[name] = {
            "original": base64.b64encode(original).decode(),
            "temporary": base64.b64encode(text.encode()).decode(),
        }
    record = {"repo": str(repo), "active": True, "images": resolved, "files": files}
    receipt.write_text(json.dumps(record))
    try:
        for name, item in files.items():
            (repo / name).write_bytes(base64.b64decode(item["temporary"]))
        yield
    finally:
        # Leave the receipt active if any unrelated edit needs manual recovery.
        for name, item in files.items():
            if (repo / name).read_bytes() not in (
                base64.b64decode(item["original"]),
                base64.b64decode(item["temporary"]),
            ):
                raise ValueError("Preserving unexpected edit: " + str(repo / name))
        for name, item in files.items():
            (repo / name).write_bytes(base64.b64decode(item["original"]))
        record["active"] = False
        receipt.write_text(json.dumps(record))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo", type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument(
        "--full",
        action="store_true",
        help="Run doctor and all non-slow tests; default is unit checks",
    )
    parser.add_argument("--analysis-image", default=os.environ.get("ALETHEIA_PC_ANALYSIS_IMAGE"))
    parser.add_argument("--build-image", default=os.environ.get("ALETHEIA_PC_BUILD_IMAGE"))
    parser.add_argument("--log-dir", type=Path)
    parser.add_argument(
        "command",
        nargs=argparse.REMAINDER,
        help="Optional command after -- replaces standard checks",
    )
    args = parser.parse_args()
    if bool(args.analysis_image) != bool(args.build_image):
        parser.error("Supply both image bindings or neither")
    repo = args.repo.resolve()
    if not (repo / "pyproject.toml").is_file():
        parser.error("Not an Aletheia checkout")
    state = (args.log_dir or Path.home() / ".cache/aletheia-checks" / repo.name).resolve()
    state.mkdir(parents=True, exist_ok=True)
    with (state / "checks.lock").open("a") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        images = (
            {"analysis": args.analysis_image, "build": args.build_image}
            if args.analysis_image
            else {}
        )
        with image_bindings(repo, state, images):
            command = args.command[1:] if args.command[:1] == ["--"] else args.command
            commands = (
                [command]
                if command
                else [
                    ["uv", "run", "ruff", "check"],
                    ["uv", "run", "pyright"],
                    *([["uv", "run", "alth", "--json", "doctor"]] if args.full else []),
                    [
                        "uv",
                        "run",
                        "pytest",
                        *(["-m", "not slow"] if args.full else ["tests/unit"]),
                        "-q",
                    ],
                ]
            )
            for index, command in enumerate(commands, 1):
                if code := run_logged(command, repo, state / f"{index:02d}.log"):
                    return code
    print(json.dumps({"status": "passed", "logs": str(state), "image_bindings": "restored"}))
    return 0


if __name__ == "__main__":
    sys.exit(main())

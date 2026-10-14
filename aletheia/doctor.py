"""Read-only diagnostics. Never installs, pulls, or repairs."""

import importlib.metadata
import json
import platform
import re
import subprocess
import tomllib
from pathlib import Path
from typing import Any

from aletheia.config import Config


def read_lock(path: Path) -> dict[str, Any]:
    blocks = re.findall(r"^\x60\x60\x60toml\n(.*?)^\x60\x60\x60", path.read_text(), re.M | re.S)
    if len(blocks) != 1:
        raise ValueError("versions.lock.md requires exactly one TOML block")
    value = tomllib.loads(blocks[0])
    if value.get("lock_version") != 1:
        raise ValueError("unsupported lock version")
    return value


def command(args: list[str]) -> str:
    result = subprocess.run(args, capture_output=True, text=True, timeout=30, check=True)
    return result.stdout.strip()


def diagnose(config_path: Path) -> dict[str, Any]:
    checks: list[dict[str, str]] = []

    def check(name: str, action: Any) -> None:
        try:
            detail = str(action())
            checks.append({"name": name, "status": "ok", "detail": detail})
        except (
            OSError,
            ValueError,
            KeyError,
            TypeError,
            ImportError,
            subprocess.SubprocessError,
        ) as exc:
            checks.append({"name": name, "status": "error", "detail": str(exc)})

    check("config", lambda: Config.read(config_path))
    if checks[-1]["status"] == "error":
        return {"status": "error", "checks": checks}
    cfg = Config.read(config_path)
    root = config_path.resolve().parent
    check("lock", lambda: read_lock(root / "versions.lock.md")["lock_version"])
    if checks[-1]["status"] == "error":
        return {"status": "error", "checks": checks}
    lock = read_lock(root / "versions.lock.md")

    def exact(name: str, actual: str, expected: str) -> str:
        if actual != expected:
            raise ValueError(f"{name}: expected {expected}, got {actual}")
        return actual

    check(
        "python",
        lambda: exact("Python", platform.python_version(), lock["pins"]["python"]["version"]),
    )
    for package in ("pydantic", "typer", "PyYAML", "ruff", "pyright", "pytest"):
        check(
            package,
            lambda package=package: exact(
                package,
                importlib.metadata.version(package),
                lock["packages"][package.lower().replace("_", "-")],
            ),
        )
    check(
        "uv",
        lambda: exact("uv", command(["uv", "--version"]).split()[1], lock["pins"]["uv"]["version"]),
    )
    check(
        "docker",
        lambda: json.loads(command(["docker", "version", "--format", "{{json .}}"]))["Server"][
            "Version"
        ],
    )
    for kind, image in (
        ("build", cfg.sandbox.image_build),
        ("analysis", cfg.sandbox.image_analysis),
    ):

        def image_check(kind: str = kind, image: str = image) -> str:
            if not re.fullmatch(r"sha256:[0-9a-f]{64}", image):
                raise ValueError(f"{kind} image must be a full local sha256 image ID")
            exact(kind, image, lock["images"][kind])
            actual = command(["docker", "image", "inspect", image, "--format", "{{.Id}}"])
            return exact(kind, actual, image)

        check(f"image_{kind}", image_check)
    return {
        "status": "error" if any(c["status"] == "error" for c in checks) else "ok",
        "checks": checks,
    }

"""One containment policy for smoke tests and production jobs."""

import re
from pathlib import Path

from aletheia.config import Sandbox


def container_args(config: Sandbox, inputs: Path, outputs: Path, uid: int, gid: int) -> list[str]:
    if not re.fullmatch(r"sha256:[0-9a-f]{64}", config.image_analysis):
        raise ValueError("analysis image requires an immutable full local ID")
    if uid <= 0 or gid <= 0:
        raise ValueError("sandbox worker must be non-root")
    return [
        "--pull",
        "never",
        "--network",
        "none",
        "--read-only",
        "--user",
        f"{uid}:{gid}",
        "--cap-drop",
        "ALL",
        "--security-opt",
        "no-new-privileges",
        "--cpus",
        "2",
        "--memory",
        f"{config.memory_gb}g",
        "--memory-swap",
        f"{config.memory_gb}g",
        "--pids-limit",
        "256",
        "--tmpfs",
        "/scratch:rw,exec,nosuid,nodev,size=1g,mode=1777",
        "--mount",
        f"type=bind,src={inputs.resolve()},dst=/job/in,readonly",
        "--mount",
        f"type=bind,src={outputs.resolve()},dst=/job/out",
        "--log-driver",
        "local",
        "--log-opt",
        "max-size=10m",
        "--log-opt",
        "max-file=2",
    ]

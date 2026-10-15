"""Require the production mount boundary before any binary handler executes."""

import os
from pathlib import Path


def require_job_sandbox(directory: Path) -> None:
    mounts: dict[str, set[str]] = {}
    for line in Path("/proc/self/mountinfo").read_text().splitlines():
        fields = line.split()
        mounts[fields[4]] = set(fields[5].split(","))
    if (
        directory != Path("/job")
        or os.getuid() <= 0
        or any("ro" not in mounts.get(p, set[str]()) for p in ("/", "/job/in"))
        or "rw" not in mounts.get("/job/out", set[str]())
    ):
        raise ValueError("binary handlers require a non-root read-only-root sandbox")

"""Check staged blobs, including deletions/renames, against a private leakage index."""

import argparse
import hashlib
import json
import re
import shlex
import subprocess
import sys
from pathlib import Path

from aletheia.config import StrictModel
from aletheia.heldout.guard import PrivateAccessError


class LeakageIndex(StrictModel):
    program_ids: list[str]
    function_names: list[str]
    binary_sha256: list[str]


def scan_staged(repo: Path, private_root: Path) -> list[dict[str, str]]:
    try:
        index = LeakageIndex.model_validate_json((private_root / "leakage-index.json").read_bytes())
    except (OSError, ValueError) as exc:
        raise PrivateAccessError("private leakage index is unavailable; commit refused") from exc
    tokens: list[bytes] = []
    for values in (index.program_ids, index.binary_sha256):
        for value in values:
            if not value:
                raise PrivateAccessError("invalid private leakage token; commit refused")
            tokens.append(value.encode())
    functions = sorted(set(index.function_names))
    if any(not re.fullmatch(r"[A-Za-z_]\w*", name) for name in functions):
        raise PrivateAccessError("invalid private function identifier; commit refused")
    alternatives = [re.escape(token) for token in sorted(set(tokens))]
    if functions:
        alternatives.append(
            rb"(?<![A-Za-z0-9_$])(?:"
            + b"|".join(re.escape(name.encode()) for name in functions)
            + rb")(?![A-Za-z0-9_$])"
        )
    pattern = re.compile(b"|".join(alternatives)) if alternatives else None
    # Disabling rename folding exposes both old/deleted and new paths in one pass.
    staged = subprocess.check_output(
        ["git", "-C", str(repo), "diff", "--cached", "--name-status", "--no-renames", "-z"]
    )
    if not staged:
        return []
    fields = staged[:-1].split(b"\0")
    findings: list[dict[str, str]] = []
    for status, raw in zip(fields[::2], fields[1::2], strict=True):
        name = raw.decode("utf-8", errors="surrogateescape")
        blob = (
            subprocess.check_output(["git", "-C", str(repo), "show", ":" + name])
            if status != b"D"
            else None
        )
        if (pattern is not None and pattern.search(raw)) or (
            blob is not None
            and (
                hashlib.sha256(blob).hexdigest() in index.binary_sha256
                or (pattern is not None and pattern.search(blob))
            )
        ):
            findings.append({"path": name, "reason": "heldout_content"})

    return findings


def install(repo: Path, private_root: Path) -> Path:
    scan_staged(repo, private_root)
    raw = subprocess.check_output(
        ["git", "-C", str(repo), "rev-parse", "--git-path", "hooks/pre-commit"], text=True
    ).strip()
    hook = Path(raw)
    if not hook.is_absolute():
        hook = repo / hook
    script = (
        "#!/bin/sh\n# Aletheia held-out leakage guard\nexec "
        + " ".join(
            shlex.quote(arg)
            for arg in [
                sys.executable,
                "-m",
                "aletheia.heldout.hook",
                "--repo",
                str(repo.resolve()),
                "--private-root",
                str(private_root.resolve()),
            ]
        )
        + "\n"
    )
    if hook.is_symlink() or (hook.exists() and hook.read_text() != script):
        raise ValueError("preserving existing pre-commit hook; integrate the guard explicitly")
    hook.parent.mkdir(parents=True, exist_ok=True)
    hook.write_text(script)
    hook.chmod(0o755)
    return hook


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repo", type=Path, required=True)
    parser.add_argument("--private-root", type=Path, required=True)
    args = parser.parse_args()
    try:
        findings = scan_staged(args.repo, args.private_root)
    except PrivateAccessError as exc:
        print(str(exc), file=sys.stderr)
        raise SystemExit(7) from exc
    if findings:
        print(json.dumps({"status": "blocked", "findings": findings}), file=sys.stderr)
        raise SystemExit(7)


if __name__ == "__main__":
    main()

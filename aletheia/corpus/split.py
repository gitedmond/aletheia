"""Draw the private corpus once, rejecting any prior public source exposure."""

import platform
import random
import re
import shutil
import subprocess
from pathlib import Path
from typing import cast

from pydantic import JsonValue

from aletheia.corpus.lint import source_functions
from aletheia.heldout.guard import PrivateAccessError, PrivateGuard
from aletheia.schema.canonical import canonical_bytes

LEGACY = frozenset({"adlerfletch", "b64", "cmd-dispatch", "crc32tool", "hashtable"})


def _git(repo: Path, *args: str, input: bytes | None = None) -> bytes:
    return subprocess.check_output(["git", "-C", str(repo), *args], input=input)


def _functions(program: Path) -> set[str]:
    return {
        function.name
        for path in sorted((program / "src").rglob("*.c"))
        for function in source_functions(path.read_text(), path)
    }


def split_corpus(repo: Path, guard: PrivateGuard, seed: int) -> dict[str, object]:
    repo = guard.public_path(repo)
    if guard.root is None:
        raise PrivateAccessError("private_root is required for the corpus split")
    private = guard.private_output(guard.root)
    record_path = private / "split.json"
    if record_path.exists() or (private / "leakage-index.json").exists():
        raise PrivateAccessError("split or leakage index already exists; refusing replacement")
    public = repo / "corpus/tierA"
    destination = private / "corpus/tierA"
    candidates: dict[str, Path] = {}
    for root in (public, destination):
        for path in sorted(root.glob("*")):
            if path.name in LEGACY or not (path / "src").is_dir():
                continue
            if path.name in candidates:
                raise PrivateAccessError("duplicate public/private corpus program")
            if any(p.is_symlink() for p in (path, *path.rglob("*"))):
                raise PrivateAccessError("corpus split refuses symlink inputs")
            candidates[path.name] = path
    if len(candidates) != 15:
        raise PrivateAccessError("split requires exactly 15 new programs")
    population = sorted(candidates)
    draw = population.copy()
    random.Random(seed).shuffle(draw)
    heldout, dev = draw[:8], draw[8:]
    if any(candidates[name].parent != public for name in dev):
        raise PrivateAccessError("development programs must be in the public working tree")

    if _git(repo, "rev-parse", "--is-shallow-repository").strip() != b"false":
        raise PrivateAccessError("public source history requires a non-shallow repository")
    # Check every reachable blob, so a source committed under another name also fails.
    objects = {
        line.split()[0] for line in _git(repo, "rev-list", "--objects", "--all").splitlines()
    }
    private_names: set[str] = set()
    public_names = set[str]().union(
        *(_functions(p) for p in public.glob("*") if p.name not in heldout)
    )
    if objects:
        try:
            published = _git(repo, "grep", "-I", "-h", "-e", ".", "HEAD")
        except subprocess.CalledProcessError as exc:
            if exc.returncode != 1:
                raise
            published = b""
        public_names.update(token.decode() for token in re.findall(rb"[A-Za-z_]\w*", published))
    for name in heldout:
        path = candidates[name]
        if _git(repo, "log", "--all", "--format=%H", "--", "corpus/tierA/" + name).strip():
            raise PrivateAccessError("held-out program occurs in public git history")
        for source in sorted((path / "src").rglob("*")):
            if source.is_file():
                oid = _git(repo, "hash-object", "--stdin", input=source.read_bytes()).strip()
                if oid in objects:
                    raise PrivateAccessError("held-out source occurs in public git history")
        private_names.update(_functions(path))
    record: dict[str, object] = {
        "schema_version": "1.0",
        "seed": seed,
        "generator": "CPython random.Random / MT19937 / shuffle",
        "generator_version": platform.python_version(),
        "population": population,
        "heldout": heldout,
        "dev": dev,
        "legacy_dev": sorted(LEGACY),
        "history_check": "passed",
    }
    index: dict[str, object] = {
        # Canonical IDs avoid treating shared taxonomy words as secret program names.
        "program_ids": ["tierA/" + name for name in sorted(heldout)],
        "function_names": sorted(private_names - public_names),
        "binary_sha256": [],
    }
    destination.mkdir(parents=True, exist_ok=True)
    private.chmod(0o700)
    moved: list[tuple[Path, Path]] = []
    try:
        for name in heldout:
            source, target = candidates[name], destination / name
            if source != target:
                shutil.move(source, target)
                moved.append((source, target))
        for target, payload in ((record_path, record), (private / "leakage-index.json", index)):
            with target.open("xb") as stream:
                stream.write(canonical_bytes(cast(JsonValue, payload)))
            target.chmod(0o600)
    except BaseException:
        record_path.unlink(missing_ok=True)
        (private / "leakage-index.json").unlink(missing_ok=True)
        for source, target in reversed(moved):
            shutil.move(target, source)
        raise
    return record

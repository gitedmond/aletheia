import json
import subprocess

import pytest

from aletheia.corpus.split import split_corpus
from aletheia.heldout.guard import PrivateAccessError, PrivateGuard


def git(repo, *args):
    return subprocess.check_output(["git", "-C", str(repo), *args], text=True).strip()


def populate(repo):
    git(repo, "init", "-q")
    git(repo, "config", "user.email", "test@example.invalid")
    git(repo, "config", "user.name", "test")
    for i in range(15):
        source = repo / "corpus/tierA" / f"example-{i:02}" / "src/main.c"
        source.parent.mkdir(parents=True)
        source.write_text(f"int target_{i}(void) {{ return {i}; }}\n")


def test_split_is_reproducible_private_and_rejects_replacement(tmp_path):
    records = []
    for name in ("first", "second"):
        repo = tmp_path / name
        repo.mkdir()
        populate(repo)
        private = tmp_path / (name + "-private")
        guard = PrivateGuard(private, "heldout")
        import random

        draw = [f"example-{i:02}" for i in range(15)]
        random.Random(20261013).shuffle(draw)
        public_word = "target_" + str(int(draw[0].split("-")[1]))
        (repo / "README").write_text("Already public vocabulary: " + public_word)
        git(repo, "add", "README")
        git(repo, "commit", "-qm", "public vocabulary")
        record = split_corpus(repo, guard, 20261013)
        records.append(record)
        assert len(record["heldout"]) == 8 and len(record["dev"]) == 7
        assert len(list((repo / "corpus/tierA").iterdir())) == 7
        assert len(list((private / "corpus/tierA").iterdir())) == 8
        assert json.loads((private / "split.json").read_bytes()) == record
        index = json.loads((private / "leakage-index.json").read_bytes())
        assert public_word not in index["function_names"]
        assert index["function_names"]
        with pytest.raises(PrivateAccessError, match="already exists"):
            split_corpus(repo, guard, 20261013)
    assert records[0] == records[1]


def test_history_leak_fails_before_moving_anything(tmp_path):
    repo = tmp_path / "public"
    repo.mkdir()
    populate(repo)
    git(repo, "add", ".")
    git(repo, "commit", "-qm", "already exposed")
    private = tmp_path / "private"
    with pytest.raises(PrivateAccessError, match="history"):
        split_corpus(repo, PrivateGuard(private, "heldout"), 20261013)
    assert len(list((repo / "corpus/tierA").iterdir())) == 15
    assert not private.exists()


def test_shallow_history_is_refused_before_moving_sources(tmp_path):
    origin = tmp_path / "origin"
    origin.mkdir()
    populate(origin)
    (origin / "README").write_text("public baseline")
    git(origin, "add", "README")
    git(origin, "commit", "-qm", "baseline")
    repo = tmp_path / "shallow"
    subprocess.run(["git", "clone", "-q", "--depth=1", origin.as_uri(), str(repo)], check=True)
    for source in (origin / "corpus/tierA").iterdir():
        import shutil

        shutil.copytree(source, repo / "corpus/tierA" / source.name)
    private = tmp_path / "private"
    with pytest.raises(PrivateAccessError, match="non-shallow"):
        split_corpus(repo, PrivateGuard(private, "heldout"), 20261013)
    assert len(list((repo / "corpus/tierA").iterdir())) == 15
    assert not private.exists()

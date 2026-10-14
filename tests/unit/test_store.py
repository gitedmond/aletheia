import os
import sqlite3
import stat
from pathlib import Path

import pytest

from aletheia.schema.models import Claim, ClaimSubmission, Grade, Job, JobResult, Verdict
from aletheia.store.artifacts import ArtifactStore
from aletheia.store.cache import CacheContext, verdict_cache_key
from aletheia.store.database import Store


def claim(run="1", source="scripted:v1", confidence=0.9, callee=None):
    data = {
        "run_id": "r_" + run * 16,
        "source": {"origin": "scripted", "source_id": source},
        "binary_sha256": "a" * 64,
        "subject": {"address": "0x00001230"},
        "type": "algorithm_identity" if callee is None else "call_relation",
        "body": {"family": "crc32", "variant": "ieee"}
        if callee is None
        else {"callee": callee, "kind": "direct"},
        "confidence": confidence,
        "confidence_source": "scripted",
    }
    return Claim.intake(ClaimSubmission.model_validate(data))


def seeded(path):
    store = Store(path)
    store.add_binary("a" * 64, "tierA/test", "v1", "dev", "stripped/a.bin", "b" * 64)
    store.add_run("r_" + "1" * 16, "scripted", "scripted:v1", "c" * 64)
    store.add_run("r_" + "2" * 16, "scripted", "scripted:v1", "d" * 64)
    return store


def test_crud_reopen_and_identity_free_cache(tmp_path):
    path = tmp_path / "test.db"
    with seeded(path) as store:
        first, second = claim(), claim(run="2", source="tool-like", confidence=0.4)
        store.add_claim(first)
        store.add_claim(second)
        context = CacheContext(
            verifier_version="0.1.0",
            method_versions=["probe.crc32@1"],
            pack_hashes={"crc32": "b" * 64},
            env_digest="sha256:" + "c" * 64,
            analysis_options_hash="d" * 64,
            harness={"budget": 10},
        )
        key = verdict_cache_key(first, context)
        assert key == verdict_cache_key(second, context)
        verdict = Verdict(
            claim_id=first.claim_id,
            intrinsic_verdict="UNVERIFIABLE",
            reason="no_pack",
            verifier_version="0.1.0",
            env_digest="sha256:" + "c" * 64,
        )
        store.cache_verdict(key, verdict)
        assert (
            "claim_id"
            not in store.connection.execute("SELECT canonical_json FROM verdict_cache").fetchone()[
                0
            ]
        )
        hit = store.cached_verdict(key, second.claim_id)
        assert hit.claim_id == second.claim_id
        store.add_verdict(hit, key)
        grade = Grade(
            claim_id=second.claim_id,
            grader_version="0.1.0",
            on_target=True,
            phantom=False,
            correct_strict=True,
            correct_lenient=True,
        )
        store.add_grade(grade)
        job = Job.create("verify_static", {}, {})
        store.add_job(job)
        store.finish_job(JobResult(job_id=job.job_id, status="ok"), "sha256:" + "f" * 64)
        store.set_run_state(first.run_id, "completed")
        assert store.get_claim(first.claim_id) == first
        assert store.get_verdict(second.claim_id) == hit
        assert store.get_grade(second.claim_id) == grade
    with Store(path) as store:
        assert store.get_claim(first.claim_id) == first
        assert store.connection.execute("PRAGMA foreign_keys").fetchone()[0] == 1
        assert (
            store.connection.execute(
                "SELECT state FROM runs WHERE run_id=?", (first.run_id,)
            ).fetchone()[0]
            == "completed"
        )


def test_active_duplicates_fk_and_callee_key(tmp_path):
    with seeded(tmp_path / "test.db") as store:
        first = claim()
        store.add_claim(first)
        with pytest.raises(sqlite3.IntegrityError):
            store.add_claim(claim(confidence=0.8))
        assert store.connection.execute("SELECT count(*) FROM claims").fetchone()[0] == 1
        store.deactivate_claim(first.claim_id)
        store.add_claim(claim(confidence=0.8))
        store.add_claim(claim(callee="0x00002000"))
        store.add_claim(claim(callee="import:printf"))
        with pytest.raises(sqlite3.IntegrityError):
            store.add_claim(claim(run="3"))
        with pytest.raises(sqlite3.IntegrityError):
            store.set_run_state(first.run_id, "invalid")
        with pytest.raises(sqlite3.IntegrityError):
            store.add_binary("e" * 64, "p", "v", "bad", "path", "b" * 64)


def test_unknown_db_version_rejected(tmp_path):
    path = tmp_path / "test.db"
    with sqlite3.connect(path) as db:
        db.execute("PRAGMA user_version=99")
    with pytest.raises(ValueError):
        Store(path)


def test_artifact_fixed_hash_corruption_and_traversal(tmp_path):
    store = ArtifactStore(tmp_path)
    digest = store.put(b"abc")
    assert digest == "sha256:ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    assert store.get(digest) == b"abc"
    assert store.put(b"abc") == digest
    (tmp_path / "ba" / digest[7:]).write_bytes(b"corrupted")
    with pytest.raises(ValueError):
        store.get(digest)
    with pytest.raises(ValueError):
        store.put(b"abc")
    with pytest.raises(ValueError):
        store.get("../../private/secret")


def test_cache_affecting_configuration_changes():
    first = claim()
    context = CacheContext(
        verifier_version="v1",
        method_versions=["m@1"],
        pack_hashes={"crc32": "b" * 64},
        env_digest="sha256:" + "c" * 64,
        analysis_options_hash="d" * 64,
        harness={"budget": 10, "runtime_base": 0},
    )
    key = verdict_cache_key(first, context)
    for field, value in [
        ("verifier_version", "v2"),
        ("method_versions", ["m@2"]),
        ("pack_hashes", {"crc32": "e" * 64}),
        ("env_digest", "sha256:" + "f" * 64),
        ("analysis_options_hash", "e" * 64),
        ("harness", {"budget": 11, "runtime_base": 0}),
    ]:
        changed = CacheContext.model_validate(context.model_dump() | {field: value})
        assert verdict_cache_key(first, changed) != key
    changed = Claim.intake(
        ClaimSubmission.model_validate(
            first.model_dump(exclude={"claim_id"})
            | {"body": {"family": "crc32", "variant": "jamcrc"}}
        )
    )
    assert verdict_cache_key(changed, context) != key


def test_artifact_syncs_content_then_fanout_and_root(tmp_path, monkeypatch):
    synced = []
    original = os.fsync

    def record(fd):
        target = Path(os.readlink(f"/proc/self/fd/{fd}"))
        synced.append((stat.S_ISDIR(os.fstat(fd).st_mode), target))
        original(fd)

    monkeypatch.setattr(os, "fsync", record)
    store = ArtifactStore(tmp_path)
    digest = store.put(b"abc")
    assert len(synced) == 3
    assert synced[0][0] is False
    assert synced[1:] == [(True, tmp_path / "ba"), (True, tmp_path)]
    assert store.get(digest) == b"abc"

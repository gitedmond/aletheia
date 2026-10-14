import hashlib
from concurrent.futures import ThreadPoolExecutor

from aletheia.config import Sandbox
from aletheia.sandbox.runner import JobRunner
from aletheia.schema.models import Job
from aletheia.store.artifacts import ArtifactStore


def test_pinned_input_hash_mismatch_fails_before_docker(tmp_path):
    inputs = tmp_path / "in"
    inputs.mkdir()
    name = "a" * 64 + ".bin"
    (inputs / name).write_bytes(b"wrong hash")
    store = ArtifactStore(tmp_path / "artifacts")
    run = JobRunner(
        Sandbox(image_analysis="sha256:" + "b" * 64), tmp_path, tmp_path / "jobs", store
    )
    handle = run.submit(Job.create("ghidra_analyze", {"binary": "in/" + name}, {}))
    assert handle.container_id is None
    result = run.wait(handle)
    assert result.status == "error" and result.error_code == "bad_input"
    assert handle.result_artifact and store.get(handle.result_artifact)


def test_artifact_concurrent_identical_writes_are_atomic(tmp_path):
    store = ArtifactStore(tmp_path)
    with ThreadPoolExecutor(max_workers=8) as pool:
        values = list(pool.map(store.put, [b"same"] * 32))
    assert len(set(values)) == 1
    assert store.get(values[0]) == b"same"
    assert not list(tmp_path.rglob(".tmp-*"))


def test_artifact_symlink_directory_cannot_escape(tmp_path):
    root, outside = tmp_path / "root", tmp_path / "outside"
    root.mkdir()
    outside.mkdir()
    data = b"abc"
    (root / hashlib.sha256(data).hexdigest()[:2]).symlink_to(outside, target_is_directory=True)
    store = ArtifactStore(root)
    try:
        store.put(data)
    except ValueError:
        pass
    else:
        raise AssertionError("store followed a symlink outside its root")
    assert list(outside.iterdir()) == []

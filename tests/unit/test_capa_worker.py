"""Worker pin/timeout/fallback behavior with I/O mocked, never host ELF parsing."""

import json
import subprocess
from pathlib import Path
from types import SimpleNamespace

import pytest

from aletheia.schema.models import Job
from aletheia.sources import capa_worker


@pytest.fixture
def worker(tmp_path, monkeypatch):
    inputs = tmp_path / "in"
    inputs.mkdir()
    binary = inputs / ("a" * 64 + ".bin")
    binary.write_bytes(b"opaque test payload")
    monkeypatch.setenv("ALETHEIA_CAPA_RULES_SHA256", "1" * 64)
    monkeypatch.setattr(capa_worker, "require_job_sandbox", lambda directory: None)
    monkeypatch.setattr(capa_worker, "_validate_stripped_elf", lambda path: None)
    monkeypatch.setattr(capa_worker.importlib.metadata, "version", lambda name: "9.4.0")
    job = Job.create(
        "capa_scan",
        {"binary": "in/" + binary.name},
        {"capa_version": "9.4.0", "rules_sha256": "1" * 64},
    )
    return tmp_path, job


@pytest.mark.parametrize("missing", [False, True])
def test_capa_report_removes_information_and_fills_base_only_in_worker(
    worker, monkeypatch, missing
):
    root, job = worker
    report = {
        "meta": {
            "version": "9.4.0",
            "timestamp": "variable",
            "argv": ["variable"],
            "sample": {"path": "variable", "sha256": "a" * 64},
            "analysis": {},
        },
        "rules": {},
    }
    if not missing:
        report["meta"]["analysis"]["base_address"] = {"type": "absolute", "value": 0x2000000}
    called = []

    def execute(command, **kwargs):
        assert kwargs["env"]["LOGNAME"].isdigit()
        return subprocess.CompletedProcess(command, 0, json.dumps(report), "")

    monkeypatch.setattr(subprocess, "run", execute)
    monkeypatch.setattr(
        capa_worker, "_fallback_base", lambda binary: called.append(binary) or 0x2000000
    )
    result = capa_worker.scan_capa(root, job)
    assert result.status == "ok"
    meta = result.output["capa"]["meta"]
    assert "timestamp" not in meta and "argv" not in meta and "path" not in meta["sample"]
    assert meta["analysis"]["base_address"]["value"] == 0x2000000
    assert len(called) == int(missing)
    assert result.output["address_base_source"] == (
        "pinned_vivisect_elf_loader" if missing else "metadata"
    )


def test_worker_timeout_is_counted(worker, monkeypatch):
    root, job = worker

    def timeout(*args, **kwargs):
        raise subprocess.TimeoutExpired("capa", 55)

    monkeypatch.setattr(subprocess, "run", timeout)
    result = capa_worker.scan_capa(root, job)
    assert result.status == "error" and result.error_code == "wall_timeout"


def test_worker_mismatched_rules_pin_fails_before_process(worker, monkeypatch):
    root, job = worker
    bad = Job.create(job.type, job.inputs, job.params | {"rules_sha256": "2" * 64})
    with pytest.raises(ValueError, match="pins mismatch"):
        capa_worker.scan_capa(root, bad)


def test_fallback_uses_the_observed_capa_filemeta_policy_without_analysis(monkeypatch):
    calls = []

    def workspace(filename, **kwargs):
        calls.append((filename, kwargs))
        return SimpleNamespace(filemeta={"sample": {"imagebase": 0x2000000}})

    monkeypatch.setattr(
        capa_worker.importlib, "import_module", lambda name: SimpleNamespace(getWorkspace=workspace)
    )
    assert capa_worker._fallback_base(Path("/public/sample.bin")) == 0x2000000
    assert calls == [("/public/sample.bin", {"analyze": False, "should_save": False})]


@pytest.mark.parametrize(
    "missing_or_wrong",
    [
        "meta_missing",
        "meta_wrong",
        "analysis_missing",
        "analysis_wrong",
        "sample_missing",
        "sample_wrong",
    ],
)
def test_malformed_metadata_has_structured_input_error(worker, monkeypatch, missing_or_wrong):
    """Missing and mistyped capa metadata must retain an actionable bad-input detail."""
    from functools import partial

    from aletheia.schema.canonical import canonical_bytes
    from aletheia.worker.main import execute

    root, job = worker
    raw = {"meta": {"analysis": {}, "sample": {}}, "rules": {}}
    field, change = missing_or_wrong.split("_")
    parent = raw if field == "meta" else raw["meta"]
    if change == "missing":
        del parent[field]
    else:
        parent[field] = []
    monkeypatch.setattr(
        subprocess,
        "run",
        lambda command, **kwargs: subprocess.CompletedProcess(command, 0, json.dumps(raw), ""),
    )
    (root / "in/job.json").write_bytes(canonical_bytes(job))
    (root / "out").mkdir()
    result = execute(root, {"capa_scan": partial(capa_worker.scan_capa, root)})
    assert result.status == "error" and result.error_code == "bad_input"
    assert result.output["detail"] == "capa report lacks meta/analysis/sample objects"

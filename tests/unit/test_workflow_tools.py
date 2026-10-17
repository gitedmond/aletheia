"""Validation wrappers retain full failures and restore bindings without losing edits."""

import importlib.util
import json
import sys
from pathlib import Path

import pytest

spec = importlib.util.spec_from_file_location("workflow_check", Path("tools/check.py"))
assert spec and spec.loader
workflow = importlib.util.module_from_spec(spec)
spec.loader.exec_module(workflow)


def test_log_retains_full_failure_with_bounded_console(tmp_path, capsys):
    log = tmp_path / "check.log"
    code = workflow.run_logged(
        [sys.executable, "-c", "print('failure\\n' * 50); raise SystemExit(3)"], tmp_path, log
    )
    result = json.loads(capsys.readouterr().out)
    assert code == result["exit_code"] == 3
    assert len(result["summary"]) == 25 and log.read_text().count("failure") == 50


def test_image_bindings_restore_failure_and_recover_interruption(tmp_path, monkeypatch):
    repo, state = tmp_path / "repo", tmp_path / "state"
    repo.mkdir()
    state.mkdir()
    originals = {
        "aletheia.toml": b'image_analysis = "old-a"\nimage_build = "old-b"\n',
        "versions.lock.md": b'analysis = "old-a"\nbuild = "old-b"\n',
    }
    for name, raw in originals.items():
        (repo / name).write_bytes(raw)
    monkeypatch.setattr(workflow.subprocess, "check_output", lambda *a, **kw: "sha256:" + "a" * 64)
    with pytest.raises(RuntimeError):
        with workflow.image_bindings(repo, state, {"analysis": "test", "build": "test"}):
            assert (repo / "aletheia.toml").read_bytes() != originals["aletheia.toml"]
            raise RuntimeError("injected child failure")
    assert all((repo / name).read_bytes() == raw for name, raw in originals.items())
    receipt = state / "image-bindings.json"
    record = json.loads(receipt.read_bytes())
    record["active"] = True
    receipt.write_text(json.dumps(record))
    import base64

    (repo / "aletheia.toml").write_bytes(
        base64.b64decode(record["files"]["aletheia.toml"]["temporary"])
    )
    with workflow.image_bindings(repo, state, {}):
        assert (repo / "aletheia.toml").read_bytes() == originals["aletheia.toml"]
    with pytest.raises(ValueError, match="Preserving unexpected edit"):
        with workflow.image_bindings(repo, state, {"analysis": "test", "build": "test"}):
            (repo / "aletheia.toml").write_text("concurrent edit")
    assert (repo / "aletheia.toml").read_text() == "concurrent edit"
    assert json.loads(receipt.read_bytes())["active"] is True


def test_successful_json_is_summarized_without_dumping_details(tmp_path, capsys):
    log = tmp_path / "doctor.log"
    command = [
        sys.executable,
        "-c",
        "import json; print(json.dumps({'status':'ok','details':'x'*5000}))",
    ]
    assert workflow.run_logged(command, tmp_path, log) == 0
    result = json.loads(capsys.readouterr().out)
    assert result["summary"] == ["status: ok"] and log.stat().st_size > 5000

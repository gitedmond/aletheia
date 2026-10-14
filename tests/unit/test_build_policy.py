import shutil
import subprocess
from pathlib import Path

import pytest
from typer.testing import CliRunner

from aletheia.cli import app
from aletheia.corpus.build import BuildError, Variant, _publish, build_program


def test_variant_rejects_mutable_images_and_other_variants():
    for image in ("aletheia-build", "ubuntu:latest", "sha256:abc"):
        with pytest.raises(ValueError):
            Variant(image=image)
    with pytest.raises(ValueError):
        Variant(image="sha256:" + "a" * 64, compiler_major=22)


def test_source_symlink_and_empty_sources_fail_before_docker(tmp_path, monkeypatch):
    called = []
    monkeypatch.setattr(subprocess, "run", lambda *a, **kw: called.append(a))
    source = tmp_path / "corpus/tierA/p/src"
    source.mkdir(parents=True)
    variant = Variant(image="sha256:" + "a" * 64, output_root=tmp_path / "out")
    with pytest.raises(BuildError):
        build_program(source.parent, variant)
    (source / "main.c").symlink_to(Path("corpus/tierA/crc32tool/src/main.c").resolve())
    with pytest.raises(BuildError, match="symlink"):
        build_program(source.parent, variant)
    assert not called


def test_cli_build_missing_selection_is_explicit():
    result = CliRunner().invoke(app, ["--json", "corpus", "build", "--program", "absent"])
    assert result.exit_code == 1
    assert "program_missing" in result.stdout


def test_output_symlink_is_rejected(tmp_path):
    destination = tmp_path / "redirect"
    destination.mkdir()
    output = tmp_path / "build"
    output.symlink_to(destination, target_is_directory=True)
    variant = Variant(image="sha256:" + "a" * 64, output_root=output)
    with pytest.raises(BuildError, match="symlink"):
        build_program(Path("corpus/tierA/crc32tool"), variant)


def test_publication_failure_restores_previous_bundle(tmp_path, monkeypatch):
    from aletheia.corpus import build

    previous, staging = tmp_path / "previous", tmp_path / "staging"
    previous.mkdir()
    staging.mkdir()
    (previous / "build.json").write_text("old")
    (staging / "build.json").write_text("new")
    original = build.os.replace

    def fail_publish(source, target):
        if source == staging:
            raise OSError("injected publication failure")
        return original(source, target)

    monkeypatch.setattr(build.os, "replace", fail_publish)
    with pytest.raises(OSError, match="injected"):
        _publish(staging, previous)
    assert (previous / "build.json").read_text() == "old"


def test_unrecognized_outputs_are_preserved(tmp_path):
    previous, staging = tmp_path / "previous", tmp_path / "staging"
    previous.mkdir()
    staging.mkdir()
    (previous / "build.json").write_text("old")
    (previous / "notes.txt").write_text("keep")
    with pytest.raises(BuildError, match="unknown build output"):
        _publish(staging, previous)
    assert (previous / "notes.txt").read_text() == "keep"


def test_unsupported_source_file_is_not_silently_omitted(tmp_path, monkeypatch):
    copied = tmp_path / "corpus"
    shutil.copytree("corpus", copied)
    (copied / "tierA/crc32tool/src/extra.S").write_text("unsupported")
    called = []
    monkeypatch.setattr(subprocess, "run", lambda *a, **kw: called.append(a))
    with pytest.raises(BuildError, match="c17_only"):
        build_program(
            copied / "tierA/crc32tool",
            Variant(image="sha256:" + "a" * 64, output_root=tmp_path / "build"),
        )
    assert not called


def test_compiler_jobs_reject_root_identity(tmp_path, monkeypatch):
    from aletheia.corpus import build

    monkeypatch.setattr(build.os, "getuid", lambda: 0)
    with pytest.raises(BuildError, match="non-root"):
        build._execute("sha256:" + "a" * 64, tmp_path, tmp_path, "p")


@pytest.mark.parametrize("cleanup_timeout", [False, True])
def test_cleanup_exceptions_preserve_compiler_failure(tmp_path, monkeypatch, cleanup_timeout):
    import subprocess

    from aletheia.corpus.build import _execute
    source = tmp_path / "snapshot/tierA/example/src"
    source.mkdir(parents=True)
    (source / "main.c").write_text("int main(void) { return 0; }")
    def fail(command, **kwargs):
        if command[1] == "run":
            raise FileNotFoundError("compiler Docker executable missing")
        if cleanup_timeout:
            raise subprocess.TimeoutExpired(command, 15)
        raise FileNotFoundError("cleanup Docker executable missing")
    monkeypatch.setattr(subprocess, "run", fail)
    with pytest.raises(BuildError, match="sandbox unavailable:.*compiler Docker.*cleanup failed"):
        _execute("sha256:" + "1" * 64, tmp_path / "snapshot", tmp_path / "out", "example")

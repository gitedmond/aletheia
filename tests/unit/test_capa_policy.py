"""Source boundaries fail before host binary parsing or a sandbox submission."""

from pathlib import Path

import pytest

from aletheia.schema.models import Job
from aletheia.sources.base import BinaryRef
from aletheia.sources.capa_worker import scan_capa


def test_binary_reference_rejects_private_names_and_symlinks(tmp_path):
    sha = "a" * 64
    for path in (
        tmp_path / "private/stripped" / (sha + ".bin"),
        tmp_path / "stripped/unstripped.bin",
    ):
        with pytest.raises(ValueError):
            BinaryRef(sha, path, "variant")
    path = tmp_path / "stripped" / (sha + ".bin")
    path.parent.mkdir()
    path.symlink_to(tmp_path / "unknown")
    with pytest.raises(ValueError, match="symlink"):
        BinaryRef(sha, path, "variant")


def test_binary_handler_refuses_cloud_host_before_opening_inputs():
    with pytest.raises(ValueError, match="sandbox"):
        scan_capa(Path("/job"), Job.create("capa_scan", {}, {}))

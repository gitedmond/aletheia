"""T08 private extraction rejects invalid jobs before parsing any binary."""

from pathlib import Path

import pytest

from aletheia.corpus.ground_truth import GroundTruthError, _run
from aletheia.corpus.ground_truth_worker import annotations, require_sandbox


def test_private_worker_refuses_cloud_host_mounts():
    with pytest.raises(ValueError, match="sandbox"):
        require_sandbox()


def test_mutable_image_is_rejected(tmp_path):
    with pytest.raises(GroundTruthError, match="immutable"):
        _run("aletheia-build:latest", tmp_path, tmp_path, tmp_path)


def test_root_job_is_rejected(tmp_path, monkeypatch):
    import os

    monkeypatch.setattr(os, "getuid", lambda: 0)
    with pytest.raises(GroundTruthError, match="non-root"):
        _run("sha256:" + "1" * 64, tmp_path, tmp_path, tmp_path)


def test_annotations_use_source_linter_boundaries():
    parsed = annotations(Path("corpus/tierA/cmd-dispatch"))
    assert parsed["fnv1a_32_local"][0].family == "fnv"
    assert parsed["dispatch"][1] == ["cmd_hash", "cmd_sum", "cmd_help"]
    assert parsed["main"][0].family == "none"


def test_header_definitions_keep_algorithm_and_indirect_annotations(tmp_path):
    import shutil

    copied = tmp_path / "corpus"
    shutil.copytree("corpus", copied)
    program = copied / "tierA/cmd-dispatch"
    header = program / "src/header_functions.h"
    header.write_text("""#include "program.h"
// @algorithm fnv/fnv1a-32
static inline uint32_t header_hash(const uint8_t *buf, size_t len) {
    uint32_t hash = 0x811c9dc5u;
    for (size_t i = 0; i < len; ++i) hash = (hash ^ buf[i]) * 0x01000193u;
    return hash;
}
// @algorithm none
// @indirect-targets cmd_hash,cmd_sum,cmd_help
static inline int header_dispatch(int (*handler)(int, char **), int argc, char **argv) {
    return handler(argc, argv);
}
""")
    parsed = annotations(program)
    assert parsed["header_hash"][0].family == "fnv"
    assert parsed["header_hash"][0].variant == "fnv1a-32"
    assert parsed["header_dispatch"][1] == ["cmd_hash", "cmd_sum", "cmd_help"]

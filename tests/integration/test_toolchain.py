import json
import os
import subprocess
from pathlib import Path

import pytest

from aletheia.config import Config
from aletheia.sandbox.policy import container_args

pytestmark = pytest.mark.integration


def test_pinned_analysis_tools_start_under_containment(tmp_path):
    cfg = Config.read(Path("aletheia.toml")).sandbox
    inputs, outputs = tmp_path / "in", tmp_path / "out"
    inputs.mkdir()
    outputs.mkdir()
    script = (
        "import json, importlib.metadata as m; import unicorn, elftools, pyghidra; "
        "pyghidra.start(); import jpype; "
        "print(json.dumps({'ghidra':str(jpype.JClass('ghidra.framework.Application')"
        ".getApplicationVersion()),'pyghidra':m.version('pyghidra'),"
        "'unicorn':m.version('unicorn'),'capa':m.version('flare-capa')}))"
    )
    result = subprocess.run(
        [
            "docker",
            "run",
            "--rm",
            *container_args(cfg, inputs, outputs, os.getuid(), os.getgid()),
            "--entrypoint",
            "python",
            cfg.image_analysis,
            "-c",
            script,
        ],
        capture_output=True,
        text=True,
        check=True,
        timeout=120,
    )
    assert json.loads(result.stdout.splitlines()[-1]) == {
        "ghidra": "11.4.3",
        "pyghidra": "2.2.1",
        "unicorn": "2.1.4",
        "capa": "9.4.0",
    }


def test_build_compiler_and_strip_work_without_network(tmp_path):
    cfg = Config.read(Path("aletheia.toml")).sandbox
    (tmp_path / "main.c").write_text("int main(void) { return 0; }\n")
    # The only C input here is an independently authored compiler smoke check.
    script = "clang -std=c17 /input/main.c -o /scratch/a && llvm-strip /scratch/a && /scratch/a"
    subprocess.run(
        [
            "docker",
            "run",
            "--rm",
            "--pull",
            "never",
            "--network",
            "none",
            "--read-only",
            "--user",
            f"{os.getuid()}:{os.getgid()}",
            "--tmpfs",
            "/scratch:rw,exec,nosuid,nodev,size=1g,mode=1777",
            "--mount",
            f"type=bind,src={tmp_path},dst=/input,readonly",
            cfg.image_build,
            "sh",
            "-ec",
            script,
        ],
        check=True,
        capture_output=True,
        timeout=30,
    )

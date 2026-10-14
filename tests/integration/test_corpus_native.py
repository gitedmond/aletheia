"""T06 acceptance: compile/test original C sources only in the pinned build sandbox."""

import os
import re
import subprocess
from pathlib import Path

import pytest

from aletheia.config import Config

pytestmark = pytest.mark.integration

OUTPUTS = {
    "crc32tool": (
        "e8b7be43\ne8b7be43\n174841bc\ne8b7be43\n",
        "00000000\n00000000\nffffffff\n00000000\n",
        "15e87871\n15e87871\nea17878e\n15e87871\n",
    ),
    "adlerfletch": (
        "00620062\n00620062\n6161\n",
        "00000001\n00000001\n0000\n",
        "018800c4\n018800c4\n86c3\n",
    ),
    "hashtable": (
        "e40c292c\n050c5d7e\n0002b606\n0002b606\n0002b5c4\n00000001\n00000001\n",
        "811c9dc5\n811c9dc5\n00001505\n00001505\n00001505\n00000001\n00000001\n",
        "10f3abd2\n659c64cc\n0002b606\n0b884fe8\n0b8736a6\n00000001\n00000001\n",
    ),
    "b64": ("59513d3d\n5951\n61\n", "\n\n\n", "59514269\n59514269\n610062\n"),
    "cmd-dispatch": ("e40c292c\n", "811c9dc5\n", "10f3abd2\n"),
}


@pytest.mark.parametrize("program", tuple(OUTPUTS))
def test_native_vectors_and_file_stdin_workflow(tmp_path, program):
    image = Config.read(Path("aletheia.toml")).sandbox.image_build
    assert re.fullmatch(r"sha256:[0-9a-f]{64}", image)
    for index, data in enumerate((b"a", b"", b"a\0b")):
        (tmp_path / f"input-{index}").write_bytes(data)
        (tmp_path / f"expected-{index}").write_text(OUTPUTS[program][index])
    command = f"/scratch/native/{program}" + (" hash" if program == "cmd-dispatch" else "")
    script = (
        "cp -R /corpus /scratch/corpus; "
        f"make -C /scratch/corpus/tierA/{program} BUILD_DIR=/scratch/native all test; "
        "for i in 0 1 2; do "
        f"{command} /cases/input-$i > /scratch/file-output; "
        f"{command} < /cases/input-$i > /scratch/stdin-output; "
        "cmp /cases/expected-$i /scratch/file-output; "
        "cmp /cases/expected-$i /scratch/stdin-output; done; "
        f"if {command} /cases/absent > /scratch/out 2> /scratch/err; then exit 1; fi; "
        "test -s /scratch/err"
    )
    result = subprocess.run(
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
            "--cap-drop",
            "ALL",
            "--security-opt",
            "no-new-privileges",
            "--cpus",
            "2",
            "--memory",
            "1g",
            "--memory-swap",
            "1g",
            "--pids-limit",
            "64",
            "--tmpfs",
            "/scratch:rw,exec,nosuid,nodev,size=256m,mode=1777",
            "--mount",
            f"type=bind,src={Path('corpus').resolve()},dst=/corpus,readonly",
            "--mount",
            f"type=bind,src={tmp_path.resolve()},dst=/cases,readonly",
            image,
            "sh",
            "-ec",
            script,
        ],
        capture_output=True,
        text=True,
        timeout=60,
    )
    assert result.returncode == 0, result.stdout + result.stderr
    counts = re.findall(r"^ok ([0-9]+)$", result.stdout, re.M)
    assert len(counts) == 1 and int(counts[0]) > 0, result.stdout
    print(
        f"{program}: {counts[0]} native assertions; "
        "file/stdin/empty/embedded-NUL/missing-file checks passed"
    )

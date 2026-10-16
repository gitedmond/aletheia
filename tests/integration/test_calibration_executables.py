"""New calibration fixtures must also run as standalone programs in the sandbox."""

import os
import subprocess
from pathlib import Path

import pytest

from aletheia.config import Config
from aletheia.corpus.build import FLAGS
from aletheia.sandbox.policy import container_args

pytestmark = pytest.mark.integration


@pytest.mark.parametrize(
    "fixture",
    [
        "near_miss/fletcher16",
        "near_miss-v2/base64",
        "near_miss/md5",
        "near_miss/sha1",
        "near_miss/sha256",
    ],
)
def test_new_calibration_main_has_valid_anchor_storage(tmp_path, fixture):
    cfg = Config.read(Path("aletheia.toml"))
    source = Path("tests/fixtures") / fixture
    output = tmp_path / "out"
    output.mkdir()
    script = (
        "import subprocess;"
        f"subprocess.run(['clang',*{list(FLAGS)!r},'/job/in/calibration.c',"
        "'-o','/job/out/calibration'],check=True);"
        "subprocess.run(['/job/out/calibration'],check=True)"
    )
    subprocess.run(
        [
            "docker",
            "run",
            "--rm",
            *container_args(cfg.sandbox, source, output, os.getuid(), os.getgid()),
            "--entrypoint",
            "python",
            cfg.sandbox.image_build,
            "-c",
            script,
        ],
        check=True,
        capture_output=True,
        text=True,
        timeout=cfg.sandbox.wall_timeout_s,
    )

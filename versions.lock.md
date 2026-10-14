# Version lock

Bootstrap pins are frozen in T00. T01 completes native tools and image identity.
The TOML block is machine-readable; measurements are informational.

```toml
lock_version = 1
[pins.python]
version = "3.12.15"
[pins.uv]
version = "0.13.0"
url = "https://github.com/astral-sh/uv/releases/download/0.13.0/uv-x86_64-unknown-linux-gnu.tar.gz"
sha256 = "1468ebd5a5541121837c5a2817b9972ba6090fa6caa3d142620850a47fb75154"
[pins.uv_build]
version = "0.13.0"
[pins.ruff]
version = "0.17.0"
[pins.pyright]
version = "1.1.414"
[pins.pytest]
version = "9.1.1"
[pins.nodejs_wheel_binaries]
version = "24.19.0"
[images]
[measurements]
```

Python distributions and dependency artifact URLs/hashes are completed at T01;
uv.lock already records exact resolved Python dependencies and artifact hashes.

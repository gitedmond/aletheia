# Aletheia

Aletheia verifies structured reverse engineering claims with deterministic evidence.
The repository contains the CLI, contracts, storage, bounded sandbox runner, source
linter, and five C17 corpus programs. The analysis and verification pipeline is
under development. Development uses Linux amd64 and the pinned tools below.

```sh
export PATH="$HOME/.local/bin:$PATH"
uv sync --frozen
uv run alth --help
uv run ruff check
uv run pyright
uv run pytest -m "not slow and not integration"
```

Global `--config PATH` and `--json` flags precede the command.
LLM runs are disabled, with hosted spend capped at zero. No provider is installed.

MIT covers original Aletheia code and dev corpus; dependencies retain their licenses.
Images and binary artifacts are built locally, not distributed by this repository.
This is a single-maintainer project with best-effort support.

Before rebuilding images, fetch the pinned Ubuntu certificate bootstrap into its ignored
local build path (it is not distributed by this repository):

```sh
curl -fsSL --retry 2 -o docker/ca-certificates.deb https://archive.ubuntu.com/ubuntu/pool/main/c/ca-certificates/ca-certificates_20260601~24.04.1_all.deb
echo '6bac2a01979e210d9eac1d4d56747ec709ea60654744d66705dc3c36e7629e50  docker/ca-certificates.deb' | sha256sum -c -
docker build -f docker/build.Dockerfile -t aletheia-build .
docker build -f docker/analysis.Dockerfile -t aletheia-analysis .
```

Record the new full image IDs in the config and lock after reviewing a rebuild. Doctor fails
on stale or missing identities; it does not pull or repair anything. CI records its own rebuilt
image IDs only in its temporary checkout.

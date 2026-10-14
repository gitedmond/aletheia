# Aletheia

Aletheia verifies structured reverse engineering claims with deterministic evidence.
Phase 1A builds the no-LLM foundation; algorithm verification and the corpus follow
after the infrastructure milestone.

Development runs as `edmond` in Ubuntu-24.04 WSL2 at
`/home/edmond/src/aletheia`. Original documents remain in the Windows staging folder.
`SPEC-PHASE-1A.md` is authoritative for this phase; see `STATUS.md` for actual progress.

```sh
export PATH="$HOME/.local/bin:$PATH"
uv sync --frozen
uv run alth --help
uv run ruff check
uv run pyright
uv run pytest -m "not slow"
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

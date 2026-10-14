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

# Compact local workflow

Use `check.py` from WSL with Python 3.12. It runs Ruff, Pyright and unit tests by default.
`--full` adds doctor and the required non-slow integration suite. It stops on the first
failure, saves complete output, and prints only a short summary and the log path.
Use `-- <command>` to run a specific acceptance check instead of the standard suite.

```sh
uv run python tools/check.py
uv run python tools/check.py --full --analysis-image sha256:<analysis-id> --build-image sha256:<build-id>
uv run python tools/check.py -- uv run pytest tests/unit/test_report_phase1b.py -q
```

The optional image bindings are temporary. Both tracked files are restored byte-for-byte,
and an interrupted binding is recovered on the next invocation. Unexpected edits are
preserved and reported. The per-checkout lock prevents overlapping validation bindings.
Logs default to `~/.cache/aletheia-checks/<checkout>-<path-hash>/`; use `--log-dir` to retain a separately
named validation run. Do not read entire logs when a failure excerpt is enough.

Run `pr-status.ps1` from Windows PowerShell, where the PC's GitHub authentication is set up.
It summarizes the current PR heads, CI and unresolved reviews without downloading review
bodies. `MoreThreads=True` means that PR needs a targeted paginated review query.

```powershell
pwsh -NoProfile -ExecutionPolicy Bypass -File '\\wsl.localhost\Ubuntu-24.04\home\edmond\src\aletheia-t68\tools\pr-status.ps1'
```

Read the schema/caller before editing. During edits, run the affected acceptance check;
run the normal suite once the change stabilizes. Re-run only when a relevant change or
failure justifies it. A short summary is not proof that unrun checks passed.

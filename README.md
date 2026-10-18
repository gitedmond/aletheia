# Aletheia

Aletheia verifies structured reverse engineering claims with deterministic evidence.
Phase 1A includes five C17 dev programs, scripted/capa/FindCrypt claim sources,
Ghidra analysis, bounded function emulation, independent grading, deterministic replay
and reports. Development uses Linux amd64 and the pinned tools below.

```sh
export PATH="$HOME/.local/bin:$PATH"
uv sync --frozen
uv run alth --help
uv run ruff check
uv run pyright
uv run pytest -m "not slow and not integration"
```

Global `--config PATH` and `--json` flags precede the command.
Agent runs require an explicit provider configuration. Hosted benchmark spending
defaults to zero; there is no automatic paid fallback.

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


From the Linux checkout, prepare the full Phase 1A experiment and inspect its gate:

```sh
uv run alth --json gate 1a --execute
uv run alth --json gate 1a
```

Preparation builds each program twice, checks leakage, runs calibration and all three
sources, replays every run with fresh verifier methods, and writes reports and receipts
under `runs/phase1a/`. The gate checks existing receipts without repeating the experiment.
A passing gate also requires `reviews.json` dispositions bound to the current review
scopes and final evidence; record author reviews and explicit delegation honestly.

Individual runs use `alth run --source scripted|capa|findcrypt --program PROGRAM`.
`alth verify --run ID`, `alth score --run ID`, `alth replay --run ID`, and
`alth report --runs ID1,ID2 --out report.md` support the same persisted run lifecycle.
FindCrypt is labeled as a shared backend and excluded from independent scripted reliability.
Results cover five dev programs; their cluster intervals are not held-out generalization evidence.


Phase 1B extends this foundation with compiler-derived ABI signatures, purpose
claims, hardened builds, a private held-out split, three local agent configurations,
dev-only confidence fitting, and a stdio verifier MCP server. `alth gate 1b` checks
existing hash-bound receipts; it does not launch experiments. Engineering tests
alone do not establish empirical acceptance or human validation.

The 22 installed pack files include memory operations, repeating-key XOR, RC4
composites, SHA-1/SHA-256 block transforms, and bounded read/print behavior. I/O
probes use only emulator-owned virtual input files and captured stdout; unsupported
ABIs, imports, and formatting abstain. Host files and real descriptors are not
available. Potential coverage requires a compatible compiler ABI and complete
composite scope; measured decisiveness is reported separately.

`tools/phase1b-matrix.py --help` describes the current PC-local coordinator. It uses
explicit WSL storage paths, freezes its inputs, runs local models serially, and
keeps mixed ledgers and raw held-out evidence private. AI-assisted annotations
retain their provenance; independent human labels and review dispositions must
never be fabricated to satisfy the gate.

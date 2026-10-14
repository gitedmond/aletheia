# Cloud environment receipt

This record describes the managed cloud instance, not the historical workstation.
Machine/image/scan/source identifiers are in cloud-environment.json. The original
versions.lock.md, aletheia.toml, image inventory/audit, and workstation source hashes
are preserved. No dependency or host pin was silently changed.

The cloud uses Debian 13 amd64, non-root UID/GID 1000, 4 CPU quota, 32 GiB memory,
and a 32 GiB disk quota. Docker 28.4.0/containerd 1.7.28/runc 1.3.0 differ from the
recorded workstation versions. Doctor verifies package pins, daemon availability,
and the configured image identities; it does not enforce those three host version
fields. A doctor success under cloud-local image fields is not an exact host-pin match.

uv 0.13.0 and Python 3.12.15 come from the locked upstream archives, verified by
SHA-256. Host dependencies are installed with uv sync --frozen. Builds use the
locked Ubuntu base/snapshot, LLVM, JDK, Ghidra, extension, and rules checksums.
api.github.com and snapshot.ubuntu.com were added to the existing network draft;
subsequent GitHub API reads and signed snapshot package installation succeeded.
No additional credential was requested or copied from the workstation.

## Setup adaptations

All helper files and caches are outside the checkout except the supported ignored
CA bootstrap package and .venv. The tracked Dockerfiles are not edited. Generated
copies add a BuildKit secret mount of the session's combined CA bundle to every RUN;
apt/curl/uv use the mounted trust file. Its mode is 0444 because apt drops privileges.
TLS, signed package indexes, and pinned artifact checksums remain enabled. The
session CA is not copied into any image layer.

The cloud defaults to umask 0077. A test script copied into a Docker image became
root-owned mode 0600, causing four worker tests to fail before handlers ran. Setting
umask 0022 for the validation process made generated public test code readable by
the non-root worker. Test assertions and containment requirements were unchanged.

Docker's VFS storage and duplicate intermediate filesystem copies exhausted disk
when image scans/derived workers overlapped. Generated scanner databases, this task's
build caches, and generated failed-test images were cleaned; unrelated workloads
were not removed. The analysis image was flattened through Docker export/import.
A complete comparison confirmed all 23,533 exported filesystem entries (file hashes,
modes, ownership, and link semantics), plus Env/Entrypoint/Cmd/User/WorkingDir/Labels,
were preserved. The proof and raw/final IDs are in cloud-environment.json. This is a
local storage adaptation, not a version upgrade or image publication. Jobs still run
by the full inspected local image ID with the original containment policy.

Fresh static Trivy 0.75.0 scans of the rebuilt files report 2,670 build-image and
64 analysis-image findings. The flattened analysis filesystem equals the scanned
raw image's filesystem. Findings include 3 critical and 23 high analysis records;
the pending Ghidra reachability/disposition review remains open. These counts do not
establish exploitable paths or grant a security exception. Host kernel/daemon
assessment and dynamic exploit reachability remain unvalidated. The Java database
and SBOM interpretation limitations remain as described in toolchain-review.md.
Raw reports were retained outside the checkout; their SHA-256 hashes are recorded.

## Activation and validation

Use the existing checkout. Each cloud task is isolated; do not create a worktree
unless explicitly requested. Activate the pinned tools in each shell:

```bash
cd /workspace/aletheia
export PATH="/workspace/.tools/aletheia-pinned/uv-x86_64-unknown-linux-gnu:$PATH"
export UV_CACHE_DIR=/workspace/.cache/uv
export UV_PYTHON_INSTALL_DIR=/workspace/.tools/python
export BUILDX_CONFIG=/workspace/.cache/buildx
umask 0022
```

The saved environment install_script reproduces these steps and writes the helper
below. It reuses installed images only when both immutable IDs and the complete
Docker/package input fingerprint match. Live processes are not assumed to survive.
There is no long-running application service to start in T05/T06.

The integration tests read aletheia.toml; doctor also reads its adjacent version lock.
The author authorized temporary cloud-local image fields. run-checks.py serializes
configuration edits, saves original bytes in memory, replaces only those image fields,
runs the requested command, and restores both files in finally. Use it for cloud checks:

```bash
uv run ruff check
uv run pyright
env -u FORCE_COLOR TERM=dumb NO_COLOR=1 python3 /workspace/.setup/aletheia/cloud/run-checks.py uv run pytest -m "not slow"
python3 /workspace/.setup/aletheia/cloud/run-checks.py uv run alth --json doctor
uv run alth --json corpus lint
git diff --check
```

Do not run concurrent installers/config mutations outside the helper lock. Check free
disk before Docker work; serialize vulnerability scans with full sandbox tests. The
saved install script and configuration draft do not publish the environment. No
image/package release or automatic PR merge has occurred.

All seven worker acceptance checks passed against the flattened analysis image in
63.63 seconds. Full final check counts and task review state are in STATUS.md.
No slow test is currently implemented; the slow end-to-end pipeline and X1-X10 are
not validated. Ghidra startup smoke checks do not analyze an untrusted binary.

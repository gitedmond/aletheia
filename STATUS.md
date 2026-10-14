# Aletheia status

Active phase: Phase 1A. The T00-T04 foundation is implemented and validated.
Author-confirmed employment/IP review: not applicable. No private agreement contents recorded.
Historical workstation checkout: /home/edmond/src/aletheia, edmond UID/GID 1001.
Active implementation destination: cloud Linux checkout (author request 2026-10-14). Remote: https://github.com/gitedmond/aletheia.
Main contains the approved document baseline; code is on the stacked task branches awaiting review.

## Accepted decisions

- Public personal gitedmond/aletheia; original code and planned original dev corpus MIT.
- Native Docker reused in Ubuntu WSL2. Existing users, unrelated images, and data preserved.
- uv_build is approved build-only; required upstream dependencies are pinned and audited.
- Local project images use full SHA-256 IDs. No image registry, package release, or image distribution.
- LLM disabled, provider empty, cost cap zero. Lane G, held-out infrastructure/providers deferred;
  agent power analysis awaits real agent data. Draft verifiability is recorded.
- C1-C7 are settled spec choices. Their later implementation remains in the assigned tasks.
- Protected goldens, fixtures, mappings, analyzer options, and every HR gate remain human-owned.
- DESIGN.md is the maintained design source after conversion; author approved the conversion on 2026-10-14.
- Original OneDrive staging documents are unchanged. On final recheck, design DOCX SHA-256 was
  1aaaf52a274efee2c737b78b1e962bc08dc1601ad5292ace11e4aaa6dc97f51d and staging Phase 1A
  SHA-256 was 9fb6f1802b589777f5cae5eebb637bfcddffdb690af60693179cffc0c640e6fe.

## Task and review state

Implemented means code exists. Validated means acceptance and normal checks passed.
Awaiting review means a draft PR or designated human decision remains open. Done requires
acceptance and any required HR approval; merge status is recorded separately. T00-T04 have
no task-specific HR gate, but their PRs remain unmerged. No Phase 1A exit gate has passed.

| Task | Implementation/validation | Review | Implementation commits |
|---|---|---|---|
| T00 | done: scaffold, CLI aliases, pinned checks | PR #1 draft | 340438e, e84b587 |
| T01 | done: verified images, config, doctor, licenses and scans | PR #2 draft; residual security review open | 0d655e0 |
| T02 | done: records, canonical hashes, nine schemas | PR #3 draft | c717897 |
| T03 | done: transactional metadata, opaque artifacts, cache foundations | PR #4 draft | 001acbe |
| T04 | done: bounded Docker runner and worker protocol; CI repaired | PR #5 draft | 0328420, 59cbbd4, 0eec482 |
| T05 | done: source policy and CLI; 35 acceptance cases, full cloud validation | PR #6 draft -> t04-sandbox; no T05 HR gate | 039b6fc, 62c861d, 57d504e |
| T06 | prepared and validated: five C17 programs, 172 native assertions | PR #7 draft -> t05-corpus-lint; annotation/semantic HR pending | cc05cca, dc74d4e |
| T07-T27 | planned dependency roadmap in spec Section 17 | Required HR gates pending | none |
| T30-T32 | deferred, LLM lane disabled | none | none |

PR stack: #1 targets main; #2 targets t00-scaffold; #3 targets t01-toolchain;
#4 targets t02-contracts; #5 targets t03-storage. Review/merge in that order.
After a base PR merges, rebase/retarget its child as needed; do not merge protected proposals.

## Exact validation evidence

Acceptance tests were written before their implementation and failed with the missing CLI,
config, schema, store, and worker modules. Additional checks independently exposed timestamp
hashing, schema body correlation, forbidden paths, compiler runtime requirements, and cleanup
failure handling. Their assertions remain intact. The compiler sandbox setup explicitly permits
execution in scratch; Docker's implicit tmpfs noexec prevented its independently authored smoke
binary from running. Dropped capabilities, non-root UID, and network/read-only limits remain.

Committed T01 snapshot: Ruff pass, strict Pyright 0 errors/warnings, 11 tests passed.
Committed T02 snapshot: Ruff pass, strict Pyright 0 errors/warnings, 35 tests passed.
Committed T03 snapshot: Ruff pass, strict Pyright 0 errors/warnings, 40 tests passed.
Full T04 checkout on 2026-10-14:
- uv run ruff check: pass.
- uv run pyright: 0 errors, 0 warnings.
- uv run pytest -m "not slow" -q: 64 passed in 17.14 seconds.
- uv run alth --json doctor: status ok, exit 0.
- Both CLI aliases --help exit 0; schema export is deterministic.
- Installed worker/main, worker entrypoint, canonicalizer, and model source SHA-256 hashes
  match the checkout exactly; docs/image-worker-sources.json records them.
- Nine real Docker checks: tool startup, C compile/strip, all-type contract round trips,
  echo/order/concurrency, network/root/input isolation and limits, timeout removal,
  OOMKilled reporting, wrong identity, and explicit unimplemented handler failure.
- Source guards reject private/truth/unstripped/O0/source/test paths and escaping symlinks.
- Artifact concurrency/corruption/traversal and malformed-result/cleanup failure checks pass.

GitHub checks and sandbox jobs for the latest T01-T03 PR heads passed. T00's latest checks
passed. T04 sandbox CI at 59cbbd4 failed with 59 passed / 5 setup errors while building the test image.
BuildKit cannot use a local config image ID directly in FROM (moby/moby issue 39769).
The test builder now uses a local named alias checked against that exact image ID, exposes
build stderr on failure, and executes the resulting image by inspected immutable ID.
The sandbox assertions and production policy are unchanged. At 0eec482, both quick checks
and the full sandbox job passed on GitHub (run 38554858480); locally all 64 tests passed.
Initial T00 CI failed under forced terminal color; setting a stable plain-text CI environment
fixed captured help output with the test assertions unchanged.

OSV checked all 73 locked Python dependencies and reported zero advisories on 2026-10-13.
Trivy 0.75.0 scans report 2,670 build-image and 64 analysis-image findings, retained in
docs/image-audit.json. This is not a claim of zero vulnerabilities. Raw scans and diagnostic
logs are in /home/edmond/.cache/aletheia. Exact immutable image IDs are in versions.lock.md.

## Reviews, blockers, and next eligible work

Design conversion approved by the author on 2026-10-14; retention checks covered 48 tables,
102 headings, and all extracted text. No F1-F7 or HR gate is approved. Review packages are the
task PR diffs, acceptance tests, schemas, pin/license/audit evidence, and these task states.

Ghidra 11.4.3 bundled Java vulnerabilities need reachability/disposition review before T09/T12
introduce untrusted binary analysis. Keep the required 11.x pin until an explicit compatibility
decision changes it; do not swap JARs silently. The current worker has no analysis handlers.
Some Python findings are from bundled SBOMs rather than the active locked environment.
The build header-package findings do not constitute a WSL host-kernel assessment.

WSL currently exposes about 15 GiB despite 32 GB physical RAM. Default concurrency is four;
T09 must measure peak Ghidra RAM and establish headroom before concurrent analysis. Do not
silently raise WSL memory or restart Docker. Host-kernel/daemon vulnerability assessment,
dynamic exploit reachability, slow end-to-end checks, and X1-X10 are not validated.

The author approved the foundation direction and authorized the T04 CI fix, T05, and preparation
of T06 for review on 2026-10-14. No future HR gate or security exception is approved. T06 and protected
fixture proposals require their explicit HR review. T09 must wait for analyzer option proposal F6;
T15 must wait for T11 and its HR, and T17 retains T08/T02/T03 dependencies. Follow the spec roadmap.
T16 owns the engine and construction of complete effective harness/cache inputs. No general
orchestrator, emulation, corpus binaries, sources, grading, replay, reports, or provider runs exist yet.

Author clarification for T05 (2026-10-14): every source definition, including main and trivial
helpers, must be annotated. T08 still derives exact non-triviality from O0 instructions.

## Cloud handoff stop (2026-10-14)

The author requested an immediate stop on this PC and a handoff to a cloud agent.
No further implementation is authorized here. Existing T05 work is checkpointed on
t05-corpus-lint; the cloud agent must clone that branch, not the docs-only main.
No cloud agent has been started or messaged. See CLOUD-HANDOFF.md for resume instructions.

Last T05 working-tree validation before the stop:
- uv run ruff check: pass.
- uv run pyright: 0 errors, 0 warnings.
- uv run pytest -m "not slow" -q: 97 passed in 20.18 seconds (64 foundation + 33 T05).
- git diff --check: pass.
These are workstation results, not cloud validation. No T05 GitHub CI has run yet.
Acceptance initially failed because aletheia.corpus.lint did not exist; later independent
negative cases exposed source parsing/policy gaps before their fixes. Assertions remain intact.

Next eligible cloud work: inspect the checkpoint, reproduce checks in its own environment,
finish T05 and prepare T06's five programs/native tests for author review. T06 HR and the
Ghidra security review remain open. No protected fixtures or Phase 1A exit gates are approved.


## Cloud resumption (2026-10-14)

Existing clean /workspace/aletheia checkout switched to t05-corpus-lint at
9864f6e1b95130e60f9e290be28868780e678533; expected implementation checkpoint
039b6fcd6121f27553e0c3a47e40ba6936703042 verified as an ancestor.
Managed environment: ccarenv_b64_Y2NhcmVudl9iNGY4ZTZiM2I1MDA4MTkxOGFhMjI3NTY0OWRhY2E5Mg.
Debian 13 Linux amd64, non-root UID/GID 1000, 4 CPU quota, 32 GiB memory limit,
about 30 GiB disk available. Docker 28.4.0/containerd 1.7.28/runc 1.3.0 differ
from historical host pins; those pins have not been changed. No security exception.
Pinned uv 0.13.0 and Python 3.12.15 downloaded from the locked release URLs and
verified against their recorded SHA-256 values. uv sync --frozen succeeded.

T05 review found the documented --program selector absent. Two independent CLI
selection/missing-program acceptance checks first failed (exit 2); the selector
was implemented with existing positional-directory behavior preserved. Cloud checks:
- uv run ruff check: passed.
- uv run pyright: 0 errors, 0 warnings.
- env -u FORCE_COLOR TERM=dumb NO_COLOR=1 uv run pytest -m "not slow and not integration" -q:
  90 passed, 9 deselected (full sandbox validation still pending).
- git diff --check: passed.

GitHub API and the locked Ubuntu snapshot domain initially denied HTTP CONNECT
with 403. api.github.com and snapshot.ubuntu.com additions saved in the managed
environment draft; saving does not apply/publish them. Full image rebuilding,
full sandbox validation, live GitHub checks, and T05 draft PR creation remain pending.
Cloud-local build adaptations live outside the checkout: writable Buildx/uv caches
and a combined CA bundle mounted as a BuildKit secret, with TLS/signature/hash
verification preserved. Historical image inventory/audit/source records are unchanged.


## Completed cloud validation (2026-10-14)

T05 source at 62c861dc7321e0bd987da7b8d744b11f12a53d8d was validated as part of
T06 source checkpoint 3d6f2c9 (same Python package). Full normal command:
env -u FORCE_COLOR TERM=dumb NO_COLOR=1 python3 /workspace/.setup/aletheia/cloud/run-checks.py
uv run pytest -m "not slow" -q -s: **109 passed in 87.40 seconds**.
This includes all 99 foundation/T05 tests (64 foundation + 35 T05) and 10 T06 checks.
Ruff passed; strict Pyright reported 0 errors and 0 warnings. Both aliases --help
and doctor exited 0 with cloud-local image fields. Original configuration/lock bytes
were restored; git diff --check and protected setup-file diff checks passed.
No slow tests currently exist; full end-to-end, replay, and X1-X10 remain unvalidated.

The initially missing --program selector was repaired without weakening acceptance.
The initial full run had 4 worker setup failures (mode 0600/root-owned test script under
cloud umask 0077), diagnosed from container stderr. Validation umask 0022 fixed access.
Subsequent VFS/scan disk exhaustion interrupted checks and was not counted as passing.
After storage recovery and verified analysis-image flattening, all seven worker tests
passed in 63.63 seconds; the final complete 109-test run passed.

Cloud image IDs, complete flattening proof, installed worker source hashes, and fresh
static scan evidence are recorded in docs/cloud-environment.json and explained in
docs/cloud-environment.md. Host versions remain different from historical pins, and
Ghidra security review remains open. No provider calls, protected fixture edits,
automatic merges, image/package releases, or environment publication were performed.
Network destinations now respond; no external setup access blocker remains.
Reusable managed install/start instructions are being updated from the old main-only
bootstrap to the tested checkpoint workflow. T05 review and T06 HR remain separate.


## T06 cloud review preparation (2026-10-14)

The complete source/native acceptance run above exercised original T06 code at
3d6f2c9. After a documentation-only T05 base update, equivalent source commits are
cc05cca4e48850adf5c8afd5e3511526607656b3 and dc74d4e18ab59a479ed27fe29a1b979ee9a0f13d.
The source changes are unchanged by the rebase; later commits record review evidence.
The expected PC checkpoint 039b6fcd6121f27553e0c3a47e40ba6936703042 remains an ancestor.

- Full normal cloud suite: 109 passed in 87.40 seconds; Ruff/Pyright passed.
- alth --json corpus lint: 5 programs, 0 errors. Both CLI aliases --help exit 0.
- Native assertions: crc32tool 19, adlerfletch 16, hashtable 35, b64 89,
  cmd-dispatch 13; total 172, active under NDEBUG. File/stdin, empty input,
  and missing-file behavior passed for every program.
- Build image: sha256:0d62a62235770bf4f62cfb2c3ad0bf532d593287fa25a3f544c188fa49cac959.
- Analysis image: sha256:b3148c7aa100c6bfc7a92c21862f828fd86b76d69528738e808b4b6c034230c5.
- Pinned Capstone 5.0.9/pyelftools 0.33 are installed in the approved corpus group.
- Tested installer repeat reused the inspected image IDs with the exact input/source
  fingerprint. Cached outputs and tool activation are reusable; live processes are not.
- Trivy freshly scanned the final compiler image: 2,670 findings; analysis scan of
  the filesystem proven equal to the flattened image: 64 findings (including 3 critical,
  23 high). Reachability/disposition is pending; no exception is approved.

Review source/annotation/callback inventory and native results in docs/corpus-review.md.
T05 draft: https://github.com/gitedmond/aletheia/pull/6 -> t04-sandbox.
T06 draft: https://github.com/gitedmond/aletheia/pull/7 -> t05-corpus-lint.
No automatic merge is authorized. No protected
fixtures/mappings/analyzer settings or additional dependencies were created.

**Next step: author T06 annotation/semantic HR review. Stop before T07/dependent work.**
The separate Ghidra security review and all future applicable HR gates remain open.

### 2026-10-14 — authorized PR review follow-up

The author authorized ready-for-review conversion, CodeRabbit review, necessary
corrections, and merges of the existing PR stack. This supersedes the earlier
no-merge instruction for PRs #1–#7; future task/security prerequisites remain.
CodeRabbit skipped drafts, then skipped non-default base branches; manual review
requests were posted on #2–#7. PR #1 fixes disable checkout credential persistence
and clarify the quick test selection. T02 reproduces and fixes six exported-schema
acceptance gaps (invalid/hashless/private paths and unknown/cross-family variants),
retains runtime validation, and checks committed exports against a fresh export.
`uv run ruff check`, `uv run pyright`, both contract test files (30 passed), and
`git diff --check` passed in the pinned cloud Python environment. Merge results and
remaining review dispositions will be recorded after live CI/review checks.


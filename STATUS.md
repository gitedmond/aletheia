# Aletheia status

Active phase: Phase 1A. The T00-T04 foundation is implemented and validated.
Author-confirmed employment/IP review: not applicable. No private agreement contents recorded.
Checkout: /home/edmond/src/aletheia, edmond UID/GID 1001. Remote: https://github.com/gitedmond/aletheia.
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
- DESIGN.md is the maintained design source after conversion; semantic author review is pending.
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
| T04 | done: bounded Docker runner and worker protocol | PR #5 draft | t04-sandbox implementation commit; see Git log |
| T05-T27 | planned dependency roadmap in spec Section 17 | Required HR gates pending | none |
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
- Nine real Docker checks: tool startup, C compile/strip, all-type contract round trips,
  echo/order/concurrency, network/root/input isolation and limits, timeout removal,
  OOMKilled reporting, wrong identity, and explicit unimplemented handler failure.
- Source guards reject private/truth/unstripped/O0/source/test paths and escaping symlinks.
- Artifact concurrency/corruption/traversal and malformed-result/cleanup failure checks pass.

GitHub checks and sandbox jobs for the latest T01-T03 PR heads passed. T00's latest checks
passed. T04 remote CI is pending until the final head completes; do not infer success.
Initial T00 CI failed under forced terminal color; setting a stable plain-text CI environment
fixed captured help output with the test assertions unchanged.

OSV checked all 73 locked Python dependencies and reported zero advisories on 2026-10-13.
Trivy 0.75.0 scans report 2,670 build-image and 64 analysis-image findings, retained in
docs/image-audit.json. This is not a claim of zero vulnerabilities. Raw scans and diagnostic
logs are in /home/edmond/.cache/aletheia. Exact immutable image IDs are in versions.lock.md.

## Reviews, blockers, and next eligible work

Design conversion semantic review remains pending; retention checks covered 48 tables,
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

The next implementation task is T05 after review of this foundation milestone. T06 and protected
fixture proposals require their explicit HR review. T09 must wait for analyzer option proposal F6;
T15 must wait for T11 and its HR, and T17 retains T08/T02/T03 dependencies. Follow the spec roadmap.
T16 owns the engine and construction of complete effective harness/cache inputs. No general
orchestrator, emulation, corpus binaries, sources, grading, replay, reports, or provider runs exist yet.

# Aletheia cloud agent handoff

Prepared 2026-10-14. This file is the resume prompt: give the cloud agent this entire file.
The author asked to stop implementation on the Windows PC and continue in the cloud.
Only checkpointing and handoff documentation were done after that request.

## Start here: clone the checkpoint, not main

Repository: https://github.com/gitedmond/aletheia (public, personal, original code MIT).
Main currently contains the document baseline; the implementation is on stacked task branches.
Use the cloud Linux filesystem. Do not mount OneDrive, /mnt/c, or the old workstation.

```bash
mkdir -p "$HOME/src"
git clone --branch t05-corpus-lint https://github.com/gitedmond/aletheia.git "$HOME/src/aletheia"
cd "$HOME/src/aletheia"
git status --short
git rev-parse HEAD
git merge-base --is-ancestor 039b6fcd6121f27553e0c3a47e40ba6936703042 HEAD
```

Expected code checkpoint: **039b6fcd6121f27553e0c3a47e40ba6936703042**.
The branch also contains a later documentation commit with this handoff. Verify the code
checkpoint is an ancestor; record the actual checkout SHA in STATUS.md.
If the directory already exists, inspect it and preserve changes rather than replacing it.
If the expected branch/commit is inaccessible, report the blocker; do not start from main.

Read AGENTS.md, then SPEC-PHASE-1A.md **v0.4 in full**, STATUS.md, and DESIGN.md
(design v0.4.1, approved conversion), including tables and appendices.
The spec is authoritative for Phase 1A; intentional design deviations are in Section 21.
Do not use the Phase 1B spec to override Phase 1A. Report actual remaining contradictions.
Read docs/corpus-lint.md, docs/toolchain-review.md, versions.lock.md, uv.lock,
docker/ Dockerfiles, and .github/workflows/checks.yml before environment changes.

## Authorized scope and decisions

Resume T05, then prepare T06 for the author's review. Keep the Ghidra security review open.
Do not expand scope into Phase 1B, a general orchestrator, provider calls, publication,
or future tasks gated on human review. No cloud agent was started or messaged from the PC.

The author has already confirmed:
- Employment/IP prerequisite is **not applicable**; do not ask for private agreements.
- Public gitedmond/aletheia and MIT original code/planned original development corpus.
- Design conversion and T00-T04 foundation direction approved on 2026-10-14.
- T04 CI repair, T05 completion, and T06 preparation for review authorized.
- Every source function definition, including main and trivial helpers, must have an
  annotation. T08 still determines exact non-triviality from O0 instruction counts.
- uv_build is approved build-only; required existing locked upstream dependencies are approved.
  New dependencies still require author approval.
- Project jobs execute by full local sha256 image ID; base images use registry manifest digests.
  No registry distribution or package release was authorized.
- LLM disabled, provider empty, cost cap zero. Optional lane G and held-out/provider
  infrastructure deferred to Phase 1B; agent power analysis awaits actual agent data.

C1-C7 in spec Section 0.2 remain settled:
1. Inputs at 0x78000000; validate all emulator regions and guard gaps.
2. Deterministic correct, family-only, and genuinely false mutation scenario/case runs;
   retain one active claim.
3. Registered unprobed variant => UNVERIFIABLE no_pack. Incomplete coverage cannot
   support a family contradiction; a supported clean match may verify a family claim.
4. T15 waits for T11 plus its human review; production arity analysis and real callers
   establish self-test binding.
5. Cache payload omits claim identity, reattaches requester ID, and uses semantic keys
   containing all verdict-affecting configuration.
6. Record FindCrypt's shared backend. Scripted claims drive the independent reliability
   aggregate; tool-conditioned results remain separate and FindCrypt labeled.
7. Track unwritten .bss and initially zero-filled mutable .data as
   uninitialized_state_reads, restoring initialization state per invocation.

No protected golden, fixture, mapping, analyzer setting, F1-F7 proposal, or HR gate is approved.
Acceptance of the above decisions is not approval of future fixture contents.
Do not auto-merge the draft PR stack. Inspect live GitHub state before any PR changes.
Task-sized draft PRs are the review workflow; merging needs appropriate author authorization.
Use the cloud's own authentication for pushes/PRs; never transfer workstation credentials.

## Saved implementation and review state

| Task | Saved state | Draft PR / base |
|---|---|---|
| T00 | Scaffold and CLI aliases aletheia / alth; validated | #1 -> main |
| T01 | Pinned tools/images, doctor, license/audit inventory; validated, security review open | #2 -> t00-scaffold |
| T02 | Contracts, canonical hashing, nine exported schemas; validated | #3 -> t01-toolchain |
| T03 | SQLite seven tables, partial active uniqueness, opaque CAS artifacts/cache foundations; validated | #4 -> t02-contracts |
| T04 | Bounded Docker runner and worker protocol; local and GitHub validation passed | #5 -> t03-storage |
| T05 | Source linter WIP checkpoint; 33 new tests, final task review/PR pending | t05-corpus-lint derives from t04-sandbox |
| T06 | No programs or native tests authored yet; prepare for author review | HR pending |
| Later tasks | Roadmap only, requirements in spec Section 17 | All applicable reviews pending |

Draft PRs:
- https://github.com/gitedmond/aletheia/pull/1
- https://github.com/gitedmond/aletheia/pull/2
- https://github.com/gitedmond/aletheia/pull/3
- https://github.com/gitedmond/aletheia/pull/4
- https://github.com/gitedmond/aletheia/pull/5

Latest observed checks for PRs #1-#5 passed on 2026-10-14. Recheck live state.
T04 CI repair commit: 0eec482. Successful run:
https://github.com/gitedmond/aletheia/actions/runs/38554858480
Before that repair, T04 CI at 59cbbd4 had 59 passed / 5 setup errors:
BuildKit cannot use a local config image ID directly in FROM.
The test builder now tags the pinned local ID temporarily, verifies the alias against the
ID before/after build, and runs the resulting image by inspected ID. Assertions and
production policy were unchanged. Do not regress this portability fix.

## Evidence: workstation results, not cloud results

Last T05 source validation before stopping:
- uv run ruff check: passed.
- uv run pyright: 0 errors, 0 warnings.
- uv run pytest -m "not slow" -q: **97 passed in 20.18 seconds**.
- git diff --check: passed.

These checks precede checkpoint packaging/documentation edits; no implementation edits followed.
T05 acceptance first failed with a missing aletheia.corpus.lint module.
Independent negative cases then exposed parsing/policy gaps before fixes.
The 97 tests comprise 64 foundation and 33 T05 cases.
No T05 PR exists yet, and no remote T05 CI has run. A branch-only push does not trigger the
current workflow, which runs for main pushes and pull requests.

Foundation checks included real Docker isolation, worker protocol, compile/strip, tool startup,
timeouts/removal, OOM reporting, identities, concurrency, and private-path/symlink rejection.
Installed worker source hashes were checked against source and recorded in
docs/image-worker-sources.json. This is workstation-image evidence, not a claim about rebuilt images.
Slow end-to-end checks, the full pipeline, replay, and all X1-X10 remain unvalidated.

## Bootstrap in the cloud: inspect, then use pinned inputs

If this is a managed cloud environment, read its available cloud runtime skill first
(network proxy, CA trust, Docker access). Use the cloud runtime's configuration and secrets.
Inspect OS, x86_64 architecture, user/UID, CPU, memory/disk, Git, uv, and Docker client/server
with read-only commands. Do not assume installed tools, permissions, or Docker isolation work.
Use a non-root job identity. Do not reinstall Docker, start privileged Docker-in-Docker,
or expose the Docker socket inside workers to bypass an unavailable sandbox.

Required target is Linux amd64, Python 3.12.15, uv 0.13.0, Ghidra 11.4.3, JDK21,
Capstone5.0.9, Unicorn2.1.4; all exact inputs are in versions.lock.md / uv.lock / Dockerfiles.
Do not silently change pins to suit the cloud. Report incompatible architecture/tools.
Follow the checksum-verified uv installation in .github/workflows/checks.yml if needed;
use uv sync --frozen, never regenerate the lock as a bootstrap shortcut.

The workstation build/analysis image IDs in aletheia.toml and versions.lock.md will not
exist in the cloud. They are local config IDs, **not pullable registry digests**.
Build from the pinned Dockerfiles, after obtaining the ignored CA bootstrap input:

```bash
curl -fsSL --retry 2 -o docker/ca-certificates.deb https://archive.ubuntu.com/ubuntu/pool/main/c/ca-certificates/ca-certificates_20260601~24.04.1_all.deb
echo '6bac2a01979e210d9eac1d4d56747ec709ea60654744d66705dc3c36e7629e50  docker/ca-certificates.deb' | sha256sum -c -
docker build -f docker/build.Dockerfile -t aletheia-build .
docker build -f docker/analysis.Dockerfile -t aletheia-analysis .
docker image inspect aletheia-build --format '{{.Id}}'
docker image inspect aletheia-analysis --format '{{.Id}}'
uv sync --frozen
```

Respect runtime proxy/CA requirements when executing these commands.
Use full inspected IDs for job execution. Do not publish these images.
The workflow shows how to temporarily replace the two image IDs in aletheia.toml;
integration tests currently read that file. Back up/restore tracked environment files
before commits and record cloud-local IDs/evidence separately. Doctor also compares
config against versions.lock.md, so a cloud doctor check needs corresponding temporary
image lock fields. Do not overwrite historical workstation source/audit evidence or
claim it applies to a newly built image. Propose a minimal reviewed persistent cloud
environment record if needed; don't redesign environment orchestration.

Host Docker29.1.3/containerd2.2.1/runc1.3.4 are recorded pins; cloud may differ.
Report doctor mismatches honestly rather than weakening checks/changing required pins.
Old Docker aliases, audit caches, local .venv, Windows gh helper, and raw workstation
logs are not transferable prerequisites.

Run normal validation:
```bash
uv run ruff check
uv run pyright
env -u FORCE_COLOR TERM=dumb NO_COLOR=1 uv run pytest -m "not slow"
git diff --check
```

If Docker is unavailable, source/unit work can continue with
pytest -m "not slow and not integration", but record the full sandbox check as blocked.
A reduced test selection is not full task validation. Do not pretend setup failures are passes.
Run applicable slow checks before human review gates when such checks exist.

## Next implementation steps and review package

1. Review T05 WIP against spec Section 4.1 and docs/corpus-lint.md, independently reproduce
   its contract checks, and make only necessary corrections. Current files:
   aletheia/corpus/lint.py, aletheia/cli.py, tests/unit/test_corpus_lint*.py.
   No new dependency was added. This is a source linter, not a complete C parser,
   preprocessor, compiler, or proof of indirect-target completeness. Native builds and
   emitted-code inspection remain later tasks; do not overclaim its guarantees.
2. When T05 acceptance and normal checks pass in the cloud, update STATUS.md with exact
   commit/commands/counts, environment IDs, blockers, and pending reviews. Open a task
   draft PR against t04-sandbox if that base remains unmerged; inspect the stack first.
   Attach any created PR to the chat when the tool is available.
3. Prepare T06's five C17 programs and their native unit tests exactly from spec Sections
   4.2 and 10.4, under corpus/tierA/<program>/{src,tests,Makefile}. Programs are crc32tool,
   adlerfletch, hashtable, b64, and cmd-dispatch; verify names/signatures from the spec.
   Include required shared noinline support, every-definition annotations, indirect
   target lists, supported/unsupported variants, file/stdin input and neutral hex output.
   Preserve runtime .bss table initialization cases and actual main-to-target call paths.
   Use libc only and native test assertions that remain active with NDEBUG.
   Compile/run in the pinned build sandbox; do not move binary parsing to the host.
4. Present T06 source, annotation/variant/indirect-call inventory, native vector results,
   linter results, exact build commands/image ID, and limitations as a concrete review
   package. **Stop for T06 author HR approval before dependent work.**
   Do not create protected probes/goldens/near-miss fixtures along the way.
5. Keep the rest of Section 17 as the dependency roadmap. T09 waits for F6 analyzer
   options and the security prerequisite; T15 waits for T11 plus its human review;
   T17 retains T08/T02/T03 dependencies. T16 owns the engine/effective cache inputs.
   Protected F1-F7 proposals, HR gates, replay/reports, and X1-X10 are separate work.

## Open risks and boundaries

Ghidra11.4.3 bundled Java vulnerabilities require reachability/disposition review before
T09/T12 untrusted binary analysis. No security exception was approved.
docs/image-audit.json records **2,670 build-image and 64 analysis-image findings**.
The 73 locked Python dependencies had zero OSV advisories on 2026-10-13, not a blanket
image-security clearance. Bundled SBOM findings and header-package findings need accurate
interpretation; no host-kernel assessment or dynamic exploit reachability test passed.
Rebuilt cloud images require their own evidence.

The old WSL runtime exposed about15GiB RAM. The cloud must measure its own resources;
default concurrency4 and 6GiB/job require headroom. T09 peak Ghidra memory is unmeasured.
Keep dropped capabilities, non-root execution, no-new-privileges, no network, read-only
root/input mounts, bounded scratch, CPU/PID/memory/time limits and deterministic budgets.
Production worker handlers remain unimplemented and fail explicitly; no analyzer pipeline exists.

No LLM/classifier/embeddings in verification or grading. Verifier code must not read truth,
source, annotations, unstripped binaries, or corpus tests. Ground truth uses symbols plus
Capstone; verifier uses clean Ghidra, with no shared analysis helpers.
Untrusted binaries are parsed only inside sandbox jobs. Canonical outputs, pinned inputs,
deterministic instruction budgets, and explicit failures are mandatory.

Use one STATUS.md as the durable ledger: distinguish implemented, validated, awaiting
human review, and done; record commits, exact evidence, reviews, blockers, next eligible task.
Keep AGENTS.md lean and requirements in design/spec. Continue with task-sized branches/PRs.
No new chat, delegation, remote message, image/package publication, or automatic merge
is authorized merely by receiving this handoff.

## Document retention

DESIGN.md is the approved, maintained design source; do not repeat the DOCX conversion.
The original DOCX and original phase specs remain unchanged in the old Windows staging
folder and are not needed to resume from this repository. Historical retention evidence
is in STATUS.md and design conversion documentation. Do not recreate workstation paths,
copy secrets, or contact the old PC to obtain its caches.

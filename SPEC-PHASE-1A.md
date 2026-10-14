# Aletheia Phase 1a Implementation Spec

| Field | Value |
|---|---|
| Document | Phase 1a implementation spec |
| Version | 0.4 |
| Depends on | DESIGN.md v0.4.1 |
| Scope | Phase 1a only: thin vertical slice, no LLM first |
| Audience | The author, and AI coding agents working under the author's review |

---

## 0. How to Use This Spec

- This spec turns DESIGN.md into buildable work for Phase 1a. Read this spec first, then the
  DESIGN.md sections it references.
- **On conflicts, this spec wins for Phase 1a.** Every intentional deviation from DESIGN.md is
  listed in Section 21. Any other conflict is a bug: stop and raise it with the author.
- Keywords: **MUST** is required, **SHOULD** is expected unless there is a recorded reason,
  **MAY** is optional.
- Work is broken into tasks (Section 17). Each task has dependencies, deliverables, an acceptance
  test, and, where marked **HR**, a human review gate. A task is done only when its acceptance
  test passes and any HR gate is signed off.

### 0.2 Accepted clarifications (v0.2, 2026-10-13)

The author authorized recording these choices before implementation. Their normative details
are in the sections listed below; this table is a decision index, not a separate contract.

| Decision | Chosen fix | Sections |
|---|---|---|
| C1 | Move inputs to `0x78000000`; validate all memory regions and guard gaps before emulation | 10.3, T12 |
| C2 | Separate correct, family-only, and mutated scripted scenarios into deterministic, collision-free case runs | 6.7, 11.1, T17 |
| C3 | Explicitly handle registered but unprobed variants; incomplete family coverage cannot support a family-level contradiction | 10.4, X5 |
| C4 | T15 depends on T11 including its HR sign-off; self-tests use production arity analysis on real fixture callers | 10.4, T15 |
| C5 | Cache verification payloads without claim identity, keyed by semantic claim content and all verdict-affecting configuration | 7, T16 |
| C6 | Mark FindCrypt's shared backend; use scripted claims for the independent reliability aggregate and label FindCrypt results separately | 6.2, 11.3, 12.2, 14, T21 |
| C7 | Track unwritten `.bss` and initially zero-filled mutable `.data`; rename the flag to `uninitialized_state_reads` | 9, 10.3, 10.4, T12 |

### 0.1 Phase 1a scope

**In scope**

- 5 corpus programs, one build variant: `clang<pinned>-O2-x64-pie-hardoff`.
- Ground truth extraction, stripping, leakage checks, target lists.
- Claim types `algorithm_identity` and `call_relation`.
- Verifier methods: static call edges, static arity (internal), static constants (supporting),
  and emulation probe packs for 5 algorithm families.
- Claim sources: scripted claims, capa adapter, FindCrypt adapter.
- Grader, metrics per source, verifier reliability metrics.
- Storage, verdict cache, deterministic replay, reports.
- CLI only.

**Optional in 1a (may slip to 1b): lane G**

- LLM provider interface, a fake provider for tests, the Harness MCP Proxy, and the agent loop.
  LLM runs stay disabled by default (D23).

**Out of scope for 1a**

- MCP server, Ghidra plugin, other variants, traps, held-out split, `function_signature`,
  `function_purpose`, `struct_layout`, symbolic execution, classifier, human study.

### 0.3 Foundation decisions authorized with the implementation plan

- The employment/IP prerequisite is not applicable, as confirmed by the author.
- Public personal repository `gitedmond/aletheia` from inception; original code and dev corpus MIT.
- Non-root `edmond`, `/home/edmond/src/aletheia`; native Docker Engine in Ubuntu WSL2.
- `uv_build` is approved as build-only dependency. Required upstream/native/tool dependencies
  are permitted when pinned, license-reviewed, and vulnerability-checked.
- Bootstrap tools are pinned in T00; T01 completes the full pin and audit inventory.
- Local project images use full `sha256:<image ID>` references; downloaded bases use registry
  manifest digests. `env_digest` identifies the immutable local analysis image. No registry
  service, image distribution, or package publication is included.
- Draft verifiability before code; held-out infrastructure/providers are deferred to Phase 1B,
  power analysis until real agent data exists. Hosted spend stays zero; lane G is deferred.
- Every stored protocol record carries `schema_version`, default `1.0`; unknown versions fail.
- Counterexamples may include `matches_variant`; `unsupported_relocation` is a reason code.
- Job IDs are `j_` plus the full canonical job-input hash. Each Phase 1A run has one binary.
- T04's echo test uses an injected test-only worker handler for an existing production type.
  The five production job types are unchanged.

These decisions do not approve protected fixture contents, analyzer options, conversion
semantics, or future HR gates. The original Windows staging documents remain untouched.

---

## 1. Non-Negotiable Rules

These rules are also copied into `AGENTS.md` (Appendix A). Violating any of them fails review.

| ID | Rule |
|---|---|
| R1 | **No LLM, classifier, or embedding model in any verification or grading code path.** Verdicts and grades come only from deterministic code. |
| R2 | **The verifier never reads ground truth.** Code under `aletheia/verify/` MUST NOT import `aletheia/corpus/` or read `ground_truth.json`, unstripped binaries, source files, annotations, or corpus unit tests. Enforced by an import-boundary test and a runtime path guard. |
| R3 | **Ground truth and verifier share no analysis code.** Ground truth uses symbols plus capstone; the verifier uses Ghidra. This keeps their errors independent. |
| R4 | **Determinism.** No decision may depend on wall-clock time, thread scheduling, dictionary order, or unseeded randomness. Budgets are counted in instructions, not seconds. All JSON written for hashing is canonical (Section 6.1). |
| R5 | **Protected fixtures.** Files under `tests/golden/` and `tests/fixtures/` and all mapping tables are human-owned. Agents MUST NOT edit them. Changes require the author's approval (CODEOWNERS). |
| R6 | **Pinned everything.** Every external tool, rule set, image, and library version is pinned in `versions.lock.md` and recorded in run manifests. |
| R7 | **No silent fallbacks.** Anything the system cannot do produces an explicit verdict reason, error code, or counted exclusion. Nothing is dropped quietly. |
| R8 | **Tests first.** Every task lands with its acceptance test. A task whose test was changed to pass is not done. |
| R9 | **Dependencies.** Only dependencies listed in Section 2 may be used. Anything new needs the author's approval, a license check, and a vulnerability scan. |
| R10 | **Untrusted binaries are parsed only inside the sandbox** (Ghidra, capa, emulation). The host process handles only files it produced itself. |

---

## 2. Environment and Pins

### 2.1 Host

- Windows 11 with **WSL2, Ubuntu 24.04 LTS**. All project work happens inside WSL2.
- The repository lives in the WSL2 filesystem (for example `~/src/aletheia`), **not** under
  `/mnt/c`, for file-system performance.
- Docker Engine inside WSL2, or Docker Desktop with the WSL2 backend.
- Hardware: 32 GB RAM, RTX 5070 Ti (unused in 1a). Default worker concurrency: **4** (each
  Ghidra job is expected to peak at 2 to 4 GB; measured in T09 and recorded).

### 2.2 Pinned toolchain

Exact versions are chosen at T01 (latest stable on that day unless noted) and written to
`versions.lock.md` with download URLs and SHA-256 hashes.

| Component | Pin | Used by |
|---|---|---|
| Python | 3.12.x | Host and containers |
| uv | Latest stable | Dependency management, lockfile |
| ruff | Latest stable | Lint and format |
| pyright | Latest stable | Type checking (strict on `aletheia/`) |
| pytest | Latest stable | Tests |
| pydantic | v2 | Data models and JSON Schema export |
| typer | Latest stable | CLI |
| PyYAML | Latest stable | Pack and mapping files |
| jsonschema | Latest stable | Schema validation in tests |
| pyelftools | Latest stable | ELF parsing (ground truth and emulator loader) |
| capstone | 5.x | Ground-truth disassembly only (R3) |
| unicorn | 2.x | Emulation |
| clang and LLVM binutils | One pinned major version | Build image |
| Ghidra | Latest stable 11.x at T01 | Analysis image |
| JDK | The version the pinned Ghidra requires (JDK 21 for current 11.x) | Analysis image |
| pyghidra | Matching the pinned Ghidra release | Analysis image |
| GhidraFindcrypt | antoniovazquezblanco/GhidraFindcrypt, release matching the pinned Ghidra | Analysis image |
| capa | Latest stable at T01 | Analysis image |
| capa-rules | The tag matching the pinned capa release | Analysis image |

License review of capa, capa-rules, and GhidraFindcrypt is recorded in `LICENSES.md` at T01.

### 2.3 Container images

| Image | Contents | Network |
|---|---|---|
| `aletheia-build` | clang, LLVM binutils, make | Build time only |
| `aletheia-analysis` | JDK, Ghidra, pyghidra, GhidraFindcrypt, capa plus rules, Python 3.12 with unicorn, pyelftools, and the `aletheia` package | Runs with `--network none` |

Every analysis job runs in a fresh `aletheia-analysis` container: `--network none`, read-only
root, tmpfs `/scratch`, non-root user, CPU, memory (6 GB), and PID limits. The job directory is
mounted read-only for inputs and a separate directory is mounted writable for outputs.

---

## 3. Repository Layout (Phase 1a)

```
aletheia/                        # public repo root
  AGENTS.md                      # Appendix A
  CODEOWNERS                     # protects tests/golden, tests/fixtures, mappings
  DESIGN.md
  SPEC-PHASE-1A.md
  LICENSES.md
  versions.lock.md
  pyproject.toml
  uv.lock
  aletheia.toml                  # default config (Section 8)
  docker/
    build.Dockerfile
    analysis.Dockerfile
  spec/
    claims-v1/                   # exported JSON Schemas (Section 6)
  algorithms.yaml                # algorithm families and variants (Section 4.3)
  packs/                         # probe packs (Section 10.4)
    crc32.yaml
    adler32.yaml
    fnv.yaml
    djb2.yaml
    base64.yaml
  mappings/                      # human-owned tool label mappings (R5)
    capa.yaml
    findcrypt.yaml
  corpus/
    tierA/<program>/src/*.c
    tierA/<program>/tests/*.c
    tierA/<program>/Makefile
  aletheia/                      # Python package (published as aletheia-re)
    __init__.py
    cli.py
    config.py
    schema/                      # pydantic models, canonical JSON, schema export
    store/                       # sqlite, artifact store
    sandbox/                     # docker job runner (host side)
    worker/                      # job handlers (container side)
    corpus/                      # build pipeline, ground truth, lint, leakage
    analysis/                    # Ghidra session wrapper (container side)
    verify/
      engine.py
      static_edges.py
      static_arity.py
      static_constants.py
      emulate/                   # loader, memory, stubs, harness
      probes/                    # pack loader, generators, oracles, runner
    sources/
      scripted.py
      capa_adapter.py
      findcrypt_adapter.py
    grade/
    metrics/
    report/
    replay.py
    llm/                         # lane G: interfaces only, disabled by default
  tests/
    unit/
    integration/
    selftest/
    golden/                      # human-verified expected outputs (R5)
    fixtures/
      near_miss/<family>/*.c     # human-reviewed near-miss implementations (R5)
  build/                         # gitignored: corpus build outputs
  runs/                          # gitignored: run records
  artifacts/                     # gitignored: content-addressed store
```

---

## 4. Corpus (5 Programs)

### 4.1 Authoring rules

1. Plain C17, no third-party dependencies, libc only.
2. **Function names are unique within a program** (no two static functions share a name).
3. Every source function definition, including `main` and trivial helpers, carries annotations
   on the lines directly above its definition. The author approved this conservative T05
   convention on 2026-10-14; exact non-triviality still comes from the O0 instruction count at T08:
   - `// @algorithm <family>/<variant>` or `// @algorithm none`
   - Optional `// @indirect-targets <fn1>,<fn2>,...` on any function that contains an indirect
     call, listing every function it can reach indirectly.
4. Functions that are scoring targets are marked `ALETHEIA_TARGET`, defined in a shared header as
   `__attribute__((noinline))`. This guarantees they exist at O2 in Phase 1a. (Recorded as a
   realism trade-off in Section 21; Phase 2 removes it.)
5. No strings that name the program or its algorithms (no "usage: crc32tool", no "CRC32 ok").
   Messages are neutral ("ok", "error", "usage: <in> <out>").
6. No `__attribute__((constructor))` and no `.init_array` entries in Phase 1a programs.
7. `main` reads input from a file path or stdin, calls target functions, prints results as hex.
8. Every program has native unit tests under `tests/` that check target functions against the
   fixed vectors in Section 10.4. These tests are **never** visible to the verifier (R2).

### 4.2 Programs and target functions

Algorithm values refer to `algorithms.yaml` (Section 4.3). "Natural confuser" marks real code
patterns that commonly mislead tools. They are not traps; traps start in Phase 2a.

**P1 `crc32tool`**

| Function | Signature | @algorithm | Notes |
|---|---|---|---|
| `crc32_update` | `uint32_t (uint32_t crc, const uint8_t *buf, size_t len)` | `crc32/ieee` | Table-driven, table is `static const` in `.rodata`. `crc32_update(0, b, n) == zlib.crc32(b)` |
| `crc32_bitwise` | `uint32_t (const uint8_t *buf, size_t len)` | `crc32/ieee` | Bit loop with `0xEDB88320` |
| `jamcrc` | `uint32_t (const uint8_t *buf, size_t len)` | `crc32/jamcrc` | CRC-32 without the final XOR |
| `crc32_table_init` | `void (void)` | `none` | Fills a `static uint32_t[256]` in `.bss`. Natural confuser: contains the polynomial and a bit loop |
| `crc32_update_rt` | `uint32_t (uint32_t crc, const uint8_t *buf, size_t len)` | `crc32/ieee` | Uses the runtime table filled by `crc32_table_init`, which `main` calls. Expected verdict: INCONCLUSIVE `state_dependent` |
| `crc32_selftest` | `int (void)` | `none` | Reads the `.rodata` table and compares a known vector. Natural confuser for constant cross-references |
| `hex_print32` | `void (uint32_t v)` | `none` | Calls `printf` |

**P2 `adlerfletch`**

| Function | Signature | @algorithm | Notes |
|---|---|---|---|
| `adler32_update` | `uint32_t (uint32_t adler, const uint8_t *buf, size_t len)` | `adler32/zlib` | `adler32_update(1, b, n) == zlib.adler32(b)` |
| `adler32` | `uint32_t (const uint8_t *buf, size_t len)` | `adler32/zlib` | Wrapper: calls `adler32_update(1, buf, len)` |
| `fletcher16` | `uint16_t (const uint8_t *buf, size_t len)` | `fletcher16/std` | No pack in 1a. Expected verdict for claims on it: UNVERIFIABLE |
| `sum_file` | `int (const char *path, uint32_t *out)` | `none` | Calls `fopen`, `fread`, `fclose`, `adler32_update` |

**P3 `hashtable`**

| Function | Signature | @algorithm | Notes |
|---|---|---|---|
| `fnv1a_32` | `uint32_t (const uint8_t *buf, size_t len)` | `fnv/fnv1a-32` | |
| `fnv1_32` | `uint32_t (const uint8_t *buf, size_t len)` | `fnv/fnv1-32` | Multiply, then XOR |
| `djb2` | `uint32_t (const char *s)` | `djb2/add` | NUL-terminated input |
| `djb2_buf` | `uint32_t (const uint8_t *buf, size_t len)` | `djb2/add` | |
| `djb2a_buf` | `uint32_t (const uint8_t *buf, size_t len)` | `djb2/xor` | |
| `ht_create` | `ht_t *(size_t buckets, hash_fn_t fn)` | `none` | Calls `calloc` |
| `ht_insert` | `int (ht_t *t, const char *key, int value)` | `none` | **Indirect call** through `t->fn`. `@indirect-targets fnv1a_32,djb2_buf` |
| `ht_lookup` | `int (ht_t *t, const char *key, int *out)` | `none` | Indirect call through `t->fn`. Same targets |
| `ht_destroy` | `void (ht_t *t)` | `none` | Calls `free` |

**P4 `b64`**

| Function | Signature | @algorithm | Notes |
|---|---|---|---|
| `b64_encode` | `size_t (const uint8_t *in, size_t len, char *out)` | `base64/std-padded` | Writes exactly `4 * ceil(len / 3)` chars, no NUL; returns that count |
| `b64_encode_url` | `size_t (const uint8_t *in, size_t len, char *out)` | `base64/url-nopad` | URL-safe alphabet, no padding; returns chars written |
| `b64_decode` | `ptrdiff_t (const char *in, size_t len, uint8_t *out)` | `base64/std-padded-decode` | No decode pack in 1a. Expected verdict: UNVERIFIABLE |
| `b64_encoded_len` | `size_t (size_t len)` | `none` | |

**P5 `cmd-dispatch`**

| Function | Signature | @algorithm | Notes |
|---|---|---|---|
| `lookup_cmd` | `const cmd_t *(const char *name)` | `none` | Linear search calling `strcmp` |
| `dispatch` | `int (const char *name, int argc, char **argv)` | `none` | Indirect call through `cmd->handler`. `@indirect-targets cmd_hash,cmd_sum,cmd_help` |
| `run_command` | `int (int argc, char **argv)` | `none` | Ends with `return dispatch(...)`; may be emitted as a tail call |
| `cmd_hash` | `int (int argc, char **argv)` | `none` | Calls `fnv1a_32_local` |
| `cmd_sum` | `int (int argc, char **argv)` | `none` | Calls `sum8` |
| `cmd_help` | `int (int argc, char **argv)` | `none` | Calls `puts` |
| `fnv1a_32_local` | `uint32_t (const uint8_t *buf, size_t len)` | `fnv/fnv1a-32` | Duplicate of P3's function in a different program |
| `sum8` | `uint8_t (const uint8_t *buf, size_t len)` | `none` | Simple byte sum (no family in registry) |
| `log_msg` | `void (const char *fmt, ...)` | `none` | **Variadic**, calls `vfprintf`. Tests the arity rule's varargs exclusion |

### 4.3 Algorithm registry (`algorithms.yaml`)

Format: `<family>/<variant>`. A claim may name a family only (variant null).

| Family | Variants (1a) | Pack in 1a |
|---|---|---|
| `crc32` | `ieee`, `jamcrc`, `crc32c`, `bzip2` | Yes |
| `adler32` | `zlib` | Yes |
| `fletcher16` | `std` | No |
| `fnv` | `fnv1a-32`, `fnv1-32`, `fnv1a-64`, `fnv1-64` | Yes (32-bit variants; 64-bit variants recognized but not probed in 1a) |
| `djb2` | `add`, `xor` | Yes |
| `base64` | `std-padded`, `url-nopad`, `std-padded-decode` | Yes for the two encode variants only |

`crc32c` and `bzip2` have no corpus functions in 1a; they exist so that near-miss fixtures and
variant-level claims can name them.

---

## 5. Build Pipeline and Ground Truth

### 5.1 Variant

Variant ID: `clang<N>-O2-x64-pie-hardoff`, where `<N>` is the pinned clang major version.

Compile and link flags (exact):

```
-std=c17 -O2 -g -march=x86-64 -mtune=generic -fPIE -pie -fno-stack-protector
-U_FORTIFY_SOURCE -D_FORTIFY_SOURCE=0 -fcf-protection=none -fno-ident
-ffile-prefix-map=<src_root>=. -DNDEBUG -Wl,--build-id=none
```

An auxiliary **O0 build** (same flags with `-O0`) is produced only to count instructions for the
non-trivial rule. It is never given to any claim source or the verifier.

Builds MUST be reproducible: building twice produces byte-identical stripped binaries
(`SOURCE_DATE_EPOCH` fixed, sorted inputs, pinned image).

### 5.2 Outputs per program

```
build/<program>/<variant_id>/
  stripped/<sha256>.bin          # the only binary sources and the verifier see
  private/unstripped.bin         # ground truth only (R2)
  private/o0.bin                 # instruction counts only
  private/ground_truth.json      # Section 6.4
  targets.json                   # Section 6.5, given to all sources
  build.json                     # flags, tool versions, hashes
```

### 5.3 Ground truth extraction (capstone plus symbols, no Ghidra, R3)

1. **Function entries.** From the unstripped `.symtab`: every `STT_FUNC` symbol with
   `st_size > 0` in an executable section. Record `name`, `address` (link-time VA, which is the
   canonical address for PIE at image base 0), and `size`.
2. **Annotations.** Parse each source file. An annotation block is one or more `// @...` lines
   immediately above a line containing a function definition (the function name followed by
   `(` and, on that or a following line, `{`). The linter (T05) rejects anything ambiguous.
3. **Name to address.** Match annotated names to symbols.
   - Symbols matching `^(.+)\.(constprop|isra|part)\.\d+$` are clones: `clone_of` is the base
     name, category and algorithm are inherited.
   - Symbols matching `^(.+)\.cold(\.\d+)?$` are split cold parts: excluded, reason
     `cold_split`.
   - Annotated names with no symbol: excluded, reason `fully_inlined`.
4. **Non-trivial.** Count instructions in the O0 build's symbol range with capstone. More than
   10 instructions is non-trivial; otherwise excluded, reason `trivial`.
5. **Scorable** = present, non-trivial, not excluded.
6. **Call edges.** Disassemble each function's `[address, address + size)` with capstone:
   - `call rel32` to a function entry: edge `direct`.
   - `jmp rel32` to a function entry outside the current function's range: edge `tail`.
   - `call` or `jmp` to a PLT stub: resolve the stub to its import through `.rela.plt`; edge
     `direct` (or `tail`) with callee `import:<symbol>`.
   - `call qword ptr [rip + X]` where X is a GOT slot with a `GLOB_DAT` or `JUMP_SLOT`
     relocation: callee `import:<symbol>`.
   - Any other `call reg` or `call mem`: an indirect site. Ground-truth indirect edges come only
     from `@indirect-targets` annotations, kind `indirect`.
7. **Source signature** (informational only in 1a): from DWARF. ABI signature extraction is
   deferred to 1b (Section 21).
8. **Targets.** `targets.json` lists every scorable function's canonical address, sorted. It
   contains no names, algorithms, or other ground-truth content.
9. **Leakage check.** Scan the stripped binary for: every function name of 4+ characters, every
   `@algorithm` and `@indirect-targets` string, `.c` and `.h` file names, and the source root
   path. Any hit fails the build.

### 5.4 Splits

All 5 Phase 1a programs are **dev split**. There is no held-out split in 1a, so every 1a number
is a dev number and is labeled as such in reports. The held-out split starts in 1b
(`aletheia-private`).

---

## 6. Data Contracts

All records are pydantic v2 models in `aletheia/schema/`. JSON Schemas are exported to
`spec/claims-v1/` by `alth schema export` and checked into the repo. Unknown fields are rejected.

### 6.1 Canonical JSON and hashing

- UTF-8, object keys sorted, separators `,` and `:` with no whitespace, no NaN or Infinity.
- Addresses are strings: `"0x"` plus lowercase hex, zero-padded to at least 8 digits
  (`"0x00001230"`).
- Floats are rounded to 6 decimal places before serialization.
- Content hash = SHA-256 of the canonical bytes. Fields marked **informational** (timestamps,
  hostnames) are excluded before hashing.

### 6.2 Claim (Phase 1a subset)

| Field | Type | Rules |
|---|---|---|
| `schema_version` | string | `"1.0"` |
| `claim_id` | string | Deterministic: `"c_"` plus the first 24 hex chars of the SHA-256 of the canonical claim without `claim_id`. Assigned at intake |
| `client_ref` | string or null | Optional |
| `run_id` | string | The source run that produced the claim |
| `source` | object | `{origin, source_id, shares_backend}`. `origin` in `scripted`, `tool`, `agent`, `human`, `classifier`. `source_id` like `tool:capa@<ver>+rules@<tag>`. `shares_backend` is a bool, defaults to false, and is true for FindCrypt (Sections 11.3 and 12.2) |
| `binary_sha256` | string | |
| `subject` | object | `{kind: "function", address}` |
| `type` | enum | `algorithm_identity` or `call_relation` |
| `body` | object | See below |
| `confidence` | number | In [0, 1] |
| `confidence_source` | enum | `stated`, `tool_default`, `scripted` |
| `rationale` | string or null | Optional, never graded |
| `evidence_refs` | array of strings | May be empty |
| `depends_on` | array of strings | Claim IDs or client refs; empty for tool sources |
| `supersedes` | string or null | |
| `derived_from` | enum or null | `capa_rule`, `constant_xref`, `scripted_correct`, `scripted_mutated`, or null |
| `tool_label` | string or null | The raw tool label (for example a capa rule name), kept for analysis |
| `algorithms_version` | string | Version of `algorithms.yaml` |

Bodies:

- `algorithm_identity`: `{family: string, variant: string or null}`. Null variant means a
  family-level claim.
- `call_relation`: `{callee: address or "import:<symbol>", kind: "direct" or "tail" or "indirect"}`.

Intake rules:

- **One active claim per key.** Key for `algorithm_identity`: (run, subject, type). Key for
  `call_relation`: (run, subject, type, callee). A duplicate is rejected with
  `duplicate_active_claim`.
- `family` and `variant` must exist in `algorithms.yaml`; otherwise `INVALID_CLAIM`.
- `subject.address` must be canonical (Section 8.1 of DESIGN.md). Tool adapters normalize before
  submission.

### 6.3 Verdict

| Field | Type | Rules |
|---|---|---|
| `claim_id` | string | |
| `intrinsic_verdict` | enum | `VERIFIED`, `CONTRADICTED`, `INCONCLUSIVE`, `UNVERIFIABLE`, `NOT_CHECKED`, `ERROR`, `INVALID_CLAIM` |
| `strength` | enum or null | `E1`, `E2`, or null |
| `aspects` | object | Phase 1a: `output_match` for `algorithm_identity`; `edge_exists` for `call_relation`. Each `{verdict, strength, method}` |
| `graph_status` | enum | `OK` in 1a (tool and scripted sources declare no reasoning edges) |
| `methods_run` | array | Versioned method IDs, sorted, for example `probe.crc32@1` |
| `reason` | string or null | Required for INCONCLUSIVE, UNVERIFIABLE, ERROR, INVALID_CLAIM |
| `harness` | string or null | Required for VERIFIED and CONTRADICTED (format in Section 10.7) |
| `evidence` | array | `{kind, artifact, summary}`; `artifact` is a content hash |
| `counterexample` | object or null | `{call_shape, input_hex, expected_hex, actual_hex, variant, matches_variant?}` |
| `budget_used` | object | `{instructions}` |
| `verifier_version` | string | |
| `env_digest` | string | Analysis image digest |

Reason codes in 1a: `state_dependent`, `unsupported_import`, `no_matching_call_shape`,
`budget_exhausted`, `emulation_fault`, `binding_not_verified`, `indirect_unresolved`,
`no_pack`, `subject_not_found`, `wall_timeout`, `internal`, `unknown_family`,
`duplicate_active_claim`, `unknown_variant`, `unsupported_relocation`.

### 6.4 Ground truth (private)

```json
{
  "schema_version": "1.0",
  "binary_sha256": "...",
  "program_id": "tierA/crc32tool",
  "variant_id": "clang18-O2-x64-pie-hardoff",
  "build_flags": "...",
  "algorithms_version": "1.0",
  "functions": [
    {
      "address": "0x00001230",
      "size": 112,
      "name": "crc32_update",
      "algorithm": { "family": "crc32", "variant": "ieee" },
      "clone_of": null,
      "scorable": true,
      "exclusion_reason": null,
      "callees": [ { "target": "import:printf", "kind": "direct" } ],
      "source_signature": "uint32_t (uint32_t, const uint8_t *, size_t)"
    }
  ],
  "excluded_functions": [ { "name": "helper", "reason": "fully_inlined" } ]
}
```

`algorithm` is `{"family": "none", "variant": null}` for functions annotated `@algorithm none`.

### 6.5 Targets (public to sources)

```json
{ "schema_version": "1.0", "binary_sha256": "...", "variant_id": "...",
  "targets": ["0x00001230", "0x000012a0"] }
```

### 6.6 Grade

| Field | Type | Rules |
|---|---|---|
| `claim_id` | string | |
| `grader_version` | string | |
| `on_target` | bool | Subject is in `targets.json` |
| `phantom` | bool | Subject is not a ground-truth function entry |
| `family_correct` | bool or null | `algorithm_identity` only |
| `variant_correct` | bool or null | Null when the claim's variant is null |
| `edge_correct` | bool or null | `call_relation` only |
| `correct_strict` | bool | `algorithm_identity`: family and variant both correct. `call_relation`: callee and kind correct |
| `correct_lenient` | bool | `algorithm_identity`: family correct. `call_relation`: callee correct, any kind |
| `verdict_correct` | bool or null | Null when the verdict is not decisive |

A family-level claim (variant null) can be lenient-correct but never strict-correct. Reports show
each source's granularity so this is not mistaken for a strict error.

### 6.7 Run manifest

`run_id` is deterministic: `"r_"` plus the first 16 hex chars of the hash of (source config,
binary hashes, versions, pack and mapping hashes). Fields: source config, binaries, every pinned
version from `versions.lock.md`, image digests, Ghidra analysis options hash, pack hashes,
mapping table hashes, `algorithms_version`, verifier and grader versions, seeds, and
`created_at` (informational).

For scripted sources, source config also includes `scenario` (`correct`, `family_only`, or
`mutated`) and the deterministic `case_index` from Section 11.1. These fields distinguish the
scenario runs and participate in the run ID hash.

### 6.8 Sandbox job protocol

Host writes `in/job.json` and inputs; the container writes `out/result.json`.

```json
{ "job_id": "j_...", "type": "ghidra_analyze", "inputs": { "binary": "in/<sha>.bin" },
  "params": { "analysis_options": "configs/ghidra-analysis.json" } }
```

```json
{ "job_id": "j_...", "status": "ok", "error_code": null,
  "output": { "...": "..." }, "budget_used": { "instructions": 0 } }
```

Job types in 1a: `ghidra_analyze`, `findcrypt_scan`, `capa_scan`, `verify_static`,
`verify_probe`. `status` is `ok` or `error`; error codes: `wall_timeout`, `oom`, `internal`,
`bad_input`.

---

## 7. Storage

SQLite database at `runs/aletheia.db`. Artifacts in `artifacts/<sha256[0:2]>/<sha256>`.

```sql
CREATE TABLE binaries (
  sha256 TEXT PRIMARY KEY, program_id TEXT NOT NULL, variant_id TEXT NOT NULL,
  split TEXT NOT NULL CHECK (split IN ('dev','heldout','train')),
  stripped_path TEXT NOT NULL, targets_hash TEXT NOT NULL
);
CREATE TABLE runs (
  run_id TEXT PRIMARY KEY, origin TEXT NOT NULL, source_id TEXT NOT NULL,
  manifest_hash TEXT NOT NULL, state TEXT NOT NULL
    CHECK (state IN ('pending','running','completed','failed','budget_exhausted')),
  created_at TEXT
);
CREATE TABLE claims (
  claim_id TEXT PRIMARY KEY, run_id TEXT NOT NULL REFERENCES runs(run_id),
  binary_sha256 TEXT NOT NULL REFERENCES binaries(sha256),
  subject_address TEXT NOT NULL, type TEXT NOT NULL, active_key TEXT NOT NULL,
  is_active INTEGER NOT NULL, canonical_json TEXT NOT NULL
);
CREATE UNIQUE INDEX claims_active ON claims(active_key) WHERE is_active = 1;
CREATE TABLE verdicts (
  claim_id TEXT PRIMARY KEY REFERENCES claims(claim_id),
  intrinsic_verdict TEXT NOT NULL, strength TEXT, reason TEXT,
  cache_key TEXT NOT NULL, canonical_json TEXT NOT NULL
);
CREATE TABLE verdict_cache (
  cache_key TEXT PRIMARY KEY, canonical_json TEXT NOT NULL
);
CREATE TABLE grades (
  claim_id TEXT PRIMARY KEY REFERENCES claims(claim_id),
  grader_version TEXT NOT NULL, canonical_json TEXT NOT NULL
);
CREATE TABLE jobs (
  job_id TEXT PRIMARY KEY, type TEXT NOT NULL, input_hash TEXT NOT NULL,
  status TEXT NOT NULL, result_artifact TEXT
);
```

**Verdict cache key** = hash of the following explicit canonical inputs:

- Binary SHA-256; claim `schema_version`, `subject`, `type`, `body`, and `algorithms_version`.
- Verifier version, sorted method versions, and applicable pack hashes.
- Analysis image digest and Ghidra analysis-options hash.
- Effective deterministic harness configuration: instruction budgets, memory-region addresses
  and sizes, runtime image base, and stub-set identity. Other fixed harness behavior is covered
  by the verifier/method versions and pack hashes.

Claim identity, run identity, source metadata (including `shares_backend`), confidence,
rationale, labels, and other provenance are excluded. Equivalent semantic claims from different
sources reuse one verification payload.

`verdict_cache.canonical_json` stores the verdict payload **without `claim_id`**. On a cache hit,
attach the requesting claim's ID before returning the verdict and writing its complete JSON to
`verdicts`. Evidence artifacts are shared by content hash; they MUST NOT depend on a source's
claim ID. Tests cover cross-source reuse with different provenance and confidence, correct ID
attachment, and invalidation when any verdict-affecting input changes.

Ground truth is **not** stored in this database. The grader reads it from `build/.../private/`.

---

## 8. Configuration (`aletheia.toml`)

```toml
[paths]
build = "build"
runs = "runs"
artifacts = "artifacts"

[sandbox]
image_analysis = "sha256:<local analysis image ID>"
image_build = "sha256:<local build image ID>"
concurrency = 4
memory_gb = 6
wall_timeout_s = 60          # safety cap only; returns ERROR wall_timeout

[budgets]
instructions_per_invocation = 10_000_000
instructions_per_claim = 200_000_000
heap_mb = 64
stack_mb = 1

[ghidra]
analysis_options = "configs/ghidra-analysis.json"   # pinned; Function ID off, FindCrypt off

[sources.capa]
enabled = true
mapping = "mappings/capa.yaml"

[sources.findcrypt]
enabled = true
mapping = "mappings/findcrypt.yaml"

[llm]
enabled = false              # D23: no provider committed
provider = ""
cost_cap_usd = 0

[metrics]
bootstrap_resamples = 1000
bootstrap_seed = 20261013
cwr_thresholds = [0.8, 0.9]
```

---

## 9. Components and Interfaces

Signatures are normative; names may gain parameters only with a recorded reason.

```python
# aletheia/sandbox/runner.py  (host side)
class JobRunner:
    def submit(self, job: Job) -> JobHandle: ...
    def wait(self, handle: JobHandle) -> JobResult: ...           # enforces wall_timeout
    def run_many(self, jobs: list[Job]) -> list[JobResult]: ...   # bounded by sandbox.concurrency

# aletheia/worker/main.py  (container entrypoint: python -m aletheia.worker /job)
HANDLERS: dict[str, Callable[[Job], JobResult]]   # ghidra_analyze, findcrypt_scan, capa_scan,
                                                  # verify_static, verify_probe

# aletheia/corpus/
def build_program(program_dir: Path, variant: Variant) -> BuildOutput: ...
def extract_ground_truth(build: BuildOutput, program_dir: Path) -> GroundTruth: ...
def check_leakage(stripped: Path, gt: GroundTruth, program_dir: Path) -> list[LeakHit]: ...
def lint_program(program_dir: Path) -> list[LintError]: ...

# aletheia/analysis/ghidra_session.py  (container side)
class GhidraAnalysis:                       # built once per (binary sha, options hash), cached
    functions: list[FunctionInfo]           # entry, body ranges, is_thunk, import_name
    def call_sites(self, fn: int) -> list[CallSite]: ...          # address, kind, target or None
    def arg_regs_set_before(self, site: CallSite) -> set[str]: ...
    def decompiler_param_count(self, fn: int) -> int | None: ...
    def is_variadic_like(self, fn: int) -> bool: ...
    def xrefs_to(self, addr: int) -> list[int]: ...               # referencing function entries

# aletheia/verify/
class Method(Protocol):
    id: str                                  # e.g. "probe.crc32"
    version: int
    handles: dict[str, set[str]]             # claim type -> aspects
    def applicable(self, claim: Claim, ctx: BinaryContext) -> bool: ...
    def run(self, claim: Claim, ctx: BinaryContext, budget: Budget) -> AspectResults: ...

class Engine:
    def verify(self, claims: list[Claim], mode: Literal["audit", "runtime"]) -> list[Verdict]: ...

# aletheia/verify/emulate/
class Emulator:
    def __init__(self, stripped: Path, budget: Budget): ...
    def call(self, entry: int, args: list[Arg], ret_width: int) -> CallResult: ...
    # CallResult: ret, out_buffers, instructions, fault, uninitialized_state_reads, imports_called

# aletheia/sources/
class ClaimSource(Protocol):
    origin: str
    source_id: str
    def produce(self, binary: BinaryRef, targets: Targets) -> list[Claim]: ...

# aletheia/grade/ and aletheia/metrics/
def grade(claims: list[Claim], verdicts: list[Verdict], gt: GroundTruth, targets: Targets) -> list[Grade]: ...
def compute_metrics(grades: list[Grade], claims: list[Claim], verdicts: list[Verdict], cfg: MetricsCfg) -> MetricsReport: ...
```

`BinaryContext` is built inside the worker and holds the stripped binary path, its SHA-256, the
cached `GhidraAnalysis`, and the static arity results. It never holds ground truth (R2).

---

## 10. Verifier (Phase 1a)

### 10.1 Static call-edge method (`static.edges@1`)

Input: a `call_relation` claim. Uses `GhidraAnalysis.call_sites` on the subject function.

| Claimed kind | VERIFIED (E1) | CONTRADICTED (E1) | Otherwise |
|---|---|---|---|
| `direct` | A direct call site targets the callee (imports matched by symbol name through Ghidra's thunk or external reference) | No direct call site targets the callee, and the subject's body was fully disassembled (no undefined bytes in its ranges) | INCONCLUSIVE `indirect_unresolved` if any indirect site exists and the body is incomplete |
| `tail` | A jump leaves the function to the callee's entry | No such jump, body fully disassembled | Same as above |
| `indirect` | Never in 1a | Never in 1a | INCONCLUSIVE `indirect_unresolved` |

If the subject address is not a function in Ghidra's analysis, the method asks Ghidra to create
one there; on failure the verdict is ERROR `subject_not_found`.

### 10.2 Static arity method (`static.arity@1`, internal)

Produces `arity` for the subject, used only to verify bindings for probes. Not a claim verdict in
1a.

1. **Callee side:** `decompiler_param_count(fn)`.
2. **Caller side:** for every direct call site targeting `fn`, the highest-index SysV integer
   argument register (`rdi, rsi, rdx, rcx, r8, r9`) written within the same basic block before the
   call, with all lower registers also written. Sites where this cannot be determined are
   skipped.
3. **Decisive** only if: the callee count and every determinable caller count agree, at least one
   caller was determinable, the function is not a tail-call target, `is_variadic_like` is false,
   and the count is at most 6.
4. Output: `{arity: int or null, decisive: bool, reason}`.

### 10.3 Emulator

**Address spaces.** The canonical address is the link-time VA. The emulator loads the image at
runtime base `B = 0x10000000`, so `runtime = B + canonical`. All evidence reports canonical
addresses.

**Memory map**

| Region | Runtime range | Contents |
|---|---|---|
| Image | `B` plus segment VAs | `PT_LOAD` segments with their permissions; `.bss` zero-filled |
| Stub page | `0x70000000` (64 KB) | One 16-byte slot per import, each containing `ret` (`0xC3`) |
| Sentinel page | `0x71000000` (4 KB) | Return trap; emulation stops when RIP reaches it |
| TLS | `0x72000000` (64 KB) | FS base points here; canary at `fs:0x28` = `0x2F8A_5C11_D3E0_7B46` (fixed) |
| Heap | `0x73000000` (`heap_mb`) | Bump allocator for stubs |
| Inputs | `0x78000000` (16 MB) | Argument buffers |
| Stack | `0x7F000000` (`stack_mb`) | RSP starts 16-byte aligned minus 8, return address = sentinel |

Guard gaps separate all regions. Address 0 through `B` is unmapped, so null dereferences fault.

With the default sizes, heap is `[0x73000000, 0x77000000)` and inputs are
`[0x78000000, 0x79000000)`. Before mapping memory, validate every page-aligned region,
including loaded image segments and configurable heap/stack sizes. Distinct regions MUST be
disjoint and retain at least one unmapped guard page between them; adjacent image segments are
validated as one image region, preserving their segment permissions. Invalid configuration or
an image colliding with a reserved region fails the job explicitly with `bad_input`.

**Relocations** (from `.rela.dyn` and `.rela.plt`):

- `R_X86_64_RELATIVE`: write `B + addend`.
- `R_X86_64_JUMP_SLOT`, `R_X86_64_GLOB_DAT` for function imports: write the import's stub slot
  address.
- `R_X86_64_GLOB_DAT` or `R_X86_64_64` for data imports (for example `stderr`): point at a zeroed
  256-byte object in the heap region, and record `data_import:<name>`.
- Any other relocation type: the binary is marked `unsupported_relocation`, and every probe on it
  returns INCONCLUSIVE with that reason.

**Import stubs** (a code hook on the stub page runs the Python implementation, sets RAX, and the
`ret` returns): `memcpy`, `memmove`, `memset`, `memcmp`, `strlen`, `strcmp`, `strncmp`,
`malloc`, `calloc`, `realloc`, `free` (no-op), `__stack_chk_fail` (fault). Any other import
called during a probe ends that invocation with INCONCLUSIVE `unsupported_import:<name>`.

**Initial state.** Run `.init_array` entries if present (none in 1a programs). Track writes
(`UC_HOOK_MEM_WRITE`) at byte granularity to `.bss` and to bytes in mutable `.data` whose loaded
initial value is zero. A read (`UC_HOOK_MEM_READ`) of a tracked byte not written during this
invocation or by initializers sets `uninitialized_state_reads`; probes report `state_dependent`.
Loading the image's initial zero bytes does not count as an initializing write. Relocations
initialize their destination bytes. Initialized nonzero `.data` and read-only constants remain
valid inputs and are not flagged by this rule.

**Budgets.** `emu_start(entry, until=sentinel, count=instructions_per_invocation)`. If emulation
stops without RIP at the sentinel, the invocation is `budget_exhausted`. Per-claim instruction
totals are capped by `instructions_per_claim`. The host's wall-time cap returns ERROR
`wall_timeout` and never INCONCLUSIVE (R4).

**Faults.** Unmapped access, invalid instruction, or `__stack_chk_fail` produce
`emulation_fault`. Faults never produce CONTRADICTED.

**Return values.** RAX masked to the call shape's `return_width`.

**Fresh state per invocation.** Each input runs in a freshly reset emulator (image, heap, stack,
and TLS restored from a snapshot). Restore the initializer-write mask too; writes from one
invocation MUST NOT initialize state for another. Evidence uses `uninitialized_state_reads`
consistently with `CallResult` and the probe checks.

### 10.4 Probe packs

**Pack schema (YAML)**

```yaml
family: crc32
version: 1
call_shapes:                     # tried in order
  - id: seed_buf_len
    roles: [seed, buf, len]
    return_width: 32
  - id: buf_len
    roles: [buf, len]
    return_width: 32
variants:
  ieee:
    oracle: crc32_ieee           # name in aletheia/verify/probes/oracles.py
    bind: { seed: 0 }            # constant bindings per variant
  jamcrc:
    oracle: crc32_jamcrc
    bind: { seed: 0 }
  crc32c:
    oracle: crc32c
    bind: { seed: 0 }
  bzip2:
    oracle: crc32_bzip2
    bind: { seed: 0 }
inputs:
  fixed: ["", "a", "123456789", "The quick brown fox jumps over the lazy dog"]
  random: { count: 64, max_len: 4096, seed: 4411 }
near_miss: [crc32c_impl, jamcrc_impl, bzip2_impl, crc32_no_final_xor, crc32_len_off_by_one]
```

Role semantics: `buf` (pointer to input bytes), `len` (byte count), `cstr` (pointer to a
NUL-terminated copy of the input; inputs containing NUL are skipped for this shape), `seed`
(bound constant), `out` (pointer to a zeroed output buffer of `out_size(len)` bytes, declared
per pack), `ret` (the return value).

**The five packs**

| Family | Call shapes | Variants and oracles | Output compared | Human-verifiable fixed vectors |
|---|---|---|---|---|
| `crc32` | `seed_buf_len`, `buf_len` | `ieee` (zlib), `jamcrc`, `crc32c`, `bzip2` | 32-bit return | `"123456789"`: ieee `0xCBF43926`, jamcrc `0x340BC6D9`, crc32c `0xE3069283`, bzip2 `0xFC891918` |
| `adler32` | `seed_buf_len` with seed 1, `buf_len` | `zlib` | 32-bit return | `"Wikipedia"`: `0x11E60398` |
| `fnv` | `buf_len` | `fnv1a-32`, `fnv1-32` | 32-bit return | `"a"`: fnv1a-32 `0xE40C292C`, fnv1-32 `0x050C5D7E`; `""`: both `0x811C9DC5` |
| `djb2` | `buf_len`, `cstr` | `add`, `xor` | 32-bit return | `"a"`: add `0x0002B606`, xor `0x0002B5C4`; `""`: both `0x00001505` |
| `base64` | `buf_len_out` (roles `[buf, len, out]`, `out_size = 4 * ceil(len / 3) + 4`) | `std-padded`, `url-nopad` | Return value equals expected length **and** first `ret` bytes of `out` equal the oracle | `"Man"` -> `TWFu`; `"M"` -> `TQ==` (std) and `TQ` (url); bytes `FB FF` -> `+/8=` (std) and `-_8` (url) |

Every fixed vector above MUST be re-checked by the author against a published reference before
T15 is signed off (HR).

T15 starts only after T11 and its HR gate are complete. Reference and near-miss fixture binaries
include real direct callers sufficient for the production `static.arity@1` method to establish
binding; tests MUST NOT inject trusted arity or bypass that method. Each supported reference
variant is VERIFIED and each near miss of that variant is CONTRADICTED using variant-level
claims. A fixture with non-decisive binding and mismatching outputs returns INCONCLUSIVE rather
than CONTRADICTED.

**Near-miss fixtures** (`tests/fixtures/near_miss/<family>/`, human-reviewed C sources compiled
with the 1a variant flags into one fixture binary per family):

| Family | Near misses |
|---|---|
| `crc32` | CRC-32C, JAMCRC, BZIP2 bit order, missing final XOR, length off by one |
| `adler32` | Modulus 65535 instead of 65521, initial value 0, Fletcher-32 |
| `fnv` | FNV-1 vs FNV-1a swap, wrong offset basis, wrong prime |
| `djb2` | Initial value 0, multiplier 31, sdbm |
| `base64` | URL alphabet in the std function, missing padding, padding with `.` |

**Probe algorithm for an `algorithm_identity` claim**

1. Validate the family and, if set, its variant against `algorithms.yaml`. Unknown family:
   INVALID_CLAIM `unknown_family`; unknown variant: INVALID_CLAIM `unknown_variant`.
   No family pack, or an explicit registered variant without an applicable probe/oracle:
   UNVERIFIABLE `no_pack`. Supporting constants cannot change this outcome.
2. Variants in scope: `{body.variant}` if set, otherwise all supported variants of the family.
   If a family-only claim has no supported variants, return UNVERIFIABLE `no_pack`. Record
   registered but unsupported variants in evidence so the tested scope is explicit.
3. Get `static.arity@1` for the subject.
4. For each call shape (in pack order) and each variant in scope: run all inputs (fixed plus
   seeded random). Record per input: match, mismatch, fault, budget, unsupported import, or
   state dependence.
5. **VERIFIED (E2)** if some (shape, variant in scope) pair matches every input with no faults,
   no `uninitialized_state_reads`, and no unsupported imports. A family-only claim may be
   VERIFIED by a clean match to a supported variant even if other variants are unsupported.
6. **CONTRADICTED (E2)** only if all hold:
   - arity is decisive, at least one shape has that arity, and all such shapes ran cleanly (no
     faults, no state dependence, no unsupported imports);
   - for a family-only claim, every registered variant has an applicable probe/oracle;
   - for every variant in scope, at least one input mismatches under every such shape;
   - the minimized counterexample (step 7) reproduces in a fresh emulator.
   For a variant-level claim whose function matches a different variant of the same family, the
   counterexample records `"matches_variant": "<other>"`.
7. **Minimization:** take the failing inputs, choose the shortest (ties by lexical order of
   hex), then repeatedly drop the last byte while it still fails. Deterministic.
8. Otherwise **INCONCLUSIVE**, with the first applicable reason in this order:
   `state_dependent`, `unsupported_import`, `emulation_fault`, `budget_exhausted`,
   `binding_not_verified`, `no_matching_call_shape`, `no_pack`. The final reason applies when
   supported variants mismatch cleanly but registered, unprobed variants prevent a family-level
   contradiction. It means incomplete variant coverage, not evidence that the claim is wrong.

### 10.5 Static constants method (`static.constants@1`, supporting only)

Scans the subject for known constants of the claimed family (polynomial, table prefix, FNV
basis and prime, 5381). Adds evidence with kind `constant_match`. It never sets a verdict (DESIGN
Section 10.2).

### 10.6 Engine

- Methods applicable in 1a: `algorithm_identity` uses `probe.<family>@1` plus
  `static.constants@1`; `call_relation` uses `static.edges@1`.
- Merge and precedence exactly as DESIGN Sections 8.4 and 9.5, restricted to the 1a aspects.
- **Audit mode only** in 1a: every applicable method runs.
- Results are written through the verdict cache (Section 7).

### 10.7 Harness description format

```
Function-level emulation of <canonical entry>; shape <shape id> (<roles>); stubs S1;
initial state: <init_array run | none>; <N> inputs (<k> fixed, <m> random, seed <s>);
oracle <oracle name> (<family>/<variant>) at <width>-bit width: <all matched | mismatch on input <hex>>.
```

For static methods: `Static analysis (Ghidra <version>, options <hash>): <finding>.`

---

## 11. Claim Sources

All sources receive the stripped binary and `targets.json` only. Claims about addresses not in
the targets are still verified but graded as `on_target: false` and reported separately.

### 11.1 Scripted claims (`origin: scripted`)

- Input format: JSONL, one claim per line, without `claim_id` (assigned at intake).
- `alth claims scripted --program <p>` generates the standard scripted set from ground truth. It
  lives in `aletheia/sources/scripted.py`, **outside** `aletheia/verify/` (R2), and it is a test
  source, not part of the verifier:
  - For every scorable function with a non-`none` algorithm: one correct claim (family and
    variant), one family-only claim, and one mutated claim (sibling variant if one exists,
    otherwise a different family).
  - For every scorable function with `@algorithm none`: one claim naming a random family
    (seeded).
  - For every ground-truth direct or tail edge: one correct `call_relation` claim and one with a
    wrong callee (another function in the binary, seeded).
  - Confidence: correct claims 0.9, mutated claims 0.9 (`confidence_source: scripted`).
- `derived_from` is `scripted_correct` or `scripted_mutated` so reliability metrics can be split.

**Scenario runs.** Generate the following separate source scenarios, never putting competing
algorithm claims in one run:

- `correct`: exact algorithm claims and correct direct/tail call claims.
- `family_only`: family-level claims for non-`none` algorithm functions; confidence 0.9 and
  `derived_from: scripted_correct` (correct at the claimed granularity).
- `mutated`: mutated algorithm claims, false labels on `none` functions, and wrong-callee claims.

Wrong-callee candidates are other function entries for which ground truth contains no edge of
the claimed kind from the subject. Choose deterministically with the recorded seed. If there
is no candidate, record a counted exclusion `no_wrong_callee_candidate`; never emit a supposedly
mutated claim that is actually correct.

Within each scenario, sort claims by canonical subject, type, callee (empty for algorithm
claims), kind, and canonical body. In that order, assign each claim to the lowest numbered case
that does not already contain its Section 6.2 active key, creating a case when needed. This
also handles collisions between call mutations or different kinds targeting the same callee.
Each nonempty case is a separate deterministic run; `scenario` and `case_index` are part of
source config (Section 6.7). Emit no empty runs and do not drop claims to avoid collisions.

Across all cases, expected claim count is `3*A + N + 2*E - X`, where `A` is the number of
scorable non-`none` algorithm functions, `N` is scorable `none` functions, `E` is the number of
distinct direct/tail ground-truth edges emitted by the generator, and `X` is the counted number
of edges without a wrong-callee candidate. T17 checks counts, deterministic case assignment,
and successful intake of every case without active-key collisions.

### 11.2 capa adapter (`origin: tool`)

1. Job `capa_scan`: run `capa --json -r <pinned rules> <stripped bin>` inside the sandbox.
2. Keep only matches of **function-scope** rules. Other scopes are counted as `unmapped_scope`.
3. Normalize addresses to canonical: subtract the image base capa reports in its JSON metadata.
   T18 MUST confirm the exact field name for the pinned capa version and record it in
   `mappings/capa.yaml`. If the field is absent, compute the base from the ELF headers the same
   way capa's loader does, and add a test against a known function.
4. Map rule names through `mappings/capa.yaml` (human-owned):

   ```yaml
   capa_version: "<pinned>"
   rules_tag: "<pinned>"
   address_base_field: "<confirmed in T18>"
   map:
     "hash data with CRC32":      { family: crc32,   variant: null }
     "compute adler32 checksum":  { family: adler32, variant: null }
     "hash data using fnv":       { family: fnv,     variant: null }   # rule matches any FNV variant
     "hash data using djb2":      { family: djb2,    variant: null }
     "encode data using Base64":  { family: base64,  variant: null }
   ```

5. Unmapped rule matches are counted per rule name as `unmapped_label`, never dropped silently.
6. Claims: `algorithm_identity`, `confidence: 1.0`, `confidence_source: tool_default`,
   `derived_from: capa_rule`, `tool_label: <rule name>`.

Expected behavior to check (from reading the rules, not yet observed): the CRC32 rule keys on the
polynomial constant and a bit loop, so it may also fire on `crc32_table_init`; the FNV rule
cannot tell FNV-1 from FNV-1a. Both make good writeup material if they happen.

### 11.3 FindCrypt adapter (`origin: tool`)

1. Job `findcrypt_scan`: import the stripped binary into a **fresh** Ghidra project at image base
   0 with the pinned analysis options **plus** the "Find Crypt" analyzer enabled.
2. Collect every symbol whose name starts with `CRYPT_`. Record name and address.
3. Map label names through `mappings/findcrypt.yaml` (human-owned). T19 runs the analyzer on the
   fixture binaries first and records the actual label names before the mapping is written.
4. For each mapped label, find every function that references its address (`xrefs_to`). Emit one
   `algorithm_identity` claim per (function, family), deduplicated.
5. Claims: `confidence: 1.0`, `confidence_source: tool_default`, `derived_from: constant_xref`,
   `tool_label: <label>`, variant from the mapping (usually null), and
   `source.shares_backend: true`. This records the shared Ghidra backend even though the source
   and verifier use separate projects. It is reporting metadata and never changes a verdict.

Expected natural confusers: `crc32_selftest` references the CRC table without computing a CRC;
`crc32_table_init` writes a table but computes no checksum of data.

### 11.4 LLM source (lane G, optional in 1a)

- `aletheia/llm/` defines `Provider` (`send(messages, tools) -> Response`), a `FakeProvider` that
  replays scripted tool calls, the Harness MCP Proxy (DESIGN Section 9.3), and the agent loop.
- `llm.enabled = false` by default. With it disabled, `alth run --source agent` exits with
  code 3 and a clear message.
- All lane G tests use `FakeProvider` only. No network.

---

## 12. Grading and Metrics

### 12.1 Grading

- Grader reads ground truth from `build/.../private/ground_truth.json`; the verifier never does.
- `on_target`: subject in `targets.json`. `phantom`: subject is not any ground-truth function
  entry (including excluded ones).
- `algorithm_identity` on a function with `@algorithm none`: family is wrong by definition.
- `call_relation`: ground-truth edges from Section 5.3 step 6; indirect edges from annotations.
- `verdict_correct`: VERIFIED is correct iff `correct_strict` (or `correct_lenient` for a
  family-level claim); CONTRADICTED is correct iff the claim is wrong at the claimed
  granularity. Null for non-decisive verdicts.

### 12.2 Metrics (per source, per program, and aggregated)

| Metric | Definition |
|---|---|
| Strict accuracy | Strict-correct on-target claims / on-target claims |
| Lenient accuracy | Lenient-correct on-target claims / on-target claims |
| Granularity | Share of a source's claims that are family-level |
| Algorithm coverage (strict, lenient) | Scorable functions with a non-`none` algorithm that received a correct claim / those functions |
| False-label rate | Claims on `none` functions / claims |
| CWR@t | count(c >= t and not strict-correct) / count(c >= t), for t in 0.8 and 0.9, also with lenient correctness |
| Brier | Mean of (c - strict_correct)^2 |
| Decisiveness | Decisive verdicts / claims, per method |
| Catch rate | Wrong claims CONTRADICTED / wrong claims |
| False alarm rate | Correct claims CONTRADICTED / correct claims |
| Verification precision | Correct / VERIFIED |
| Verdict confusion table | Verdict by (correct, wrong), per source and per method |
| Unmapped counts | Per tool label and scope |

**Independent verifier reliability.** The Phase 1a independent aggregate uses scripted claims
only, split by scenario/`derived_from` and claim type. Correctness for catch rate, false alarm
rate, verification precision, and verdict confusion is evaluated at the claim's granularity
(Section 12.1), so correct family-only claims are not treated as wrong variant-level claims.

Retain source accuracy, coverage, granularity, calibration, unmapped counts, counterexamples,
and verdict confusion tables for tool sources. FindCrypt's confusion table is labeled
**shared Ghidra backend** and is excluded from the independent verifier-reliability aggregate.
capa tool-conditioned reliability is also reported separately from the controlled scripted
aggregate. Shared-backend metadata does not invalidate independent E2 emulation evidence or
alter claim grading. Reports MUST identify the population and exclusions for each aggregate.

**Bootstrap CIs:** cluster bootstrap with programs as clusters, `bootstrap_resamples` and
`bootstrap_seed` from config. With only 5 programs, CIs are wide; reports say so.

---

## 13. Determinism and Replay

**Determinism rules (all MUST)**

- Seeds come only from config or pack files.
- All lists written to disk are sorted by a documented key.
- Ghidra analysis output is canonicalized (sorted functions, sorted references) before hashing.
- Jobs are content-addressed by input hash; a rerun with identical inputs reuses the stored
  result unless `--no-cache` is passed.

**Replay (`alth replay --run <run_id>`)**

1. Load the run manifest; refuse if any pinned version, image digest, pack, or mapping hash
   differs from the current checkout (exit code 4, listing differences).
2. Reload the run's claims from the database.
3. Recompute verdicts by re-running every method with **no verdict cache** but with cached job
   results allowed only for `ghidra_analyze`, `capa_scan`, and `findcrypt_scan`.
4. Recompute grades and metrics.
5. Compare canonical hashes of verdicts, grades, and metrics with the originals. Any difference
   exits with code 5 and a diff. Any cache miss for a source job exits with code 6.

---

## 14. Reports

`alth report --runs <ids> --out report.md` (Markdown; HTML optional) produces:

1. Header: benchmark version, split (dev), all versions, run IDs.
2. Per-source table of the metrics in Section 12.2 with CIs.
3. Per-source verdict confusion tables.
4. **Contradicted claims:** each with source, tool label, subject, harness description, and the
   minimized counterexample (input, expected, actual, and `matches_variant` if present).
5. **Wrong claims the verifier did not catch:** each with its verdict and reason. Honest
   reporting of misses is required.
6. Unmapped tool labels and excluded functions with reasons.
7. Independent scripted verifier-reliability aggregate, plus separate tool-conditioned tables;
   label FindCrypt's table as shared backend and list the aggregate's inclusion/exclusion rules.

---

## 15. CLI (`alth`, alias of `aletheia`)

| Command | Purpose | Exit codes |
|---|---|---|
| `alth doctor` | Check WSL2, Docker, images, and that versions match `versions.lock.md` | 0 ok, 2 mismatch |
| `alth schema export` | Write JSON Schemas to `spec/claims-v1/` | 0 |
| `alth corpus lint [--program P]` | Annotation and authoring rules | 0, 1 lint errors |
| `alth corpus build [--program P]` | Build, extract ground truth, strip, leakage check | 0, 1 build or leakage failure |
| `alth claims scripted --program P` | Generate the scripted claim set | 0 |
| `alth tools run --tool capa,findcrypt [--program P]` | Run tool adapters, store claims | 0, 1 |
| `alth claims submit --file F --source ID` | Ingest a JSONL claims file | 0, 1 invalid |
| `alth verify [--run R]` | Verify all unverified active claims (audit mode) | 0 |
| `alth score [--run R]` | Grade and compute metrics | 0 |
| `alth report --runs R1,R2 --out F` | Write the report | 0 |
| `alth replay --run R` | Deterministic replay | 0, 4 version drift, 5 mismatch, 6 cache miss |
| `alth selftest [--family F]` | Variant-level reference and near-miss checks with production arity; static method fixtures | 0, 1 failure |
| `alth verifiability [--program P]` | Generate the verifiability table from ground truth and the pack registry | 0 |
| `alth gate 1a` | Check the Phase 1a exit criteria (Section 19) | 0 pass, 1 fail |
| `alth run --source agent` | Lane G only | 3 when `llm.enabled = false` |

All commands accept `--config PATH` and `--json` (machine-readable output).

---

## 16. Testing

| Kind | What | Where |
|---|---|---|
| Unit | Schemas, canonical JSON, merge and precedence tables, metric math with hand-computed values, generators, scenario assignment, minimization, semantic cache keys and identity attachment, unsupported variant outcomes, memory-map validation | `tests/unit/` |
| Golden | Ground truth for `crc32tool` (hand-checked), verdicts for its scripted claims, adapter outputs, a report snapshot | `tests/golden/` (R5) |
| Self-test | Every supported reference variant VERIFIED and every near miss of that variant CONTRADICTED using production arity; unverified binding and incomplete variant coverage never contradict; static methods on fixture binaries | `tests/selftest/` |
| Boundary | Import test: nothing under `aletheia/verify/` imports `aletheia/corpus/` or `aletheia/sources/scripted.py`; runtime path guard rejects `private/` paths | `tests/unit/` |
| Sandbox | Network blocked, root read-only, memory limit enforced, wall timeout returns ERROR | `tests/integration/` |
| Determinism | Two builds byte-identical; two `ghidra_analyze` runs canonically identical; replay of a mini run passes | `tests/integration/` |
| Contract | Job protocol round trips for every job type | `tests/integration/` |
| End to end | One program through every command | `tests/integration/` (marked slow) |

`uv run pytest -m "not slow"` MUST pass on every task. Slow tests run before each HR gate.

---

## 17. Task Breakdown

Lanes: **A** infrastructure, **B** corpus and ground truth, **C** emulation and packs, **D**
static analysis, **E** engine, grading, and runs, **F** claim sources, **G** LLM (optional).
**HR** = human review gate by the author before dependent tasks start.

| ID | Lane | Task | Depends on | Acceptance test | HR |
|---|---|---|---|---|---|
| T00 | A | Repo scaffold: uv project, ruff, pyright strict, pytest, `AGENTS.md`, `CODEOWNERS`, empty package layout | none | `uv run ruff check`, `uv run pyright`, `uv run pytest` all pass on the empty skeleton | |
| T01 | A | Pin versions; write `versions.lock.md` and `LICENSES.md`; build both Docker images; `alth doctor` | T00 | `alth doctor` exits 0; analysis container cannot reach the network (test) | |
| T02 | A | Pydantic models for Sections 6.2 to 6.8; canonical JSON; schema export | T00 | Round-trip and canonical-hash tests with fixed vectors; exported schemas validate the Appendix B examples | |
| T03 | A | SQLite schema (Section 7) and artifact store | T02 | CRUD tests; partial unique index rejects a second active claim | |
| T04 | A | Sandbox job runner (host) and worker entrypoint (container) | T01, T02 | Echo job round trip; network blocked; read-only root; wall timeout returns `wall_timeout` | |
| T05 | B | Corpus linter (Section 4.1) | T00 | Lint fixtures: each rule has one passing and one failing sample | |
| T06 | B | Write the 5 programs and native unit tests (Section 4.2) | T05 | `alth corpus lint` clean; native tests pass in the build image | HR: annotations and semantics |
| T07 | B | Build pipeline (Section 5.1, 5.2), O0 auxiliary build, strip, rename | T01, T06 | Two consecutive builds produce identical SHA-256 for all 5 stripped binaries | |
| T08 | B | Ground truth extraction (Section 5.3), `targets.json`, leakage check | T07 | `crc32tool` ground truth equals golden F1 exactly; leakage check passes on all 5 and fails on a planted-leak fixture | HR: F1 |
| T09 | D | `ghidra_analyze` job: pinned options (Function ID off, FindCrypt off), image base 0, canonical output, cache; measure peak RAM | T04 | Recall of ground-truth scorable entries recorded; two runs canonically identical; peak RAM recorded in `versions.lock.md` | |
| T10 | D | `static.edges@1` (Section 10.1) | T09, T02 | Golden verdicts on fixture `call_relation` claims, including import and tail cases | |
| T11 | D | `static.arity@1` (Section 10.2) | T09 | Matches golden arity table F7; `log_msg` not decisive | HR |
| T27 | D | `static.constants@1` (Section 10.5) | T09 | Constant evidence found for `crc32_update`, `fnv1a_32`, `djb2_buf`; never sets a verdict | |
| T12 | C | Emulator core: loader at runtime base, relocations, validated memory map, TLS and canary, sentinel, budgets, `.bss`/zero-filled mutable `.data` tracking, snapshot reset | T04, T07 | `crc32_bitwise("123456789") == 0xCBF43926` on the stripped binary; budget exhaustion detected; `crc32_update_rt` reports `uninitialized_state_reads`; default regions disjoint with guard gaps and overlaps rejected; unwritten `.bss`/zero `.data`, write-before-read, valid nonzero `.data`/read-only constants, and per-invocation reset covered | HR: loader and relocations |
| T13 | C | Import stubs (Section 10.3) | T12 | One unit test per stub; an unknown import yields `unsupported_import:<name>` | |
| T14 | C | Pack schema, loader, generators, oracle registry, minimization | T02 | Schema tests; seeded generators reproduce identical inputs; minimization deterministic | |
| T15 | C | Five packs, near-miss fixture sources and build, `alth selftest`; production arity analysis with real fixture callers | T11 (including HR), T12, T13, T14 | Every supported reference variant VERIFIED and every near miss of that variant CONTRADICTED; non-decisive mismatching binding INCONCLUSIVE; explicit unsupported variants UNVERIFIABLE and incomplete family coverage cannot contradict | HR: vectors (F2) and near misses (F3) |
| T16 | E | Engine: method registry, audit mode, merge and precedence, CONTRADICTED preconditions, harness description, semantic verdict cache without claim identity | T03, T10, T11, T15, T27 | Table-driven merge tests covering every row of DESIGN 8.4 precedence; cross-source cache reuse attaches correct claim ID; changes to verdict-affecting configuration invalidate cache | HR: merge logic |
| T17 | F | Scripted source and generator: deterministic scenarios and collision-free case runs (Section 11.1) | T08, T02, T03 | Generated set and case assignment deterministic; counts match formula in 11.1; every case ingested without duplicates; wrong-callee mutations are false or counted exclusions | |
| T18 | F | capa adapter (Section 11.2): confirm base-address field, mapping, unmapped counting | T04, T02 | Adapter output on `crc32tool` and `hashtable` equals golden F4 after author review | HR: `mappings/capa.yaml` |
| T19 | F | FindCrypt adapter (Section 11.3): record real label names, mapping, xrefs | T09 | Adapter output on `crc32tool` equals golden after author review | HR: `mappings/findcrypt.yaml` |
| T20 | E | Grader (Section 12.1) | T08, T02 | Golden grades for `crc32tool` scripted claims | |
| T21 | E | Metrics and cluster bootstrap; independent scripted aggregate and labeled tool-conditioned populations (Section 12.2) | T20 | Hand-computed examples for every metric; family-only reliability uses claimed granularity; FindCrypt/capa excluded from independent aggregate and retained in separate tables; bootstrap reproducible with configured seed | HR: metric math |
| T22 | E | Orchestration: `alth run`, `verify`, `score`, manifests, run states, concurrency | T16, T17, T18, T19, T20 | One program end to end for all three sources | |
| T23 | E | Replay (Section 13) | T22 | Replay identical; injected drift exits 4; injected cache miss exits 6 | |
| T24 | E | Report (Section 14) | T21, T22 | Snapshot test on a fixed mini run | |
| T26 | B | `alth verifiability` table generator (DESIGN 10.7) | T08, T14 | Table for all 5 programs; decidable share computed | |
| T25 | E | `alth gate 1a` and full end-to-end run on all 5 programs | T23, T24, T26 | All Section 19 criteria pass | HR: final sign-off |
| T30 | G | Provider interface and `FakeProvider` | T02 | Unit tests with recorded tool calls | |
| T31 | G | Harness MCP Proxy over pyghidra-mcp (allowlist, budgets, logging, canonicalization, one-active-claim) | T04, T30 | Contract tests with `FakeProvider`; budget exhaustion; duplicate claim rejected | |
| T32 | G | Agent loop and `alth run --source agent` | T31 | Runs with `FakeProvider`; exits 3 when `llm.enabled = false` | |

**Parallel plan.** Lane A first (T00 to T04). Then lanes B, C, D, and F (T18) run in parallel.
Lane E starts when T16 and T20 dependencies land. Lane G can run any time after T04 and never
blocks T25.

**Critical path:** T00, T01, T04, T07, T12, T13, T15, T16, T22, T23, T25.
T07 also requires the completed corpus-authoring gate (T05/T06); T15 additionally waits for
T09/T11 and T11's HR sign-off. These dependency branches may determine the actual critical path.

---

## 18. Protected Fixtures (Human-Verified, R5)

| ID | Fixture | How it is verified |
|---|---|---|
| F1 | `tests/golden/crc32tool/ground_truth.json` | Author checks every entry against an `llvm-objdump -d` listing of the unstripped build |
| F2 | `tests/golden/vectors.yaml` | Every fixed vector cites a published reference; author re-computes each with an independent implementation |
| F3 | `tests/fixtures/near_miss/**` | Author reviews each near-miss source and confirms it differs from the reference on at least one fixed vector |
| F4 | `tests/golden/adapters/*.json` | Author reviews the first adapter outputs line by line before they become golden |
| F5 | `mappings/capa.yaml`, `mappings/findcrypt.yaml` | Author writes them after inspecting real tool output |
| F6 | `configs/ghidra-analysis.json` | Author reviews the pinned analyzer option list |
| F7 | `tests/golden/arity.yaml` | Author derives expected arity and decisiveness from source and disassembly |

Agents MAY propose fixture content in a pull request labeled `fixture-proposal`. Only the author
merges it.

---

## 19. Phase 1a Exit Criteria (`alth gate 1a`)

| ID | Criterion | Automated |
|---|---|---|
| X1 | All 5 programs build reproducibly and pass the leakage check | Yes |
| X2 | `crc32tool` ground truth equals F1 | Yes |
| X3 | `alth selftest` passes: every supported reference variant VERIFIED and every near miss of that variant CONTRADICTED using production arity | Yes |
| X4 | Zero CONTRADICTED verdicts on scripted correct `algorithm_identity` claims | Yes |
| X5 | Designated verdicts: `crc32_update_rt` INCONCLUSIVE `state_dependent`; exact claims on `fletcher16/std`, `base64/std-padded-decode`, and unprobed 64-bit FNV variants UNVERIFIABLE `no_pack`; family-only claims cannot contradict with incomplete variant coverage; `log_msg` arity not decisive | Yes |
| X6 | Replay identical for every 1a run (scripted, capa, FindCrypt) | Yes |
| X7 | Report generated, including contradicted claims and verifier misses | Yes |
| X8 | Compute time per run and peak RAM recorded | Yes |
| X9 | Verifiability table generated; decidable share reported (the 40% gate applies from 1b) | Yes |
| X10 | Author sign-off on all HR gates | No |

**Deliverable after the gate:** the author writes the no-LLM writeup from the report.

---

## 20. Known Risks and Spec-Level Open Items

| Item | Resolved in | Notes |
|---|---|---|
| capa JSON field for the image base | T18 | Recorded in `mappings/capa.yaml` |
| FindCrypt label names | T19 | Recorded before the mapping is written |
| Ghidra headless option name for image base 0, and pyghidra compatibility | T09 | Recorded in `configs/ghidra-analysis.json` |
| SIMD in optimized code | T07, T12 | Build pins `-march=x86-64` (baseline, SSE2). If Unicorn lacks an instruction the build emits, the probe returns `emulation_fault`; T12 adds a test that every 1a target emulates on the reference input |
| Tail call emission for `run_command` | T08 | Ground truth records whatever the binary contains |
| Docker in WSL2 performance and Ghidra memory | T09 | Lower `concurrency` to 3 if peak RAM requires it |
| capa speed and support on PIE ELF | T18 | Record runtime per binary |
| `noinline` reduces realism | Phase 2 | Removed when variants arrive |

---

## 21. Deviations from DESIGN.md (to be folded back after 1a)

| ID | Deviation | Reason |
|---|---|---|
| V1 | `origin` adds `scripted` | Scripted claims are a distinct test source |
| V2 | `claim_id` is a content hash, not a ULID | ULIDs embed time and break deterministic replay |
| V3 | Family-level `algorithm_identity` claims (variant null), verified against every variant in the family | Tools such as capa identify families, not variants |
| V4 | `ALETHEIA_TARGET` (`noinline`) on target functions | Guarantees scorable targets in the single 1a variant |
| V5 | No held-out split in 1a | 5 programs are too few to split; held-out starts in 1b |
| V6 | ABI signature ground truth deferred to 1b; arity derived internally | No signature claims in 1a |
| V7 | One-active-claim key for `call_relation` includes the callee | A caller has many legitimate callees |
| V8 | Emulation faults never produce CONTRADICTED, for any claim type | Conservative extension of DESIGN 10.1 |
| V9 | No parser packs in 1a | No parser targets in 1a |
| V10 | Additional reason codes (Section 6.3) | Precise INCONCLUSIVE and ERROR reporting |
| V11 | `-march=x86-64` pinned in build flags | Keeps emitted instructions within what the emulator supports |
| V12 | Registered but unsupported variants are explicit; family-level contradiction requires coverage of every registered variant | Avoids refuting a family by testing only a supported subset; no extra 1a packs |
| V13 | Independent 1a verifier-reliability aggregate uses scripted claims; tool-conditioned tables remain separate and FindCrypt carries `source.shares_backend` | Prevents shared-backend and tool-selection dependencies from being hidden in the independent aggregate; E2 evidence remains valid |

| V14 | Public repository and MIT original code/corpus from inception | Author-selected publication timing and license |
| V15 | IP review not applicable; held-out/provider infrastructure deferred; agent power analysis awaits agent data | Author-confirmed Phase 0 interpretation |
| V16 | uv_build and required locked upstream/native/tool dependencies allowed; bootstrap pins recorded in T00 | Installable package and reproducible tooling require these components |
| V17 | Local project image IDs, registry digests only for downloaded bases | Immutable local execution without registry or image distribution |
| V18 | Uniform schema_version defaults, matches_variant, unsupported_relocation, and deterministic full job IDs | Complete fields already required by the design/procedures |

| V19 | Source annotations required on every function definition at T05, including main and trivial helpers | Author-approved conservative source check before exact O0 instruction counts exist |

### 21.1 Revision history

| Version | Date | Change |
|---|---|---|
| 0.1 | 2026-10-13 | Initial Phase 1a implementation spec |
| 0.2 | 2026-10-13 | Recorded author-authorized C1-C7: disjoint emulator memory, deterministic scripted scenarios, unsupported-variant handling, arity-gated self-tests, semantic cache payloads, independent reliability reporting, and `.bss`/zero-filled `.data` state tracking; updated contracts and acceptance checks |

| 0.3 | 2026-10-13 | Recorded author-approved foundation implementation decisions; completed protocol fields and local image references |
| 0.4 | 2026-10-14 | Author approved the design conversion and foundation direction, authorized T04 CI/T05/T06 preparation, and required source annotations on every definition for T05; security review remains open |

---


## Appendix A: `AGENTS.md`

```markdown
# AGENTS.md (Aletheia)

You are working on Aletheia Phase 1a. Read SPEC-PHASE-1A.md before anything else.

## Non-negotiable rules
1. No LLM, classifier, or embedding model in verification or grading code.
2. Code under aletheia/verify/ never imports aletheia/corpus/ and never reads ground truth,
   unstripped binaries, sources, annotations, or corpus tests.
3. Ground truth uses symbols plus capstone; the verifier uses Ghidra. Do not share code.
4. Determinism: no wall-clock decisions, no unseeded randomness, sorted outputs, canonical JSON.
5. Never edit tests/golden/, tests/fixtures/, mappings/, or configs/ghidra-analysis.json.
   Propose changes in a PR labeled fixture-proposal.
6. Pin every version. Never add a dependency without the author's approval.
7. No silent fallbacks: every failure becomes a reason code, error code, or counted exclusion.
8. Untrusted binaries are parsed only inside the sandbox.
9. Never weaken or edit a test to make it pass.

## Workflow per task
1. Pick a task from Section 17 whose dependencies are done.
2. Write or confirm the acceptance test first; it must fail.
3. Implement until it passes.
4. Run: uv run ruff check, uv run pyright, uv run pytest -m "not slow".
5. Open a PR titled "T<id>: <task>", listing the acceptance test and any HR gate.
6. If the spec is ambiguous or contradicts DESIGN.md, stop and ask. Do not guess.
```

## Appendix B: Examples

**Scripted claims (JSONL, before intake)**

Run IDs, hashes, and addresses below are illustrative placeholders. Actual scenario run IDs
are computed from the manifest inputs in Section 6.7; a mutated callee must be selected and
checked against ground truth as specified in Section 11.1.

```
{"schema_version":"1.0","run_id":"r_correct_example","source":{"origin":"scripted","source_id":"scripted:v1","shares_backend":false},"binary_sha256":"<sha>","subject":{"kind":"function","address":"0x00001230"},"type":"algorithm_identity","body":{"family":"crc32","variant":"ieee"},"confidence":0.9,"confidence_source":"scripted","rationale":null,"evidence_refs":[],"depends_on":[],"supersedes":null,"derived_from":"scripted_correct","tool_label":null,"algorithms_version":"1.0","client_ref":null}
{"schema_version":"1.0","run_id":"r_mutated_example","source":{"origin":"scripted","source_id":"scripted:v1","shares_backend":false},"binary_sha256":"<sha>","subject":{"kind":"function","address":"0x00001230"},"type":"call_relation","body":{"callee":"0x00002000","kind":"direct"},"confidence":0.9,"confidence_source":"scripted","rationale":null,"evidence_refs":[],"depends_on":[],"supersedes":null,"derived_from":"scripted_mutated","tool_label":null,"algorithms_version":"1.0","client_ref":null}
```

**A capa-derived claim after intake**

```json
{
  "schema_version": "1.0",
  "claim_id": "c_3f9a0c1e2b7d4a6e8f10c2d4",
  "run_id": "r_8d2e4f6a0b1c3d5e",
  "source": { "origin": "tool", "source_id": "tool:capa@<ver>+rules@<tag>", "shares_backend": false },
  "binary_sha256": "<sha>",
  "subject": { "kind": "function", "address": "0x00001410" },
  "type": "algorithm_identity",
  "body": { "family": "crc32", "variant": null },
  "confidence": 1.0,
  "confidence_source": "tool_default",
  "rationale": null,
  "evidence_refs": [],
  "depends_on": [],
  "supersedes": null,
  "derived_from": "capa_rule",
  "tool_label": "hash data with CRC32",
  "algorithms_version": "1.0",
  "client_ref": null
}
```

**A verdict (family-level claim on a table generator, binding not verified)**

```json
{
  "claim_id": "c_3f9a0c1e2b7d4a6e8f10c2d4",
  "intrinsic_verdict": "INCONCLUSIVE",
  "strength": null,
  "aspects": { "output_match": { "verdict": "INCONCLUSIVE", "strength": null, "method": "probe.crc32@1" } },
  "graph_status": "OK",
  "methods_run": ["probe.crc32@1", "static.constants@1"],
  "reason": "no_matching_call_shape",
  "harness": null,
  "evidence": [ { "kind": "constant_match", "artifact": "sha256:...", "summary": "0xEDB88320 present" } ],
  "counterexample": null,
  "budget_used": { "instructions": 0 },
  "verifier_version": "0.1.0",
  "env_digest": "sha256:..."
}
```

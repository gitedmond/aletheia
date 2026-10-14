# Phase 1A verifiability draft

This is a pre-build estimate from SPEC-PHASE-1A.md, not measured coverage.
T26 replaces estimates with ground-truth counts and registered probe support.

| Family | Expected E2 support | Known blockers |
|---|---|---|
| crc32 | ieee, jamcrc, crc32c, bzip2 | Runtime-initialized table is state-dependent; arity/binding must be checked |
| adler32 | zlib | Wrapper may be a tail-call target, preventing decisive arity |
| fnv | fnv1a-32, fnv1-32 | 64-bit variants unprobed; incomplete family coverage cannot contradict |
| djb2 | add, xor | C-string shape skips inputs containing NUL; binding must be checked |
| base64 | std-padded encode, url-nopad encode | Decode unprobed; return length and output bytes both checked |
| fletcher16 | none | UNVERIFIABLE no_pack |

All five programs are dev split. Scorable and decidable counts are unknown before T08/T26.
The 40% coverage gate applies from Phase 1B.

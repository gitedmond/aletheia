# T06 corpus review package

Status: preparation for author review; T06 HR is not approved. No dependent T07/T08
work or protected fixtures have been introduced. Source is original MIT C17, libc only.

The five programs live under `corpus/tierA/<program>/{src,tests,Makefile}`. Shared
noinline and input declarations are in `corpus/include/aletheia.h`. The shared native
Makefile records the Phase 1A flags, including `-DNDEBUG`; `native-check.h` implements
explicit checks that cannot be compiled out. Input is binary file/stdin, bounded to
16 MiB with an explicit error on excess; returned buffers include a trailing NUL.
The limit is a corpus CLI choice, not a verifier instruction or input budget.

## Annotation and target inventory

Every definition, including main and helpers, has an adjacent annotation. All Section
4.2 targets carry ALETHEIA_TARGET. Helpers read_input (all five) and print_bytes (b64)
also carry it; decode_digit is a private none helper. Exact scorable counts and emitted
call shapes remain T08 work.

| Program | Algorithm annotations | Other required targets annotated none |
| --- | --- | --- |
| crc32tool | crc32_update, crc32_bitwise, crc32_update_rt: crc32/ieee; jamcrc: crc32/jamcrc | crc32_table_init, crc32_selftest, hex_print32 |
| adlerfletch | adler32_update, adler32: adler32/zlib; fletcher16: fletcher16/std | sum_file |
| hashtable | fnv1a_32: fnv/fnv1a-32; fnv1_32: fnv/fnv1-32; djb2, djb2_buf: djb2/add; djb2a_buf: djb2/xor | ht_create, ht_insert, ht_lookup, ht_destroy |
| b64 | b64_encode: base64/std-padded; b64_encode_url: base64/url-nopad; b64_decode: base64/std-padded-decode | b64_encoded_len |
| cmd-dispatch | fnv1a_32_local: fnv/fnv1a-32 | lookup_cmd, dispatch, run_command, cmd_hash, cmd_sum, cmd_help, sum8, log_msg |

Indirect inventory: ht_insert and ht_lookup list fnv1a_32,djb2_buf; ht_create rejects
other callbacks. dispatch lists cmd_hash,cmd_sum,cmd_help, matching its const table.
run_command ends in dispatch and preserves the intended tail-call opportunity.
log_msg is genuinely variadic and calls vfprintf. No provider or classifier is used.

crc32tool retains the constant .rodata table, mutable static runtime table initialized
only by crc32_table_init, a self-test referencing the constant table, and actual main
calls to all checksum paths. No source constructor is added. The eventual isolated
probe of crc32_update_rt is still expected to be state-dependent; native tests initialize
the table normally and do not establish any verifier verdict.

Unsupported Phase 1A packs remain unsupported: fletcher16/std and padded decode are
native corpus functions, not new probe packs. No 64-bit FNV implementation/pack was added.

## Native behavior and review choices

CRC checks cover empty input, the 123456789 reference vector, JAMCRC's complement,
seed preservation, streaming updates, initialized runtime-table updates, and self-test.
Adler checks cover Wikipedia, a, streaming, 70,000 bytes of 0xff, Fletcher-16, file I/O,
and missing files. Hash checks cover published empty/a/foobar values, embedded NULs,
both permitted callbacks, collisions, overwrite, empty keys, and absent lookup.
Base64 checks use RFC 4648 examples, std/URL alphabets, exact lengths, no appended NUL,
buffer guards, all 256 byte values, and strict malformed/padding rejection. Decode
accepts canonical padded standard form only, with zero pad bits; it rejects URL/whitespace
and malformed/noncanonical input. Dispatch checks cover the three handlers, unknown
commands, byte-sum wraparound, and the duplicate FNV reference.

The four numeric programs emit results as hex, without algorithm/program labels.
b64 emits standard encoding, URL encoding, and round-trip bytes as hex. cmd-dispatch
uses neutral command selectors hash/sum/help, defaults to hash, and reads input in main;
handlers operate on that prepared buffer. help emits neutral ok. Stateful orchestration
functions are annotated none; the algorithm targets themselves take explicit buffers.

## Validation commands

Cloud build image: `sha256:ea13f398a0a0db21e60b5389f94280f1ed788c5dbac246f47509c61783f6e4d2`.
Clang 23.1.3 is built from the locked archive and checksum, against the locked Ubuntu
snapshot/base. The session CA is supplied by a transient BuildKit mount, never embedded.

Run source checks from the repository root:

```bash
uv run alth --json corpus lint
uv run alth corpus lint --program crc32tool
uv run pytest tests/unit/test_corpus_programs.py
```

Native acceptance is `tests/integration/test_corpus_native.py`. For each program it runs
`make -C /scratch/corpus/tierA/<program> BUILD_DIR=/scratch/native all test`, then compares
both file/stdin output against independent fixed expectations for a and empty input,
and requires missing input to fail explicitly. The corpus and test cases are read-only
mounts; only bounded scratch is writable. Docker runs by the full inspected image ID,
non-root, no network, read-only root, dropped capabilities, no-new-privileges, 2 CPUs,
1 GiB memory/swap, 64 PIDs, and a 60-second host timeout. All compilation/execution occurs
inside that container, never on the host.

Initial source acceptance failed for all five missing Makefiles before implementation.
Native C tests were written before their target implementations. Cloud source lint is
clean for all five programs. Native integration acceptance passed 5 tests in 9.38 seconds.
Final normal validation, exact assertion counts, PR IDs, and immutable commit evidence
are recorded in STATUS.md after the complete cloud run.

No Ghidra binary analysis, emulator/probe result, reproducible stripped build, leakage
check, ground truth, protected F1-F7 proposal, or X1-X10 gate is claimed here. Those are
later tasks. Author approval of annotations and semantics is required before T07.

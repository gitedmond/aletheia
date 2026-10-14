# Foundation interfaces

T00-T04 provide configuration, storage, transport, and contracts. Analysis handlers, emulation,
claim sources, grading, orchestration, replay, reports, and exit gates remain later tasks.

Global CLI flags precede the subcommand: alth --config aletheia.toml --json doctor.
Both alth and aletheia entrypoints use the same command tree. Schema export writes nine
canonical JSON Schema files. Pydantic additionally validates semantic requirements, including
content-derived IDs, registry membership, verdict prerequisites, and sorted targets. The
exported claim schemas also enforce the type/body discriminator. Appendix B placeholders are
substituted explicitly in tests; their illustrative IDs are not treated as real hashes.

RunManifest.created_at is informational and excluded from content hashing. Arrays preserve
meaningful order. Targets and methods_run require canonical sorted unique order. Version 1.0's
algorithm registry is mirrored by algorithms.yaml and an independent equality check prevents
drift; changing the registry requires a version/contract review.

SQLite owns metadata for binaries, runs, claims, verdicts, grades, cache payloads, and jobs.
Each public write is a transaction. Foreign keys and the partial active index enforce intake
integrity. No ground truth enters this database. Existing unknown schema versions fail without
migration or deletion. ArtifactStore transports opaque bytes by full SHA-256 and refuses
corrupt existing objects.

CacheContext lists version, method, pack, image, analyzer-option, and effective harness inputs.
T16 must construct the harness dictionary with every normative instruction budget, memory
region/address/size, runtime base, and stub-set identity; the foundation does not infer omitted
future emulator configuration. Claim and run identity and source provenance are excluded.
Cache payloads omit claim_id and hits attach the requesting identity.

Job IDs are j_ plus the hash of the canonical JobInput. Input files use full SHA-256 filenames;
the host checks bytes against those names without parsing them. A JobRunner receives Sandbox,
an input_root containing in/, a jobs_root, and an ArtifactStore. It creates isolated per-attempt
in/out directories, retains them for diagnostics, returns JobHandle from submit and JobResult
from wait, and stores the canonical result artifact on the handle. run_many is bounded and
returns submission order. SQLite writes belong to the caller, not concurrent worker threads.

Every worker starts fresh. HANDLERS is empty until its five production handlers are implemented;
missing handlers return bad_input. Tests inject a handler for verify_static using a disposable
test image; no echo handler or arbitrary plugin loader is in production. Infrastructure failures
return explicit protocol codes. Invalid/missing worker identities fail, and results are bounded
to 16 MiB. Docker's OOMKilled state determines oom; exit 137 alone does not.
If artifact persistence fails, wait returns an internal error with result_artifact
left unset; other jobs in the batch still return their own results.

guarded_input rejects private paths, .c/.h inputs, truth/unstripped/O0 names, corpus/test
directories, traversal, and escaping symlinks. The host mounts only staged input files and a
separate output directory. Input identity and these path checks are necessary constraints;
T07/T09 must still establish stripped-binary provenance and check binary structure inside jobs.
No host binary parser is introduced. The default Docker seccomp profile remains enabled.

Host Python dev dependencies are separate from corpus and analysis dependency groups. T08
will use uv run --group corpus when ground-truth dependencies are needed; analysis dependencies
are installed only in the image. No Capstone helper is shared with the verifier.

CI's quick job checks units, lint, and types. Its sandbox job rebuilds verified pinned inputs,
records its own local image IDs in the ephemeral configuration, then runs the complete non-slow
suite. CI image IDs may differ from workstation IDs; outputs are tested within one immutable
environment. Workstation doctor compares local config and lock IDs. No CI result is claimed
before it actually completes.

Scratch explicitly permits execution for native corpus smoke binaries and Java native helpers;
network, UID, read-only mounts, capabilities, CPU/memory/PID limits still apply. Container cleanup
failures return internal with a diagnostic detail; they cannot silently report a successful job.

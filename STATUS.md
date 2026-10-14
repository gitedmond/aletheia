# Aletheia status

Active phase: Phase 1A. Active milestone: T00-T04 infrastructure.
Author confirmed the employment/IP review is not applicable before implementation.
This record contains project decisions, not private agreement contents.

## Accepted setup decisions

- Non-root WSL account edmond; checkout /home/edmond/src/aletheia.
- Public personal repository gitedmond/aletheia; original code and dev corpus MIT.
- Native Docker Engine reused; no existing workloads or data removed.
- uv_build approved as build-only dependency; required upstream dependencies locked and audited.
- Project images referenced by full local SHA-256 IDs; no image registry or image publishing.
- Hosted spend zero; providers, lane G, held-out infrastructure, and agent power analysis deferred.
- C1-C7 remain settled. No fixtures, mappings, analyzer options, or HR gates approved.
- Original OneDrive documents are immutable staging sources; Linux checkout is maintained.

## Environment observed

Windows personal development host: AMD Ryzen 7 9700X (8 cores/16 threads), 32 GB RAM,
RTX 5070 Ti. Ubuntu 24.04.4 WSL2, kernel 6.18.33.2; WSL memory about 15 GiB.
Native Docker Engine/client 29.1.3, containerd 2.2.1, runc 1.3.4.
Account edmond UID/GID 1001, Docker group 110. Python managed by pinned uv 0.13.0.

## Tasks

| Task | State | Evidence / pending work |
|---|---|---|
| T00 | validated; conversion awaiting human review | CLI acceptance failed with missing aletheia.cli before implementation; after implementation Ruff/Pyright passed, pytest 2 passed; both aliases --help exit 0 |
| T01 | planned | Pins, audits, images, doctor |
| T02 | planned | Contract models, canonicalization, export |
| T03 | planned | SQLite and artifact store |
| T04 | planned | Container runner and worker protocol |

No human review gates are signed off. Conversion review remains pending.
Next eligible task after T00 validation: T01.

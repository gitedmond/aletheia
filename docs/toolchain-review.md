# Toolchain review

Both image builds verify external download SHA-256 hashes. Ubuntu packages come from signed
snapshot 20261013T000000Z; certificate trust is bootstrapped from a pinned, hash-verified Ubuntu
ca-certificates package. The images use the same pinned Python, and Ghidra 11.4.3 starts with
PyGhidra 2.2.1 and Temurin 21 under containment. capa uses its default Vivisect backend; its
optional Ghidra extra requires PyGhidra 3 and is intentionally absent. Capstone is locked in
the corpus dependency group and absent from the analysis image.

The static Trivy scan reported 2,670 build-image findings and 64 analysis-image findings.
These counts are scanner records, not confirmed exploitable paths. Build findings are dominated
by linux-libc-dev header-package CVEs: that package supplies compilation headers, and the
container runs the WSL host kernel. This does not assess whether the WSL kernel is patched.

Analysis findings include old Java libraries shipped in Ghidra's server, debugger, BSim, and
core components. The server and debugger are not started. Some core JAR findings still require
reachability review before untrusted binary analysis is introduced in T09/T12. The required
latest stable 11.x release remains pinned; libraries have not been silently replaced with
untested versions or Ghidra 12. This review is pending, and no binary-analysis handler exists yet.

Python findings against msgpack 1.1.2, setuptools 70.3.0, and urllib3 2.7.0 were imported from
bundled SBOM metadata. The active environment contains locked msgpack 1.2.3 and does not install
urllib3 or setuptools. These are possible stale-SBOM findings, recorded rather than blanket
suppressed. Inspect actual paths and bundled components before disposition.

The pinned image is a development sandbox, not evidence that hostile binaries are safe.
Network isolation, read-only root, non-root UID, dropped capabilities, no-new-privileges,
instruction limits in future handlers, and measured memory/time caps reduce exposure.
No image is distributed, and no server, provider, classifier, or embedding service runs.

Audit evidence is static and date-specific. It does not cover every native tool advisory,
the WSL host kernel, Docker daemon, or dynamic reachability. Repeat the scan after changing
image inputs; preserve findings and resolve applicable vulnerabilities before enabling their
affected paths. Human review of the residual 11.x risks is pending.


Review metadata clarification (2026-10-14): the six historical Python findings
against msgpack 1.1.2, setuptools 70.3.0, and urllib3 2.7.0 are the possible
stale-SBOM records discussed above. This caveat applies to each record; none is
suppressed or treated as disposed. The historical scanner findings remain unchanged.
The Unicorn inventory now distinguishes its PyPI BSD metadata from the reviewed
GPL-2.0-only engine and bundled-component notices.

Recompute historical finding counts from the retained JSON when preparing a review:
```sh
python3 -c 'import json; from pathlib import Path; print({r["image"]: len(r["findings"]) for r in json.loads(Path("docs/image-audit.json").read_text())})'
```

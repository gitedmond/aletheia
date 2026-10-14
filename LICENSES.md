# Dependency licenses and audit

Original Aletheia code and the planned original dev corpus are MIT. This does not relicense
dependencies or bundled third-party components. No images or third-party binaries are published.

| Component | License | Reviewed source |
|---|---|---|
| Python | PSF-2.0 plus bundled licenses | https://github.com/python/cpython/blob/3.12/LICENSE |
| uv / uv_build / ruff | MIT OR Apache-2.0 | https://github.com/astral-sh/uv |
| LLVM / clang | Apache-2.0 WITH LLVM-exception | https://github.com/llvm/llvm-project/blob/llvmorg-23.1.3/LICENSE.TXT |
| Ghidra / PyGhidra | Apache-2.0 plus bundled components | https://github.com/NationalSecurityAgency/ghidra/blob/Ghidra_11.4.3_build/LICENSE |
| Temurin JDK | GPL-2.0 WITH Classpath-exception-2.0 plus bundled components | https://adoptium.net/about |
| GhidraFindcrypt | GPL-3.0-or-later | https://github.com/antoniovazquezblanco/GhidraFindcrypt |
| capa / capa-rules | Apache-2.0 | https://github.com/mandiant/capa and https://github.com/mandiant/capa-rules |
| Unicorn | GPL-2.0-only plus bundled components | https://github.com/unicorn-engine/unicorn/blob/2.1.4/COPYING |
| Capstone | BSD-3-Clause | https://github.com/capstone-engine/capstone |
| GNU make | GPL-3.0-or-later | https://www.gnu.org/software/make/ |
| Trivy (audit tool only) | Apache-2.0 | https://github.com/aquasecurity/trivy |

The version-specific metadata for all 73 locked Python dependencies is retained in
[dependencies.json](licenses/dependencies.json). ida-settings omits the license in its
PyPI metadata; its upstream ida-plugin.json declares Apache 2.0:
https://github.com/williballenthin/ida-settings/blob/master/ida-plugin.json.
Its installed package is used by capa, and this source-level declaration is recorded explicitly.
The upstream declaration is not a license grant invented by Aletheia.

The images retain Ubuntu package copyright files under /usr/share/doc, Ghidra license notices, the JDK
legal directory, and upstream plugin/rule notices. Local use is the current scope. Any later
distribution of images requires a separate review of copyleft source and notice obligations.

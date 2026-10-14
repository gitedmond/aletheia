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
[dependency-licenses.json](docs/dependency-licenses.json). ida-settings omits the license in its
PyPI metadata; its upstream ida-plugin.json declares Apache 2.0:
https://github.com/williballenthin/ida-settings/blob/master/ida-plugin.json.
Its installed package is used by capa, and this source-level declaration is recorded explicitly.
The upstream declaration is not a license grant invented by Aletheia.

Native package versions are in [image-inventory.json](docs/image-inventory.json); the images
retain Ubuntu package copyright files under /usr/share/doc, Ghidra license notices, the JDK
legal directory, and upstream plugin/rule notices. Local use is the current scope. Any later
distribution of images requires a separate review of copyleft source and notice obligations.

OSV queried every locked Python dependency on 2026-10-13 and returned zero advisories; this is
the limited result of that database query, not a clean bill of health for the image.
Trivy 0.75.0 scanned both images, including OS, Java, and Python contents. Every reported finding
is retained in [image-audit.json](docs/image-audit.json); raw scanner output stays in the local
audit cache. [toolchain-review.md](docs/toolchain-review.md) describes residual risks and
scanner limitations. Scanning never suppresses findings automatically.

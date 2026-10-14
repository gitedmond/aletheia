# Version lock

Bootstrap pins are frozen in T00. T01 completes native tools and image identity.
The TOML block is machine-readable; measurements are informational.

```toml
lock_version = 1
[pins.python]
version = "3.12.15"
url = "https://github.com/astral-sh/python-build-standalone/releases/download/20261009/cpython-3.12.15%2B20261009-x86_64-unknown-linux-gnu-install_only_stripped.tar.gz"
sha256 = "ffa8f85f1b56e88b687f08d743d817015524b86a9365fd921243132b80f1a36d"
[pins.uv]
version = "0.13.0"
url = "https://github.com/astral-sh/uv/releases/download/0.13.0/uv-x86_64-unknown-linux-gnu.tar.gz"
sha256 = "1468ebd5a5541121837c5a2817b9972ba6090fa6caa3d142620850a47fb75154"
[pins.uv_build]
version = "0.13.0"
url = "https://files.pythonhosted.org/packages/99/c9/d0e1efbc7c4f67b406bbd0b98b0ffdcf18c28bd9b9fe0049412f519441ad/uv_build-0.13.0-py3-none-manylinux_2_17_x86_64.manylinux2014_x86_64.whl"
sha256 = "450818d52535a43663982fa8306e4b8057986234b94a6cecb964958fd49b5602"
[pins.ruff]
version = "0.17.0"
[pins.pyright]
version = "1.1.414"
[pins.pytest]
version = "9.1.1"
[pins.nodejs_wheel_binaries]
version = "24.19.0"

[pins.clang]
version = "23.1.3"
url = "https://github.com/llvm/llvm-project/releases/download/llvmorg-23.1.3/LLVM-23.1.3-Linux-X64.tar.xz"
sha256 = "ca9fe385a5d9e2d88132dc0e23a00e9f87f38fa75f67207b5e457d208e71d013"
[pins.ghidra]
version = "11.4.3"
url = "https://github.com/NationalSecurityAgency/ghidra/releases/download/Ghidra_11.4.3_build/ghidra_11.4.3_PUBLIC_20251203.zip"
sha256 = "b22a8baebb14339f19903c54363ba7e01781930cc43ab430539aabce0d58547a"
[pins.jdk]
version = "21.0.12.1+1"
url = "https://github.com/adoptium/temurin21-binaries/releases/download/jdk-21.0.12.1%2B1/OpenJDK21U-jdk_x64_linux_hotspot_21.0.12.1_1.tar.gz"
sha256 = "ce79869e1307ed8ee1e2baa86a412b1eb5b75d10a01006d788a6f968bcfaee94"
[pins.findcrypt]
version = "3.1.10"
url = "https://github.com/antoniovazquezblanco/GhidraFindcrypt/releases/download/v3.1.10/ghidra_11.4.3_PUBLIC_20260927_GhidraFindcrypt.zip"
sha256 = "4cf4e47b9243b8c1d668ca067d658e91b62292e2df2048bf93f9dfc442970ba3"
[pins.capa_rules]
version = "9.4.0"
url = "https://github.com/mandiant/capa-rules/archive/2af9fbfc1c9b4634dbeb76b5d34fca9389fa7f80.tar.gz"
sha256 = "d18c5d57c3ab2089a54ca95da2b54d83ccb7dbc6c9db071f47d3f6c4afe703de"
[pins.trivy]
version = "0.75.0"
url = "https://github.com/aquasecurity/trivy/releases/download/v0.75.0/trivy_0.75.0_Linux-64bit.tar.gz"
sha256 = "c6e65abddb348e25f10549df887045629cf28cc72453cd1c63acb717316b3f3f"
[pins.ca_bootstrap]
version = "20260601~24.04.1"
url = "https://archive.ubuntu.com/ubuntu/pool/main/c/ca-certificates/ca-certificates_20260601~24.04.1_all.deb"
sha256 = "6bac2a01979e210d9eac1d4d56747ec709ea60654744d66705dc3c36e7629e50"
[packages]
"annotated-doc" = "0.0.5"
"annotated-types" = "0.8.0"
"anyio" = "4.15.1"
"attrs" = "26.1.0"
"capstone" = "5.0.9"
"certifi" = "2026.7.22"
"click" = "8.5.0"
"colorama" = "0.4.6"
"cxxfilt" = "0.3.0"
"dncil" = "1.0.2"
"dnfile" = "0.18.0"
"flare-capa" = "9.4.0"
"funcy" = "2.1"
"h11" = "0.16.0"
"httpcore" = "1.0.9"
"httpx" = "0.28.1"
"humanize" = "4.16.0"
"ida-hcli" = "0.26.3"
"ida-netnode" = "3.0"
"ida-settings" = "3.5.2"
"idapro" = "0.0.11"
"idna" = "3.20"
"iniconfig" = "2.3.1"
"intervaltree" = "3.2.1"
"jpype1" = "1.7.1"
"jsonschema" = "4.26.0"
"jsonschema-specifications" = "2025.9.1"
"markdown-it-py" = "4.2.0"
"mdurl" = "0.1.2"
"msgpack" = "1.2.3"
"msgspec" = "0.22.0"
"networkx" = "3.7"
"nodeenv" = "1.11.0"
"nodejs-wheel-binaries" = "24.19.0"
"packaging" = "26.3"
"pefile" = "2024.8.26"
"pip" = "26.2.1"
"platformdirs" = "4.13.0"
"pluggy" = "1.6.0"
"prompt-toolkit" = "3.0.53"
"protobuf" = "7.36.2"
"pyasn1" = "0.6.4"
"pyasn1-modules" = "0.4.2"
"pycparser" = "3.11"
"pydantic" = "2.14.1"
"pydantic-core" = "2.50.1"
"pyelftools" = "0.33"
"pyghidra" = "2.2.1"
"pygments" = "2.21.0"
"pyright" = "1.1.414"
"pytest" = "9.1.1"
"python-flirt" = "0.10.0"
"pyyaml" = "6.0.3"
"questionary" = "2.1.1"
"referencing" = "0.37.0"
"rich" = "15.0.0"
"rich-click" = "1.9.9"
"rpds-py" = "2026.9.1"
"ruamel-yaml" = "0.19.1"
"ruff" = "0.17.0"
"semantic-version" = "2.10.0"
"shellingham" = "1.5.4"
"six" = "1.17.0"
"sortedcontainers" = "2.4.0"
"tenacity" = "9.2.1"
"typer" = "0.27.3"
"typing-extensions" = "4.16.0"
"typing-inspection" = "0.4.4"
"unicorn" = "2.1.4"
"viv-utils" = "0.8.1"
"vivisect" = "1.3.2"
"wcwidth" = "0.9.2"
"xmltodict" = "1.0.4"
[images]
build = "sha256:32287de49948decfc85fa7f7d63f5636be723cfa34429524d617329ed98adbca"
analysis = "sha256:ba2695133fd3b74d0e96eeea69fa2a1b5eb83340c75789164153c389cc2056fd"
base = "ubuntu@sha256:534baea6a22c03a63003dbc8dbe78fe34bc0d7e595d9a9dc9834884ff530eb55"
[ubuntu]
snapshot = "20261013T000000Z"
[host]
docker = "29.1.3"
containerd = "2.2.1"
runc = "1.3.4"
[measurements]
```

All Python dependency URLs and SHA-256 hashes are in uv.lock. Native package versions and licenses are retained in docs/image-inventory.json. Local image IDs are immutable; rebuilding requires an explicit lock update. T09 peak-RAM measurement is pending.

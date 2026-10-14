FROM ubuntu@sha256:534baea6a22c03a63003dbc8dbe78fe34bc0d7e595d9a9dc9834884ff530eb55
ENV DEBIAN_FRONTEND=noninteractive SOURCE_DATE_EPOCH=0 TZ=UTC LC_ALL=C.UTF-8
COPY docker/ca-certificates.deb /tmp/ca.deb
RUN echo '6bac2a01979e210d9eac1d4d56747ec709ea60654744d66705dc3c36e7629e50  /tmp/ca.deb' | sha256sum -c - && dpkg-deb -x /tmp/ca.deb /tmp/ca && mkdir -p /etc/ssl/certs && cat /tmp/ca/usr/share/ca-certificates/mozilla/*.crt > /etc/ssl/certs/ca-certificates.crt && rm -rf /tmp/ca /tmp/ca.deb
RUN printf 'Types: deb\nURIs: https://snapshot.ubuntu.com/ubuntu/20261013T000000Z/\nSuites: noble noble-updates noble-security\nComponents: main universe restricted multiverse\nSigned-By: /usr/share/keyrings/ubuntu-archive-keyring.gpg\nSnapshot: no\n' > /etc/apt/sources.list.d/ubuntu.sources && apt-get -o Acquire::Retries=3 update --error-on=any && apt-get -o Acquire::Retries=3 install -y --no-install-recommends ca-certificates curl xz-utils make libc6-dev libgcc-13-dev libstdc++6 libxml2 zlib1g libzstd1 libtinfo6 && rm -rf /var/lib/apt/lists/*
RUN curl -fsSL --retry 2 -o /tmp/llvm.tar.xz https://github.com/llvm/llvm-project/releases/download/llvmorg-23.1.3/LLVM-23.1.3-Linux-X64.tar.xz && echo 'ca9fe385a5d9e2d88132dc0e23a00e9f87f38fa75f67207b5e457d208e71d013  /tmp/llvm.tar.xz' | sha256sum -c - && mkdir -p /opt/llvm && tar -xf /tmp/llvm.tar.xz --strip-components=1 -C /opt/llvm && find /opt/llvm/bin -mindepth 1 -maxdepth 1  ! -name clang ! -name clang-23 ! -name lld ! -name ld.lld ! -name llvm-strip ! -name llvm-objcopy ! -name llvm-objdump ! -name llvm-readobj ! -name llvm-nm ! -name llvm-ar ! -name llvm-ranlib ! -name llvm-size -delete && find /opt/llvm/lib -mindepth 1 -maxdepth 1 ! -name clang -exec rm -rf {} + && rm -rf /opt/llvm/include /opt/llvm/libexec && rm /tmp/llvm.tar.xz
ENV PATH=/opt/llvm/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
RUN ln -s /opt/llvm/bin/ld.lld /usr/local/bin/ld && clang --version && llvm-strip --version && make --version
RUN curl -fsSL --retry 2 -o /tmp/uv.tar.gz https://github.com/astral-sh/uv/releases/download/0.13.0/uv-x86_64-unknown-linux-gnu.tar.gz && echo '1468ebd5a5541121837c5a2817b9972ba6090fa6caa3d142620850a47fb75154  /tmp/uv.tar.gz' | sha256sum -c - && tar -xzf /tmp/uv.tar.gz -C /tmp && install /tmp/uv-x86_64-unknown-linux-gnu/uv /usr/local/bin/uv && rm -rf /tmp/uv*
ENV UV_PYTHON_INSTALL_DIR=/opt/python UV_PROJECT_ENVIRONMENT=/opt/venv
COPY docker/python-release.json /tmp/python-release.json
RUN PYTHON_URL="$(sed -n 's/^[[:space:]]*"url":[[:space:]]*"\([^" ]*\)".*/\1/p' /tmp/python-release.json)" && PYTHON_SHA256="$(sed -n 's/^[[:space:]]*"digest":[[:space:]]*"sha256:\([^" ]*\)".*/\1/p' /tmp/python-release.json)" && test -n "$PYTHON_URL" && test -n "$PYTHON_SHA256" && curl -fsSL --retry 2 -o /tmp/python.tar.gz "$PYTHON_URL" && printf '%s  /tmp/python.tar.gz\n' "$PYTHON_SHA256" | sha256sum -c - && mkdir -p /opt/python && tar -xzf /tmp/python.tar.gz --strip-components=1 -C /opt/python && rm /tmp/python.tar.gz
WORKDIR /opt/aletheia
COPY pyproject.toml uv.lock README.md LICENSE ./
COPY aletheia/ ./aletheia/
RUN uv sync --frozen --no-dev --group corpus --no-editable --python /opt/python/bin/python3.12 && rm -rf /root/.cache/uv
ENV PATH=/opt/venv/bin:/opt/llvm/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin PYTHONDONTWRITEBYTECODE=1 HOME=/scratch
RUN python --version && python -c "import importlib.metadata as m; assert m.version('capstone') == '5.0.9'; assert m.version('pyelftools') == '0.33'"
USER 1001:1001
ENV TMPDIR=/scratch
WORKDIR /scratch

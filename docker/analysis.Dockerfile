FROM ubuntu@sha256:534baea6a22c03a63003dbc8dbe78fe34bc0d7e595d9a9dc9834884ff530eb55
ENV DEBIAN_FRONTEND=noninteractive SOURCE_DATE_EPOCH=0 TZ=UTC LC_ALL=C.UTF-8
COPY docker/ca-certificates.deb /tmp/ca.deb
RUN echo '6bac2a01979e210d9eac1d4d56747ec709ea60654744d66705dc3c36e7629e50  /tmp/ca.deb' | sha256sum -c - && dpkg-deb -x /tmp/ca.deb /tmp/ca && mkdir -p /etc/ssl/certs && cat /tmp/ca/usr/share/ca-certificates/mozilla/*.crt > /etc/ssl/certs/ca-certificates.crt && rm -rf /tmp/ca /tmp/ca.deb
RUN printf 'Types: deb\nURIs: https://snapshot.ubuntu.com/ubuntu/20261013T000000Z/\nSuites: noble noble-updates noble-security\nComponents: main universe restricted multiverse\nSigned-By: /usr/share/keyrings/ubuntu-archive-keyring.gpg\nSnapshot: no\n' > /etc/apt/sources.list.d/ubuntu.sources && apt-get -o Acquire::Retries=3 update --error-on=any && apt-get -o Acquire::Retries=3 install -y --no-install-recommends ca-certificates curl xz-utils unzip libstdc++6 libtinfo6 libfontconfig1 && rm -rf /var/lib/apt/lists/*
RUN curl -fsSL --retry 2 -o /tmp/uv.tar.gz https://github.com/astral-sh/uv/releases/download/0.13.0/uv-x86_64-unknown-linux-gnu.tar.gz && echo '1468ebd5a5541121837c5a2817b9972ba6090fa6caa3d142620850a47fb75154  /tmp/uv.tar.gz' | sha256sum -c - && tar -xzf /tmp/uv.tar.gz -C /tmp && install /tmp/uv-x86_64-unknown-linux-gnu/uv /usr/local/bin/uv && rm -rf /tmp/uv*
RUN curl -fsSL --retry 2 -o /tmp/jdk.tar.gz https://github.com/adoptium/temurin21-binaries/releases/download/jdk-21.0.12.1%2B1/OpenJDK21U-jdk_x64_linux_hotspot_21.0.12.1_1.tar.gz && echo 'ce79869e1307ed8ee1e2baa86a412b1eb5b75d10a01006d788a6f968bcfaee94  /tmp/jdk.tar.gz' | sha256sum -c - && mkdir -p /opt/jdk && tar -xzf /tmp/jdk.tar.gz --strip-components=1 -C /opt/jdk && rm /tmp/jdk.tar.gz
RUN curl -fsSL --retry 2 -o /tmp/ghidra.zip https://github.com/NationalSecurityAgency/ghidra/releases/download/Ghidra_11.4.3_build/ghidra_11.4.3_PUBLIC_20251203.zip && echo 'b22a8baebb14339f19903c54363ba7e01781930cc43ab430539aabce0d58547a  /tmp/ghidra.zip' | sha256sum -c - && unzip -q /tmp/ghidra.zip -d /opt && mv /opt/ghidra_11.4.3_PUBLIC /opt/ghidra && rm /tmp/ghidra.zip
RUN curl -fsSL --retry 2 -o /tmp/findcrypt.zip https://github.com/antoniovazquezblanco/GhidraFindcrypt/releases/download/v3.1.10/ghidra_11.4.3_PUBLIC_20260927_GhidraFindcrypt.zip && echo '4cf4e47b9243b8c1d668ca067d658e91b62292e2df2048bf93f9dfc442970ba3  /tmp/findcrypt.zip' | sha256sum -c - && unzip -q /tmp/findcrypt.zip -d /opt/ghidra/Ghidra/Extensions && rm /tmp/findcrypt.zip
COPY docker/capa-rules.lock /tmp/capa-rules.lock
RUN . /tmp/capa-rules.lock && curl -fsSL --retry 2 -o /tmp/rules.tar.gz "$RULES_URL" && echo "$RULES_SHA256  /tmp/rules.tar.gz" | sha256sum -c - && mkdir -p /opt/capa-rules && tar -xzf /tmp/rules.tar.gz --strip-components=1 -C /opt/capa-rules && rm /tmp/rules.tar.gz
ENV UV_PYTHON_INSTALL_DIR=/opt/python UV_PROJECT_ENVIRONMENT=/opt/venv JAVA_HOME=/opt/jdk GHIDRA_INSTALL_DIR=/opt/ghidra
COPY docs/python-release.json /tmp/python-release.json
RUN PYTHON_URL="$(sed -n 's/^[[:space:]]*"url":[[:space:]]*"\([^" ]*\)".*/\1/p' /tmp/python-release.json)" && PYTHON_SHA256="$(sed -n 's/^[[:space:]]*"digest":[[:space:]]*"sha256:\([^" ]*\)".*/\1/p' /tmp/python-release.json)" && test -n "$PYTHON_URL" && test -n "$PYTHON_SHA256" && curl -fsSL --retry 2 -o /tmp/python.tar.gz "$PYTHON_URL" && printf '%s  /tmp/python.tar.gz\n' "$PYTHON_SHA256" | sha256sum -c - && mkdir -p /opt/python && tar -xzf /tmp/python.tar.gz --strip-components=1 -C /opt/python && rm /tmp/python.tar.gz
WORKDIR /opt/aletheia
COPY pyproject.toml uv.lock README.md LICENSE ./
COPY aletheia/ ./aletheia/
RUN uv sync --frozen --no-dev --group analysis --no-editable --python /opt/python/bin/python3.12 && rm -rf /root/.cache/uv
ENV PATH=/opt/venv/bin:/opt/jdk/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin PYTHONDONTWRITEBYTECODE=1 HOME=/scratch JAVA_TOOL_OPTIONS="-Duser.home=/scratch -Djava.io.tmpdir=/scratch"
RUN python --version && java -version && capa --version
USER 1001:1001
ENV TMPDIR=/scratch
WORKDIR /scratch
ENTRYPOINT ["python", "-m", "aletheia.worker"]

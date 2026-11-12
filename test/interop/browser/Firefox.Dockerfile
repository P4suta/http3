# SPDX-FileCopyrightText: 2026 the http contributors
# SPDX-License-Identifier: MIT OR Apache-2.0
# The alternative OTP 28 base is pinned in README.md; it is never a tag lookup.
ARG BASE_IMAGE=hexpm/erlang:29.0.5-ubuntu-noble-20260810@sha256:a6b64e4e3849f5a009c1839fc0ca016207b6926d7800f481e60942cc64fd50a0
FROM ${BASE_IMAGE}
SHELL ["/bin/bash", "-o", "pipefail", "-c"]
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates=20260816ubuntu0.24.04.2 \
    curl=8.5.0-2ubuntu10.16 \
    libsctp1=1.0.19+dfsg-2build1 \
    python3=3.12.3-0ubuntu2.1 \
    libnss3-tools=2:3.98-1ubuntu0.3 \
    libnss3=2:3.98-1ubuntu0.3 \
    libnspr4=2:4.35-1.1build1 \
    libatk1.0-0t64=2.52.0-1build1 \
    libatk-bridge2.0-0t64=2.52.0-1build1 \
    libcups2t64=2.4.7-1.2ubuntu7.14 \
    libdrm2=2.4.125-1ubuntu0.1~24.04.2 \
    libxkbcommon0=1.6.0-1build1 \
    libatspi2.0-0t64=2.52.0-1build1 \
    libxcomposite1=1:0.4.5-1build3 \
    libxdamage1=1:1.1.6-1build1 \
    libxfixes3=1:6.0.0-2build1 \
    libxrandr2=2:1.5.2-2build1 \
    libgbm1=25.2.8-0ubuntu0.24.04.4 \
    libasound2t64=1.2.11-1ubuntu0.3 \
    libglib2.0-0t64=2.80.0-6ubuntu3.10 \
    libgtk-3-0t64=3.24.41-4ubuntu1.3 \
    fonts-liberation=1:2.1.5-3 \
    libegl1=1.7.0-1build1 \
    libgl1-mesa-dri=25.2.8-0ubuntu0.24.04.4 \
    libglx-mesa0=25.2.8-0ubuntu0.24.04.4 \
    libpci3=1:3.10.0-2build1 \
    && rm -rf /var/lib/apt/lists/*
RUN curl --fail --location --silent --show-error --max-time 120 --max-filesize 33554432 \
      https://github.com/gleam-lang/gleam/releases/download/v1.18.1/gleam-v1.18.1-x86_64-unknown-linux-musl.tar.gz \
      --output /tmp/gleam.tar.gz \
    && printf '%s  %s\n' 4955a38c2e8c99457458e2471472ccd5ee3c45bd7637a315ce33bccf0dd75d9e /tmp/gleam.tar.gz | sha256sum -c - \
    && tar -xzf /tmp/gleam.tar.gz -C /usr/local/bin gleam \
    && curl --fail --location --silent --show-error --max-time 120 --max-filesize 16777216 \
      https://github.com/erlang/rebar3/releases/download/3.27.0/rebar3 --output /tmp/rebar3 \
    && printf '%s  %s\n' af85aab41f9fd74bdd6341ebdf6fe9c88077aab9f8eac82371583fa02f2b0bdf /tmp/rebar3 | sha256sum -c - \
    && install -m 0755 /tmp/rebar3 /usr/local/bin/rebar3
COPY firefox_setup.py firefox_archive.py archive.py firefox-pins.json /opt/browser-setup/
RUN python3 -B /opt/browser-setup/firefox_setup.py --download \
      --archives /opt/firefox-archives --destination /opt/firefox \
    && useradd -m -u 10001 -s /bin/bash interop
ENV PATH="/opt/firefox/firefox:/opt/firefox:${PATH}"
ENV PYTHONDONTWRITEBYTECODE=1
USER 10001
WORKDIR /work

# SPDX-FileCopyrightText: 2026 the http contributors
# SPDX-License-Identifier: MIT OR Apache-2.0
# The alternative OTP 28 base is pinned in README.md; it is never a tag lookup.
ARG BASE_IMAGE=hexpm/erlang@sha256:a6b64e4e3849f5a009c1839fc0ca016207b6926d7800f481e60942cc64fd50a0
FROM ${BASE_IMAGE}
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates curl libsctp1 python3 libnss3-tools libnss3 libnspr4 \
    libatk1.0-0t64 libatk-bridge2.0-0t64 libcups2t64 libdrm2 libxkbcommon0 \
    libatspi2.0-0t64 libxcomposite1 libxdamage1 libxfixes3 libxrandr2 libgbm1 \
    libasound2t64 libglib2.0-0t64 libgtk-3-0t64 fonts-liberation libegl1 libgl1-mesa-dri libglx-mesa0 libpci3
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
USER interop
WORKDIR /work

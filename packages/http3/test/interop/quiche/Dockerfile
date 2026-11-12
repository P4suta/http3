# SPDX-FileCopyrightText: 2026 the http contributors
# SPDX-License-Identifier: MIT OR Apache-2.0
FROM rust:1.98.1-slim-bookworm@sha256:6ac25dcaa81e06721043f9a815b6000c87ba2f56bf7b82a3ad0e65ae71067e0d AS build
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates git clang cmake pkg-config build-essential perl python3
WORKDIR /opt/quiche
RUN git init && git remote add origin https://github.com/cloudflare/quiche.git \
    && git fetch --depth=1 origin 55886df3be579579207104c8e645825b6347a209 \
    && git checkout --detach FETCH_HEAD \
    && test "$(git rev-parse HEAD)" = 55886df3be579579207104c8e645825b6347a209
COPY packages/http3/test/interop/quiche/Cargo.lock /opt/quiche/Cargo.lock
COPY packages/http3/test/interop/quiche/identity_patch.py /inputs/identity_patch.py
COPY scripts/process_supervisor.py /inputs/process_supervisor.py
ENV CARGO_BUILD_JOBS=2
RUN python3 /inputs/identity_patch.py apply \
    && timeout --signal=TERM --kill-after=10s 1200s cargo build --locked --release \
        --package quiche_apps --bin quiche-client --bin quiche-server \
    && python3 /inputs/identity_patch.py verify
FROM scratch AS artifacts
COPY --from=build /opt/quiche/target/release/quiche-client /bin/quiche-client
COPY --from=build /opt/quiche/target/release/quiche-server /bin/quiche-server
COPY --from=build /opt/quiche/http-interop-identity.json /build-identity.json

#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 the http contributors
# SPDX-License-Identifier: MIT OR Apache-2.0
set -Eeuo pipefail
repository_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../../.." && pwd -P)"
readonly repository_root
[[ -z ${NODE_OPTIONS:-} && -z ${NODE_PATH:-} ]]
node_version="$(node --version)"
npm_version="$(npm --version)"
readonly node_version npm_version
[[ ${node_version} == v26.13.0 ]]
[[ ${npm_version} == 11.20.0 ]]
installation="${repository_root}/build/interop/ohttpts"
readonly installation
mkdir -p "${installation}"
for file in package.json package-lock.json peer.mjs peer_test.mjs; do
	cp -- "${repository_root}/test/interop/ohttpts/${file}" "${installation}/${file}"
done
cd -- "${installation}"
timeout --signal=TERM --kill-after=5s 120s npm ci --ignore-scripts --no-audit --no-fund
cmp -- package-lock.json "${repository_root}/test/interop/ohttpts/package-lock.json"
timeout --signal=TERM --kill-after=5s 120s python3 "${repository_root}/scripts/interop_peer.py" \
	--prepare-node-archives "${repository_root}"

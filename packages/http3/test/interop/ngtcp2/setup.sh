#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 the http contributors
# SPDX-License-Identifier: MIT OR Apache-2.0
set -Eeuo pipefail
repository_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../../../../.." && pwd -P)"
readonly repository_root
cd -- "$repository_root"
[[ "$(uname -s)" == Linux ]]
command -v docker >/dev/null
command -v escript >/dev/null
escript scripts/interop_audit.escript --prepare ngtcp2-nghttp3-h3
mkdir -p build
output="$(mktemp -d "$repository_root/build/interop-ngtcp2.XXXXXX")"
readonly output
cleanup() {
	local status=$?
	trap - EXIT INT TERM
	case "$output" in
	"$repository_root"/build/interop-ngtcp2.??????) find "$output" -depth -delete ;;
	*) status=1 ;;
	esac
	exit "$status"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
timeout --signal=TERM --kill-after=10s 1800s docker build \
	-f packages/http3/test/interop/ngtcp2/Dockerfile \
	--output "type=local,dest=$output" .
destination="$repository_root/packages/http3/build/interop-ngtcp2"
mkdir -p "$destination"
for role in client server; do
	test -s "$output/bin/ngtcp2-$role"
	chmod 755 "$output/bin/ngtcp2-$role"
done
cp -a "$output/." "$destination/"
echo 'Pinned ngtcp2/nghttp3 peer binaries built; scenario execution is still required'

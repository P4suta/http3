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
escript scripts/interop_audit.escript --prepare quiche-h3
mkdir -p build
output="$(mktemp -d "$repository_root/build/interop-quiche.XXXXXX")"
readonly output
cleanup() {
	local status=$?
	trap - EXIT INT TERM
	case "$output" in
	"$repository_root"/build/interop-quiche.??????) find "$output" -depth -delete ;;
	*) status=1 ;;
	esac
	exit "$status"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
timeout --signal=TERM --kill-after=10s 1800s docker build \
	-f packages/http3/test/interop/quiche/Dockerfile \
	--output "type=local,dest=$output" .
destination="$repository_root/packages/http3/build/interop-quiche"
mkdir -p "$destination"
for name in quiche-client quiche-server; do
	test -s "$output/bin/$name"
	chmod 755 "$output/bin/$name"
	mv -- "$output/bin/$name" "$destination/$name"
done
mv -- "$output/build-identity.json" "$destination/build-identity.json"
echo 'Pinned quiche peer binaries built; scenario execution is still required'

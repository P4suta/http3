#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 the http contributors
# SPDX-License-Identifier: MIT OR Apache-2.0
set -Eeuo pipefail
repository_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../../.." && pwd -P)"
readonly repository_root
cd -- "$repository_root"
for command in go python3 erl timeout; do command -v "$command" >/dev/null; done
escript scripts/interop_audit.escript --prepare masque-independent
work_directory="$(mktemp -d "${TMPDIR:-/tmp}/http-masque-interop.XXXXXX")"
readonly work_directory
declare -A children=()
interop_run_id=""
cleanup() {
	local status=$? child attempt
	trap - EXIT INT TERM
	set +e
	for child in "${!children[@]}"; do kill -TERM "$child" 2>/dev/null; done
	for ((attempt = 0; attempt < 100; attempt += 1)); do
		local live=0
		for child in "${!children[@]}"; do if kill -0 "$child" 2>/dev/null; then live=1; fi; done
		if ((live == 0)); then break; fi
		sleep 0.05
	done
	for child in "${!children[@]}"; do
		kill -KILL "$child" 2>/dev/null || true
		wait "$child"
	done
	if ((status != 0)) && [[ -n "$interop_run_id" ]]; then
		if ! timeout --signal=TERM --kill-after=5s 60s escript scripts/interop_audit.escript \
			--driver-failure masque-independent "$interop_run_id" cleanup "$status" >/dev/null 2>&1; then
			printf '%s\n' 'interop driver failure record unavailable' >&2
		fi
	fi
	case "$work_directory" in
	"${TMPDIR:-/tmp}"/http-masque-interop.??????) find "$work_directory" -depth -delete ;;
	*) status=1 ;;
	esac
	exit "$status"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
case "${HTTP_MASQUE_INTEROP_SKIP_FRESH_BUILD:-0}" in
0) bash scripts/fresh_build.sh http ;;
1) ;;
*) exit 2 ;;
esac
bash test/interop/masquego/setup.sh
interop_run_id="$(escript scripts/interop_audit.escript --begin masque-independent 'github.com/quic-go/masque-go@v0.4.0')"
if [[ ! "$interop_run_id" =~ ^[0-9a-f]{64}$ ]]; then
	echo "interop run id is unavailable" >&2
	exit 1
fi
readonly interop_run_id
export ERL_CRASH_DUMP_BYTES=0 ERL_CRASH_DUMP_SECONDS=0
readonly fixtures="$repository_root/packages/http3/test/fixtures"
readonly peer_binary="$repository_root/build/interop/bin/masque-go"
peer_command=(python3 scripts/interop_peer.py --root "$repository_root" --peer masque-independent --run-id "$interop_run_id")
native_command=(python3 test/interop/masquego/native_runner.py --beam "$repository_root/build/dev/erlang/http/ebin/http_masque_interop.beam")
wait_for_endpoints() {
	local log=$1 child=$2 line
	line="$(python3 "$repository_root/scripts/interop_notice.py" wait "$log" "$child" 60 PORT TARGET)" || return 1
	read -r REPLY_PORT REPLY_TARGET <<<"$line"
}
join_child() {
	wait "$1"
	unset 'children['"$1"']'
}
"${native_command[@]}" --role proxy --seconds 45 --readiness "$work_directory/native-ready.json" \
	--evidence build/interop/native/masque-independent/proxy.json --stop "$work_directory/native.complete" \
	--result "$work_directory/native-proxy-result.json" >"$work_directory/native.log" 2>&1 &
native=$!
children[$native]=1
wait_for_endpoints "$work_directory/native.log" "$native"
"${peer_command[@]}" --role client --scenario two-flows-and-policy-rejection --timeout 35 -- \
	"$peer_binary" -role client -endpoint "$REPLY_PORT" -target "$REPLY_TARGET" -ca "$fixtures/ca.pem" \
	>"$work_directory/client.log" 2>&1
python3 scripts/interop_notice.py publish "$work_directory/native.complete" complete
join_child "$native"
escript scripts/interop_audit.escript --record masque-independent "$interop_run_id" client two-flows-and-policy-rejection

"${peer_command[@]}" --role proxy --scenario two-flows-and-policy-rejection --timeout 35 -- \
	"$peer_binary" -role proxy -certificate "$fixtures/server.pem" -key "$fixtures/server-key.pem" \
	>"$work_directory/proxy.log" 2>&1 &
peer=$!
children[$peer]=1
wait_for_endpoints "$work_directory/proxy.log" "$peer"
"${native_command[@]}" --role client --seconds 30 \
	--evidence build/interop/native/masque-independent/client.json --port "$REPLY_PORT" --target "$REPLY_TARGET" \
	--result "$work_directory/native-client-result.json"
join_child "$peer"
escript scripts/interop_audit.escript --record masque-independent "$interop_run_id" proxy two-flows-and-policy-rejection
escript scripts/interop_audit.escript --finish masque-independent "$interop_run_id"
echo 'Independent MASQUE CONNECT-UDP client and proxy interoperability passed'

#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 the http contributors
# SPDX-License-Identifier: MIT OR Apache-2.0
set -Eeuo pipefail
repository_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../../.." && pwd -P)"
readonly repository_root
cd -- "$repository_root"
for command in go python3 erl erlc timeout; do command -v "$command" >/dev/null; done
escript scripts/interop_audit.escript --prepare ohttp-go
work_directory="$(mktemp -d "${TMPDIR:-/tmp}/http-ohttpgo-interop.XXXXXX")"
readonly work_directory
declare -A children=()
interop_run_id=""
cleanup() {
	local status=$?
	local child attempt
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
		# Preserve only a typed receipt.
		# Native stderr and paths may be private.
		if ! timeout --signal=TERM --kill-after=5s 60s escript scripts/interop_audit.escript \
			--driver-failure ohttp-go "$interop_run_id" cleanup "$status" >/dev/null 2>&1; then
			echo "interop driver failure record unavailable" >&2
		fi
	fi
	case "$work_directory" in
	"${TMPDIR:-/tmp}"/http-ohttpgo-interop.??????) find "$work_directory" -depth -delete ;;
	*) status=1 ;;
	esac
	exit "$status"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
case "${HTTP_OHTTP_GO_INTEROP_SKIP_FRESH_BUILD:-0}" in
0) bash scripts/fresh_build.sh http ;;
1) ;;
*) exit 2 ;;
esac
bash test/interop/ohttpgo/setup.sh
interop_run_id="$(escript scripts/interop_audit.escript --begin ohttp-go 'github.com/chris-wood/ohttp-go@v0.0.0-20260205154755-776f22a178b8')"
if [[ ! "$interop_run_id" =~ ^[0-9a-f]{64}$ ]]; then
	echo "interop run id is unavailable" >&2
	exit 1
fi
readonly interop_run_id
erlc -Werror -o "$work_directory" test/interop/ohttpgo/http_ohttp_interop.erl
erlang_command=(erl -noshell -pa build/dev/erlang/*/ebin "$work_directory")
export ERL_CRASH_DUMP_BYTES=0 ERL_CRASH_DUMP_SECONDS=0
readonly fixtures="$repository_root/packages/http3/test/fixtures"
peer_command=(python3 scripts/interop_peer.py --root "$repository_root" --peer ohttp-go --run-id "$interop_run_id")
peer_binary="$repository_root/build/interop/bin/ohttp-go"
readonly peer_binary
wait_for_port() {
	local log=$1 child=$2
	REPLY="$(python3 "$repository_root/scripts/interop_notice.py" wait "$log" "$child" 60 PORT)"
}
join_child() {
	wait "$1"
	unset 'children['"$1"']'
}
native_client() {
	timeout --signal=TERM --kill-after=5s 35s "${erlang_command[@]}" \
		-eval 'try [Port, Config, Algorithm] = init:get_plain_arguments(), ok = http_ohttp_interop:run_client(list_to_integer(Port), list_to_integer(Config), list_to_integer(Algorithm)), halt(0) catch _:_ -> io:put_chars("native OHTTP client failed\n"), halt(1) end.' \
		-extra "$1" "$2" "$3" >"$4" 2>&1
}
for algorithm in 1 3; do
	if [[ "$algorithm" == 1 ]]; then scenario=aes128gcm; else scenario=chacha20poly1305; fi
	native_log="$work_directory/native-${algorithm}.log"
	timeout --signal=TERM --kill-after=5s 120s "${erlang_command[@]}" \
		-eval 'try [Stop] = init:get_plain_arguments(), ok = http_ohttp_interop:run_server(Stop), halt(0) catch _:_ -> io:put_chars("native OHTTP server failed\n"), halt(1) end.' \
		-extra "$work_directory/native-${algorithm}.complete" >"$native_log" 2>&1 &
	native=$!
	children[$native]=1
	wait_for_port "$native_log" "$native"
	native_port=$REPLY
	endpoint="https://localhost:${native_port}"
	client_scenario=$scenario
	client_alpn=true
	if [[ "$algorithm" == 1 ]]; then
		client_scenario=aes128gcm-no-alpn
		client_alpn=false
	fi
	"${peer_command[@]}" --role client --scenario "$client_scenario" --timeout 40 -- \
		"$peer_binary" -role client -aead "$algorithm" -alpn="$client_alpn" -endpoint "$endpoint" -ca "$fixtures/ca.pem" \
		>"$work_directory/client-${algorithm}.log" 2>&1
	escript scripts/interop_audit.escript --record ohttp-go "$interop_run_id" client "$client_scenario"

	"${peer_command[@]}" --role relay --scenario "$scenario" --timeout 60 -- \
		"$peer_binary" -role relay -aead "$algorithm" -endpoint "$endpoint" -ca "$fixtures/ca.pem" \
		-certificate "$fixtures/server.pem" -key "$fixtures/server-key.pem" \
		>"$work_directory/relay-${algorithm}.log" 2>&1 &
	peer=$!
	children[$peer]=1
	wait_for_port "$work_directory/relay-${algorithm}.log" "$peer"
	native_client "$REPLY" "$native_port" "$algorithm" "$work_directory/native-relay-${algorithm}.log"
	join_child "$peer"
	escript scripts/interop_audit.escript --record ohttp-go "$interop_run_id" relay "$scenario"
	python3 scripts/interop_notice.py publish "$work_directory/native-${algorithm}.complete" complete
	join_child "$native"

	"${peer_command[@]}" --role gateway --scenario "$scenario" --timeout 60 -- \
		"$peer_binary" -role gateway -aead "$algorithm" -ca "$fixtures/ca.pem" \
		-certificate "$fixtures/server.pem" -key "$fixtures/server-key.pem" \
		>"$work_directory/gateway-${algorithm}.log" 2>&1 &
	peer=$!
	children[$peer]=1
	wait_for_port "$work_directory/gateway-${algorithm}.log" "$peer"
	native_client "$REPLY" "$REPLY" "$algorithm" "$work_directory/native-gateway-${algorithm}.log"
	join_child "$peer"
	escript scripts/interop_audit.escript --record ohttp-go "$interop_run_id" gateway "$scenario"
done
escript scripts/interop_audit.escript --finish ohttp-go "$interop_run_id"
echo 'OHTTP Go client, relay and gateway interoperability passed for both AEADs'

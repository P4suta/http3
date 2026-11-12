#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 the http contributors
# SPDX-License-Identifier: MIT OR Apache-2.0
set -Eeuo pipefail
repository_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../../.." && pwd -P)"
readonly repository_root
cd -- "$repository_root"
for command in python3 erl erlc timeout; do command -v "$command" >/dev/null; done
readonly peer_directory="${HTTP_QUICHE_PEER_DIRECTORY:-$repository_root/packages/http3/build/interop-quiche}"
test -x "$peer_directory/quiche-client"
test -x "$peer_directory/quiche-server"
escript scripts/interop_audit.escript --prepare quiche-h3
work_directory="$(mktemp -d "${TMPDIR:-/tmp}/http-quiche-interop.XXXXXX")"
readonly work_directory
declare -a children=()
interop_run_id=""
cleanup() {
	local status=$?
	local child attempt
	trap - EXIT INT TERM
	set +e
	for child in "${children[@]}"; do kill -TERM "$child" 2>/dev/null; done
	for ((attempt = 0; attempt < 100; attempt += 1)); do
		local live=0
		for child in "${children[@]}"; do
			if kill -0 "$child" 2>/dev/null; then live=1; fi
		done
		if ((live == 0)); then break; fi
		sleep 0.05
	done
	for child in "${children[@]}"; do
		kill -KILL "$child" 2>/dev/null || true
		wait "$child" 2>/dev/null
	done
	if ((status != 0)) && [[ -n "$interop_run_id" ]]; then
		# Preserve only a typed receipt.
		# Native stderr and paths may be private.
		if ! timeout --signal=TERM --kill-after=5s 60s escript scripts/interop_audit.escript \
			--driver-failure quiche-h3 "$interop_run_id" cleanup "$status" >/dev/null 2>&1; then
			echo "interop driver failure record unavailable" >&2
		fi
	fi
	case "$work_directory" in
	"${TMPDIR:-/tmp}"/http-quiche-interop.??????) find "$work_directory" -depth -delete ;;
	*) status=1 ;;
	esac
	exit "$status"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
case "${HTTP_QUICHE_INTEROP_SKIP_FRESH_BUILD:-0}" in
0) bash scripts/fresh_build.sh http ;;
1) ;;
*) exit 2 ;;
esac
interop_run_id="$(escript scripts/interop_audit.escript --begin quiche-h3 'quiche@0.29.3')"
if [[ ! "$interop_run_id" =~ ^[0-9a-f]{64}$ ]]; then
	echo "interop run id is unavailable" >&2
	exit 1
fi
readonly interop_run_id
erlc -Werror -o "$work_directory" test/interop/quiche/http_quiche_interop.erl
erlang_command=(erl -noshell -pa build/dev/erlang/*/ebin "$work_directory")
export ERL_CRASH_DUMP_BYTES=0 ERL_CRASH_DUMP_SECONDS=0
unset SSLKEYLOGFILE QLOGDIR
printf 'quiche-independent-server' >"$work_directory/small"
python3 -c 'import sys; sys.stdout.buffer.write(b"quiche-flow-" * 6000)' >"$work_directory/large"
readonly ca="$repository_root/packages/quic_core/test/fixtures/ecdsa-p256-server.pem"

wait_for_port() {
	local log=$1 child=$2
	REPLY="$(python3 "$repository_root/scripts/interop_notice.py" wait "$log" "$child" 60 PORT)"
}

# The daemon binds port 0 itself.
# Discovery is restricted to its owned UDP descriptor and loopback address; no reservation socket is raced.
python3 scripts/interop_peer.py --root "$repository_root" --peer quiche-h3 --run-id "$interop_run_id" \
	--role server --scenario native-client-contract --timeout 90 -- \
	"$peer_directory/quiche-server" --listen 127.0.0.1:0 --http-version HTTP/3 \
	--cert "$ca" --key packages/quic_core/test/fixtures/ecdsa-p256-server-key.pem \
	--root "$work_directory" --max-stream-data 32768 --max-data 65536 --idle-timeout 20000 \
	>"$work_directory/quiche-server.log" 2>&1 &
peer=$!
children+=("$peer")
wait_for_port "$work_directory/quiche-server.log" "$peer"
timeout --signal=TERM --kill-after=5s 45s "${erlang_command[@]}" \
	-eval 'try [Port] = init:get_plain_arguments(), ok = http_quiche_interop:run(client, list_to_integer(Port)), halt(0) catch _:_ -> io:put_chars("native quiche client failed\n"), halt(1) end.' \
	-extra "$REPLY" >"$work_directory/native-client.log" 2>&1
escript scripts/interop_audit.escript --complete-daemon quiche-h3 "$interop_run_id" server native-client-contract
wait "$peer"
escript scripts/interop_audit.escript --record quiche-h3 "$interop_run_id" server native-client-contract

timeout --signal=TERM --kill-after=5s 120s "${erlang_command[@]}" \
	-eval 'try [Stop] = init:get_plain_arguments(), ok = http_quiche_interop:run(server, Stop), halt(0) catch _:_ -> io:put_chars("native quiche server failed\n"), halt(1) end.' \
	-extra "$work_directory/native.complete" >"$work_directory/native-server.log" 2>&1 &
native=$!
children+=("$native")
wait_for_port "$work_directory/native-server.log" "$native"
readonly native_port=$REPLY

run_client() {
	local scenario=$1 path=$2
	shift 2
	RUST_LOG=quiche_apps::common=debug,quiche_apps::client=error python3 scripts/interop_peer.py --root "$repository_root" --peer quiche-h3 --run-id "$interop_run_id" \
		--role client --scenario "$scenario" --timeout 40 -- \
		"$peer_directory/quiche-client" --wire-version 1 --http-version HTTP/3 \
		--trust-origin-ca-pem "$ca" --connect-to "127.0.0.1:$native_port" \
		--max-stream-data 32768 --max-data 65536 --idle-timeout 20000 \
		--dump-json --max-json-payload 131072 "$@" "https://localhost:${native_port}/${path}" \
		>"$work_directory/${scenario}.json" 2>"$work_directory/${scenario}.log"
	# Compare the actual decoded peer response, including status and trailers.
	# The JSON is a bounded local oracle and never enters public evidence.
	python3 test/interop/quiche/verify_response.py "$work_directory/${scenario}.json" \
		"$work_directory/${scenario}.log" "$work_directory/large"
	escript scripts/interop_audit.escript --record quiche-h3 "$interop_run_id" client "$scenario"
}
run_client response-flow-control large
run_client request-response-body echo --method POST --body "$work_directory/large"
python3 scripts/interop_notice.py publish "$work_directory/native.complete" complete
wait "$native"
escript scripts/interop_audit.escript --finish quiche-h3 "$interop_run_id"
echo 'quiche bidirectional HTTP/3 flow-control and body interoperability passed'

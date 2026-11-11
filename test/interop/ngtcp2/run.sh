#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 the http contributors
# SPDX-License-Identifier: MIT OR Apache-2.0
set -Eeuo pipefail
repository_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../../.." && pwd -P)"
readonly repository_root
cd -- "$repository_root"
for command in python3 erl erlc timeout; do command -v "$command" >/dev/null; done
readonly peer_directory="${HTTP_NGTCP2_PEER_DIRECTORY:-$repository_root/packages/http3/build/interop-ngtcp2/bin}"
test -x "$peer_directory/ngtcp2-client"
test -x "$peer_directory/ngtcp2-server"
escript scripts/interop_audit.escript --prepare ngtcp2-nghttp3-h3
work_directory="$(mktemp -d "${TMPDIR:-/tmp}/http-ngtcp2-interop.XXXXXX")"
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
			--driver-failure ngtcp2-nghttp3-h3 "$interop_run_id" cleanup "$status" >/dev/null 2>&1; then
			echo "interop driver failure record unavailable" >&2
		fi
	fi
	case "$work_directory" in
	"${TMPDIR:-/tmp}"/http-ngtcp2-interop.??????) find "$work_directory" -depth -delete ;;
	*) status=1 ;;
	esac
	exit "$status"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
case "${HTTP_NGTCP2_INTEROP_SKIP_FRESH_BUILD:-0}" in
0) bash scripts/fresh_build.sh http ;;
1) ;;
*) exit 2 ;;
esac
interop_run_id="$(escript scripts/interop_audit.escript --begin ngtcp2-nghttp3-h3 'ngtcp2@1.25.0')"
if [[ ! "$interop_run_id" =~ ^[0-9a-f]{64}$ ]]; then
	echo "interop run id is unavailable" >&2
	exit 1
fi
readonly interop_run_id
# Reuse the same bounded public-API oracle used for quiche.
# Its body markers are fixture bytes only; each peer invocation has separate identity/evidence.
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

python3 scripts/interop_peer.py --root "$repository_root" --peer ngtcp2-nghttp3-h3 --run-id "$interop_run_id" \
	--role server --scenario native-client-contract --timeout 90 -- \
	"$peer_directory/ngtcp2-server" --quiet --no-quic-dump --no-http-dump \
	--htdocs "$work_directory" --max-data 65536 --max-stream-data-bidi-remote 32768 \
	127.0.0.1 0 packages/quic_core/test/fixtures/ecdsa-p256-server-key.pem "$ca" \
	>"$work_directory/ngtcp2-server.log" 2>&1 &
peer=$!
children+=("$peer")
wait_for_port "$work_directory/ngtcp2-server.log" "$peer"
timeout --signal=TERM --kill-after=5s 45s "${erlang_command[@]}" \
	-eval 'try [Port] = init:get_plain_arguments(), ok = http_quiche_interop:run(client, list_to_integer(Port)), halt(0) catch _:_ -> io:put_chars("native ngtcp2 client failed\n"), halt(1) end.' \
	-extra "$REPLY" >"$work_directory/native-client.log" 2>&1
escript scripts/interop_audit.escript --complete-daemon ngtcp2-nghttp3-h3 "$interop_run_id" server native-client-contract
wait "$peer"
escript scripts/interop_audit.escript --record ngtcp2-nghttp3-h3 "$interop_run_id" server native-client-contract

timeout --signal=TERM --kill-after=5s 120s "${erlang_command[@]}" \
	-eval 'try [Stop] = init:get_plain_arguments(), ok = http_quiche_interop:run(server, Stop), halt(0) catch _:_ -> io:put_chars("native ngtcp2 server failed\n"), halt(1) end.' \
	-extra "$work_directory/native.complete" >"$work_directory/native-server.log" 2>&1 &
native=$!
children+=("$native")
wait_for_port "$work_directory/native-server.log" "$native"
readonly native_port=$REPLY

run_client() {
	local scenario=$1 path=$2
	shift 2
	python3 scripts/interop_peer.py --root "$repository_root" --peer ngtcp2-nghttp3-h3 --run-id "$interop_run_id" \
		--role client --scenario "$scenario" --timeout 40 -- \
		"$peer_directory/ngtcp2-client" --http3-only --silent --show-error --noproxy '*' \
		--connect-timeout 5 --max-time 30 --max-filesize 131072 --cacert "$ca" --resolve "localhost:$native_port:127.0.0.1" \
		--output "$work_directory/$scenario.body" --dump-header "$work_directory/$scenario.headers" \
		--write-out '%{http_version} %{response_code}\n' "$@" "https://localhost:$native_port/$path" \
		>"$work_directory/$scenario.summary" 2>"$work_directory/$scenario.log"
	python3 test/interop/ngtcp2/verify_response.py "$work_directory/$scenario.summary" \
		"$work_directory/$scenario.headers" "$work_directory/$scenario.body" "$work_directory/large"
	escript scripts/interop_audit.escript --record ngtcp2-nghttp3-h3 "$interop_run_id" client "$scenario"
}
run_client response-body-trailers large
run_client request-response-body echo --request POST --data-binary "@$work_directory/large"
python3 scripts/interop_peer.py --root "$repository_root" --peer ngtcp2-nghttp3-h3 --run-id "$interop_run_id" \
	--role client --scenario 'untrusted certificate refused' --timeout 15 -- \
	"$peer_directory/ngtcp2-client" --http3-only --silent --show-error --noproxy '*' \
	--connect-timeout 5 --max-time 10 --max-filesize 131072 --cacert packages/quic_core/test/fixtures/ca.pem \
	--resolve "localhost:$native_port:127.0.0.1" "https://localhost:$native_port/large" \
	>"$work_directory/untrusted.body" 2>"$work_directory/untrusted.log"
escript scripts/interop_audit.escript --record ngtcp2-nghttp3-h3 "$interop_run_id" client 'untrusted certificate refused'
python3 scripts/interop_notice.py publish "$work_directory/native.complete" complete
wait "$native"
escript scripts/interop_audit.escript --finish ngtcp2-nghttp3-h3 "$interop_run_id"
echo 'ngtcp2/nghttp3 authenticated bidirectional HTTP/3 interoperability passed'

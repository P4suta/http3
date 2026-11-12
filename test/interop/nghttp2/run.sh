#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 the http contributors
# SPDX-License-Identifier: MIT OR Apache-2.0
set -Eeuo pipefail
repository_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../../.." && pwd -P)"
readonly repository_root
cd -- "$repository_root"
for command in nghttp nghttpd python3 erl erlc timeout; do
	command -v "$command" >/dev/null
done
escript scripts/interop_audit.escript --prepare nghttp2-h2
work_directory="$(mktemp -d "${TMPDIR:-/tmp}/http-nghttp2-interop.XXXXXX")"
readonly work_directory
declare -a children=()
interop_run_id=""
cleanup() {
	local status=$?
	local child
	local attempt
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
			--driver-failure nghttp2-h2 "$interop_run_id" cleanup "$status" >/dev/null 2>&1; then
			echo "interop driver failure record unavailable" >&2
		fi
	fi
	case "$work_directory" in
	"${TMPDIR:-/tmp}"/http-nghttp2-interop.??????) find "$work_directory" -depth -delete ;;
	*) status=1 ;;
	esac
	exit "$status"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
case "${HTTP_NGHTTP2_INTEROP_SKIP_FRESH_BUILD:-0}" in
0) bash scripts/fresh_build.sh http ;;
1) ;;
*) exit 2 ;;
esac
interop_run_id="$(escript scripts/interop_audit.escript --begin nghttp2-h2 'nghttp2 1.59.0')"
if [[ ! "$interop_run_id" =~ ^[0-9a-f]{64}$ ]]; then
	echo "interop run id is unavailable" >&2
	exit 1
fi
readonly interop_run_id
erlc -o "$work_directory" test/interop/nghttp2/http_nghttp2_interop.erl
erlang_command=(erl -noshell -pa build/dev/erlang/*/ebin "$work_directory")
export ERL_CRASH_DUMP_BYTES=0 ERL_CRASH_DUMP_SECONDS=0
printf 'nghttp2-independent-server' >"$work_directory/small"
python3 -c 'import sys; sys.stdout.buffer.write(b"nghttp2-flow-" * 6000)' >"$work_directory/large"
readonly ca="$repository_root/packages/http3/test/fixtures/ca.pem"

wait_for_port() {
	local log=$1 child=$2
	REPLY="$(python3 "$repository_root/scripts/interop_notice.py" wait "$log" "$child" 60 PORT)"
}

# nghttpd owns port 0. The supervisor discovers only that process's bound loopback socket, so no reservation socket is closed before the peer binds.
: >"$work_directory/nghttpd.log"
python3 scripts/interop_peer.py --root "$repository_root" --peer nghttp2-h2 --run-id "$interop_run_id" \
	--role server --scenario native-client-contract --timeout 90 -- \
	nghttpd -a 127.0.0.1 -d "$work_directory" -v --echo-upload \
	--trailer 'x-response-finished: yes' 0 \
	packages/http3/test/fixtures/server-key.pem packages/http3/test/fixtures/server.pem \
	>"$work_directory/nghttpd.log" 2>&1 &
peer=$!
children+=("$peer")
wait_for_port "$work_directory/nghttpd.log" "$peer"
timeout --signal=TERM --kill-after=5s 45s "${erlang_command[@]}" \
	-eval 'try [Port] = init:get_plain_arguments(), ok = http_nghttp2_interop:run_client(list_to_integer(Port)), halt(0) catch _:_ -> io:put_chars("native nghttp2 client failed\n"), halt(1) end.' \
	-extra "$REPLY" >"$work_directory/native-client.log" 2>&1
grep -Fq 'x-upload-finished: yes' "$work_directory/nghttpd.log"
escript scripts/interop_audit.escript --complete-daemon nghttp2-h2 "$interop_run_id" server native-client-contract
wait "$peer"
escript scripts/interop_audit.escript --record nghttp2-h2 "$interop_run_id" server native-client-contract

: >"$work_directory/native-server.log"
timeout --signal=TERM --kill-after=5s 100s "${erlang_command[@]}" \
	-eval 'try [Stop] = init:get_plain_arguments(), ok = http_nghttp2_interop:run_server(Stop), halt(0) catch _:_ -> io:put_chars("native nghttp2 server failed\n"), halt(1) end.' \
	-extra "$work_directory/native.complete" >"$work_directory/native-server.log" 2>&1 &
native=$!
children+=("$native")
wait_for_port "$work_directory/native-server.log" "$native"
readonly native_port=$REPLY

run_client() {
	local scenario=$1
	local path=$2
	shift 2
	(
		cd -- "$work_directory"
		SSL_CERT_FILE="$ca" exec python3 "$repository_root/scripts/interop_peer.py" \
			--root "$repository_root" --peer nghttp2-h2 --run-id "$interop_run_id" --role client \
			--scenario "$scenario" --timeout 30 -- nghttp --timeout=20 --no-push \
			"$@" "https://localhost:${native_port}/${path}"
	) >"$work_directory/${scenario}.body" 2>"$work_directory/${scenario}.log"
	# nghttp reports certificate verification failures as warnings.
	# Require actual successful verification; its permissive warning mode is unused.
	if grep -Eiq 'warning|certificate verification failed|not processed' "$work_directory/${scenario}.log"; then
		return 1
	fi
	if [[ "$scenario" == response-trailers ]]; then
		grep -Fq ':status: 200' "$work_directory/${scenario}.body"
		grep -Fq 'x-response-finished: yes' "$work_directory/${scenario}.body"
	else
		cmp "$work_directory/expected" "$work_directory/${scenario}.body"
	fi
	escript scripts/interop_audit.escript --record nghttp2-h2 "$interop_run_id" client "$scenario"
}
cp "$work_directory/large" "$work_directory/expected"
run_client response-flow-control large
run_client request-response-trailers echo --data "$work_directory/expected" --trailer 'x-upload-finished: yes'
run_client response-trailers echo --null-out -v --data "$work_directory/expected" --trailer 'x-upload-finished: yes'
python3 scripts/interop_notice.py publish "$work_directory/native.complete" complete
wait "$native"
escript scripts/interop_audit.escript --finish nghttp2-h2 "$interop_run_id"
echo 'nghttp2 bidirectional HTTP/2 flow-control and trailer interoperability passed'

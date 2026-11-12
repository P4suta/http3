#!/usr/bin/env bash

set -Eeuo pipefail

repository_root="$({
	cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../../.."
	pwd -P
})"
readonly repository_root
cd -- "$repository_root"

for required_command in curl erl erlc python3 realpath timeout; do
	if ! command -v "$required_command" >/dev/null; then
		echo "required command is unavailable: $required_command" >&2
		exit 1
	fi
done

# The evidence is only pinned if the peer that produced it is. The pin lives in
# the interoperability profile the audit reads, so it is stated once and this
# harness refuses to report against a different curl.
pinned_peer="$(erl -noshell -eval '
	{ok, Bytes} = file:read_file("standards/interop-profile.json"),
	#{<<"peers">> := Peers} = json:decode(Bytes),
	[Pin] = [maps:get(<<"pin">>, Peer)
	         || Peer <- Peers, maps:get(<<"id">>, Peer) =:= <<"curl-h1-h2">>],
	io:format("~s", [Pin]),
	halt(0).')"
readonly pinned_peer
observed_peer="$(curl --version | head -n 1 | cut -d ' ' -f 1-2)"
readonly observed_peer
escript scripts/interop_audit.escript --prepare curl-h1-h2
if [[ "$observed_peer" != "$pinned_peer" ]]; then
	echo "curl peer identity drift" >&2
	exit 1
fi

temporary_root="$(realpath -m -- "${TMPDIR:-/tmp}")"
readonly temporary_root
work_directory="$(mktemp -d "${temporary_root%/}/http-curl-interop.XXXXXX")"
readonly work_directory
peer_process=""
interop_run_id=""

cleanup() {
	local exit_status=$?

	trap - EXIT INT TERM
	set +e
	if [[ -n "$peer_process" ]] && kill -0 "$peer_process" 2>/dev/null; then
		kill -TERM "$peer_process" 2>/dev/null
		for ((attempt = 0; attempt < 100; attempt += 1)); do
			kill -0 "$peer_process" 2>/dev/null || break
			sleep 0.05
		done
		kill -KILL "$peer_process" 2>/dev/null || true
		wait "$peer_process" 2>/dev/null
	fi
	if ((exit_status != 0)) && [[ -n "$interop_run_id" ]]; then
		# Preserve only a typed receipt.
		# Native stderr and paths may be private.
		if ! timeout --signal=TERM --kill-after=5s 60s escript scripts/interop_audit.escript \
			--driver-failure curl-h1-h2 "$interop_run_id" cleanup "$exit_status" >/dev/null 2>&1; then
			echo "interop driver failure record unavailable" >&2
		fi
	fi
	case "$work_directory" in
	"${temporary_root%/}"/http-curl-interop.??????)
		find "$work_directory" -depth -delete
		;;
	*)
		echo "refusing to clean unexpected work directory" >&2
		exit_status=1
		;;
	esac
	exit "$exit_status"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

case "${HTTP_CURL_INTEROP_SKIP_FRESH_BUILD:-0}" in
0) bash scripts/fresh_build.sh http ;;
1) ;;
*)
	echo "HTTP_CURL_INTEROP_SKIP_FRESH_BUILD must be 0 or 1" >&2
	exit 2
	;;
esac
interop_run_id="$(escript scripts/interop_audit.escript --begin curl-h1-h2 "$observed_peer")"
if [[ ! "$interop_run_id" =~ ^[0-9a-f]{64}$ ]]; then
	echo "interop run id is unavailable" >&2
	exit 1
fi
readonly interop_run_id
erlc -o "$work_directory" test/interop/curl/http_curl_interop.erl

readonly peer_log="$work_directory/peer.log"
: >"$peer_log"
# shellcheck disable=SC2086
# The build directory glob has to expand into separate -pa arguments.
erl -noshell \
	-pa build/dev/erlang/*/ebin "$work_directory" \
	-eval 'ok = http_curl_interop:run(0, 0), halt(0).' \
	>"$peer_log" 2>&1 &
peer_process=$!

wait_for_field() {
	local field=$1
	REPLY="$(python3 "$repository_root/scripts/interop_notice.py" wait "$peer_log" "$peer_process" 30 "$field")"
}

wait_for_field h1_port
readonly h1_port=$REPLY
wait_for_field h2_port
readonly h2_port=$REPLY
wait_for_field ready

readonly ca_certificate="packages/http3/test/fixtures/ca.pem"

# Every request reaches the loopback listener by address while still presenting
# and verifying the certificate's `localhost` identity.
curl_peer() {
	local scenario=$1
	local port=$2
	shift 2
	python3 scripts/interop_peer.py --root "$repository_root" \
		--peer curl-h1-h2 --run-id "$interop_run_id" --role client --scenario "$scenario" --timeout 30 \
		-- curl --silent --show-error \
		--cacert "$ca_certificate" \
		--resolve "localhost:${port}:127.0.0.1" \
		"$@"
}

assert_equal() {
	local label=$1
	local expected=$2
	local observed=$3

	if [[ "$observed" != "$expected" ]]; then
		echo "curl response mismatch" >&2
		return 1
	fi
	escript scripts/interop_audit.escript --record curl-h1-h2 "$interop_run_id" client "$label"
}

# HTTP/1.1 over TLS, negotiated by ALPN.
observed="$(curl_peer 'curl http/1.1 hello' "$h1_port" --http1.1 \
	--write-out ' %{http_version} %{http_code}' \
	"https://localhost:${h1_port}/hello")"
assert_equal 'curl http/1.1 hello' 'curl-interop 1.1 200' "$observed"

# The HTTP/1.1 listener advertises only `http/1.1`, so an HTTP/2-capable client
# must negotiate down rather than speak h2 to it.
observed="$(curl_peer 'curl alpn downgrade on the http/1.1 listener' "$h1_port" --http2 \
	--write-out '%{http_version}' --output /dev/null \
	"https://localhost:${h1_port}/hello")"
assert_equal 'curl alpn downgrade on the http/1.1 listener' '1.1' "$observed"

# HTTP/2 over TLS, negotiated by ALPN.
observed="$(curl_peer 'curl h2 hello' "$h2_port" --http2 \
	--write-out ' %{http_version} %{http_code}' \
	"https://localhost:${h2_port}/hello")"
assert_equal 'curl h2 hello' 'curl-interop 2 200' "$observed"

# A request body: chunked for HTTP/1.1, DATA frames for HTTP/2.
readonly payload='curl-interop-request-body'
observed="$(curl_peer 'curl http/1.1 echo' "$h1_port" --http1.1 --data-raw "$payload" \
	"https://localhost:${h1_port}/echo")"
assert_equal 'curl http/1.1 echo' "$payload" "$observed"
observed="$(curl_peer 'curl h2 echo' "$h2_port" --http2 --data-raw "$payload" \
	"https://localhost:${h2_port}/echo")"
assert_equal 'curl h2 echo' "$payload" "$observed"

# A non-2xx status crosses both protocols unchanged.
observed="$(curl_peer 'curl http/1.1 status' "$h1_port" --http1.1 \
	--write-out '%{http_code}' --output /dev/null \
	"https://localhost:${h1_port}/teapot")"
assert_equal 'curl http/1.1 status' '418' "$observed"
observed="$(curl_peer 'curl h2 status' "$h2_port" --http2 \
	--write-out '%{http_code}' --output /dev/null \
	"https://localhost:${h2_port}/teapot")"
assert_equal 'curl h2 status' '418' "$observed"

# A HEAD response carries the fields without a body.
observed="$(curl_peer 'curl http/1.1 head' "$h1_port" --http1.1 --head \
	--write-out '%{http_code} %{size_download}' --output /dev/null \
	"https://localhost:${h1_port}/hello")"
assert_equal 'curl http/1.1 head' '200 0' "$observed"

# Sequential requests on one HTTP/1.1 connection, then two multiplexed HTTP/2
# streams on one connection.
observed="$(curl_peer 'curl http/1.1 reuse' "$h1_port" --http1.1 \
	"https://localhost:${h1_port}/hello" \
	"https://localhost:${h1_port}/hello")"
assert_equal 'curl http/1.1 reuse' 'curl-interopcurl-interop' "$observed"
observed="$(curl_peer 'curl h2 multiplexing' "$h2_port" --http2 --parallel --parallel-max 2 \
	"https://localhost:${h2_port}/multiplex" \
	"https://localhost:${h2_port}/multiplex")"
assert_equal 'curl h2 multiplexing' 'overlap-verifiedoverlap-verified' "$observed"

# An unverifiable certificate must fail closed even for this peer.
python3 scripts/interop_peer.py --root "$repository_root" \
	--peer curl-h1-h2 --run-id "$interop_run_id" --role client --scenario 'untrusted certificate refused' \
	--timeout 30 -- curl --silent --show-error \
	--resolve "localhost:${h1_port}:127.0.0.1" \
	--output /dev/null \
	"https://localhost:${h1_port}/hello" 2>/dev/null

escript scripts/interop_audit.escript --record curl-h1-h2 "$interop_run_id" client 'untrusted certificate refused'
escript scripts/interop_audit.escript --finish curl-h1-h2 "$interop_run_id"
echo "curl interop: ${pinned_peer} verified HTTP/1.1 and HTTP/2 over TLS"

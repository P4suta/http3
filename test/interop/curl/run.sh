#!/usr/bin/env bash

set -Eeuo pipefail

repository_root="$({
	cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../../.."
	pwd -P
})"
readonly repository_root
cd -- "$repository_root"

for required_command in curl erlc mise realpath timeout; do
	if ! command -v "$required_command" >/dev/null; then
		echo "required command is unavailable: $required_command" >&2
		exit 1
	fi
done

# The evidence is only pinned if the peer that produced it is. The pin lives in
# the interoperability profile the audit reads, so it is stated once and this
# harness refuses to report against a different curl.
pinned_peer="$(mise exec -- erl -noshell -eval '
	{ok, Bytes} = file:read_file("standards/interop-profile.json"),
	#{<<"peers">> := Peers} = json:decode(Bytes),
	[Pin] = [maps:get(<<"pin">>, Peer)
	         || Peer <- Peers, maps:get(<<"id">>, Peer) =:= <<"curl-h1-h2">>],
	io:format("~s", [Pin]),
	halt(0).')"
readonly pinned_peer
observed_peer="$(curl --version | head -n 1 | cut -d ' ' -f 1-2)"
readonly observed_peer
if [[ "$observed_peer" != "$pinned_peer" ]]; then
	echo "curl peer drift: pinned '$pinned_peer', observed '$observed_peer'" >&2
	exit 1
fi

failure_directory="$repository_root/build/interop-curl-failure"
readonly failure_directory

clean_failure_directory() {
	case "$failure_directory" in
	"$repository_root/build/interop-curl-failure") ;;
	*)
		echo "refusing to clean unexpected failure directory" >&2
		return 1
		;;
	esac
	if [[ -d "$failure_directory" ]]; then
		find "$failure_directory" -depth -delete
	fi
}

preserve_failure() {
	local source
	local relative

	clean_failure_directory || return 1
	mkdir -p "$failure_directory"
	while IFS= read -r -d '' source; do
		relative=${source#"$work_directory"/}
		cp -- "$source" "$failure_directory/$relative"
	done < <(find "$work_directory" -type f -name '*.log' -print0)
	echo "preserved bounded curl interop diagnostics: $failure_directory" >&2
}

clean_failure_directory

temporary_root="$(realpath -m -- "${TMPDIR:-/tmp}")"
readonly temporary_root
work_directory="$(mktemp -d "${temporary_root%/}/http-curl-interop.XXXXXX")"
readonly work_directory
peer_process=""

cleanup() {
	local exit_status=$?

	trap - EXIT INT TERM
	set +e
	if [[ -n "$peer_process" ]] && kill -0 "$peer_process" 2>/dev/null; then
		kill -TERM "$peer_process" 2>/dev/null
		wait "$peer_process" 2>/dev/null
	fi
	if ((exit_status != 0)); then
		preserve_failure || exit_status=1
	fi
	case "$work_directory" in
	"${temporary_root%/}"/http-curl-interop.??????)
		find "$work_directory" -depth -delete
		;;
	*)
		echo "refusing to clean unexpected path: $work_directory" >&2
		exit_status=1
		;;
	esac
	exit "$exit_status"
}
trap cleanup EXIT INT TERM

case "${HTTP_CURL_INTEROP_SKIP_FRESH_BUILD:-0}" in
0) bash scripts/fresh_build.sh http ;;
1) ;;
*)
	echo "HTTP_CURL_INTEROP_SKIP_FRESH_BUILD must be 0 or 1" >&2
	exit 2
	;;
esac
erlc -o "$work_directory" test/interop/curl/http_curl_interop.erl

readonly peer_log="$work_directory/peer.log"
# shellcheck disable=SC2086
# The build directory glob has to expand into separate -pa arguments.
mise exec -- erl -noshell \
	-pa build/dev/erlang/*/ebin "$work_directory" \
	-eval 'ok = http_curl_interop:run(0, 0), halt(0).' \
	>"$peer_log" 2>&1 &
peer_process=$!

wait_for_field() {
	local field=$1
	local line
	local attempt

	for ((attempt = 0; attempt < 600; attempt += 1)); do
		if line="$(grep -m 1 "^${field}=" "$peer_log")"; then
			REPLY=${line#*=}
			return 0
		fi
		if ! kill -0 "$peer_process" 2>/dev/null; then
			echo "peer stopped before publishing ${field}:" >&2
			sed -n '1,120p' "$peer_log" >&2
			return 1
		fi
		sleep 0.05
	done

	echo "timed out waiting for ${field}:" >&2
	sed -n '1,120p' "$peer_log" >&2
	return 1
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
	local port=$1
	shift
	timeout 30 curl --silent --show-error \
		--cacert "$ca_certificate" \
		--resolve "localhost:${port}:127.0.0.1" \
		"$@"
}

assert_equal() {
	local label=$1
	local expected=$2
	local observed=$3

	if [[ "$observed" != "$expected" ]]; then
		echo "$label: expected '$expected', observed '$observed'" >&2
		sed -n '1,120p' "$peer_log" >&2
		return 1
	fi
}

# HTTP/1.1 over TLS, negotiated by ALPN.
observed="$(curl_peer "$h1_port" --http1.1 \
	--write-out ' %{http_version} %{http_code}' \
	"https://localhost:${h1_port}/hello")"
assert_equal 'curl http/1.1 hello' 'curl-interop 1.1 200' "$observed"

# The HTTP/1.1 listener advertises only `http/1.1`, so an HTTP/2-capable client
# must negotiate down rather than speak h2 to it.
observed="$(curl_peer "$h1_port" --http2 \
	--write-out '%{http_version}' --output /dev/null \
	"https://localhost:${h1_port}/hello")"
assert_equal 'curl alpn downgrade on the http/1.1 listener' '1.1' "$observed"

# HTTP/2 over TLS, negotiated by ALPN.
observed="$(curl_peer "$h2_port" --http2 \
	--write-out ' %{http_version} %{http_code}' \
	"https://localhost:${h2_port}/hello")"
assert_equal 'curl h2 hello' 'curl-interop 2 200' "$observed"

# A request body: chunked for HTTP/1.1, DATA frames for HTTP/2.
readonly payload='curl-interop-request-body'
observed="$(curl_peer "$h1_port" --http1.1 --data-raw "$payload" \
	"https://localhost:${h1_port}/echo")"
assert_equal 'curl http/1.1 echo' "$payload" "$observed"
observed="$(curl_peer "$h2_port" --http2 --data-raw "$payload" \
	"https://localhost:${h2_port}/echo")"
assert_equal 'curl h2 echo' "$payload" "$observed"

# A non-2xx status crosses both protocols unchanged.
observed="$(curl_peer "$h1_port" --http1.1 \
	--write-out '%{http_code}' --output /dev/null \
	"https://localhost:${h1_port}/teapot")"
assert_equal 'curl http/1.1 status' '418' "$observed"
observed="$(curl_peer "$h2_port" --http2 \
	--write-out '%{http_code}' --output /dev/null \
	"https://localhost:${h2_port}/teapot")"
assert_equal 'curl h2 status' '418' "$observed"

# A HEAD response carries the fields without a body.
observed="$(curl_peer "$h1_port" --http1.1 --head \
	--write-out '%{http_code} %{size_download}' --output /dev/null \
	"https://localhost:${h1_port}/hello")"
assert_equal 'curl http/1.1 head' '200 0' "$observed"

# Sequential requests on one HTTP/1.1 connection, then two multiplexed HTTP/2
# streams on one connection.
observed="$(curl_peer "$h1_port" --http1.1 \
	"https://localhost:${h1_port}/hello" \
	"https://localhost:${h1_port}/hello")"
assert_equal 'curl http/1.1 reuse' 'curl-interopcurl-interop' "$observed"
observed="$(curl_peer "$h2_port" --http2 \
	"https://localhost:${h2_port}/hello" \
	"https://localhost:${h2_port}/hello")"
assert_equal 'curl h2 multiplexing' 'curl-interopcurl-interop' "$observed"

# An unverifiable certificate must fail closed even for this peer.
if timeout 30 curl --silent --show-error \
	--resolve "localhost:${h1_port}:127.0.0.1" \
	--output /dev/null \
	"https://localhost:${h1_port}/hello" 2>/dev/null; then
	echo 'curl accepted the loopback certificate without the pinned CA' >&2
	exit 1
fi

echo "curl interop: ${pinned_peer} verified HTTP/1.1 and HTTP/2 over TLS"

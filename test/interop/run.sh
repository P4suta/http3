#!/usr/bin/env bash

set -Eeuo pipefail

readonly mode="${1:-all}"
case "$mode" in
all | aioquic | quicgo) ;;
*)
	echo "usage: $0 [all|aioquic|quicgo]" >&2
	exit 2
	;;
esac

repository_root="$({
	cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.."
	pwd -P
})"
readonly repository_root
cd -- "$repository_root"

temporary_root="$(realpath -m -- "${TMPDIR:-/tmp}")"
readonly temporary_root
work_directory="$(mktemp -d "${temporary_root%/}/http3-interop.XXXXXX")"
readonly work_directory
declare -a child_processes=()

cleanup() {
	local exit_status=$?
	local child_process

	trap - EXIT INT TERM
	set +e
	for child_process in "${child_processes[@]}"; do
		if kill -0 "$child_process" 2>/dev/null; then
			kill "$child_process" 2>/dev/null
		fi
	done
	for child_process in "${child_processes[@]}"; do
		wait "$child_process" 2>/dev/null
	done
	case "$work_directory" in
	"${temporary_root%/}"/http3-interop.??????)
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

start_child() {
	local log_file=$1
	shift
	"$@" >"$log_file" 2>&1 &
	STARTED_CHILD=$!
	child_processes+=("$STARTED_CHILD")
}

wait_for_field() {
	local log_file=$1
	local child_process=$2
	local field=$3
	local line
	local attempt

	for ((attempt = 0; attempt < 300; attempt += 1)); do
		if line="$(grep -m 1 "^${field}=" "$log_file")"; then
			REPLY=${line#*=}
			return 0
		fi
		if ! kill -0 "$child_process" 2>/dev/null; then
			wait "$child_process" 2>/dev/null || true
			echo "peer stopped before publishing ${field}:" >&2
			sed -n '1,240p' "$log_file" >&2
			return 1
		fi
		sleep 0.05
	done

	echo "timed out waiting for ${field}:" >&2
	sed -n '1,240p' "$log_file" >&2
	return 1
}

wait_for_child() {
	local child_process=$1
	local log_file=$2

	if ! wait "$child_process"; then
		echo "peer failed:" >&2
		sed -n '1,240p' "$log_file" >&2
		return 1
	fi
}

assert_log_contains() {
	local log_file=$1
	local expected=$2

	if ! grep -F -q -- "$expected" "$log_file"; then
		echo "missing peer observation '$expected':" >&2
		sed -n '1,240p' "$log_file" >&2
		return 1
	fi
}

assert_qlog() {
	local directory=$1
	local label=$2
	local qlog_file

	qlog_file="$(find "$directory" -type f \
		\( -name '*.qlog' -o -name '*.sqlog' \) \
		-size +0c -print -quit)"
	if [[ -z "$qlog_file" ]]; then
		echo "$label did not produce a non-empty qlog trace" >&2
		return 1
	fi
}

run_bounded() {
	timeout --signal=KILL 60s "$@"
}

for required_command in erlc mise realpath timeout; do
	if ! command -v "$required_command" >/dev/null; then
		echo "required command is unavailable: $required_command" >&2
		exit 1
	fi
done

mise run build
erlc -o "$work_directory" test/interop/http3_phase4_interop.erl
erlc -o "$work_directory" test/interop/http3_quicgo_interop.erl

erlang_command=(
	mise exec -- erl -noshell
	-pa build/dev/erlang/*/ebin "$work_directory"
)

run_quicgo_native_client() {
	local version=$1
	local version_atom=$2
	local peer_log="$work_directory/quicgo-server-${version}.log"
	local peer_qlog="$work_directory/quicgo-server-${version}-qlog"
	local native_qlog="$work_directory/native-client-${version}-qlog"
	local server_process
	local port

	mkdir "$peer_qlog" "$native_qlog"
	start_child "$peer_log" env QLOGDIR="$peer_qlog" \
		"$work_directory/quicgo" server \
		test/fixtures/server.pem test/fixtures/server-key.pem "$version"
	server_process=$STARTED_CHILD
	wait_for_field "$peer_log" "$server_process" PORT
	port=$REPLY

	run_bounded "${erlang_command[@]}" \
		-eval "[PortText, QlogText] = init:get_plain_arguments(), ok = http3_quicgo_interop:run_client(list_to_integer(PortText), ${version_atom}, list_to_binary(QlogText)), halt(0)." \
		-extra "$port" "$native_qlog"
	wait_for_child "$server_process" "$peer_log"
	assert_log_contains "$peer_log" "quic-go server interop ok"
	assert_qlog "$peer_qlog" "quic-go ${version} server"
	assert_qlog "$native_qlog" "native ${version} client"
}

run_quicgo_native_server() {
	local version=$1
	local peer_log="$work_directory/native-server-${version}.log"
	local peer_qlog="$work_directory/quicgo-client-${version}-qlog"
	local native_qlog="$work_directory/native-server-${version}-qlog"
	local server_process
	local port

	mkdir "$peer_qlog" "$native_qlog"
	start_child "$peer_log" timeout --signal=KILL 45s \
		"${erlang_command[@]}" \
		-eval '[QlogText] = init:get_plain_arguments(), ok = http3_quicgo_interop:run_server(list_to_binary(QlogText)), halt(0).' \
		-extra "$native_qlog"
	server_process=$STARTED_CHILD
	wait_for_field "$peer_log" "$server_process" PORT
	port=$REPLY

	run_bounded env QLOGDIR="$peer_qlog" \
		"$work_directory/quicgo" client test/fixtures/ca.pem "$port" "$version"
	wait_for_child "$server_process" "$peer_log"
	assert_log_contains "$peer_log" \
		"native server to quic-go client interop ok"
	assert_qlog "$peer_qlog" "quic-go ${version} client"
	assert_qlog "$native_qlog" "native ${version} server"
}

run_quicgo() {
	if ! command -v go >/dev/null; then
		echo "required command is unavailable: go" >&2
		return 1
	fi

	go -C test/interop/quicgo build \
		-trimpath -o "$work_directory/quicgo" .
	run_quicgo_native_client v1 quic_v1
	run_quicgo_native_server v1
	run_quicgo_native_client v2 quic_v2
	run_quicgo_native_server v2
	echo "quic-go bidirectional QUIC v1/v2 interop passed"
}

run_aioquic_native_client() {
	local python=$1
	local peer_log="$work_directory/aioquic-server.log"
	local peer_qlog="$work_directory/aioquic-server-qlog"
	local native_qlog="$work_directory/native-aioquic-client-qlog"
	local server_process
	local port
	local resumption_port

	mkdir "$peer_qlog" "$native_qlog"
	start_child "$peer_log" env \
		HTTP3_INTEROP_QLOG="$peer_qlog" \
		HTTP3_INTEROP_IDLE_TIMEOUT=60 \
		HTTP3_INTEROP_EXIT_ON_COMPLETE=1 \
		PYTHONDONTWRITEBYTECODE=1 \
		"$python" test/interop/aioquic_phase4_server.py
	server_process=$STARTED_CHILD
	wait_for_field "$peer_log" "$server_process" PORT
	port=$REPLY
	wait_for_field "$peer_log" "$server_process" RESUMPTION_PORT
	resumption_port=$REPLY

	if ! run_bounded "${erlang_command[@]}" \
		-eval '[PortText, ResumptionPortText, QlogText] = init:get_plain_arguments(), ok = http3_phase4_interop:run(list_to_integer(PortText), list_to_integer(ResumptionPortText), list_to_binary(QlogText)), halt(0).' \
		-extra "$port" "$resumption_port" "$native_qlog"; then
		echo "native aioquic client failed; peer log:" >&2
		sed -n '1,240p' "$peer_log" >&2
		return 1
	fi
	wait_for_child "$server_process" "$peer_log"

	assert_log_contains "$peer_log" OBSERVED_HTTP_DATAGRAM
	assert_log_contains "$peer_log" OBSERVED_POST_MIGRATION_REQUEST
	assert_log_contains "$peer_log" OBSERVED_0RTT_REQUEST
	assert_log_contains "$peer_log" OBSERVED_QUIC_V2
	assert_qlog "$peer_qlog" "aioquic server"
	assert_qlog "$native_qlog" "native aioquic client"
	if ! grep -R -E -q \
		'"packet_type"[[:space:]]*:[[:space:]]*"0RTT"' "$peer_qlog"; then
		echo "aioquic did not record an actual 0-RTT packet" >&2
		return 1
	fi
}

run_aioquic_native_server() {
	local python=$1
	local peer_log="$work_directory/native-aioquic-server.log"
	local peer_qlog="$work_directory/aioquic-client-qlog"
	local native_qlog="$work_directory/native-aioquic-server-qlog"
	local server_process
	local port

	mkdir "$peer_qlog" "$native_qlog"
	start_child "$peer_log" timeout --signal=KILL 45s \
		"${erlang_command[@]}" \
		-eval '[QlogText] = init:get_plain_arguments(), ok = http3_quicgo_interop:run_aioquic_server(list_to_binary(QlogText)), halt(0).' \
		-extra "$native_qlog"
	server_process=$STARTED_CHILD
	wait_for_field "$peer_log" "$server_process" PORT
	port=$REPLY

	run_bounded env \
		HTTP3_INTEROP_QLOG="$peer_qlog" \
		PYTHONDONTWRITEBYTECODE=1 \
		"$python" test/interop/aioquic_phase4_client.py "$port"
	wait_for_child "$server_process" "$peer_log"
	assert_log_contains "$peer_log" \
		"native server to aioquic client interop ok"
	assert_qlog "$peer_qlog" "aioquic client"
	assert_qlog "$native_qlog" "native aioquic server"
}

run_aioquic() {
	local python="${HTTP3_AIOQUIC_PYTHON:-}"

	if [[ -z "$python" && -x build/interop-venv/bin/python ]]; then
		python=build/interop-venv/bin/python
	elif [[ -z "$python" ]]; then
		python=python3
	fi

	if ! command -v "$python" >/dev/null; then
		echo "aioquic Python is unavailable: $python" >&2
		return 1
	fi
	env PYTHONDONTWRITEBYTECODE=1 "$python" -c \
		'import importlib.metadata; assert importlib.metadata.version("aioquic") == "1.3.0"'

	run_aioquic_native_client "$python"
	run_aioquic_native_server "$python"
	echo "aioquic bidirectional advanced interop passed"
}

case "$mode" in
all)
	run_quicgo
	run_aioquic
	;;
aioquic) run_aioquic ;;
quicgo) run_quicgo ;;
esac

echo "independent HTTP/3 interoperability gate passed"

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

# Store only typed scenario results in the root's shared evidence directory.
# Peer qlogs and stdout are private temporary inputs, never exported.
interop_evidence() {
	(
		cd -- "$repository_root/../.."
		escript scripts/interop_audit.escript "$@"
	)
}

declare -A interop_run_ids=()

# Completion evidence is emitted only after the actual independent process exits and its runtime/dependency identity is checked again.
interop_peer() {
	local peer=$1
	local role=$2
	local scenario=$3
	local run_id="${interop_run_ids[$peer]:-}"
	shift 3
	if [[ ! "$run_id" =~ ^[0-9a-f]{64}$ ]]; then
		echo "interop run id is unavailable" >&2
		return 1
	fi
	# Every call runs inside start_child or the owned run_logged subshell.
	# Replace that shell so its PID is the actual bounded peer supervisor.
	exec python3 "$repository_root/../../scripts/interop_peer.py" \
		--root "$repository_root/../.." --peer "$peer" --run-id "$run_id" --role "$role" \
		--scenario "$scenario" --timeout 60 -- "$@"
}

require_run_id() {
	if [[ ! "$1" =~ ^[0-9a-f]{64}$ ]]; then
		echo "interop run id is unavailable" >&2
		return 1
	fi
}

case "$mode" in
all)
	interop_evidence --prepare aioquic-h3
	interop_evidence --prepare quic-go-h3
	;;
aioquic) interop_evidence --prepare aioquic-h3 ;;
quicgo) interop_evidence --prepare quic-go-h3 ;;
esac

preserve_failure() {
	local status=$1 peer
	local -a peers=()
	case "$mode" in
	all) peers=(aioquic-h3 quic-go-h3) ;;
	aioquic) peers=(aioquic-h3) ;;
	quicgo) peers=(quic-go-h3) ;;
	*) return 1 ;;
	esac
	for peer in "${peers[@]}"; do
		local run_id="${interop_run_ids[$peer]:-}"
		if [[ -z "$run_id" ]]; then
			continue
		fi
		if ! (cd -- "$repository_root/../.." && timeout --signal=TERM --kill-after=5s 60s \
			escript scripts/interop_audit.escript --driver-failure "$peer" "$run_id" cleanup "$status") >/dev/null 2>&1; then
			echo "interop driver failure record unavailable" >&2
		fi
	done
}

if [[ -f "$repository_root/erl_crash.dump" ]]; then
	find "$repository_root/erl_crash.dump" -delete
fi

temporary_root="$(realpath -m -- "${TMPDIR:-/tmp}")"
readonly temporary_root
work_directory="$(mktemp -d "${temporary_root%/}/http3-interop.XXXXXX")"
readonly work_directory
declare -a child_processes=()

# Give instrumented peers a bounded window to close connections and flush qlog before escalating to KILL.
# Failure cleanup is part of the evidence contract: the diagnostic endpoint must not be the first process destroyed.
terminate_children() {
	local child_process
	local attempt

	for child_process in "${child_processes[@]}"; do
		if kill -0 "$child_process" 2>/dev/null; then
			kill -TERM "$child_process" 2>/dev/null || true
		fi
	done
	for ((attempt = 0; attempt < 100; attempt += 1)); do
		local live=0
		for child_process in "${child_processes[@]}"; do
			if kill -0 "$child_process" 2>/dev/null; then
				live=1
			fi
		done
		if ((live == 0)); then
			return 0
		fi
		sleep 0.05
	done
	for child_process in "${child_processes[@]}"; do
		if kill -0 "$child_process" 2>/dev/null; then
			kill -KILL "$child_process" 2>/dev/null || true
		fi
	done
}

cleanup() {
	local exit_status=$?
	local child_process

	trap - EXIT INT TERM
	set +e
	terminate_children
	for child_process in "${child_processes[@]}"; do
		wait "$child_process" 2>/dev/null
	done
	if ((exit_status != 0)); then
		preserve_failure "$exit_status" || exit_status=1
	fi
	if [[ -f "$repository_root/erl_crash.dump" ]]; then
		find "$repository_root/erl_crash.dump" -delete
	fi
	case "$work_directory" in
	"${temporary_root%/}"/http3-interop.??????)
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

start_child() {
	local log_file=$1
	shift
	"$@" >"$log_file" 2>&1 &
	STARTED_CHILD=$!
	child_processes+=("$STARTED_CHILD")
}

wait_for_field() {
	local log_file=$1 child_process=$2 field=$3
	REPLY="$(python3 "$repository_root/../../scripts/interop_notice.py" wait "$log_file" "$child_process" 60 "$field")"
}

wait_for_child() {
	local child_process=$1

	if ! wait "$child_process"; then
		echo "peer failed" >&2
		return 1
	fi
}

assert_log_contains() {
	local log_file=$1
	local expected=$2

	if ! grep -F -q -- "$expected" "$log_file"; then
		echo "required peer observation missing" >&2
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

run_logged() {
	local log_file=$1
	shift
	("$@") >"$log_file" 2>&1
}

for required_command in erl erlc python3 realpath timeout; do
	if ! command -v "$required_command" >/dev/null; then
		echo "required command is unavailable: $required_command" >&2
		exit 1
	fi
done

case "${HTTP3_INTEROP_SKIP_FRESH_BUILD:-0}" in
0) bash ../../scripts/fresh_build.sh http3 ;;
1) ;;
*)
	echo "HTTP3_INTEROP_SKIP_FRESH_BUILD must be 0 or 1" >&2
	exit 2
	;;
esac
erlc -o "$work_directory" test/interop/http3_phase4_interop.erl
erlc -o "$work_directory" test/interop/http3_quicgo_interop.erl

erlang_command=(
	erl -noshell
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
	QLOGDIR="$peer_qlog" start_child "$peer_log" \
		interop_peer quic-go-h3 server "quic-${version}" "$repository_root/../../build/interop/bin/quic-go" server \
		test/fixtures/server.pem test/fixtures/server-key.pem "$version"
	server_process=$STARTED_CHILD
	wait_for_field "$peer_log" "$server_process" PORT
	port=$REPLY

	run_logged "$work_directory/native-client-${version}.log" \
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

	QLOGDIR="$peer_qlog" run_logged "$work_directory/quicgo-client-${version}.log" \
		interop_peer quic-go-h3 client "quic-${version}" \
		"$repository_root/../../build/interop/bin/quic-go" client test/fixtures/ca.pem "$port" "$version"
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

	python3 "$repository_root/../../scripts/interop_go_build.py" \
		--root "$repository_root/../.." --peer quic-go-h3
	local observed_peer
	observed_peer="$(go version -m "$repository_root/../../build/interop/bin/quic-go" | awk '$1 == "dep" && $2 == "github.com/quic-go/quic-go" { print $2 "@" $3 }')"
	interop_run_ids["quic-go-h3"]="$(interop_evidence --begin quic-go-h3 "$observed_peer")"
	require_run_id "${interop_run_ids["quic-go-h3"]}"
	run_quicgo_native_client v1 quic_v1
	interop_evidence --record quic-go-h3 "${interop_run_ids["quic-go-h3"]}" server quic-v1
	run_quicgo_native_server v1
	interop_evidence --record quic-go-h3 "${interop_run_ids["quic-go-h3"]}" client quic-v1
	run_quicgo_native_client v2 quic_v2
	interop_evidence --record quic-go-h3 "${interop_run_ids["quic-go-h3"]}" server quic-v2
	run_quicgo_native_server v2
	interop_evidence --record quic-go-h3 "${interop_run_ids["quic-go-h3"]}" client quic-v2
	interop_evidence --finish quic-go-h3 "${interop_run_ids["quic-go-h3"]}"
	unset 'interop_run_ids[quic-go-h3]'
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
	HTTP3_INTEROP_QLOG="$peer_qlog" HTTP3_INTEROP_IDLE_TIMEOUT=60 \
		HTTP3_INTEROP_EXIT_ON_COMPLETE=1 PYTHONDONTWRITEBYTECODE=1 \
		start_child "$peer_log" interop_peer aioquic-h3 server advanced-h3 \
		"$python" -I -B test/interop/aioquic_phase4_server.py
	server_process=$STARTED_CHILD
	wait_for_field "$peer_log" "$server_process" PORT
	port=$REPLY
	wait_for_field "$peer_log" "$server_process" RESUMPTION_PORT
	resumption_port=$REPLY

	if ! run_logged "$work_directory/native-aioquic-client.log" \
		run_bounded "${erlang_command[@]}" \
		-eval '[PortText, ResumptionPortText, QlogText] = init:get_plain_arguments(), ok = http3_phase4_interop:run(list_to_integer(PortText), list_to_integer(ResumptionPortText), list_to_binary(QlogText)), halt(0).' \
		-extra "$port" "$resumption_port" "$native_qlog"; then
		echo "native aioquic client failed" >&2

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

	HTTP3_INTEROP_QLOG="$peer_qlog" PYTHONDONTWRITEBYTECODE=1 \
		run_logged "$work_directory/aioquic-client.log" \
		interop_peer aioquic-h3 client advanced-h3 \
		"$python" -I -B test/interop/aioquic_phase4_client.py "$port"
	wait_for_child "$server_process" "$peer_log"
	assert_log_contains "$peer_log" \
		"native server to aioquic client interop ok"
	assert_qlog "$peer_qlog" "aioquic client"
	assert_qlog "$native_qlog" "native aioquic server"
}

run_aioquic() {
	local python="${HTTP3_AIOQUIC_PYTHON:-}"

	# `uv venv` lays the interpreter out per platform: bin/python everywhere except Windows, which uses Scripts/python.exe.
	for candidate in build/interop-venv/bin/python \
		build/interop-venv/Scripts/python.exe; do
		if [[ -z "$python" && -x "$candidate" ]]; then
			python="$candidate"
		fi
	done
	if [[ -z "$python" ]]; then
		python=python3
	fi

	if ! command -v "$python" >/dev/null; then
		echo "aioquic Python is unavailable: $python" >&2
		return 1
	fi
	env PYTHONDONTWRITEBYTECODE=1 "$python" -c \
		'import importlib.metadata; assert importlib.metadata.version("aioquic") == "1.7.0"'
	local observed_peer
	observed_peer="$(env PYTHONDONTWRITEBYTECODE=1 "$python" -c 'import importlib.metadata; print("aioquic==" + importlib.metadata.version("aioquic"))')"
	interop_run_ids["aioquic-h3"]="$(interop_evidence --begin aioquic-h3 "$observed_peer")"
	require_run_id "${interop_run_ids["aioquic-h3"]}"

	run_aioquic_native_client "$python"
	interop_evidence --record aioquic-h3 "${interop_run_ids["aioquic-h3"]}" server advanced-h3
	run_aioquic_native_server "$python"
	interop_evidence --record aioquic-h3 "${interop_run_ids["aioquic-h3"]}" client advanced-h3
	interop_evidence --finish aioquic-h3 "${interop_run_ids["aioquic-h3"]}"
	unset 'interop_run_ids[aioquic-h3]'
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

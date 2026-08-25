#!/usr/bin/env bash

set -euo pipefail

diagnostics_dir="$(CDPATH='' cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
repository_root="$(CDPATH='' cd -- "$diagnostics_dir/../.." && pwd)"
scenario="${1:-round-trip}"

if [[ $# -gt 1 ]]; then
	printf 'usage: mise run diagnose -- <round-trip|connection-isolation|slow-consumer|cleanup>\n' >&2
	exit 2
fi

case "$scenario" in
round-trip | connection-isolation | slow-consumer | cleanup) ;;
*)
	printf 'unsupported diagnostic scenario: %s\n' "$scenario" >&2
	exit 2
	;;
esac

if [[ -n "${BEAMTRACE_BIN:-}" ]]; then
	beamtrace_bin="$BEAMTRACE_BIN"
else
	beamtrace_bin="$(command -v beamtrace || true)"
fi

if [[ -z "$beamtrace_bin" || ! -x "$beamtrace_bin" ]]; then
	printf 'BeamTrace v0.2.x is required through BEAMTRACE_BIN or PATH; nothing was downloaded.\n' >&2
	exit 2
fi

if ! beamtrace_version="$("$beamtrace_bin" --version 2>&1)"; then
	printf 'could not execute BeamTrace: %s\n' "$beamtrace_bin" >&2
	exit 2
fi
if [[ ! "$beamtrace_version" =~ ^beamtrace[[:space:]]0\.2\.[0-9]+([+-][A-Za-z0-9.-]+)?$ ]]; then
	printf 'BeamTrace v0.2.x is required; found: %s\n' "$beamtrace_version" >&2
	exit 2
fi

temporary_root="${TMPDIR:-/tmp}"
artifact_dir="$(mktemp -d "$temporary_root/http3-beamtrace-$scenario.XXXXXX")"
raw_qlog_dir="$(mktemp -d "$temporary_root/http3-qlog-raw.XXXXXX")"
trace_path="$artifact_dir/$scenario.beamtrace"
record_log="$artifact_dir/record.log"
environment_path="$artifact_dir/environment.txt"
summary_path="$artifact_dir/summary.md"
self_check_path="$artifact_dir/self-check.txt"
compare_log="$artifact_dir/compare.log"

record_status=125
export_status=125
clock_status="not-run"
timing_enabled=false
compare_enabled=false
compare_status="not-requested"
qlog_status="not-run"
qlog_count=0
summary_written=0

redact_qlogs() {
	if [[ "$qlog_status" != "not-run" ]]; then
		return
	fi
	mkdir -p "$artifact_dir/qlog"
	local source
	while IFS= read -r -d '' source; do
		qlog_count=$((qlog_count + 1))
		sed -E 's/"time":[0-9]+/"time":0/g' "$source" \
			>"$artifact_dir/qlog/redacted-$qlog_count.qlog"
	done < <(find "$raw_qlog_dir" -type f -name '*.qlog' -print0)

	if rg --ignore-case --line-number \
		'(localhost|127\.0\.0\.1|::1|connection_id|server_name|BEGIN (CERTIFICATE|PRIVATE KEY))' \
		"$artifact_dir/qlog" >"$artifact_dir/qlog-redaction-check.txt" 2>&1; then
		qlog_status="failed"
	else
		qlog_status="redacted"
		printf 'No forbidden peer, TLS, or key fields found. Relative qlog times were replaced with zero.\n' \
			>"$artifact_dir/qlog-redaction-check.txt"
	fi
}

write_summary() {
	if [[ "$summary_written" -eq 1 ]]; then
		return
	fi
	summary_written=1
	cat >"$summary_path" <<EOF
# HTTP/3 BeamTrace diagnostic

- scenario: \`$scenario\`
- BeamTrace: \`$beamtrace_version\`
- record exit: \`$record_status\`
- JSONL export exit: \`$export_status\`
- clock self-check: \`$clock_status\`
- relative timing enabled: \`$timing_enabled\`
- compare enabled: \`$compare_enabled\`
- compare status: \`$compare_status\`
- redacted qlog files: \`$qlog_count\` (\`$qlog_status\`)

This is optional development and incident-diagnostic evidence. It is not a CI,
release, or 516/344/812 performance gate, and traced timings are not benchmark
results. When the clock self-check is not \`passed\`, use only causal structure;
timing and comparison are explicitly disabled.

Review the metadata trace, redacted qlog, environment summary, and logs before
attaching selected files to an issue. Nothing in this directory was uploaded.
Do not attach it if review finds host, peer, certificate, or other sensitive
metadata.
EOF
}

cleanup() {
	local exit_status=$?
	redact_qlogs
	write_summary
	case "$raw_qlog_dir" in
	"$temporary_root"/http3-qlog-raw.*) rm -rf -- "$raw_qlog_dir" ;;
	*) printf 'refusing to clean unexpected qlog path: %s\n' "$raw_qlog_dir" >&2 ;;
	esac
	printf 'BeamTrace diagnostic artifacts: %s\n' "$artifact_dir"
	return "$exit_status"
}
trap cleanup EXIT

{
	printf 'scenario=%s\n' "$scenario"
	printf 'beamtrace=%s\n' "$beamtrace_version"
	printf 'gleam=%s\n' "$(gleam --version)"
	printf 'otp=%s\n' "$(erl -noshell -eval 'io:put_chars(erlang:system_info(otp_release)), halt().' 2>/dev/null)"
	printf 'os=%s\n' "$(uname -s)"
	printf 'kernel=%s\n' "$(uname -r)"
	printf 'architecture=%s\n' "$(uname -m)"
} >"$environment_path"

cd -- "$repository_root"
if HTTP3_DIAGNOSTIC_QLOG_DIR="$raw_qlog_dir" \
	"$beamtrace_bin" record \
	--trigger 'diagnostics@http3_diagnostic:trace_root/1' \
	--out "$trace_path" \
	--max-roots 1 \
	--preset gleam-actor \
	-- gleam run -m diagnostics/http3_diagnostic -- "$scenario" \
	>"$record_log" 2>&1; then
	record_status=0
else
	record_status=$?
fi

redact_qlogs

if [[ -f "$trace_path" ]]; then
	if "$beamtrace_bin" export "$trace_path" --format jsonl \
		>"$artifact_dir/export.log" 2>&1; then
		export_status=0
	else
		export_status=$?
	fi
else
	export_status=2
	printf 'trace container was not produced\n' >"$artifact_dir/export.log"
fi

jsonl_path="${trace_path%.beamtrace}.jsonl"
if [[ "$export_status" -eq 0 && -f "$jsonl_path" ]]; then
	if escript "$diagnostics_dir/check_trace.escript" "$jsonl_path" \
		>"$self_check_path" 2>&1; then
		clock_status="passed"
		timing_enabled=true
		compare_enabled=true
	else
		clock_status="failed"
		timing_enabled=false
		compare_enabled=false
	fi
else
	clock_status="unavailable"
	printf 'clock self-check unavailable because JSONL export failed\n' \
		>"$self_check_path"
fi

if [[ -n "${BEAMTRACE_COMPARE_BASELINE:-}" ]]; then
	if [[ "$compare_enabled" == true ]]; then
		set +e
		"$beamtrace_bin" compare "$BEAMTRACE_COMPARE_BASELINE" "$trace_path" \
			>"$compare_log" 2>&1
		compare_exit=$?
		set -e
		if [[ "$compare_exit" -eq 0 ]]; then
			compare_status="no-structural-difference"
		elif [[ "$compare_exit" -eq 1 ]]; then
			compare_status="structural-differences"
		else
			compare_status="error:$compare_exit"
		fi
	else
		compare_status="disabled-by-clock-self-check"
		printf 'compare disabled because the clock self-check did not pass\n' \
			>"$compare_log"
	fi
fi

write_summary

if [[ "$record_status" -ne 0 ]]; then
	exit "$record_status"
fi
if [[ "$export_status" -ne 0 ]]; then
	exit "$export_status"
fi
if [[ "$qlog_status" != "redacted" || "$qlog_count" -eq 0 ]]; then
	exit 1
fi

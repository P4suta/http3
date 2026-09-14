#!/usr/bin/env bash

# SPDX-FileCopyrightText: 2026 the http contributors
# SPDX-License-Identifier: MIT OR Apache-2.0

set -Eeuo pipefail

if (($# != 0)); then
	printf 'usage: %s\n' "$0" >&2
	exit 2
fi

repository_root="$({
	cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.."
	pwd -P
})"
readonly repository_root
temporary_root=${TMPDIR:-/tmp}
artifact_directory=$(mktemp -d "$temporary_root/http3-idle-wakeup.XXXXXX")
readonly artifact_directory
temporary_evidence="$artifact_directory/idle-wakeup-raw.json"
temporary_log="$artifact_directory/idle-wakeup.log"
output_directory="$repository_root/build/performance/current"
output_report="$output_directory/idle-wakeup.json"
output_raw="$output_directory/idle-wakeup.raw.json"
output_log="$output_directory/idle-wakeup.log"

# Invoked by the EXIT trap below.
# shellcheck disable=SC2329
cleanup() {
	case "$artifact_directory" in
	"$temporary_root"/http3-idle-wakeup.*)
		find "$artifact_directory" -depth -delete
		;;
	*)
		printf 'refusing to clean unexpected idle-wakeup path: %s\n' \
			"$artifact_directory" >&2
		;;
	esac
}
trap cleanup EXIT

cd -- "$repository_root"
escript scripts/performance_idle_wakeup_report.escript --self-test
(
	cd -- "$repository_root/packages/http3"
	erl -noshell -pa build/dev/erlang/http3/ebin \
		-eval 'ok = http3_idle_wakeup_ffi:self_test(), halt(0).'
)
mkdir -p -- "$output_directory"
rm -f -- "$output_report" "$output_raw" "$output_log"

set +e
(
	cd -- "$repository_root/packages/http3"
	gleam run -m http3_idle_wakeup
) >"$temporary_evidence" 2>"$temporary_log"
workload_status=$?
set -e

cp -- "$temporary_evidence" "$output_raw"
cp -- "$temporary_log" "$output_log"
if [[ -s "$temporary_log" ]]; then
	sed -n '1,240p' "$temporary_log" >&2
fi

set +e
escript scripts/performance_idle_wakeup_report.escript \
	"$workload_status" "build/performance/current/idle-wakeup.raw.json" \
	"build/performance/current/idle-wakeup.log"
report_status=$?
set -e

if ((workload_status != 0)); then
	exit "$workload_status"
fi
exit "$report_status"

#!/usr/bin/env bash

# SPDX-FileCopyrightText: 2026 the http contributors
# SPDX-License-Identifier: MIT OR Apache-2.0

set -Eeuo pipefail

if (($# != 1)); then
	printf 'usage: %s <benchmark|load|soak>\n' "$0" >&2
	exit 2
fi

mode=$1
case "$mode" in
benchmark | load | soak) ;;
*)
	printf 'unsupported performance workload: %s\n' "$mode" >&2
	exit 2
	;;
esac

repository_root="$({
	cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.."
	pwd -P
})"
readonly repository_root
temporary_root=${TMPDIR:-/tmp}
artifact_directory=$(mktemp -d "$temporary_root/http3-performance-$mode.XXXXXX")
readonly artifact_directory
temporary_log="$artifact_directory/$mode.log"
temporary_host_start="$artifact_directory/$mode-host-start.json"
temporary_host_end="$artifact_directory/$mode-host-end.json"
output_directory="$repository_root/build/performance/current"
output_log="$output_directory/$mode.log"
output_host_start="$output_directory/$mode-host-start.json"
output_host_end="$output_directory/$mode-host-end.json"

# Invoked by the EXIT trap below.
# shellcheck disable=SC2329
cleanup() {
	case "$artifact_directory" in
	"$temporary_root"/http3-performance-"$mode".*)
		find "$artifact_directory" -depth -delete
		;;
	*)
		printf 'refusing to clean unexpected performance path: %s\n' \
			"$artifact_directory" >&2
		;;
	esac
}
trap cleanup EXIT

cd -- "$repository_root"
escript scripts/performance_run_report.escript --self-test
escript scripts/performance_host_snapshot.escript --self-test
mkdir -p -- "$output_directory"
escript scripts/performance_host_snapshot.escript \
	capture start "$temporary_host_start"

set +e
(
	cd -- "$repository_root/packages/http3"
	gleam run -m http3_benchmark -- "$mode"
) 2>&1 | tee "$temporary_log"
workload_status=${PIPESTATUS[0]}
set -e

escript scripts/performance_host_snapshot.escript \
	capture end "$temporary_host_end"
cp -- "$temporary_log" "$output_log"
cp -- "$temporary_host_start" "$output_host_start"
cp -- "$temporary_host_end" "$output_host_end"
set +e
escript scripts/performance_run_report.escript \
	"$mode" "$workload_status" "$output_log" \
	"$output_host_start" "$output_host_end"
report_status=$?
set -e

if ((workload_status != 0)); then
	exit "$workload_status"
fi
exit "$report_status"

#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 the http contributors
# SPDX-License-Identifier: MIT OR Apache-2.0
set -Eeuo pipefail
if (($# != 1)); then
	printf 'usage: %s <benchmark|load|soak>\n' "$0" >&2
	exit 2
fi
mode=$1
case "$mode" in benchmark | load | soak) ;; *) exit 2 ;; esac
repository_root="$({
	cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.."
	pwd -P
})"
readonly repository_root
cd -- "$repository_root"
escript scripts/performance_runner.escript --invalidate "$mode"
escript scripts/performance_runner.escript --self-test
escript scripts/performance_run_report.escript --self-test
escript scripts/performance_host_snapshot.escript --self-test
bash scripts/fresh_build.sh http3
set +e
escript scripts/performance_runner.escript "$mode"
workload_status=$?
set -e
set +e
escript scripts/performance_run_report.escript "$mode" "$workload_status" \
	"build/performance/current/$mode.log" \
	"build/performance/current/$mode-host-start.json" \
	"build/performance/current/$mode-host-end.json"
report_status=$?
set -e
if ((workload_status)); then exit "$workload_status"; fi
exit "$report_status"

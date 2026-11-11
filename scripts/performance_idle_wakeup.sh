#!/usr/bin/env bash

# SPDX-FileCopyrightText: 2026 the http contributors
# SPDX-License-Identifier: MIT OR Apache-2.0
set -Eeuo pipefail
if (($# != 0)); then
	printf 'usage: %s\n' "$0" >&2
	exit 2
fi
repository_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)"
cd -- "$repository_root"
escript scripts/performance_idle_runner.escript --invalidate
escript scripts/performance_idle_wakeup_report.escript --self-test
escript scripts/performance_idle_runner.escript --self-test
set +e
escript scripts/performance_idle_runner.escript
workload_status=$?
set -e
set +e
escript scripts/performance_idle_wakeup_report.escript
report_status=$?
set -e
if ((workload_status)); then exit "$workload_status"; fi
exit "$report_status"

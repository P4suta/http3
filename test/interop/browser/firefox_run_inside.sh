#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 the http contributors
# SPDX-License-Identifier: MIT OR Apache-2.0
set -Eeuo pipefail
mkdir -p "$HOME"
for control in firefox_archive firefox_worker firefox_setup oracle receipt profile owned browser_worker native_runner container_owner execution run_contract; do
	python3 -B -W error "test/interop/browser/${control}_test.py"
done
escript scripts/interop_browser_test.escript
escript scripts/interop_firefox_test.escript
bash test/interop/browser/firefox_run.sh

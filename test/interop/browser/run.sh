#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 the http contributors
# SPDX-License-Identifier: MIT OR Apache-2.0
set -Eeuo pipefail
repository_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../../.." && pwd -P)"
readonly repository_root
cd -- "$repository_root"
for command in python3 erl escript; do command -v "$command" >/dev/null; done
escript scripts/interop_audit.escript --prepare chromium
case "${HTTP_BROWSER_SKIP_FRESH_BUILD:-0}" in
0) bash scripts/fresh_build.sh http ;;
1) ;;
*) exit 2 ;;
esac
python3 -B test/interop/browser/run.py

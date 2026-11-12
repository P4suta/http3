#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 the http contributors
# SPDX-License-Identifier: MIT OR Apache-2.0
set -Eeuo pipefail
repository_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../../.." && pwd -P)"
readonly repository_root
cd -- "$repository_root"
[[ $(uname -s) == Linux && $(id -u) != 0 ]]
python3 -B -c 'from pathlib import Path; [path.unlink(missing_ok=True) for path in (Path("build/interop/peers/chromium.json"), Path("build/interop/report.json"))]'
readonly otp="${HTTP_BROWSER_OTP:-29.0.5}"
case "$otp" in
29.0.5) base=hexpm/erlang@sha256:a6b64e4e3849f5a009c1839fc0ca016207b6926d7800f481e60942cc64fd50a0 ;;
28.5.0.6) base=hexpm/erlang@sha256:2f4fe0bea2303f2020d5ab8642c23e1d346bef3e39dca8259745ff11bf5d2223 ;;
*) exit 2 ;;
esac
readonly image="http-browser:otp-${otp}-chrome153.0.8010.36"
timeout --signal=TERM --kill-after=10s 900s docker build --build-arg "BASE_IMAGE=$base" -t "$image" test/interop/browser
python3 -B -W error test/interop/browser/container_daemon_test.py "$image"
# Retrieve packages and compile first.
# The actual browser execution is a separate container whose network namespace contains loopback only.
python3 -B test/interop/browser/container_owner.py --image "$image" --phase build
python3 -B test/interop/browser/container_owner.py --image "$image" --phase run

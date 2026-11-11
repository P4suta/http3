#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 the http contributors
# SPDX-License-Identifier: MIT OR Apache-2.0
"""Fixed two-generation console-inheritance fixture for process_runner."""

from __future__ import annotations

import subprocess
import sys
import time
from pathlib import Path

from process_supervisor import owned_run, windows_console_attached


def leaf() -> int:
    if not windows_console_attached():
        return 1
    sys.stdout.buffer.write(b"console_attached=true\n")
    sys.stdout.buffer.flush()
    # Span several 20 ms watcher samples so the visibility proof cannot depend on catching a short-lived leaf process by chance.
    time.sleep(0.25)
    return 0


def root() -> int:
    if not windows_console_attached():
        return 1
    result = owned_run(
        [sys.executable, "-E", "-s", "-B", str(Path(__file__)), "--leaf"],
        timeout=5.0,
        max_output_bytes=64,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        stdin=subprocess.DEVNULL,
    )
    if result.returncode != 0 or result.stdout != b"console_attached=true\n":
        return 1
    sys.stdout.buffer.write(
        b"console_inheritance_fixture passed=true generations=2\n"
    )
    sys.stdout.buffer.flush()
    return 0


def main() -> int:
    if sys.argv[1:] == ["--root"]:
        return root()
    if sys.argv[1:] == ["--leaf"]:
        return leaf()
    return 2


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except SystemExit:
        raise
    except Exception:
        # No traceback, path, argument, handle, or exception value is emitted.
        sys.stdout.buffer.write(b"console_inheritance_fixture failed=true\n")
        sys.stdout.buffer.flush()
        raise SystemExit(127)

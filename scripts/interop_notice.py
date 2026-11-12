#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 the http contributors
# SPDX-License-Identifier: MIT OR Apache-2.0
"""Bounded local readiness records and complete stop notifications."""
import sys
sys.dont_write_bytecode = True
import os
from pathlib import Path
import select
import signal
import stat
import time

FIELDS = {"PORT", "TARGET", "RESUMPTION_PORT", "h1_port", "h2_port", "ready"}
MARKERS = {"complete", "trusted-complete", "untrusted-complete"}
MAX_LOG = 1_048_576


class Failure(Exception):
    def __init__(self, code):
        self.code = code


def failure_code(error):
    if type(error) is Failure and type(error.code) is int and 1 <= error.code <= 6:
        return error.code
    return 6


def failure_exit_status(error):
    if type(error) is SystemExit and type(error.code) is int and 1 <= error.code <= 255:
        return error.code
    if type(error) is KeyboardInterrupt:
        return 130
    return 1


def safe_failure_line(code):
    try:
        print("interop notification failed: " + str(code), file=sys.stderr)
    except BaseException:
        pass


def interrupted(signum, _frame):
    raise SystemExit(128 + signum)


def install_signal_handlers():
    for name in ("SIGINT", "SIGTERM", "SIGBREAK"):
        signum = getattr(signal, name, None)
        if signum is not None:
            signal.signal(signum, interrupted)


def publish(path, marker):
    if marker not in MARKERS:
        raise Failure(1)
    path = Path(path)
    pending = path.with_name(path.name + ".pending")
    target = pending.open("x", encoding="ascii")
    try:
        with target:
            target.write(marker)
        os.link(pending, path)
    finally:
        pending.unlink()


def read_fields(path, fields):
    if not fields or len(fields) > 3 or len(set(fields)) != len(fields) or any(field not in FIELDS for field in fields):
        raise Failure(1)
    try:
        descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NONBLOCK", 0)
            | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_BINARY", 0))
    except FileNotFoundError:
        return None
    try:
        opened = os.fstat(descriptor)
        if not stat.S_ISREG(opened.st_mode) or opened.st_nlink != 1:
            raise Failure(3)
        data = bytearray()
        while len(data) <= MAX_LOG:
            chunk = os.read(descriptor, min(65536, MAX_LOG + 1 - len(data)))
            if not chunk:
                break
            data.extend(chunk)
    finally:
        os.close(descriptor)
    try:
        current = os.stat(path, follow_symlinks=False)
    except (FileNotFoundError, OSError):
        raise Failure(3) from None
    if (not stat.S_ISREG(current.st_mode) or current.st_nlink != 1
            or (current.st_dev, current.st_ino) != (opened.st_dev, opened.st_ino)):
        raise Failure(3)
    if len(data) > MAX_LOG:
        raise Failure(2)
    result = []
    lines = [line.removesuffix(b"\r") for line in data.split(b"\n")[:-1]]
    for field in fields:
        prefix = field.encode() + b"="
        values = [line[len(prefix):] for line in lines if line.startswith(prefix)]
        if not values:
            return None
        if len(values) != 1 or not 1 <= len(values[0]) <= 5 or not values[0].isdigit():
            raise Failure(3)
        value = int(values[0])
        if not 1 <= value <= 65535 or str(value).encode() != values[0] or (field == "ready" and value != 1):
            raise Failure(3)
        result.append(value)
    return result


def wait(path, pid, seconds, fields):
    if type(pid) is not int or pid <= 0 or type(seconds) not in (int, float) or not 0 < seconds <= 60:
        raise Failure(1)
    deadline = time.monotonic() + seconds
    try:
        descriptor = os.pidfd_open(pid)
    except ProcessLookupError:
        raise Failure(4) from None
    try:
        while time.monotonic() < deadline:
            if select.select([descriptor], [], [], 0)[0]:
                raise Failure(4)
            result = read_fields(path, fields)
            if result is not None:
                if select.select([descriptor], [], [], 0)[0]:
                    raise Failure(4)
                if time.monotonic() >= deadline:
                    raise Failure(5)
                return result
            select.select([descriptor], [], [], min(.05, max(0, deadline - time.monotonic())))
        raise Failure(5)
    finally:
        os.close(descriptor)


def main(arguments):
    if len(arguments) == 3 and arguments[0] == "publish":
        publish(Path(arguments[1]), arguments[2])
    elif 5 <= len(arguments) <= 7 and arguments[0] == "wait":
        values = wait(arguments[1], int(arguments[2]), int(arguments[3]), arguments[4:])
        print(" ".join(map(str, values)))
    else:
        raise Failure(1)


def cli(arguments):
    try:
        install_signal_handlers()
        main(arguments)
        return 0
    except BaseException as error:
        safe_failure_line(failure_code(error))
        return failure_exit_status(error)


if __name__ == "__main__":
    sys.exit(cli(sys.argv[1:]))

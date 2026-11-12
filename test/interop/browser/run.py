#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 the http contributors
# SPDX-License-Identifier: MIT OR Apache-2.0
"""Execute all six declared Chromium scenarios against the native server."""
import sys
sys.dont_write_bytecode = True
import argparse
from pathlib import Path
import re
import signal
from receipt import nonce_for, scenario, require

ROOT = Path(__file__).resolve().parents[3]
ACTIVE_RUN_ID = None
ACTIVE_PHASE = "setup"
sys.path.insert(0, str(ROOT / "scripts"))
from interop_peer import run, read_json, collect


def audit(arguments):
    completed, output = collect(["escript", "scripts/interop_audit.escript", *arguments], 120, limit=65536)
    require(completed["outcome"] == "completed" and completed["exit_status"] == 0)
    return output


def begin(peer, pin):
    output = audit(["--begin", peer, pin])
    try:
        receipt = output.decode("ascii")
    except UnicodeDecodeError:
        raise ValueError("invalid_interop_begin_receipt") from None
    if re.fullmatch(r"[0-9a-f]{64}\n", receipt) is None:
        raise ValueError("invalid_interop_begin_receipt")
    return receipt[:-1]


def record_active_failure(peer, run_id, phase, exit_status=1):
    if run_id is not None:
        audit(["--driver-failure", peer, run_id, phase, str(exit_status)])


def failure_exit_status(error):
    if type(error) is SystemExit and type(error.code) is int and 1 <= error.code <= 255:
        return error.code
    if type(error) is KeyboardInterrupt:
        return 130
    return 1


def interrupted(signum, _frame):
    raise SystemExit(128 + signum)


def install_signal_handlers():
    for name in ("SIGINT", "SIGTERM", "SIGBREAK"):
        signum = getattr(signal, name, None)
        if signum is not None:
            signal.signal(signum, interrupted)


def safe_failure_line(message):
    try:
        print(message, file=sys.stderr)
    except BaseException:
        pass


def main():
    global ACTIVE_RUN_ID, ACTIVE_PHASE
    run_id = begin("chromium", "chromium 153.0.8010.36")
    ACTIVE_RUN_ID = run_id
    report = read_json(ROOT / "build/interop/peers/chromium.json")
    if report["run_id"] != run_id:
        raise ValueError("peer_run_changed")
    for protocol in (1, 2, 3):
        for trusted in (True, False):
            ACTIVE_PHASE = "execution"
            report = read_json(ROOT / "build/interop/peers/chromium.json")
            nonce = nonce_for(report["run_id"], protocol, trusted)
            destination = ROOT / "build/interop/native/chromium" / (nonce + ".controls") / "browser"
            name = scenario(protocol, trusted)
            run(argparse.Namespace(root=str(ROOT), peer="chromium", role="client", scenario=name,
                run_id=run_id, timeout=65,
                command=["--", sys.executable, str(ROOT / "test/interop/browser/browser_worker.py"),
                    str(protocol), "trusted" if trusted else "untrusted", "0", str(destination), nonce]))
            ACTIVE_PHASE = "verification"
            audit(["--record", "chromium", run_id, "client", name])
    ACTIVE_PHASE = "verification"
    audit(["--finish", "chromium", run_id])
    ACTIVE_RUN_ID = None


def cli():
    try:
        install_signal_handlers()
        main()
        return 0
    except BaseException as error:
        status = failure_exit_status(error)
        try:
            record_active_failure("chromium", ACTIVE_RUN_ID, ACTIVE_PHASE, status)
        except BaseException:
            pass
        safe_failure_line("Chromium interoperability failed")
        return status


if __name__ == "__main__":
    sys.exit(cli())

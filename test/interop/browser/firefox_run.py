#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 the http contributors
# SPDX-License-Identifier: MIT OR Apache-2.0
"""Run all six source-bound Firefox scenarios and verify retained receipts."""
import sys
sys.dont_write_bytecode = True
import argparse
from pathlib import Path
from receipt import nonce_for, scenario
from run import (audit, begin, failure_exit_status, install_signal_handlers,
                 record_active_failure, safe_failure_line)

ROOT = Path(__file__).resolve().parents[3]
ACTIVE_RUN_ID = None
ACTIVE_PHASE = "setup"
sys.path.insert(0, str(ROOT / "scripts"))
from interop_peer import run, read_json


def main():
    global ACTIVE_RUN_ID, ACTIVE_PHASE
    run_id = begin("firefox", "firefox 155.0.1")
    ACTIVE_RUN_ID = run_id
    report = read_json(ROOT / "build/interop/peers/firefox.json")
    if report["run_id"] != run_id:
        raise ValueError("peer_run_changed")
    for protocol in (1, 2, 3):
        for trusted in (True, False):
            ACTIVE_PHASE = "execution"
            report = read_json(ROOT / "build/interop/peers/firefox.json")
            nonce = nonce_for(report["run_id"], protocol, trusted)
            destination = ROOT / "build/interop/native/firefox" / (nonce + ".controls") / "browser"
            name = scenario(protocol, trusted)
            run(argparse.Namespace(root=str(ROOT), peer="firefox", role="client", scenario=name,
                run_id=run_id, timeout=65,
                command=["--", sys.executable, str(ROOT / "test/interop/browser/firefox_worker.py"),
                    str(protocol), "trusted" if trusted else "untrusted", "0", str(destination), nonce]))
            ACTIVE_PHASE = "verification"
            audit(["--record", "firefox", run_id, "client", name])
    ACTIVE_PHASE = "verification"
    audit(["--finish", "firefox", run_id])
    ACTIVE_RUN_ID = None


def cli():
    try:
        install_signal_handlers()
        main()
        return 0
    except BaseException as error:
        status = failure_exit_status(error)
        try:
            record_active_failure("firefox", ACTIVE_RUN_ID, ACTIVE_PHASE, status)
        except BaseException:
            pass
        safe_failure_line("Firefox interoperability failed")
        return status


if __name__ == "__main__":
    sys.exit(cli())

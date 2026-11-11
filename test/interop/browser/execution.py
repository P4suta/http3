# SPDX-FileCopyrightText: 2026 the http contributors
# SPDX-License-Identifier: MIT OR Apache-2.0
"""Start the opposite endpoint only after the browser identity is verified."""
import sys
sys.dont_write_bytecode = True
import os
from pathlib import Path
import signal
import subprocess
import time
from receipt import browser, native, completion, nonce_for, scenario, require
sys.path.insert(0, str(Path(__file__).resolve().parents[3] / "scripts"))
from interop_notice import publish
from process_supervisor import owned_popen


def publish_stop(path, trusted):
    publish(path, "trusted-complete" if trusted else "untrusted-complete")


def execute(root, report, command, expected_scenario):
    from interop_peer import collect, read_json, invocation_name, decode_json
    peer = report["peer"]
    require(peer in ("chromium", "firefox"))
    validate_browser = browser
    if peer == "firefox":
        from firefox_receipt import browser as validate_browser
    require(len(command) == 7 and command[2] in ("1", "2", "3")
            and command[3] in ("trusted", "untrusted") and command[4] == "0")
    protocol, trusted = int(command[2]), command[3] == "trusted"
    require(expected_scenario == scenario(protocol, trusted))
    nonce = nonce_for(report["run_id"], protocol, trusted)
    require(command[6] == nonce)
    basename = invocation_name("client", expected_scenario)
    directory = root / "build/interop/native" / peer
    controls = directory / (nonce + ".controls")
    controls.mkdir(parents=True, exist_ok=False)
    ready, stop, result = [controls / name for name in ("ready", "stop", "result")]
    evidence = directory / basename
    evidence.unlink(missing_ok=True)
    require(Path(command[5]).resolve() == (controls / "browser").resolve())
    native_command = [sys.executable, "-B", str(root / "test/interop/browser/native_runner.py"),
        "--peer", peer, "--protocol", str(protocol), "--trust", command[3], "--evidence", str(evidence),
        "--result", str(result), "--ready", str(ready), "--stop", str(stop)]
    child = owned_popen(native_command, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                             start_new_session=True, cwd=root)
    try:
        deadline = time.monotonic() + 10
        while not ready.exists():
            require(child.poll() is None and time.monotonic() < deadline)
            time.sleep(0.01)
        with ready.open("rb") as source:
            raw = source.read(257)
        require(len(raw) <= 256)
        observed = decode_json(raw)
        require(type(observed) is dict and set(observed) == {"port"}
                and type(observed["port"]) is int and 0 < observed["port"] <= 65535)
        actual = command.copy()
        actual[4] = str(observed["port"])
        completed, output = collect(actual, 65, limit=65536)
        require(not output)
        completion(completed, 65)
        receipt = validate_browser(read_json(command[5]), nonce, protocol, trusted)
        publish_stop(stop, trusted)
        require(child.wait(timeout=10) == 0)
        opposite = read_json(evidence)
        require(opposite["status"] == "Passed" and opposite["run_id"] == report["run_id"]
                and opposite["source_sha256"] == report["source_sha256"])
        completion(opposite["completion"], 50)
        native(opposite["child"], nonce, protocol, trusted)
        return completed, receipt
    finally:
        if child.poll() is None:
            try:
                os.killpg(child.pid, signal.SIGTERM)
                child.wait(timeout=7)
            except (ProcessLookupError, subprocess.TimeoutExpired):
                try: os.killpg(child.pid, signal.SIGKILL)
                except ProcessLookupError: pass
                child.wait(timeout=5)

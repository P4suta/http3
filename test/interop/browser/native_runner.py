#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 the http contributors
# SPDX-License-Identifier: MIT OR Apache-2.0
"""Own one native browser-facing VM and retain only validated scalar facts."""
import sys
sys.dont_write_bytecode = True
import argparse
import os
from pathlib import Path
import shutil
from receipt import native, completion, nonce_for, require

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / "scripts"))
from interop_peer import (collect, command_exit_status, digest_file,
                          install_signal_handlers, read_json, write_json_atomic)


def run(args):
    require(os.name == "posix" and args.protocol in (1, 2, 3) and args.trust in ("trusted", "untrusted"))
    trusted = args.trust == "trusted"
    peer = getattr(args, "peer", "chromium")
    require(peer in ("chromium", "firefox"))
    report_path = ROOT / "build/interop/peers" / (peer + ".json")
    report = read_json(report_path)
    require(report["schema"] == 2 and report["status"] == "Running")
    nonce = nonce_for(report["run_id"], args.protocol, trusted)
    source = ROOT / "test/interop/browser/http_browser_interop.erl"
    beam = ROOT / "build/dev/erlang/http/ebin/http_browser_interop.beam"
    runtime = Path(shutil.which("erl")).resolve(strict=True)
    before = {"source": digest_file(source), "beam": digest_file(beam), "runtime": digest_file(runtime)}
    destination = Path(args.evidence)
    result = Path(args.result)
    require(not destination.exists() and not result.exists()
            and not Path(args.ready).exists() and not Path(args.stop).exists())
    record = {"schema": 1, "status": "Failed", "protocol": args.protocol, "trusted": trusted,
        "timeout_seconds": 50, "nonce": nonce, "fixture": before, "completion": None, "child": None,
        "run_id": report["run_id"], "source_sha256": report["source_sha256"]}
    write_json_atomic(destination, record)
    paths = [str(path) for path in sorted((ROOT / "build/dev/erlang").glob("*/ebin"))]
    environment = {key: value for key, value in os.environ.items()
                   if key not in ("ERL_AFLAGS", "ERL_FLAGS", "ERL_ZFLAGS", "ERL_LIBS")}
    environment.update(ERL_CRASH_DUMP_BYTES="0", ERL_CRASH_DUMP_SECONDS="0")
    evaluation = ('try [Beam,Hash,Protocol,Ready,Stop,Result,Nonce]=init:get_plain_arguments(),'
        '{ok,Bytes}=file:read_file(Beam),Expected=list_to_binary(Hash),'
        'Expected=binary:encode_hex(crypto:hash(sha256,Bytes),lowercase),'
        '{module,http_browser_interop}=code:load_binary(http_browser_interop,"verified-browser-native",Bytes),'
        'ok=http_browser_interop:run(list_to_integer(Protocol),Ready,Stop,Result,list_to_binary(Nonce)),halt(0) '
        'catch _:_ -> halt(1) end.')
    command = [str(runtime), "+S", "2:2", "+SDcpu", "1", "+SDio", "1", "+A", "2",
        "+hmax", "33554432", "+hmaxib", "true", "+hmaxk", "true",
        "+hmaxel", "false", "-noshell", "-noinput", "-pa", *paths, "-eval", evaluation,
        "-extra", str(beam), before["beam"]["sha256"], str(args.protocol), args.ready, args.stop,
        str(result), nonce]
    completed, output = collect(command, 50, limit=65536, env=environment)
    record["completion"] = completed
    valid = False
    try:
        require(not output)
        completion(completed, 50)
        record["child"] = native(read_json(result), nonce, args.protocol, trusted)
        require(before == {"source": digest_file(source), "beam": digest_file(beam), "runtime": digest_file(runtime)})
        require(read_json(report_path) == report)
        valid = True
    except Exception:
        # Only the fixed fixture phase can survive a failed child execution.
        # Raw messages, certificate values and unchecked JSON never enter it.
        try:
            failed = read_json(result)
            require(type(failed) is dict and set(failed) == {"schema", "nonce", "failure_phase"})
            require(type(failed["schema"]) is int and failed["schema"] == 1 and failed["nonce"] == nonce
                    and type(failed["failure_phase"]) is int and 1 <= failed["failure_phase"] <= 4)
            record["child"] = failed
        except Exception:
            record["child"] = None
    record["status"] = "Passed" if valid else "Failed"
    write_json_atomic(destination, record)
    return 0 if valid else 1


def main(arguments=None):
    parser = argparse.ArgumentParser()
    parser.add_argument("--peer", choices=("chromium", "firefox"), default="chromium")
    parser.add_argument("--protocol", required=True, type=int)
    parser.add_argument("--trust", required=True)
    parser.add_argument("--evidence", required=True)
    parser.add_argument("--result", required=True)
    parser.add_argument("--ready", required=True)
    parser.add_argument("--stop", required=True)
    return run(parser.parse_args(arguments))


def safe_failure_line():
    try:
        print("native browser execution failed", file=sys.stderr)
    except BaseException:
        pass


def cli(arguments=None):
    try:
        install_signal_handlers()
        return main(arguments)
    except BaseException as error:
        status = command_exit_status(error)
        if status != 0:
            safe_failure_line()
        return status


if __name__ == "__main__":
    sys.exit(cli())

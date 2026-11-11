#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 the http contributors
# SPDX-License-Identifier: MIT OR Apache-2.0
"""Bound a native opposite endpoint and retain only safe execution metadata."""
import argparse
import os
from pathlib import Path
import secrets
import shutil
import sys

sys.dont_write_bytecode = True

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / "scripts"))
from interop_peer import (collect, command_exit_status, decode_json, digest_file,
                          install_signal_handlers, read_json, write_json_atomic)  # noqa: E402


def readiness(path):
    if not path.is_file():
        return False
    with path.open("rb") as handle:
        data = handle.read(257)
    if len(data) > 256:
        raise ValueError("invalid_readiness")
    value = decode_json(data)
    if not isinstance(value, dict) or set(value) != {"port", "target"}:
        raise ValueError("invalid_readiness")
    if any(type(port) is not int or not 1 <= port <= 65535 for port in value.values()):
        raise ValueError("invalid_readiness")
    print("PORT=" + str(value["port"]), flush=True)
    print("TARGET=" + str(value["target"]), flush=True)
    return True


def terminal(path, nonce):
    with path.open("rb") as handle:
        data = handle.read(2049)
    if len(data) > 2048:
        raise ValueError("invalid_terminal")
    value = decode_json(data)
    failure_keys = {"schema", "nonce", "failure_phase"}
    if isinstance(value, dict) and set(value) == failure_keys:
        if value["schema"] == 1 and type(value["schema"]) is int and value["nonce"] == nonce and \
                type(value["failure_phase"]) is int and 1 <= value["failure_phase"] <= 255:
            return value
        raise ValueError("invalid_failure_terminal")
    expected = {"schema": 1, "nonce": nonce, "completed_flows": 2,
                "completed_datagrams": 16, "completed_rejections": 1, "workers_down": True}
    if value != expected or any(type(value[key]) is not type(item) for key, item in expected.items()):
        raise ValueError("invalid_terminal")
    return value


def run(args):
    if os.name != "posix" or not 1 <= args.seconds <= 60:
        raise ValueError("invalid_native_runner")
    if args.role not in ("client", "proxy"):
        raise ValueError("invalid_native_role")
    source = ROOT / "test/interop/masquego/http_masque_interop.erl"
    beam = Path(args.beam).resolve(strict=True)
    if beam != (ROOT / "build/dev/erlang/http/ebin/http_masque_interop.beam").resolve(strict=True):
        raise ValueError("unbound_fixture_beam")
    peer_path = ROOT / "build/interop/peers/masque-independent.json"
    peer_run = read_json(peer_path)
    if peer_run.get("schema") != 2 or peer_run.get("status") != "Running":
        raise ValueError("missing_native_peer_run")
    runtime = Path(shutil.which("erl")).resolve(strict=True)
    before = {"source": digest_file(source), "beam": digest_file(beam), "runtime": digest_file(runtime)}
    nonce = secrets.token_hex(16)
    result_path = Path(args.result).resolve()
    if result_path.exists():
        raise ValueError("existing_result")
    paths = [str(path) for path in sorted((ROOT / "build/dev/erlang").glob("*/ebin"))]
    environment = os.environ.copy()
    for key in ("ERL_AFLAGS", "ERL_FLAGS", "ERL_ZFLAGS", "ERL_LIBS"):
        environment.pop(key, None)
    environment["ERL_CRASH_DUMP_BYTES"] = "0"
    environment["ERL_CRASH_DUMP_SECONDS"] = "0"
    command = [str(runtime), "+hmax", "33554432", "+hmaxib", "true", "+hmaxk", "true",
               "+hmaxel", "false", "-noshell", "-noinput", "-pa", *paths]
    load = "[Beam,Hash|Arguments]=init:get_plain_arguments(),{ok,Bytes}=file:read_file(Beam),Expected=list_to_binary(Hash),Expected=binary:encode_hex(crypto:hash(sha256,Bytes),lowercase),{module,http_masque_interop}=code:load_binary(http_masque_interop,\"verified-masque-native\",Bytes),"
    if args.role == "proxy":
        if not args.stop or not args.readiness or Path(args.readiness).exists():
            raise ValueError("invalid_proxy_control")
        evaluation = "try " + load + "[Stop,Ready,Result,Nonce]=Arguments,ok=http_masque_interop:run_proxy(Stop,Ready,Result,list_to_binary(Nonce)),halt(0) catch _:_ -> halt(1) end."
        extra = [args.stop, args.readiness]
    else:
        if any(type(port) is not int or not 1 <= port <= 65535 for port in [args.port, args.target]):
            raise ValueError("invalid_client_control")
        evaluation = "try " + load + "[Port,Target,Result,Nonce]=Arguments,ok=http_masque_interop:run_client(list_to_integer(Port),list_to_integer(Target),Result,list_to_binary(Nonce)),halt(0) catch _:_ -> halt(1) end."
        extra = [str(args.port), str(args.target)]
    command += ["-eval", evaluation, "-extra", str(beam), before["beam"]["sha256"], *extra, str(result_path), nonce]
    record = {"schema": 1, "status": "Failed", "role": args.role,
              "configured_flows": 2, "configured_datagrams": 16,
              "configured_rejections": 1, "timeout_seconds": args.seconds,
              "nonce": nonce, "fixture": before, "completion": None, "child": None,
              "run_id": peer_run["run_id"], "source_sha256": peer_run["source_sha256"]}
    destination = Path(args.evidence)
    write_json_atomic(destination, record)
    completion, output = collect(command, args.seconds, limit=65536,
        ready=(lambda _pid: readiness(Path(args.readiness))) if args.readiness else None,
        env=environment)
    # Captured bytes may contain foreign crash output.
    # Neither the bytes nor a hash of them enter a shareable record.
    # The known fixture writes no output.
    valid = not output and completion["outcome"] == "completed" and completion["exit_status"] == 0
    valid = valid and before == {"source": digest_file(source), "beam": digest_file(beam), "runtime": digest_file(runtime)}
    valid = valid and read_json(peer_path) == peer_run
    record["completion"] = completion
    try:
        record["child"] = terminal(result_path, nonce)
        valid = valid and "failure_phase" not in record["child"]
    except Exception:
        valid = False
    record["status"] = "Passed" if valid else "Failed"
    write_json_atomic(destination, record)
    return 0 if valid else 1


def main(arguments=None):
    parser = argparse.ArgumentParser()
    parser.add_argument("--role", required=True)
    parser.add_argument("--beam", required=True)
    parser.add_argument("--evidence", required=True)
    parser.add_argument("--readiness")
    parser.add_argument("--stop")
    parser.add_argument("--result", required=True)
    parser.add_argument("--port", type=int)
    parser.add_argument("--target", type=int)
    parser.add_argument("--seconds", type=int, default=40)
    return run(parser.parse_args(arguments))


def safe_failure_line():
    try:
        print("native MASQUE execution failed", file=sys.stderr)
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

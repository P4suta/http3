#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 the http contributors
# SPDX-License-Identifier: MIT OR Apache-2.0
"""Build a fixed independent Go peer and bind its executable to actual inputs."""
import argparse
import hashlib
import os
from pathlib import Path
import re
import secrets
import struct
import sys

# Qualification inventories include every file under scripts and test.
# A harness import must not create a new input halfway through an execution.
sys.dont_write_bytecode = True

import interop_peer as peer_tools

PEERS = {
    "quic-go-h3": ("packages/http3/test/interop/quicgo", "packages/http3/test/interop/run.sh", "quic-go"),
    "ohttp-go": ("test/interop/ohttpgo", "test/interop/ohttpgo/setup.sh", "ohttp-go"),
    "masque-independent": ("test/interop/masquego", "test/interop/masquego/setup.sh", "masque-go"),
}
COMMON_RECIPES = ["scripts/interop_go_build.py", "scripts/interop_peer.py", "standards/interop-profile.json"]
COMPLETION_KEYS = {"outcome", "exit_status", "exit_observed", "controlled_shutdown",
                   "elapsed_milliseconds", "stdout_bytes", "stderr_bytes"}
RECEIPT_KEYS = {"schema", "status", "peer", "nonce", "sources", "recipes", "lock",
                "compiler", "toolchain", "binary", "module_info", "steps"}
STEP_NAMES = ["download", "verify_before", "build", "verify_after"]
UNSUPPORTED_SUFFIXES = {".s", ".syso", ".c", ".h", ".cc", ".hh", ".cpp", ".hpp",
                        ".cxx", ".hxx", ".m", ".mm", ".f", ".for", ".f90", ".swig", ".swigcxx"}
GO_LITERAL = re.compile(rb'''//[^\n]*|/\*.*?\*/|"(?:\\.|[^"\\])*"|`[^`]*`|'(?:\\.|[^'\\])*' ''', re.S | re.X)
C_LITERALS = {b'"C"', b'"\\x43"', b'"\\u0043"', b'"\\U00000043"', b'"\\103"'}


def pure_go_source(content):
    require(b"//go:embed" not in content, "unbound_go_embedded_input")
    # A conservative policy for these fixed fixtures, not a general Go parser:
    # no string literal may denote the special C import.
    # Comments and rune literals are separate tokens; URL-looking strings cannot hide imports.
    for token in GO_LITERAL.finditer(content):
        value = token.group()
        require(value not in C_LITERALS and value.replace(b"\r", b"") != b"`C`", "unbound_go_cgo_import")


def require(condition, code):
    peer_tools.require(condition, code)


def digest_valid(value):
    return isinstance(value, dict) and set(value) == {"sha256", "bytes"} and \
        isinstance(value["sha256"], str) and re.fullmatch(r"[a-f0-9]{64}", value["sha256"]) and \
        type(value["bytes"]) is int and 0 < value["bytes"] <= peer_tools.MAX_FILE


def rows_digest(rows):
    digest = hashlib.sha256(b"http-go-build-files-v1\x00")
    digest.update(struct.pack(">Q", len(rows)))
    for row in rows:
        name = row["path"].encode("utf-8")
        digest.update(struct.pack(">Q", len(name)))
        digest.update(name)
        digest.update(struct.pack(">Q", row["bytes"]))
        digest.update(bytes.fromhex(row["sha256"]))
    return digest.hexdigest()


def input_rows_valid(rows):
    return isinstance(rows, list) and 0 < len(rows) <= 256 and all(
        isinstance(row, dict) and set(row) == {"path", "sha256", "bytes"}
        and isinstance(row["path"], str) and 0 < len(row["path"].encode()) <= 1024
        and isinstance(row["sha256"], str) and re.fullmatch(r"[a-f0-9]{64}", row["sha256"])
        and type(row["bytes"]) is int and 0 <= row["bytes"] <= peer_tools.MAX_FILE for row in rows)


def inventory(root, names):
    require(0 < len(names) <= 20000 and len(names) == len(set(names)), "invalid_go_input_inventory")
    result = []
    for name in sorted(names):
        path = root / name
        require(not path.is_symlink() and path.is_file() and path.resolve().is_relative_to(root),
                "unsafe_go_input")
        result.append(dict(path=name, **peer_tools.digest_file(path, allow_empty=True)))
    return result


def inputs(root, peer):
    require(peer["id"] in PEERS, "unknown_go_peer")
    directory, recipe, _ = PEERS[peer["id"]]
    folder = root / directory
    require(folder.is_dir() and not folder.is_symlink(), "missing_go_source_directory")
    files = []
    visited = 0
    # Every Go file, including newly added files and tests, is an input.
    # Symlinked directories are rejected instead of allowing them to hide compiler inputs.
    for current, directories, names in os.walk(folder, followlinks=False):
        visited += 1
        require(len(files) <= 256 and len(directories) <= 256 and visited <= 256, "too_many_go_sources")
        require(all(not (Path(current) / item).is_symlink() for item in directories), "unsafe_go_source_directory")
        for name in names:
            require(Path(name).suffix.lower() not in UNSUPPORTED_SUFFIXES, "unbound_go_native_input")
            if name.endswith(".go") or name in ("go.mod", "go.sum"):
                path = Path(current) / name
                require(path.stat().st_size <= 1048576, "oversized_go_source")
                if name.endswith(".go"):
                    pure_go_source(peer_tools.read_bytes_stable(path, 1048576))
                files.append(path.relative_to(root).as_posix())
    require(0 < len(files) <= 256, "invalid_go_source_count")
    require(peer["lock"] == directory + "/go.sum", "unexpected_go_lock")
    recipes = COMMON_RECIPES + [recipe]
    if recipe.endswith("setup.sh"):
        recipes.append(directory + "/run.sh")
    sources = inventory(root, files)
    require(directory + "/go.mod" in files and directory + "/go.sum" in files, "missing_go_module_inputs")
    lock = peer_tools.digest_file(root / peer["lock"])
    require(lock["sha256"] == peer["lock_sha256"], "go_lock_drift")
    return {"sources": sources, "recipes": inventory(root, recipes), "lock": lock}


def environment():
    # No user Go configuration, cross compiler, injected cache helper or C tool participates in these pure Go fixtures.
    # Network proxy settings stay local.
    result = {key: value for key, value in os.environ.items()
              if not key.upper().startswith("GO") and not key.upper().startswith("CGO_")}
    result.update(GOENV="off", GOTOOLCHAIN="local", GOWORK="off", CGO_ENABLED="0",
                  GOFLAGS="", GOMEMLIMIT="1GiB")
    return result


def probe(command, env):
    completed, output = peer_tools.collect(command, 20, limit=1048576, env=env)
    require(completed["outcome"] == "completed" and completed["exit_status"] == 0,
            "go_probe_failed")
    return output.decode("utf-8")


def toolchain(compiler, env):
    observed = peer_tools.decode_json(probe([str(compiler), "env", "-json", "GOROOT", "GOTOOLDIR", "GOHOSTOS", "GOHOSTARCH"], env))
    require(set(observed) == {"GOROOT", "GOTOOLDIR", "GOHOSTOS", "GOHOSTARCH"}, "invalid_go_toolchain_probe")
    root = Path(observed["GOROOT"]).resolve(strict=True)
    tools = Path(observed["GOTOOLDIR"]).resolve(strict=True)
    require(tools.is_relative_to(root), "go_tools_outside_runtime")
    names = []
    total = 0
    for folder in [root / "src", tools]:
        for current, directories, files in os.walk(folder, followlinks=False):
            require(all(not (Path(current) / item).is_symlink() for item in directories), "go_runtime_symlink")
            for name in files:
                path = Path(current) / name
                total += path.stat().st_size
                require(len(names) < 20000 and total <= 1073741824, "go_runtime_inventory_limit")
                names.append(path.relative_to(root).as_posix())
    rows = inventory(root, names)
    return {"sha256": rows_digest(rows), "files": len(rows)}


def module_info(output, version):
    require(isinstance(output, str) and len(output.encode()) <= 1048576, "oversized_go_module_info")
    lines = output.splitlines()
    require(lines and lines[0].split()[-1] == version, "go_compiler_version_drift")
    result = {"version": version, "path": "", "module": "", "dependencies": [], "settings": []}
    for line in lines[1:]:
        fields = line.split()
        require(fields and len(fields) <= 4 and fields[0] in ("path", "mod", "dep", "build"), "invalid_go_module_row")
        kind = fields[0]
        if kind == "path":
            require(len(fields) == 2 and not result["path"], "invalid_go_main_path")
            result["path"] = fields[1]
        elif kind == "mod":
            require(len(fields) == 3 and fields[2] == "(devel)" and not result["module"], "invalid_go_main_module")
            result["module"] = fields[1]
        elif kind == "dep":
            require(len(fields) == 4, "invalid_go_dependency")
            result["dependencies"].append(dict(zip(("name", "version", "sum"), fields[1:])))
        else:
            require(len(fields) == 2 and "=" in fields[1], "invalid_go_build_setting")
            key, value = fields[1].split("=", 1)
            result["settings"].append({"name": key, "value": value})
    require(result["path"] == result["module"] and re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._/+~-]{0,191}", result["path"]), "invalid_go_main_module")
    require(0 < len(result["dependencies"]) <= 128 and len(result["settings"]) <= 32, "invalid_go_module_count")
    for field in ("dependencies", "settings"):
        result[field].sort(key=lambda item: item["name"])
        require(len({item["name"] for item in result[field]}) == len(result[field]), "duplicate_go_module_row")
    for dependency in result["dependencies"]:
        require(re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._/+~-]{0,191}", dependency["name"])
                and re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9.+_-]{0,63}", dependency["version"])
                and re.fullmatch(r"h1:[A-Za-z0-9+/]{43}=", dependency["sum"]), "invalid_go_dependency_field")
    settings = {item["name"]: item["value"] for item in result["settings"]}
    required = {"-buildmode": "exe", "-compiler": "gc", "-trimpath": "true", "CGO_ENABLED": "0"}
    require(all(settings.get(key) == value for key, value in required.items()), "uncontrolled_go_build_settings")
    allowed = set(required) | {"GOARCH", "GOOS", "GOAMD64", "GOARM64", "GOARM", "GO386", "GOMIPS", "GOMIPS64", "GOPPC64", "GORISCV64", "DefaultGODEBUG"}
    require(set(settings) <= allowed and {"GOARCH", "GOOS"} <= set(settings), "unknown_go_build_setting")
    for key, value in settings.items():
        if key == "DefaultGODEBUG":
            pairs = value.split(",")
            require(0 < len(value) <= 4096 and 0 < len(pairs) <= 128
                    and all(re.fullmatch(r"[a-z][a-z0-9]{0,63}=[0-9]{1,10}", item) for item in pairs)
                    and len({item.split("=", 1)[0] for item in pairs}) == len(pairs), "private_go_build_setting")
        else:
            require(re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9.,_+-]{0,63}", value), "private_go_build_setting")
    return result


def receipt_path(root, identifier):
    require(identifier in PEERS, "unknown_go_peer")
    return root / "build/interop/go-build" / (identifier + ".json")


def attempt_path(root, identifier):
    return receipt_path(root, identifier).with_name(identifier + "-attempt.json")


def load_receipt(root, peer):
    path = receipt_path(root, peer["id"])
    require(path.is_file() and not path.is_symlink(), "missing_go_build_receipt")
    receipt = peer_tools.read_json(path)
    require(isinstance(receipt, dict) and set(receipt) == RECEIPT_KEYS, "invalid_go_build_receipt_fields")
    require(type(receipt["schema"]) is int and receipt["schema"] == 1 and receipt["status"] == "Passed"
            and receipt["peer"] == peer["id"] and isinstance(receipt["nonce"], str)
            and re.fullmatch(r"[a-f0-9]{32}", receipt["nonce"]), "incomplete_go_build_receipt")
    attempt_file = attempt_path(root, peer["id"])
    require(attempt_file.is_file() and not attempt_file.is_symlink(), "missing_go_build_attempt")
    attempt = peer_tools.read_json(attempt_file)
    require(attempt == {"schema": 1, "peer": peer["id"], "nonce": receipt["nonce"]}
            and type(attempt["schema"]) is int, "stale_go_build_attempt")
    require(all(digest_valid(receipt[key]) for key in ("lock", "compiler", "binary")), "invalid_go_build_digest")
    require(all(input_rows_valid(receipt[key]) for key in ("sources", "recipes")), "invalid_go_input_rows")
    runtime = receipt["toolchain"]
    require(isinstance(runtime, dict) and set(runtime) == {"sha256", "files"}
            and isinstance(runtime["sha256"], str) and re.fullmatch(r"[a-f0-9]{64}", runtime["sha256"])
            and type(runtime["files"]) is int and 0 < runtime["files"] <= 20000, "invalid_go_runtime_identity")
    steps = receipt["steps"]
    require(isinstance(steps, list) and len(steps) == len(STEP_NAMES), "incomplete_go_build_steps")
    for step, name in zip(steps, STEP_NAMES):
        require(isinstance(step, dict) and set(step) == COMPLETION_KEYS | {"step"}
                and step["step"] == name, "invalid_go_build_step_fields")
        require(step["outcome"] == "completed" and type(step["exit_status"]) is int and step["exit_status"] == 0
                and step["exit_observed"] is True and step["controlled_shutdown"] is False, "failed_go_build_step")
        require(all(type(step[key]) is int and 0 <= step[key] <= maximum for key, maximum in
                    [("elapsed_milliseconds", 125000), ("stdout_bytes", 1048576), ("stderr_bytes", 1048576)])
                and step["stdout_bytes"] + step["stderr_bytes"] <= 1048576, "invalid_go_build_measurement")
    return receipt


def verify(root, peer, binary, actual_info):
    receipt = load_receipt(root, peer)
    current = inputs(root, peer)
    require(all(receipt[key] == value for key, value in current.items()), "stale_go_build_inputs")
    compiler = peer_tools.executable("go")
    require(receipt["compiler"] == peer_tools.digest_file(compiler), "go_build_compiler_changed")
    expected_binary = root / "build/interop/bin" / PEERS[peer["id"]][2]
    require(not expected_binary.is_symlink() and binary == expected_binary.resolve(strict=True),
            "unbound_go_build_binary")
    require(receipt["binary"] == peer_tools.digest_file(binary), "go_build_binary_changed")
    info = module_info(actual_info, peer["go_version"])
    require(receipt["module_info"] == info, "go_build_module_info_changed")
    lock = set(peer_tools.read_bytes_stable(
        root / peer["lock"], peer_tools.MAX_JSON).decode("utf-8").splitlines())
    require(all(" ".join(item[key] for key in ("name", "version", "sum")) in lock
                for item in info["dependencies"]), "go_dependency_not_locked")
    require(any(item["name"] + "@" + item["version"] == peer["pin"] for item in info["dependencies"]), "go_version_drift")
    require(receipt["toolchain"] == toolchain(compiler, environment()), "go_build_runtime_changed")
    return receipt


def build(root, identifier):
    root = peer_tools._plain_directory(root)
    destination = receipt_path(root, identifier)
    # Invalidate old success before any build/probe.
    # No old binary may satisfy an attempt that never reaches the real compiler and all postconditions.
    peer_tools.write_json_atomic(destination, {"schema": 1, "status": "Failed"})
    nonce = secrets.token_hex(16)
    peer_tools.write_json_atomic(attempt_path(root, identifier), {"schema": 1, "peer": identifier, "nonce": nonce})
    profile = peer_tools.read_json(root / "standards/interop-profile.json")
    matches = [peer for peer in profile["peers"] if peer["id"] == identifier]
    require(len(matches) == 1 and matches[0]["identity_kind"] == "go", "invalid_go_peer_profile")
    peer = matches[0]
    compiler = peer_tools.executable("go")
    env = environment()
    require(probe([str(compiler), "version"], env).split()[2] == peer["go_version"], "go_compiler_version_drift")
    before = inputs(root, peer)
    compiler_digest = peer_tools.digest_file(compiler)
    runtime_digest = toolchain(compiler, env)
    directory, _, name = PEERS[identifier]
    binary = root / "build/interop/bin" / name
    binary.parent.mkdir(parents=True, exist_ok=True)
    commands = [["mod", "download"], ["mod", "verify"],
                ["build", "-a", "-mod=readonly", "-trimpath", "-buildvcs=false", "-o", str(binary), "."],
                ["mod", "verify"]]
    steps = []
    for name, command in zip(STEP_NAMES, commands):
        if name == "build":
            require(not binary.is_symlink(), "unsafe_go_output")
            binary.unlink(missing_ok=True)
        completed, _ = peer_tools.collect([str(compiler), "-C", str(root / directory), *command],
                                         120, limit=1048576, env=env)
        require(completed["outcome"] == "completed" and completed["exit_status"] == 0, "go_build_step_failed")
        steps.append(dict(step=name, **completed))
    info = probe([str(compiler), "version", "-m", str(binary)], env)
    require(before == inputs(root, peer), "go_inputs_changed_during_build")
    require(compiler_digest == peer_tools.digest_file(compiler)
            and runtime_digest == toolchain(compiler, env), "go_toolchain_changed_during_build")
    receipt = dict(schema=1, status="Passed", peer=identifier, nonce=nonce,
                   **before, compiler=compiler_digest, toolchain=runtime_digest,
                   binary=peer_tools.digest_file(binary), module_info=module_info(info, peer["go_version"]), steps=steps)
    peer_tools.write_json_atomic(destination, receipt)
    try:
        verify(root, peer, binary, info)
    except BaseException:
        try:
            peer_tools.write_json_atomic(destination, {"schema": 1, "status": "Failed"})
        except BaseException:
            # Publication failure cannot replace the original termination.
            pass
        raise


def main(arguments=None):
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument("--peer", choices=sorted(PEERS), required=True)
    args = parser.parse_args(arguments)
    build(args.root, args.peer)


def safe_line(message, stream):
    try:
        print(message, file=stream)
    except BaseException:
        pass


def cli(arguments=None):
    try:
        peer_tools.install_signal_handlers()
        main(arguments)
    except BaseException as error:
        status = peer_tools.command_exit_status(error)
        if status != 0:
            safe_line("Independent Go peer build failed", sys.stderr)
        return status
    safe_line("Independent Go peer build verified", sys.stdout)
    return 0


if __name__ == "__main__":
    sys.exit(cli())

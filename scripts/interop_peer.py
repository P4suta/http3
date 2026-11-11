#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 the http contributors
# SPDX-License-Identifier: MIT OR Apache-2.0
"""Run one independent peer; retain identities and completed exit facts only.

This is a development harness for the POSIX interop scripts. It never records
arguments, endpoints, environment values, output contents, or output hashes.
The Erlang auditor separately verifies the scenario oracle and current source.
"""

import argparse
import base64
import hashlib
import importlib.metadata
import io
import json
import os
from pathlib import Path, PurePosixPath
import re
import selectors
import secrets
import shutil
import signal
import stat
import struct
import subprocess
import sys
import tarfile
import time
import urllib.request
import zlib

sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).resolve().parent))

from process_supervisor import owned_popen

MAX_OUTPUT = 8 * 1024 * 1024
MAX_FILE = 256 * 1024 * 1024
MAX_JSON = 1024 * 1024
MAX_NODE_ENTRIES = 20_000
MAX_NODE_DEPTH = 64
MAX_NODE_PATH_BYTES = 1024
MAX_IDENTITY_TOTAL_BYTES = 512 * 1024 * 1024
ORIGINAL_PARENT = os.getppid()
CANCELLATION_EXIT_STATUSES = frozenset({130, 143, 149})
FAILURE_PHASES = frozenset({
    "identity_before", "execution", "identity_after",
    "exit_validation", "publication",
})
FAILURE_COMPLETION_KEYS = frozenset({
    "outcome", "exit_status", "exit_observed", "controlled_shutdown",
    "elapsed_milliseconds", "stdout_bytes", "stderr_bytes",
})


def require(condition, code):
    if not condition:
        raise ValueError(code)


def failure_exit_status(error):
    if type(error) is SystemExit and type(error.code) is int and 1 <= error.code <= 255:
        return error.code
    if type(error) is KeyboardInterrupt:
        return 130
    return 1


def command_exit_status(error):
    if type(error) is SystemExit and type(error.code) is int and 0 <= error.code <= 255:
        return error.code
    return failure_exit_status(error)


def failure_result(error):
    status = failure_exit_status(error)
    cancelled = type(error) is KeyboardInterrupt or (
        type(error) is SystemExit and status in CANCELLATION_EXIT_STATUSES
    )
    return {"kind": "cancelled" if cancelled else "failed", "exit_status": status}


def validate_peer_failure_report(report):
    """Reject every value that cannot be shared as bounded failure evidence."""
    require(type(report) is dict and set(report) == {
        "schema", "status", "peer", "run_id", "source_sha256", "role",
        "scenario", "phase", "completion", "result",
    }, "invalid_failure_fields")
    require(type(report["schema"]) is int and report["schema"] == 1
            and report["status"] == "Failed",
            "invalid_failure_status")
    require(type(report["peer"]) is str
            and re.fullmatch(r"[a-z0-9][a-z0-9-]{0,63}", report["peer"]),
            "invalid_failure_peer")
    require(type(report["run_id"]) is str
            and re.fullmatch(r"[0-9a-f]{64}", report["run_id"]),
            "invalid_failure_identity")
    require(type(report["source_sha256"]) is str
            and re.fullmatch(r"[0-9A-Fa-f]{64}", report["source_sha256"]),
            "invalid_failure_identity")
    require(type(report["role"]) is str
            and report["role"] in {"client", "server", "proxy", "relay", "gateway"},
            "invalid_failure_role")
    require(type(report["scenario"]) is str, "invalid_failure_scenario")
    try:
        scenario_bytes = report["scenario"].encode("utf-8")
    except UnicodeError:
        raise ValueError("invalid_failure_scenario") from None
    require(0 < len(scenario_bytes) <= 128, "invalid_failure_scenario")
    phase = report["phase"]
    require(type(phase) is str and phase in FAILURE_PHASES,
            "invalid_failure_phase")
    result = report["result"]
    require(type(result) is dict and set(result) == {"kind", "exit_status"},
            "invalid_failure_result")
    status = result["exit_status"]
    require(type(status) is int and 1 <= status <= 255,
            "invalid_failure_exit_status")
    require(type(result["kind"]) is str
            and ((result["kind"] == "cancelled"
             and status in CANCELLATION_EXIT_STATUSES)
            or (result["kind"] == "failed"
                and status not in CANCELLATION_EXIT_STATUSES)),
            "invalid_failure_result")
    completion = report["completion"]
    if completion is None:
        require(phase in {"identity_before", "execution"},
                "missing_failure_completion")
        return report
    require(phase != "identity_before" and type(completion) is dict
            and set(completion) == FAILURE_COMPLETION_KEYS,
            "invalid_failure_completion")
    require(type(completion["outcome"]) is str
            and completion["outcome"] in {"completed", "timeout", "output_limit"},
            "invalid_failure_outcome")
    require(type(completion["exit_status"]) is int
            and -255 <= completion["exit_status"] <= 255,
            "invalid_failure_process_status")
    require(completion["exit_observed"] is True,
            "unobserved_failure_exit")
    require(type(completion["controlled_shutdown"]) is bool,
            "invalid_failure_shutdown")
    require(type(completion["elapsed_milliseconds"]) is int
            and 0 <= completion["elapsed_milliseconds"] <= 125_000,
            "invalid_failure_elapsed")
    for field in ("stdout_bytes", "stderr_bytes"):
        require(type(completion[field]) is int
                and 0 <= completion[field] <= MAX_OUTPUT,
                "invalid_failure_output_count")
    require(completion["stdout_bytes"] + completion["stderr_bytes"] <= MAX_OUTPUT,
            "oversized_failure_output")
    return report


def peer_failure_report(peer, run_id, source_sha256, role, scenario, phase,
                        completion, error):
    captured_completion = dict(completion) if type(completion) is dict else completion
    report = {
        "schema": 1, "status": "Failed", "peer": peer,
        "run_id": run_id, "source_sha256": source_sha256,
        "role": role, "scenario": scenario, "phase": phase,
        "completion": captured_completion, "result": failure_result(error),
    }
    return validate_peer_failure_report(report)


def safe_failure_line():
    try:
        print("independent peer execution or identity verification failed", file=sys.stderr)
    except BaseException:
        pass


def interrupted(signum, _frame):
    raise SystemExit(128 + signum)


def install_signal_handlers():
    for name in ("SIGINT", "SIGTERM", "SIGBREAK"):
        signum = getattr(signal, name, None)
        if signum is not None:
            signal.signal(signum, interrupted)


def decode_json(data):
    def unique_object(pairs):
        result = {}
        for key, value in pairs:
            require(key not in result, "duplicate_json_key")
            result[key] = value
        return result
    return json.loads(data, object_pairs_hook=unique_object)


def _has_reparse_point(metadata):
    return bool(
        getattr(metadata, "st_file_attributes", 0)
        & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
    )


def _file_identity(metadata, *, same_handle_domain=False):
    identity = (
        metadata.st_dev,
        metadata.st_ino,
        stat.S_IFMT(metadata.st_mode),
        metadata.st_nlink,
        metadata.st_size,
        getattr(metadata, "st_mtime_ns", int(metadata.st_mtime * 1_000_000_000)),
    )
    # Windows reports a handle ctime that can differ from the path ctime for the same NTFS file immediately after replace.
    # Device/inode, mode, link count, size and mtime still bind path-to-handle checks.
    # Comparisons within the handle domain retain ctime; POSIX can retain it for every comparison.
    if os.name != "nt" or same_handle_domain:
        identity += (
            getattr(metadata, "st_ctime_ns", int(metadata.st_ctime * 1_000_000_000)),
        )
    return identity


def _absolute_path(path):
    # abspath removes `.` and `..` without resolving links or junctions.
    return Path(os.path.abspath(os.fspath(path)))


def _plain_directory(path, create=False):
    path = _absolute_path(path)
    components = [*reversed(path.parents), path]
    for component in components:
        try:
            metadata = os.lstat(component)
        except FileNotFoundError:
            require(create, "missing_evidence_directory")
            try:
                os.mkdir(component)
            except FileExistsError:
                pass
            except OSError:
                raise ValueError("cannot_create_evidence_directory") from None
            try:
                metadata = os.lstat(component)
            except OSError:
                raise ValueError("cannot_inspect_evidence_directory") from None
        except OSError:
            raise ValueError("cannot_inspect_evidence_directory") from None
        require(
            stat.S_ISDIR(metadata.st_mode)
            and not stat.S_ISLNK(metadata.st_mode)
            and not _has_reparse_point(metadata),
            "unsafe_evidence_directory",
        )
    return path


def _plain_file_metadata(path, *, missing_code="missing_peer_json"):
    try:
        metadata = os.lstat(path)
    except FileNotFoundError:
        raise ValueError(missing_code) from None
    except OSError:
        raise ValueError("cannot_inspect_peer_json") from None
    require(
        stat.S_ISREG(metadata.st_mode)
        and not stat.S_ISLNK(metadata.st_mode)
        and not _has_reparse_point(metadata),
        "unsafe_peer_json",
    )
    require(metadata.st_nlink == 1, "peer_json_hardlink")
    return metadata


def read_bytes_stable(path, limit=MAX_JSON):
    require(isinstance(limit, int) and 0 <= limit <= MAX_FILE, "invalid_peer_json_limit")
    path = _absolute_path(path)
    _plain_directory(path.parent)
    initial = _plain_file_metadata(path)
    require(0 <= initial.st_size <= limit, "oversized_peer_json")
    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError:
        raise ValueError("cannot_open_peer_json") from None
    try:
        opened = os.fstat(descriptor)
        require(
            stat.S_ISREG(opened.st_mode)
            and not _has_reparse_point(opened)
            and opened.st_nlink == 1
            and _file_identity(initial) == _file_identity(opened),
            "peer_json_changed",
        )
        chunks = []
        observed = 0
        while True:
            chunk = os.read(descriptor, min(65536, limit + 1 - observed))
            if not chunk:
                break
            chunks.append(chunk)
            observed += len(chunk)
            require(observed <= limit, "oversized_peer_json")
        finished = os.fstat(descriptor)
        require(
            _file_identity(opened, same_handle_domain=True)
            == _file_identity(finished, same_handle_domain=True),
            "peer_json_changed",
        )
    finally:
        os.close(descriptor)
    final = _plain_file_metadata(path)
    require(_file_identity(finished) == _file_identity(final), "peer_json_changed")
    _plain_directory(path.parent)
    data = b"".join(chunks)
    require(len(data) == initial.st_size, "peer_json_changed")
    return data


def read_json(path):
    return decode_json(read_bytes_stable(path))


def digest_file(path, allow_empty=False, require_single_link=False, maximum=MAX_FILE):
    require(type(allow_empty) is bool and type(require_single_link) is bool
            and type(maximum) is int and 0 <= maximum <= MAX_FILE,
            "invalid_identity_file_limit")
    try:
        path = Path(path).resolve(strict=True)
        initial = os.lstat(path)
    except FileNotFoundError:
        raise FileNotFoundError("identity_file_missing") from None
    except OSError:
        raise ValueError("unreadable_identity_file") from None
    require(
        stat.S_ISREG(initial.st_mode)
        and not stat.S_ISLNK(initial.st_mode)
        and not _has_reparse_point(initial),
        "unsafe_identity_file",
    )
    require(not require_single_link or initial.st_nlink == 1,
            "identity_file_hardlink")
    size = initial.st_size
    require(0 <= size <= maximum and (allow_empty or size > 0),
            "invalid_identity_file_size")
    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError:
        raise ValueError("unreadable_identity_file") from None
    digest = hashlib.sha256()
    seen = 0
    try:
        opened = os.fstat(descriptor)
        require(_file_identity(initial) == _file_identity(opened), "identity_file_changed")
        while True:
            chunk = os.read(descriptor, min(65536, size - seen + 1))
            if not chunk:
                break
            seen += len(chunk)
            require(seen <= size, "identity_file_changed")
            digest.update(chunk)
        finished = os.fstat(descriptor)
        require(
            _file_identity(opened, same_handle_domain=True)
            == _file_identity(finished, same_handle_domain=True),
            "identity_file_changed",
        )
    finally:
        os.close(descriptor)
    try:
        final = os.lstat(path)
    except OSError:
        raise ValueError("identity_file_changed") from None
    require(
        seen == size and _file_identity(finished) == _file_identity(final),
        "identity_file_changed",
    )
    return {"sha256": digest.hexdigest(), "bytes": size}


def digest_rows(rows):
    require(isinstance(rows, (list, tuple))
            and 0 < len(rows) <= MAX_NODE_ENTRIES,
            "invalid_dependency_file_count")
    validated = []
    names = set()
    for row in rows:
        require(isinstance(row, (list, tuple)) and len(row) == 2,
                "invalid_dependency_file_identity")
        name, details = row
        require(type(name) is str, "invalid_dependency_file_name")
        require(name not in names, "duplicate_dependency_file")
        names.add(name)
        validated.append((name, details))
    ordered = sorted(validated, key=lambda row: row[0])
    digest = hashlib.sha256(b"http-interop-files-v1\x00")
    digest.update(struct.pack(">Q", len(ordered)))
    for name, details in ordered:
        require(type(name) is str and isinstance(details, dict)
                and set(details) == {"sha256", "bytes"}
                and type(details["sha256"]) is str
                and re.fullmatch(r"[a-f0-9]{64}", details["sha256"])
                and type(details["bytes"]) is int
                and 0 <= details["bytes"] <= MAX_FILE,
                "invalid_dependency_file_identity")
        try:
            encoded = name.encode("utf-8")
        except UnicodeError:
            raise ValueError("invalid_dependency_file_name") from None
        require(0 < len(encoded) <= 4096, "invalid_dependency_file_name")
        digest.update(struct.pack(">Q", len(encoded)))
        digest.update(encoded)
        digest.update(bytes.fromhex(details["sha256"]))
    return digest.hexdigest()


def digest_files(entries):
    require(isinstance(entries, (list, tuple))
            and 0 < len(entries) <= MAX_NODE_ENTRIES,
            "invalid_dependency_file_count")
    names = set()
    validated = []
    for entry in entries:
        require(isinstance(entry, (list, tuple)) and len(entry) == 2,
                "invalid_dependency_file_identity")
        name, path = entry
        require(type(name) is str, "invalid_dependency_file_name")
        require(name not in names, "duplicate_dependency_file")
        names.add(name)
        validated.append((name, path))
    rows = []
    total = 0
    for name, path in validated:
        # Empty metadata files are valid, while executables cannot be empty.
        details = digest_file(path, allow_empty=True,
                              maximum=min(MAX_FILE,
                                          MAX_IDENTITY_TOTAL_BYTES - total))
        total += details["bytes"]
        rows.append((name, details))
    return digest_rows(rows)


def collect(command, seconds, relay=False, limit=MAX_OUTPUT, stop_requested=None, ready=None, env=None):
    """An absolute deadline and output ceiling both kill and reap the group."""
    require(os.name == "posix", "peer_runner_requires_posix")
    require(0 < seconds <= 120 and 0 < limit <= MAX_OUTPUT, "invalid_process_limit")
    started = time.monotonic()
    deadline = started + seconds
    child = owned_popen(command, stdout=subprocess.PIPE,
                             stderr=subprocess.PIPE, start_new_session=True, env=env)
    selector = selectors.DefaultSelector()
    selector.register(child.stdout, selectors.EVENT_READ, "stdout")
    selector.register(child.stderr, selectors.EVENT_READ, "stderr")
    counts = {"stdout": 0, "stderr": 0}
    captured = bytearray()
    outcome = "completed"
    controlled_shutdown = False
    old_handlers = {}
    try:
        for number in (signal.SIGTERM, signal.SIGINT):
            old_handlers[number] = signal.signal(number, interrupted)
        while selector.get_map() or child.poll() is None:
            require(os.getppid() == ORIGINAL_PARENT, "peer_supervisor_owner_exited")
            if ready is not None and ready(child.pid):
                ready = None
            if (stop_requested is not None and not controlled_shutdown
                    and child.poll() is None and stop_requested()):
                controlled_shutdown = True
                child.terminate()
                deadline = min(deadline, time.monotonic() + 5)
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                outcome = "timeout"
                break
            for key, _mask in selector.select(min(remaining, 0.1)):
                chunk = os.read(key.fileobj.fileno(), 65536)
                if not chunk:
                    selector.unregister(key.fileobj)
                    continue
                counts[key.data] += len(chunk)
                if sum(counts.values()) > limit:
                    outcome = "output_limit"
                    break
                if relay:
                    target = sys.stdout.buffer if key.data == "stdout" else sys.stderr.buffer
                    target.write(chunk)
                    target.flush()
                else:
                    captured.extend(chunk)
            if outcome != "completed":
                break
        if outcome != "completed":
            child.kill()
        status = child.wait(timeout=5)
    finally:
        # Reap even a process whose parent exited but left inherited pipes open.
        if child.poll() is None:
            child.kill()
        child.wait(timeout=5)
        selector.close()
        child.stdout.close()
        child.stderr.close()
        for number, handler in old_handlers.items():
            signal.signal(number, handler)
        # The repository process supervisor owns the complete native tree and attests it after this bounded child has been joined.
    return ({"outcome": outcome, "exit_status": status,
             "exit_observed": True,
             "controlled_shutdown": controlled_shutdown,
             "elapsed_milliseconds": int((time.monotonic() - started) * 1000),
             "stdout_bytes": counts["stdout"], "stderr_bytes": counts["stderr"]},
            bytes(captured))


def probe(command, env=None):
    completion, output = collect(command, 20, limit=1024 * 1024, env=env)
    require(completion["outcome"] == "completed" and completion["exit_status"] == 0,
            "identity_probe_failed")
    return output.decode("utf-8")


def executable(name):
    found = shutil.which(name)
    require(found is not None, "missing_peer_executable")
    return Path(found).resolve(strict=True)


def shared_libraries(path, allow_static=False, *, env=None):
    completion, captured = collect(["ldd", str(path)], 20, limit=1024 * 1024, env=env)
    output = captured.decode("utf-8")
    require(completion["outcome"] == "completed", "library_probe_failed")
    if allow_static and output.strip() in ("not a dynamic executable", "statically linked"):
        return []
    require(completion["exit_status"] == 0, "library_probe_failed")
    require("not found" not in output, "missing_shared_library")
    paths = set(re.findall(r"(?:=>\s+|^\s*)(/[^\s]+)\s+\(", output, re.MULTILINE))
    require(0 < len(paths) <= 128, "missing_dynamic_runtime_identity")
    return [{"name": Path(name).name, "version": "binary",
             "sha256": digest_file(name)["sha256"], "files": 1}
            for name in sorted(paths)]


def python_dependencies(lock):
    """Version-check the lock and hash actual installed files, including pyc."""
    dependencies = []
    entries = re.findall(
        r"^([A-Za-z0-9_-]+)==([^\s;]+)",
        read_bytes_stable(lock, MAX_JSON).decode("utf-8"),
        re.MULTILINE,
    )
    require(0 < len(entries) <= 128, "invalid_python_lock")
    canonical_names = [re.sub(r"[-_.]+", "-", name).lower()
                       for name, _version in entries]
    require(len(set(canonical_names)) == len(canonical_names),
            "duplicate_python_dependency")
    total_files = 0
    total_bytes = 0
    for name, version in entries:
        distribution = importlib.metadata.distribution(name)
        require(distribution.version == version, "installed_package_version_drift")
        files = distribution.files
        require(isinstance(files, (list, tuple)) and 0 < len(files)
                and total_files + len(files) <= MAX_NODE_ENTRIES,
                "python_package_file_limit")
        actual = []
        observed_names = set()
        for item in files:
            try:
                item_name = str(item)
                location = Path(distribution.locate_file(item))
                encoded_name = item_name.encode("utf-8")
            except (OSError, TypeError, UnicodeError, ValueError):
                raise ValueError("invalid_python_package_file") from None
            require(0 < len(encoded_name) <= 4096,
                    "invalid_python_package_file")
            require(item_name not in observed_names,
                    "duplicate_python_package_file")
            observed_names.add(item_name)
            require(location.is_file(), "missing_installed_package_file")
            details = digest_file(
                location, allow_empty=True,
                maximum=min(MAX_FILE, MAX_IDENTITY_TOTAL_BYTES - total_bytes))
            total_bytes += details["bytes"]
            total_files += 1
            actual.append((item_name, details))
        dependencies.append({"name": name, "version": version,
                             "sha256": digest_rows(actual), "files": len(actual)})
    return dependencies


def node_archive_files(archive, expected):
    """Verify npm SRI, then parse a bounded tar without extracting any paths."""
    require(not archive.is_symlink(), "node_archive_symlink")
    compressed = read_bytes_stable(archive, 8 * 1024 * 1024)
    require("sha512-" + base64.b64encode(hashlib.sha512(compressed).digest()).decode() == expected["integrity"],
            "node_archive_integrity")
    inflater = zlib.decompressobj(16 + zlib.MAX_WBITS)
    raw = inflater.decompress(compressed, 64 * 1024 * 1024 + 1)
    require(len(raw) <= 64 * 1024 * 1024 and inflater.eof
            and not inflater.unconsumed_tail and not inflater.unused_data, "node_archive_expansion_limit")
    files, count = {}, 0
    with tarfile.open(fileobj=io.BytesIO(raw), mode="r:") as package:
        for entry in package:
            count += 1
            parts = PurePosixPath(entry.name).parts
            require(count <= 20000 and len(entry.name.encode()) <= 512
                    and len(parts) >= 1 and parts[0] == "package" and not "\\" in entry.name
                    and all(part not in (".", "..") for part in parts), "unsafe_node_archive_path")
            require(entry.isdir() or entry.isfile(), "node_archive_special_entry")
            if entry.isfile():
                name = "/".join(parts[1:])
                require(name and name not in files and 0 <= entry.size <= 8 * 1024 * 1024, "invalid_node_archive_file")
                source = package.extractfile(entry)
                require(source is not None, "missing_node_archive_file")
                with source:
                    content = source.read(entry.size + 1)
                require(len(content) == entry.size, "truncated_node_archive_file")
                files[name] = {"bytes": entry.size, "sha256": hashlib.sha256(content).hexdigest()}
    require(files, "empty_node_archive")
    return files


def node_dependency_inventory(package, maximum_entries=MAX_NODE_ENTRIES,
                              maximum_bytes=64 * 1024 * 1024):
    """List one installed package with global entry, depth and path bounds."""
    require(type(maximum_entries) is int and 0 < maximum_entries <= MAX_NODE_ENTRIES
            and type(maximum_bytes) is int and 0 <= maximum_bytes <= 64 * 1024 * 1024,
            "invalid_node_dependency_limit")
    package = _plain_directory(package)
    directories = set()
    files = []
    entries = 0
    total_bytes = 0
    directory_identities = {}
    pending = [package]
    while pending:
        current = pending.pop()
        try:
            relative_directory = current.relative_to(package)
            metadata = os.lstat(current)
        except (OSError, ValueError):
            raise ValueError("node_dependency_walk_failed") from None
        require(stat.S_ISDIR(metadata.st_mode) and not stat.S_ISLNK(metadata.st_mode)
                and not _has_reparse_point(metadata), "node_dependency_symlink")
        directory_name = relative_directory.as_posix() or "."
        try:
            encoded_directory = directory_name.encode("utf-8")
        except UnicodeError:
            raise ValueError("node_dependency_path_limit") from None
        require(len(relative_directory.parts) <= MAX_NODE_DEPTH
                and len(encoded_directory) <= MAX_NODE_PATH_BYTES,
                "node_dependency_path_limit")
        directories.add(directory_name)
        directory_identities[current] = _file_identity(metadata)
        children = []
        names = set()
        try:
            with os.scandir(current) as scanned:
                for child in scanned:
                    entries += 1
                    require(entries <= maximum_entries,
                            "node_dependency_inventory_limit")
                    require(child.name not in names,
                            "duplicate_node_dependency_entry")
                    names.add(child.name)
                    path = current / child.name
                    relative = path.relative_to(package)
                    try:
                        encoded = relative.as_posix().encode("utf-8")
                    except UnicodeError:
                        raise ValueError("node_dependency_path_limit") from None
                    require(len(relative.parts) <= MAX_NODE_DEPTH
                            and 0 < len(encoded) <= MAX_NODE_PATH_BYTES,
                            "node_dependency_path_limit")
                    child_metadata = os.lstat(path)
                    require(not stat.S_ISLNK(child_metadata.st_mode)
                            and not _has_reparse_point(child_metadata),
                            "node_dependency_symlink")
                    if stat.S_ISDIR(child_metadata.st_mode):
                        children.append(path)
                    else:
                        require(stat.S_ISREG(child_metadata.st_mode),
                                "node_dependency_special_file")
                        require(child_metadata.st_nlink == 1,
                                "node_dependency_hardlink")
                        observed = digest_file(
                            path, allow_empty=True, require_single_link=True,
                            maximum=maximum_bytes - total_bytes)
                        total_bytes += observed["bytes"]
                        files.append((relative.as_posix(), observed))
        except ValueError:
            raise
        except OSError:
            raise ValueError("node_dependency_walk_failed") from None
        pending.extend(reversed(sorted(children, key=os.fspath)))
    for directory, identity in directory_identities.items():
        try:
            current = os.lstat(directory)
        except OSError:
            raise ValueError("node_dependency_walk_changed") from None
        require(stat.S_ISDIR(current.st_mode)
                and not stat.S_ISLNK(current.st_mode)
                and not _has_reparse_point(current)
                and _file_identity(current) == identity,
                "node_dependency_walk_changed")
    _plain_directory(package)
    require(entries == len(directories) - 1 + len(files),
            "node_dependency_walk_changed")
    return directories, files, entries, total_bytes


def prepare_node_archives(root):
    peer = next(item for item in read_json(root / "standards/interop-profile.json")["peers"]
                if item["id"] == "ohttp-typescript")
    lock = root / peer["lock"]
    require(digest_file(lock)["sha256"] == peer["lock_sha256"], "dependency_lock_drift")
    archives = root / peer["installation"] / "archives"
    archives.mkdir(parents=True, exist_ok=True)
    require(not archives.is_symlink() and archives.resolve().is_relative_to(root.resolve())
            and archives.resolve().is_relative_to((root / "build").resolve()), "node_archive_location")
    entries = read_json(lock)["packages"]
    require(1 < len(entries) <= 129, "invalid_node_package_count")
    deadline = time.monotonic() + 90
    for path, expected in sorted(entries.items()):
        if path == "":
            continue
        require(re.fullmatch(r"node_modules/[a-z0-9][a-z0-9._-]{0,100}", path), "unsupported_node_dependency_path")
        name, version = path.removeprefix("node_modules/"), expected["version"]
        require(re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+", version), "invalid_node_dependency_version")
        url = f"https://registry.npmjs.org/{name}/-/{name}-{version}.tgz"
        require(expected["resolved"] == url and time.monotonic() < deadline, "node_archive_source")
        destination = archives / f"{name}-{version}.tgz"
        if not destination.exists():
            class NoRedirect(urllib.request.HTTPRedirectHandler):
                def redirect_request(self, *args, **kwargs):
                    raise ValueError("node_archive_redirect")
            opener = urllib.request.build_opener(NoRedirect)
            with opener.open(url, timeout=min(20, deadline-time.monotonic())) as response:
                require(response.geturl() == url and response.status == 200, "node_archive_redirect")
                data = response.read(8 * 1024 * 1024 + 1)
            require(len(data) <= 8 * 1024 * 1024 and time.monotonic() < deadline, "node_archive_limit")
            require("sha512-" + base64.b64encode(hashlib.sha512(data).digest()).decode() == expected["integrity"],
                    "node_archive_integrity")
            with destination.open("xb") as output:
                output.write(data)
        node_archive_files(destination, expected)


def node_identity(root, peer, selected, command):
    """Hash the exact isolated Node interpreter's installed, locked JS closure."""
    require(not os.environ.get("NODE_OPTIONS") and not os.environ.get("NODE_PATH"),
            "node_environment_override")
    flags = ["--disable-proto=throw", "--no-addons", "--no-global-search-paths"]
    require(len(command) >= 5 and command[1:4] == flags, "node_not_isolated")
    runtime_version = probe([selected, *flags, "--version"]).strip()
    require(runtime_version == peer["node_version"], "node_version_drift")
    installation = root / peer["installation"]
    require(installation.is_relative_to(root / "build") and not installation.is_symlink(),
            "node_installation_outside_build")
    installation = installation.resolve(strict=True)
    require(installation.is_relative_to((root / "build").resolve()), "node_installation_outside_build")
    source = root / peer["fixture"]
    fixture = installation / source.name
    require(not source.is_symlink() and not fixture.is_symlink()
            and source.resolve(strict=True).is_relative_to(root.resolve())
            and Path(command[4]).resolve(strict=True) == fixture.resolve(strict=True)
            and digest_file(source) == digest_file(fixture), "stale_node_fixture")
    lock = root / peer["lock"]
    require(digest_file(lock) == digest_file(installation / "package-lock.json"), "stale_node_lock")
    locked = read_json(lock)
    require(locked.get("lockfileVersion") == 3 and isinstance(locked.get("packages"), dict), "invalid_node_lock")
    entries = locked["packages"]
    require("" in entries and 1 < len(entries) <= 129, "invalid_node_package_count")
    modules = installation / "node_modules"
    require(not modules.is_symlink(), "node_dependency_symlink")
    names, dependencies, total_bytes, total_entries = set(), [], 0, 0
    for relative, expected in sorted(entries.items()):
        if relative == "":
            continue
        require(re.fullmatch(r"node_modules/[a-z0-9][a-z0-9._-]{0,100}", relative) is not None,
                "unsupported_node_dependency_path")
        name = relative.removeprefix("node_modules/")
        names.add(name)
        version = expected.get("version")
        require(isinstance(version, str) and re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+", version), "invalid_node_dependency_version")
        require(expected.get("resolved") == f"https://registry.npmjs.org/{name}/-/{name}-{version}.tgz"
                and re.fullmatch(r"sha512-[A-Za-z0-9+/]{86}==", expected.get("integrity", ""))
                and not expected.get("link"), "unlocked_node_dependency")
        package = installation / relative
        require(not package.is_symlink(), "node_dependency_symlink")
        metadata = read_json(package / "package.json")
        require(metadata.get("name") == name and metadata.get("version") == version,
                "installed_package_version_drift")
        pristine = node_archive_files(installation / "archives" / f"{name}-{version}.tgz", expected)
        remaining_entries = MAX_NODE_ENTRIES - total_entries
        require(remaining_entries > 0, "node_dependency_inventory_limit")
        observed_directories, installed_files, package_entries, package_bytes = \
            node_dependency_inventory(
                package, remaining_entries,
                64 * 1024 * 1024 - total_bytes)
        total_bytes += package_bytes
        total_entries += package_entries
        expected_directories = {"."}
        for relative_file in pristine:
            parent = PurePosixPath(relative_file).parent
            while str(parent) != ".":
                expected_directories.add(parent.as_posix())
                parent = parent.parent
        require(observed_directories == expected_directories,
                "node_package_content_drift")
        actual = []
        for relative_file, observed in installed_files:
            require(pristine.get(relative_file) == observed,
                    "node_package_content_drift")
            actual.append((relative_file, observed))
        require(set(pristine) == {name for name, _ in actual}, "node_package_content_drift")
        dependencies.append({"name": name, "version": version,
                             "sha256": digest_rows(actual), "files": len(actual)})
    observed = set(item.name for item in modules.iterdir()) - {".package-lock.json"}
    require(observed == names, "unlocked_installed_node_package")
    require(any(item["name"] + "@" + item["version"] == peer["pin"] for item in dependencies), "node_package_version_drift")
    return {"version": runtime_version, "lock_sha256": digest_file(lock)["sha256"],
            "fixture_sha256": digest_file(fixture)["sha256"], "dependencies": dependencies}


def rust_identity(root, peer, output):
    """Check identity emitted from the compiled, test-only upstream entrypoint."""
    import tomllib
    require(len(output.encode()) <= 1024 * 1024, "oversized_rust_identity")
    version, metadata_text, embedded_lock = output.split("\n", 2)
    metadata = decode_json(metadata_text)
    fields = {"schema", "source_commit", "source_sha256", "source_files", "lock_sha256",
        "patch_sha256", "rust_version", "rustc_sha256", "rustc_driver_sha256",
        "cargo_sha256", "native_tools"}
    require(isinstance(metadata, dict) and set(metadata) == fields, "invalid_rust_identity_fields")
    require(metadata["schema"] == 1 and metadata["source_commit"] == peer["source_commit"],
            "wrong_rust_source_revision")
    require(re.fullmatch(r"[0-9a-f]{40}", metadata["source_commit"]) is not None,
            "invalid_rust_source_revision")
    for field in fields - {"schema", "source_commit", "source_files", "rust_version", "native_tools"}:
        require(isinstance(metadata[field], str) and re.fullmatch(r"[0-9a-f]{64}", metadata[field]) is not None,
                "invalid_rust_digest")
    require(type(metadata["source_files"]) is int and 0 < metadata["source_files"] <= 20000,
            "invalid_rust_source_count")
    require("quiche@" + version == peer["pin"], "wrong_compiled_quiche_version")
    require(metadata["rust_version"] == peer["rust_version"], "wrong_rust_compiler_version")
    lock_sha = digest_file(root / peer["lock"])["sha256"]
    require(lock_sha == peer["lock_sha256"] == metadata["lock_sha256"]
            == hashlib.sha256(embedded_lock.encode()).hexdigest(), "stale_embedded_rust_lock")
    require(metadata["patch_sha256"] == digest_file(root / peer["identity_patch"])["sha256"],
            "stale_compiled_identity_patch")
    packages = tomllib.loads(embedded_lock).get("package", [])
    require([item["version"] for item in packages if item["name"] == "quiche"] == [version],
            "quiche_version_not_locked")
    native_tools = metadata["native_tools"]
    names = ["cc", "c++", "clang", "cmake", "make", "ar", "ld"]
    require(isinstance(native_tools, list) and len(native_tools) == len(names), "invalid_native_build_tools")
    require([item.get("name") for item in native_tools] == names, "wrong_native_build_tools")
    for item in native_tools:
        require(set(item) == {"name", "sha256"} and isinstance(item["sha256"], str)
                and re.fullmatch(r"[0-9a-f]{64}", item["sha256"]) is not None, "invalid_native_build_tool")
    def dependency(name, item_version, digest, count=1):
        return {"name": name, "version": item_version, "sha256": digest, "files": count}
    return {"version": "rustc " + metadata["rust_version"], "lock_sha256": lock_sha,
        "fixture_sha256": metadata["patch_sha256"],
        "dependencies": [
            dependency("quiche", version, metadata["source_sha256"], metadata["source_files"]),
            dependency("quiche-source-revision", "git", hashlib.sha256(metadata["source_commit"].encode()).hexdigest(), 0),
            dependency("cargo-lock", "locked", lock_sha),
            dependency("rustc", metadata["rust_version"], metadata["rustc_sha256"]),
            dependency("rustc-driver", metadata["rust_version"], metadata["rustc_driver_sha256"]),
            dependency("cargo", metadata["rust_version"], metadata["cargo_sha256"])
        ] + [dependency("build-" + item["name"], "binary", item["sha256"]) for item in native_tools]}


def native_identity(root, peer, output):
    """Verify compiled native provenance and the two loaded library versions."""
    require(len(output.encode()) <= 1048576, "oversized_native_identity")
    versions, metadata_text = output.split("\n", 1)
    metadata = decode_json(metadata_text)
    fields = {"schema", "role", "compiler_version", "lock_sha256", "patch_sha256",
              "recipe_sha256", "sources", "native_tools"}
    require(isinstance(metadata, dict) and set(metadata) == fields, "invalid_native_identity_fields")
    require(metadata["schema"] == 1 and metadata["role"] in ("client", "server"), "invalid_native_role")
    require(metadata["compiler_version"] == peer["compiler_version"], "native_compiler_drift")
    for field in ("lock_sha256", "patch_sha256", "recipe_sha256"):
        require(isinstance(metadata[field], str) and re.fullmatch(r"[0-9a-f]{64}", metadata[field]),
                "invalid_native_digest")
    lock_sha = digest_file(root / peer["lock"])["sha256"]
    require(lock_sha == peer["lock_sha256"] == metadata["lock_sha256"], "stale_native_lock")
    require(metadata["patch_sha256"] == digest_file(root / peer["identity_patch"])["sha256"],
            "stale_native_patch")
    require(metadata["recipe_sha256"] == digest_file(root / peer["build_recipe"])["sha256"],
            "stale_native_recipe")
    lock = read_json(root / peer["lock"])
    require(lock["schema"] == 1 and lock["compiler_version"] == peer["compiler_version"],
            "invalid_native_lock")
    sources = metadata["sources"]
    require(isinstance(sources, list) and len(sources) == len(lock["sources"]) == 3,
            "missing_native_source")
    dependencies = []
    for observed, expected in zip(sources, lock["sources"]):
        require(isinstance(observed, dict) and set(observed) ==
                {"name", "version", "archive_sha256", "sha256", "files"}, "invalid_native_source_fields")
        require((observed["name"], observed["version"], observed["archive_sha256"]) ==
                (expected["name"], expected["version"], expected["sha256"]), "native_source_drift")
        require(isinstance(observed["sha256"], str) and re.fullmatch(r"[0-9a-f]{64}", observed["sha256"])
                and type(observed["files"]) is int and 0 < observed["files"] <= 20000, "invalid_native_source_digest")
        dependencies.append({key: observed[key] for key in ("name", "version", "sha256", "files")})
        dependencies.append({"name": observed["name"] + "-archive", "version": observed["version"],
                             "sha256": observed["archive_sha256"], "files": 1})
    named = {item["name"]: item["version"] for item in sources}
    require(versions == named["ngtcp2"] + " " + named["nghttp3"]
            and peer["pin"] == "ngtcp2@" + named["ngtcp2"], "native_runtime_version_drift")
    tools = metadata["native_tools"]
    names = ["gcc", "g++", "cc1", "cc1plus", "as", "ld", "ar", "ranlib", "cmake", "make", "pkg-config", "patchelf"]
    require(isinstance(tools, list) and len(tools) == len(names), "missing_native_tool")
    for observed, expected in zip(tools, names):
        require(isinstance(observed, dict) and set(observed) == {"name", "sha256"}
                and observed["name"] == expected and isinstance(observed["sha256"], str)
                and re.fullmatch(r"[0-9a-f]{64}", observed["sha256"]), "invalid_native_tool")
        dependencies.append({"name": "build-" + expected, "version": "binary", "files": 1,
                             "sha256": observed["sha256"]})
    dependencies += [
        {"name": "source-lock", "version": "locked", "sha256": lock_sha, "files": 1},
        {"name": "build-recipe", "version": "locked", "sha256": metadata["recipe_sha256"], "files": 1},
        {"name": "peer-role", "version": metadata["role"], "files": 0,
         "sha256": hashlib.sha256(metadata["role"].encode()).hexdigest()}]
    return {"version": "gcc " + metadata["compiler_version"], "lock_sha256": lock_sha,
            "fixture_sha256": metadata["patch_sha256"], "dependencies": dependencies}


def identify(root, peer, command):
    path = executable(command[0])
    # Hash the resolved file, but invoke the selected path: resolving a venv's Python symlink before exec silently switches to the system environment.
    selected = str(Path(shutil.which(command[0])).absolute())
    kind = peer["identity_kind"]
    identity = {"kind": kind, "executable": digest_file(path),
                "version": "", "lock_sha256": None,
                "fixture_sha256": None, "dependencies": []}
    if kind == "curl":
        version = " ".join(probe([str(path), "--version"]).splitlines()[0].split()[:2])
        require(version == peer["pin"], "curl_version_drift")
        identity.update(version=version, dependencies=shared_libraries(path))
    elif kind == "nghttp2":
        observed = probe([str(path), "--version"]).strip()
        found = re.fullmatch(r"nghttpd? nghttp2/([0-9.]+)", observed)
        require(found is not None and "nghttp2 " + found.group(1) == peer["pin"],
                "nghttp2_version_drift")
        identity.update(version=peer["pin"], dependencies=shared_libraries(path))
    elif kind == "go":
        import interop_go_build
        info = probe(["go", "version", "-m", str(path)], env=interop_go_build.environment())
        require("=>" not in info, "replaced_go_dependency")
        require(info.splitlines()[0].split()[-1] == peer["go_version"],
                "go_compiler_version_drift")
        lock = root / peer["lock"]
        locked = set(read_bytes_stable(lock, MAX_JSON).decode("utf-8").splitlines())
        dependencies = []
        for line in info.splitlines():
            fields = line.split()
            if fields and fields[0] == "dep":
                require(len(fields) == 4 and " ".join(fields[1:]) in locked,
                        "go_dependency_not_locked")
                name, version, checksum = fields[1:]
                dependencies.append({"name": name, "version": version,
                                     "sha256": hashlib.sha256(checksum.encode()).hexdigest(),
                                     "files": 0})
        require(any(item["name"] + "@" + item["version"] == peer["pin"]
                    for item in dependencies), "go_version_drift")
        receipt = interop_go_build.verify(root, peer, path, info)
        require(identity["executable"] == receipt["binary"], "go_identity_binary_changed")
        libraries = shared_libraries(path, allow_static=True)
        require(not libraries, "unexpected_go_dynamic_runtime")
        identity.update(version=info.splitlines()[0].split()[-1],
                        lock_sha256=digest_file(lock)["sha256"],
                        fixture_sha256=interop_go_build.rows_digest(receipt["sources"]),
                        build=receipt,
                        dependencies=dependencies)
    elif kind == "rust":
        identity.update(rust_identity(root, peer, probe([str(path), "--http-interop-identity"])))
        identity["dependencies"] += shared_libraries(path, allow_static=True)
    elif kind == "native":
        identity.update(native_identity(root, peer, probe([str(path), "--http-interop-identity"])))
        identity["dependencies"] += shared_libraries(path)
    elif kind == "node":
        identity.update(node_identity(root, peer, selected, command))
        identity["dependencies"] += shared_libraries(path)
    elif kind == "browser":
        sys.path.insert(0, str(root / "test/interop/browser"))
        if peer["id"] == "firefox":
            from firefox_identity import identify as browser_identity
        else:
            from identity import identify as browser_identity
        identity.update(browser_identity(root, peer, selected, command))
    elif kind == "python":
        lock = root / peer["lock"]
        dependencies = decode_json(probe([selected, "-I", "-B", str(Path(__file__).resolve()),
                                        "--python-identity", str(lock)]))
        require(any(item["name"] + "==" + item["version"] == peer["pin"]
                    for item in dependencies), "python_version_drift")
        # The script itself is a source input, identified separately from the interpreter.
        require(len(command) >= 4 and command[1:3] == ["-I", "-B"], "python_not_isolated")
        fixture = Path(command[3]).resolve(strict=True)
        require(fixture.is_relative_to(root), "fixture_outside_source")
        identity.update(version=probe([selected, "--version"]).strip(),
                        lock_sha256=digest_file(lock)["sha256"],
                        fixture_sha256=digest_file(fixture)["sha256"],
                        dependencies=dependencies + shared_libraries(path))
    else:
        raise ValueError("unsupported_peer_identity")
    require(identity["lock_sha256"] == peer.get("lock_sha256"), "dependency_lock_drift")
    identity["dependencies"].sort(key=lambda entry: entry["name"])
    require(len(identity["dependencies"]) <= 128, "too_many_dependencies")
    return identity


def invocation_name(role, scenario):
    return hashlib.sha256((role + "\x00" + scenario).encode()).hexdigest() + ".json"


def publish_owned_listener(pid, transport="tcp"):
    """Discover port 0 from the owned Linux process, without a bind/close race."""
    require(transport in ("tcp", "udp"), "unsupported_listener_transport")
    try:
        descriptors = list((Path("/proc") / str(pid) / "fd").iterdir())
    except FileNotFoundError:
        return False
    require(len(descriptors) <= 128, "too_many_peer_descriptors")
    sockets = set()
    for descriptor in descriptors:
        try:
            target = os.readlink(descriptor)
        except FileNotFoundError:
            continue
        matched = re.fullmatch(r"socket:\[(\d+)\]", target)
        if matched:
            sockets.add(matched.group(1))
    try:
        with (Path("/proc") / str(pid) / ("net/" + transport)).open("rb") as table:
            data = table.read(65537)
    except FileNotFoundError:
        return False
    require(len(data) <= 65536, "oversized_peer_socket_table")
    ports = []
    for row in data.decode("ascii").splitlines()[1:]:
        fields = row.split()
        state = "0A" if transport == "tcp" else "07"
        if len(fields) >= 10 and fields[3] == state and fields[9] in sockets:
            address, port = fields[1].split(":")
            require(address == "0100007F", "peer_listener_not_loopback")
            ports.append(int(port, 16))
    require(len(ports) <= 1, "ambiguous_peer_listener")
    if ports:
        print("PORT=" + str(ports[0]), flush=True)
        return True
    return False


def control_matches(path, nonce):
    try:
        return read_bytes_stable(path, 64) == nonce.encode("ascii")
    except (FileNotFoundError, ValueError):
        return False


def write_json_atomic(destination, value):
    destination = _absolute_path(destination)
    parent = _plain_directory(destination.parent, create=True)
    encoded = (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode("utf-8")
    require(len(encoded) <= MAX_JSON, "oversized_peer_json")
    try:
        existing = os.lstat(destination)
    except FileNotFoundError:
        existing = None
    except OSError:
        raise ValueError("cannot_inspect_peer_json") from None
    if existing is not None:
        require(
            stat.S_ISREG(existing.st_mode)
            and not stat.S_ISLNK(existing.st_mode)
            and not _has_reparse_point(existing)
            and existing.st_nlink == 1,
            "unsafe_peer_json_destination",
        )
    temporary = parent / (destination.name + "." + secrets.token_hex(16) + ".pending")
    flags = (
        os.O_WRONLY
        | os.O_CREAT
        | os.O_EXCL
        | getattr(os, "O_BINARY", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )
    descriptor = None
    try:
        try:
            descriptor = os.open(temporary, flags, 0o600)
        except OSError:
            raise ValueError("cannot_create_peer_json") from None
        offset = 0
        while offset < len(encoded):
            written = os.write(descriptor, encoded[offset:])
            require(written > 0, "cannot_write_peer_json")
            offset += written
        os.fsync(descriptor)
        os.close(descriptor)
        descriptor = None
        require(read_bytes_stable(temporary) == encoded, "peer_json_changed")
        _plain_directory(parent)
        try:
            current = os.lstat(destination)
        except FileNotFoundError:
            current = None
        except OSError:
            raise ValueError("cannot_inspect_peer_json") from None
        if current is not None:
            require(
                stat.S_ISREG(current.st_mode)
                and not stat.S_ISLNK(current.st_mode)
                and not _has_reparse_point(current)
                and current.st_nlink == 1,
                "unsafe_peer_json_destination",
            )
        try:
            os.replace(temporary, destination)
        except OSError:
            raise ValueError("cannot_publish_peer_json") from None
        require(read_bytes_stable(destination) == encoded, "peer_json_changed")
        if hasattr(os, "O_DIRECTORY"):
            directory_descriptor = os.open(parent, os.O_RDONLY | os.O_DIRECTORY)
            try:
                os.fsync(directory_descriptor)
            finally:
                os.close(directory_descriptor)
        _plain_directory(parent)
    finally:
        if descriptor is not None:
            os.close(descriptor)
        try:
            os.unlink(temporary)
        except FileNotFoundError:
            pass
        except OSError:
            raise ValueError("cannot_remove_peer_json_temporary") from None


def run(args):
    root = _plain_directory(args.root)
    profile = read_json(root / "standards/interop-profile.json")
    peers = [peer for peer in profile["peers"] if peer["id"] == args.peer]
    require(len(peers) == 1, "unknown_peer")
    peer = peers[0]
    scenario = {"role": args.role, "scenario": args.scenario}
    require(scenario in peer["scenarios"], "unknown_scenario")
    path = root / "build/interop/peers" / (args.peer + ".json")
    report = read_json(path)
    require(report["status"] == "Running" and report["schema"] == 2, "peer_not_running")
    require(
        isinstance(args.run_id, str)
        and len(args.run_id) == 64
        and all(character in "0123456789abcdef" for character in args.run_id),
        "invalid_run_id",
    )
    require(report["run_id"] == args.run_id, "peer_run_changed")
    directory = root / "build/interop/invocations" / args.peer
    directory.mkdir(parents=True, exist_ok=True)
    destination = directory / invocation_name(args.role, args.scenario)
    destination.unlink(missing_ok=True)
    failure_path = root / "build/interop/failures" / args.peer / destination.name
    failure_path.unlink(missing_ok=True)
    require(args.command and args.command[0] == "--", "missing_command_separator")
    command = args.command[1:]
    daemon = args.peer in ("nghttp2-h2", "quiche-h3", "ngtcp2-nghttp3-h3") and args.role == "server"
    transport = "udp" if args.peer in ("quiche-h3", "ngtcp2-nghttp3-h3") else "tcp"
    control = root / "build/interop/control" / args.peer / invocation_name(args.role, args.scenario)
    if daemon:
        control.unlink(missing_ok=True)
    phase = "identity_before"
    completion = None
    try:
        before = identify(root, peer, command)
        phase = "execution"
        execution_env = None
        if peer["identity_kind"] == "go":
            import interop_go_build
            execution_env = interop_go_build.environment()
        browser_receipt = None
        if peer["identity_kind"] == "browser":
            require(args.peer in ("chromium", "firefox") and args.role == "client" and args.timeout == 65,
                    "invalid_browser_execution_scope")
            from execution import execute as browser_execute
            completion, browser_receipt = browser_execute(root, report, command, args.scenario)
        else:
            completion, _ = collect(command, args.timeout, relay=True,
                env=execution_env,
                stop_requested=(lambda: control_matches(control, report["run_id"])) if daemon else None,
                ready=(lambda pid: publish_owned_listener(pid, transport)) if daemon else None)
        phase = "identity_after"
        after = identify(root, peer, command)
        require(before == after, "peer_changed_during_execution")
        phase = "exit_validation"
        expected = 60 if args.peer in ("curl-h1-h2", "ngtcp2-nghttp3-h3") and args.scenario == "untrusted certificate refused" else 0
        if daemon:
            expected = -15
        require(completion["outcome"] == "completed" and completion["exit_status"] == expected,
                "peer_did_not_complete_scenario")
        require(completion["controlled_shutdown"] == daemon, "missing_daemon_completion_oracle")
        phase = "publication"
        require(read_json(path) == report, "peer_run_changed")
        invocation = dict(scenario, run_id=report["run_id"], source_sha256=report["source_sha256"],
                          identity=before, completion=completion)
        if browser_receipt is not None:
            invocation["browser"] = browser_receipt
            write_json_atomic(root / "build/interop/browser" / args.peer / destination.name, browser_receipt)
        write_json_atomic(destination, invocation)
    except BaseException as error:
        # Failed runs still explain where progress stopped.
        # No exception text,
        # arguments, output contents or output hashes enter this safe artifact.
        try:
            failure = peer_failure_report(
                args.peer, report["run_id"], report["source_sha256"],
                args.role, args.scenario, phase, completion, error)
            write_json_atomic(failure_path, failure)
        except BaseException:
            # Evidence publication cannot replace the original termination.
            pass
        raise


def main():
    if len(sys.argv) == 3 and sys.argv[1] == "--prepare-node-archives":
        prepare_node_archives(_plain_directory(sys.argv[2]))
        return
    if len(sys.argv) == 3 and sys.argv[1] == "--python-identity":
        print(json.dumps(python_dependencies(sys.argv[2])))
        return
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", required=True)
    parser.add_argument("--peer", required=True)
    parser.add_argument("--run-id", required=True)
    parser.add_argument("--role", required=True)
    parser.add_argument("--scenario", required=True)
    parser.add_argument("--timeout", type=int, default=60)
    parser.add_argument("command", nargs=argparse.REMAINDER)
    run(parser.parse_args())


def cli():
    try:
        install_signal_handlers()
        main()
        return 0
    except BaseException as error:
        # Exceptions can contain endpoint-bearing arguments and host paths.
        status = command_exit_status(error)
        if status != 0:
            safe_failure_line()
        return status


if __name__ == "__main__":
    sys.exit(cli())

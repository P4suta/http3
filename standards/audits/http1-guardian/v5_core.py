#!/usr/bin/env python3
"""Bounded, secret-safe primitives for the HTTP/1 guardian release gate."""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import shutil
import stat
import subprocess
import sys
import tempfile
import threading
import time
import tomllib
import types
from typing import Any, Callable


MAX_SOURCE_BYTES = 4 * 1024 * 1024
MAX_TOOL_BYTES = 64 * 1024 * 1024
MAX_REPORT_BYTES = 1024 * 1024
MAX_PROCESS_OUTPUT_BYTES = 1024 * 1024
EXPECTED_PYTHON = "3.12.13"
CONTROL_EXCEPTIONS = (KeyboardInterrupt, SystemExit, GeneratorExit)


class AuditFailure(Exception):
    """A finite classification.  Its message must never contain input data."""

    def __init__(self, code: str) -> None:
        safe = (
            code
            if re.fullmatch(r"[a-z][a-z0-9_]{0,79}", code)
            else "validation_rejected"
        )
        self.code = safe
        super().__init__(safe)


@dataclass(frozen=True)
class Snapshot:
    data: bytes
    sha256: str
    identity: tuple[int, int, int, int, int, int]


@dataclass(frozen=True)
class ProcessResult:
    exit_code: int
    stdout: bytes
    stderr: bytes
    timed_out: bool
    output_exceeded: bool
    reaped: bool


@dataclass(frozen=True)
class RuntimeResolution:
    authority: dict[str, object]
    python_path: Path
    python_snapshot: Snapshot
    mise_path: Path
    mise_snapshot: Snapshot
    config_snapshot: Snapshot


def classify_failure(failure: BaseException) -> str:
    if isinstance(failure, AuditFailure):
        return failure.code
    if isinstance(failure, UnicodeError):
        return "encoding_rejected"
    if isinstance(failure, OSError):
        return "io_rejected"
    if isinstance(failure, (ValueError, TypeError, KeyError)):
        return "validation_rejected"
    return "internal_rejected"


def safe_failure(phase: str, classification: str) -> dict[str, object]:
    return {
        "schema": 5,
        "status": "Rejected",
        "classification": classification,
        "phase": phase,
        "completed": False,
    }


def _reparse(metadata: os.stat_result) -> bool:
    flag = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0)
    return bool(flag and getattr(metadata, "st_file_attributes", 0) & flag)


def _identity(metadata: os.stat_result) -> tuple[int, int, int, int, int, int]:
    return (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_size,
        metadata.st_mtime_ns,
        metadata.st_ctime_ns,
        metadata.st_nlink,
    )


def _handle_identity(metadata: os.stat_result) -> tuple[int, int, int, int, int]:
    # Windows exposes a different creation-time view through fstat.
    # The path ctime remains part of the before/after CAS identity; the open handle is bound with the fields that have identical path/handle semantics.
    return (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_size,
        metadata.st_mtime_ns,
        metadata.st_nlink,
    )


def validate_plain_directory(path: Path) -> None:
    metadata = os.lstat(path)
    if (
        stat.S_ISLNK(metadata.st_mode)
        or _reparse(metadata)
        or not stat.S_ISDIR(metadata.st_mode)
    ):
        raise AuditFailure("directory_identity_rejected")


def validate_plain_parents(path: Path, stop: Path | None = None) -> None:
    current = path.parent
    stop_absolute = Path(os.path.abspath(stop)) if stop is not None else None
    if stop_absolute is not None:
        try:
            if os.path.commonpath((str(current), str(stop_absolute))) != str(
                stop_absolute
            ):
                raise AuditFailure("parent_anchor_rejected")
        except ValueError:
            raise AuditFailure("parent_anchor_rejected") from None
    while True:
        validate_plain_directory(current)
        if stop_absolute is not None and current == stop_absolute:
            break
        parent = current.parent
        if parent == current:
            break
        current = parent


def read_snapshot(
    path: Path,
    maximum: int,
    *,
    require_single_link: bool = True,
    parent_anchor: Path | None = None,
) -> Snapshot:
    absolute = Path(os.path.abspath(path))
    validate_plain_parents(absolute, parent_anchor)
    before_path = os.lstat(absolute)
    if (
        stat.S_ISLNK(before_path.st_mode)
        or _reparse(before_path)
        or not stat.S_ISREG(before_path.st_mode)
    ):
        raise AuditFailure("file_identity_rejected")
    if require_single_link and before_path.st_nlink != 1:
        raise AuditFailure("hardlink_rejected")
    if before_path.st_size <= 0 or before_path.st_size > maximum:
        raise AuditFailure("file_size_rejected")
    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0)
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(absolute, flags)
    chunks: list[bytes] = []
    consumed = 0
    try:
        before_handle = os.fstat(descriptor)
        if _handle_identity(before_path) != _handle_identity(before_handle):
            raise AuditFailure("file_handle_identity_rejected")
        while True:
            chunk = os.read(descriptor, min(1024 * 1024, maximum - consumed + 1))
            if not chunk:
                break
            consumed += len(chunk)
            if consumed > maximum:
                raise AuditFailure("file_size_rejected")
            chunks.append(chunk)
        after_handle = os.fstat(descriptor)
    finally:
        os.close(descriptor)
    after_path = os.lstat(absolute)
    identity = _identity(before_path)
    if (
        identity != _identity(after_path)
        or _handle_identity(before_path) != _handle_identity(before_handle)
        or _handle_identity(before_handle) != _handle_identity(after_handle)
    ):
        raise AuditFailure("file_changed_during_read")
    data = b"".join(chunks)
    if len(data) != before_path.st_size:
        raise AuditFailure("partial_read_rejected")
    return Snapshot(data, hashlib.sha256(data).hexdigest(), identity)


def revalidate_snapshot(
    path: Path,
    expected: Snapshot,
    maximum: int,
    *,
    parent_anchor: Path | None = None,
) -> None:
    observed = read_snapshot(path, maximum, parent_anchor=parent_anchor)
    if observed.sha256 != expected.sha256 or observed.identity != expected.identity:
        raise AuditFailure("input_identity_changed")


def strict_json_bytes(data: bytes) -> object:
    def reject_duplicates(pairs: list[tuple[str, object]]) -> dict[str, object]:
        result: dict[str, object] = {}
        for key, value in pairs:
            if key in result:
                raise AuditFailure("duplicate_json_key")
            result[key] = value
        return result

    try:
        text = data.decode("utf-8", errors="strict")
        return json.loads(
            text,
            object_pairs_hook=reject_duplicates,
            parse_constant=lambda _value: (_ for _ in ()).throw(
                AuditFailure("nonfinite_json_number")
            ),
        )
    except CONTROL_EXCEPTIONS:
        raise
    except AuditFailure:
        raise
    except BaseException as failure:
        raise AuditFailure("json_rejected") from None


def exact_keys(value: object, expected: set[str], classification: str) -> dict[str, object]:
    if not isinstance(value, dict) or set(value) != expected:
        raise AuditFailure(classification)
    return value


def path_identity_hash(path: Path) -> str:
    normal = os.path.normcase(os.path.realpath(path))
    return hashlib.sha256(os.fsencode(normal)).hexdigest()


def evidence_is_secret_safe(value: object) -> bool:
    forbidden_keys = re.compile(
        r"(?:^|_)(?:pid|socket|endpoint|exception|traceback|absolute_path|"
        r"authorization|cookie|credential|password|secret)(?:_|$)",
        re.IGNORECASE,
    )
    forbidden_values = (
        re.compile(r"SYNTHETIC_(?:PRIVATE|SECRET)", re.IGNORECASE),
        re.compile(r"PRIVATE_PATH", re.IGNORECASE),
        # Reject absolute paths even when an unsafe value prefixes them with punctuation (for example ``detail=C:\\...``).
        # The earlier whitespace-only boundary left that representation unclassified.
        re.compile(r"[A-Za-z]:[\\/]"),
        re.compile(r"\\\\[^\\\s]+\\"),
        re.compile(r"(?:^|[=\s])/(?:[^/\s]+/)+"),
        re.compile(r"#PID<|<\d+\.\d+\.\d+>"),
        re.compile(
            r"(?:\b(?:[A-Za-z0-9.-]+|\d{1,3}(?:\.\d{1,3}){3})|"
            r"\[[0-9A-Fa-f:]+\]):\d{1,5}\b"
        ),
        re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----"),
        re.compile(r"\bBearer\s+[A-Za-z0-9._~+/-]+", re.IGNORECASE),
        re.compile(r"Traceback \(most recent call last\)"),
    )

    def visit(item: object) -> bool:
        if item is None or isinstance(item, (bool, int, float)):
            return True
        if isinstance(item, str):
            return len(item) <= MAX_REPORT_BYTES and not any(
                pattern.search(item) for pattern in forbidden_values
            )
        if isinstance(item, list):
            return len(item) <= 10000 and all(visit(child) for child in item)
        if isinstance(item, dict):
            if len(item) > 10000:
                return False
            return all(
                isinstance(key, str)
                and not forbidden_keys.search(key)
                and visit(key)
                and visit(child)
                for key, child in item.items()
            )
        return False

    return visit(value)


def encode_report(report: dict[str, object]) -> bytes:
    if not evidence_is_secret_safe(report):
        raise AuditFailure("evidence_secrecy_rejected")
    payload = (
        json.dumps(report, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
        + "\n"
    ).encode("utf-8")
    if len(payload) <= 0 or len(payload) > MAX_REPORT_BYTES:
        raise AuditFailure("report_size_rejected")
    return payload


def create_immutable(
    path: Path, payload: bytes, maximum: int = MAX_REPORT_BYTES
) -> Snapshot:
    if len(payload) <= 0 or len(payload) > maximum:
        raise AuditFailure("report_size_rejected")
    absolute = Path(os.path.abspath(path))
    absolute.parent.mkdir(parents=True, exist_ok=True)
    validate_plain_parents(absolute)
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0)
    descriptor = os.open(absolute, flags, 0o600)
    try:
        view = memoryview(payload)
        written = 0
        while written < len(payload):
            count = os.write(descriptor, view[written:])
            if count <= 0:
                raise AuditFailure("report_write_rejected")
            written += count
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    observed = read_snapshot(absolute, maximum)
    if observed.data != payload:
        raise AuditFailure("report_readback_rejected")
    try:
        os.chmod(absolute, stat.S_IREAD)
    except OSError:
        raise AuditFailure("report_immutability_rejected") from None
    final = read_snapshot(absolute, maximum)
    if final.data != payload or final.sha256 != observed.sha256:
        raise AuditFailure("report_post_chmod_rejected")
    return final


def atomic_pointer(path: Path, payload: bytes) -> Snapshot:
    absolute = Path(os.path.abspath(path))
    absolute.parent.mkdir(parents=True, exist_ok=True)
    validate_plain_parents(absolute)
    if absolute.exists():
        metadata = os.lstat(absolute)
        if stat.S_ISLNK(metadata.st_mode) or _reparse(metadata):
            raise AuditFailure("pointer_identity_rejected")
        try:
            os.chmod(absolute, stat.S_IWRITE | stat.S_IREAD)
        except OSError:
            raise AuditFailure("pointer_permission_rejected") from None
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=".http1-guardian-pointer-", suffix=".tmp", dir=absolute.parent
    )
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, absolute)
        observed = read_snapshot(absolute, MAX_REPORT_BYTES)
        if observed.data != payload:
            raise AuditFailure("pointer_readback_rejected")
        return observed
    finally:
        try:
            temporary.unlink(missing_ok=True)
        except OSError:
            pass


def load_snapshot_module(
    snapshot: Snapshot,
    name: str,
    source_path: Path,
    *,
    logical_file: Path | None = None,
) -> object:
    synthetic_name = "<tracked:" + name + ":" + snapshot.sha256[:16] + ">"
    try:
        code = compile(snapshot.data, synthetic_name, "exec", dont_inherit=True)
        module = types.ModuleType(name)
        module.__file__ = str(logical_file if logical_file is not None else source_path)
        module.__package__ = ""
        sys.modules[name] = module
        exec(code, module.__dict__, module.__dict__)
    except CONTROL_EXCEPTIONS:
        raise
    except BaseException:
        raise AuditFailure("module_execution_rejected") from None
    revalidate_snapshot(source_path, snapshot, MAX_SOURCE_BYTES)
    return module


def _kill_owned_tree(process: subprocess.Popen[bytes]) -> None:
    if process.poll() is not None:
        return
    if os.name == "nt":
        creationflags = getattr(subprocess, "CREATE_NO_WINDOW", 0)
        try:
            killer = subprocess.Popen(
                ["taskkill", "/PID", str(process.pid), "/T", "/F"],
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                creationflags=creationflags,
            )
            try:
                killer.wait(timeout=5)
            except subprocess.TimeoutExpired:
                killer.kill()
                killer.wait(timeout=2)
            if killer.returncode != 0 and process.poll() is None:
                process.kill()
        except OSError:
            process.kill()
    else:
        try:
            os.killpg(process.pid, 9)
        except (OSError, ProcessLookupError):
            process.kill()


def run_bounded(
    arguments: list[str],
    *,
    cwd: Path,
    environment: dict[str, str],
    absolute_deadline: float,
    output_limit: int = MAX_PROCESS_OUTPUT_BYTES,
) -> ProcessResult:
    if not arguments or output_limit <= 0:
        raise AuditFailure("process_contract_rejected")
    if time.monotonic() >= absolute_deadline:
        raise AuditFailure("process_deadline_expired")
    creationflags = 0
    start_new_session = False
    startupinfo = None
    if os.name == "nt":
        creationflags = (
            getattr(subprocess, "CREATE_NO_WINDOW", 0)
            | getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0)
        )
        startupinfo = subprocess.STARTUPINFO()
        startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW
        startupinfo.wShowWindow = 0
    else:
        start_new_session = True
    try:
        process = subprocess.Popen(
            arguments,
            cwd=cwd,
            env=environment,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            creationflags=creationflags,
            startupinfo=startupinfo,
            start_new_session=start_new_session,
        )
    except OSError:
        raise AuditFailure("process_start_rejected") from None
    assert process.stdout is not None and process.stderr is not None
    outputs: list[bytearray] = [bytearray(), bytearray()]
    exceeded = threading.Event()
    output_lock = threading.Lock()
    total_output = 0

    def drain(stream: Any, destination: bytearray) -> None:
        nonlocal total_output
        try:
            while True:
                chunk = stream.read(65536)
                if not chunk:
                    break
                with output_lock:
                    room = max(0, output_limit + 1 - total_output)
                    if room:
                        accepted = chunk[:room]
                        destination.extend(accepted)
                        total_output += len(accepted)
                    if total_output > output_limit or len(chunk) > room:
                        exceeded.set()
        except BaseException:
            exceeded.set()

    readers = [
        threading.Thread(target=drain, args=(process.stdout, outputs[0]), daemon=True),
        threading.Thread(target=drain, args=(process.stderr, outputs[1]), daemon=True),
    ]
    for reader in readers:
        reader.start()
    timed_out = False
    while process.poll() is None:
        if exceeded.is_set():
            _kill_owned_tree(process)
            break
        if time.monotonic() >= absolute_deadline:
            timed_out = True
            _kill_owned_tree(process)
            break
        time.sleep(0.01)
    try:
        process.wait(timeout=5)
    except subprocess.TimeoutExpired:
        _kill_owned_tree(process)
        try:
            process.wait(timeout=2)
        except subprocess.TimeoutExpired:
            try:
                process.kill()
                process.wait(timeout=2)
            except (OSError, subprocess.TimeoutExpired):
                raise AuditFailure("owned_process_unreaped") from None
    for reader in readers:
        reader.join(timeout=2)
    reaped = process.poll() is not None and all(not reader.is_alive() for reader in readers)
    return ProcessResult(
        process.returncode if process.returncode is not None else -1,
        bytes(outputs[0][:output_limit]),
        bytes(outputs[1][:output_limit]),
        timed_out,
        exceeded.is_set(),
        reaped,
    )


def resolve_runtime_authority(
    root: Path,
    launcher_sha256: str,
    absolute_deadline: float,
) -> RuntimeResolution:
    config_path = root / ".mise.toml"
    config = read_snapshot(config_path, MAX_SOURCE_BYTES, parent_anchor=root)
    parsed = tomllib.loads(config.data.decode("utf-8", errors="strict"))
    tools = parsed.get("tools") if isinstance(parsed, dict) else None
    if not isinstance(tools, dict) or tools.get("python") != EXPECTED_PYTHON:
        raise AuditFailure("configured_runtime_rejected")
    # Environment-selected executables are caller-controlled evidence.
    # Resolve the configured tool through the process PATH, then snapshot and revalidate that exact executable before accepting its result.
    mise_name = shutil.which("mise")
    if not mise_name:
        raise AuditFailure("mise_resolution_rejected")
    mise_path = Path(mise_name)
    mise = read_snapshot(mise_path, MAX_TOOL_BYTES)
    environment = dict(os.environ)
    resolved = run_bounded(
        [str(mise_path), "which", "python@" + EXPECTED_PYTHON],
        cwd=root,
        environment=environment,
        absolute_deadline=absolute_deadline,
        output_limit=4096,
    )
    if (
        resolved.exit_code != 0
        or resolved.timed_out
        or resolved.output_exceeded
        or not resolved.reaped
        or resolved.stderr
    ):
        raise AuditFailure("mise_runtime_resolution_rejected")
    lines = resolved.stdout.decode("utf-8", errors="strict").splitlines()
    if len(lines) != 1 or not lines[0].strip():
        raise AuditFailure("mise_runtime_resolution_rejected")
    python_path = Path(lines[0].strip())
    if not python_path.is_absolute():
        raise AuditFailure("mise_runtime_resolution_rejected")
    python = read_snapshot(python_path, MAX_TOOL_BYTES)
    probe_source = (
        "import json,platform,sys;"
        "print(json.dumps({'implementation':sys.implementation.name,"
        "'version':platform.python_version(),'os':platform.system(),"
        "'arch':platform.machine()},sort_keys=True,separators=(',',':')))"
    )
    probe = run_bounded(
        [str(python_path), "-I", "-B", "-c", probe_source],
        cwd=root,
        environment=environment,
        absolute_deadline=absolute_deadline,
        output_limit=4096,
    )
    if (
        probe.exit_code != 0
        or probe.timed_out
        or probe.output_exceeded
        or not probe.reaped
        or probe.stderr
    ):
        raise AuditFailure("runtime_probe_rejected")
    observed = exact_keys(
        strict_json_bytes(probe.stdout),
        {"implementation", "version", "os", "arch"},
        "runtime_probe_schema_rejected",
    )
    current = read_snapshot(Path(sys.executable), MAX_TOOL_BYTES)
    if (
        observed.get("implementation") != "cpython"
        or observed.get("version") != EXPECTED_PYTHON
        or observed.get("os") != platform.system()
        or observed.get("arch") != platform.machine()
        or python.sha256 != current.sha256
        or not os.path.samefile(python_path, Path(sys.executable))
    ):
        raise AuditFailure("runtime_identity_rejected")
    revalidate_snapshot(config_path, config, MAX_SOURCE_BYTES, parent_anchor=root)
    revalidate_snapshot(mise_path, mise, MAX_TOOL_BYTES)
    revalidate_snapshot(python_path, python, MAX_TOOL_BYTES)
    authority: dict[str, object] = {
        "schema": 1,
        "tool_request": "python@3.12.13",
        "implementation": observed["implementation"],
        "version": observed["version"],
        "os": observed["os"],
        "arch": observed["arch"],
        "python_sha256": python.sha256,
        "python_path_identity_sha256": path_identity_hash(python_path),
        "mise_sha256": mise.sha256,
        "mise_path_identity_sha256": path_identity_hash(mise_path),
        "config_sha256": config.sha256,
        "launcher_sha256": launcher_sha256,
        "resolved": True,
    }
    return RuntimeResolution(
        authority,
        python_path,
        python,
        mise_path,
        mise,
        config,
    )


RUNTIME_AUTHORITY_KEYS = {
    "schema",
    "tool_request",
    "implementation",
    "version",
    "os",
    "arch",
    "python_sha256",
    "python_path_identity_sha256",
    "mise_sha256",
    "mise_path_identity_sha256",
    "config_sha256",
    "launcher_sha256",
    "resolved",
}


def validate_runtime_authority(
    authority: object,
    *,
    root: Path,
    launcher_sha256: str,
) -> dict[str, object]:
    value = exact_keys(
        authority, RUNTIME_AUTHORITY_KEYS, "runtime_authority_schema_rejected"
    )
    current_python = read_snapshot(Path(sys.executable), MAX_TOOL_BYTES)
    current_config = read_snapshot(
        root / ".mise.toml", MAX_SOURCE_BYTES, parent_anchor=root
    )
    try:
        parsed = tomllib.loads(current_config.data.decode("utf-8", errors="strict"))
    except (UnicodeError, tomllib.TOMLDecodeError):
        raise AuditFailure("configured_runtime_rejected") from None
    tools = parsed.get("tools") if isinstance(parsed, dict) else None
    mise_name = shutil.which("mise")
    if not isinstance(tools, dict) or tools.get("python") != EXPECTED_PYTHON or not mise_name:
        raise AuditFailure("configured_runtime_rejected")
    current_mise = read_snapshot(Path(mise_name), MAX_TOOL_BYTES)
    valid = (
        value.get("schema") == 1
        and value.get("tool_request") == "python@3.12.13"
        and value.get("implementation") == sys.implementation.name == "cpython"
        and value.get("version") == platform.python_version() == EXPECTED_PYTHON
        and value.get("os") == platform.system()
        and value.get("arch") == platform.machine()
        and value.get("python_sha256") == current_python.sha256
        and value.get("python_path_identity_sha256")
        == path_identity_hash(Path(sys.executable))
        and value.get("mise_sha256") == current_mise.sha256
        and value.get("mise_path_identity_sha256")
        == path_identity_hash(Path(mise_name))
        and value.get("config_sha256") == current_config.sha256
        and value.get("launcher_sha256") == launcher_sha256
        and value.get("resolved") is True
    )
    if not valid:
        raise AuditFailure("runtime_authority_rejected")
    return value


def cli_boundary(action: Callable[[], int], phase: str) -> int:
    try:
        return action()
    except CONTROL_EXCEPTIONS:
        raise
    except BaseException as failure:
        report = safe_failure(phase, classify_failure(failure))
        try:
            payload = encode_report(report)
            sys.stdout.buffer.write(payload)
            sys.stdout.buffer.flush()
        except BaseException:
            pass
        return 2

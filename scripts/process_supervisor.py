#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 the http contributors
# SPDX-License-Identifier: MIT OR Apache-2.0
"""Bounded native-process-tree supervisor used by Erlang qualification tools.

The stdout/stdin protocol is packet-4 framed.  It exposes only a fixed runtime
identity, child output frames, and a finite final lifecycle attestation.  Raw
exceptions, argv, environment values, paths, process ids, and handles are never
reported.
"""

from __future__ import annotations

import errno
import hashlib
import io
import os
import platform
import signal
import stat
import struct
import subprocess
import sys
import tempfile
import threading
import time
from pathlib import Path
from typing import BinaryIO, Callable, Sequence


MAX_FRAME_BYTES = 65_537
MAX_CONTROL_BYTES = 16
MAX_DURATION_MILLISECONDS = 5_400_000
MAX_OUTPUT_BYTES = 16_777_216
WINDOWS_CREATE_SUSPENDED = 0x00000004
TREE_JOIN_SECONDS = 5.0
OWNED_RUN_POLL_SECONDS = 0.005
OWNED_RUN_CLOSE_RESERVE_SECONDS = 0.25
OWNED_RUN_CHUNK_BYTES = 65_536
WRITE_LOCK = threading.Lock()
CONTROL_IDLE = object()
CONTROL_BUFFER = bytearray()
START_ACCEPTED = False


def suppress_thread_exception(_arguments: threading.ExceptHookArgs) -> None:
    """Prevent worker tracebacks from exposing paths or exception values."""


threading.excepthook = suppress_thread_exception


class SupervisorFailure(Exception):
    """Internal fixed-category failure; its value is never rendered."""

    def __init__(self, code: str = "supervisor_failure") -> None:
        allowed = {
            "child_start_failed",
            "child_wait_failed",
            "child_abnormal_exit",
            "child_access_denied",
            "child_access_violation",
            "child_assertion_failure",
            "child_controlled_interrupt",
            "child_dependency_missing",
            "child_entrypoint_missing",
            "child_fast_fail",
            "child_fatal_application_exit",
            "child_heap_corruption",
            "child_illegal_instruction",
            "child_initialization_failed",
            "child_invalid_handle",
            "child_invalid_crt_parameter",
            "child_invalid_image",
            "child_invalid_parameter",
            "child_no_memory",
            "child_runtime_abort",
            "child_stack_overflow",
            "group_query_failed",
            "group_termination_failed",
            "job_assign_failed",
            "job_create_failed",
            "job_query_failed",
            "job_resume_failed",
            "job_set_limits_failed",
            "job_termination_failed",
            "console_attribute_failed",
            "console_child_start_failed",
             "console_create_failed",
             "console_output_join_failed",
             "console_output_setup_failed",
             "console_pipe_failed",
             "console_prestart_cleanup_failed",
             "console_prestart_setup_failed",
             "console_isolation_unconfirmed",
             "prestart_reap_unconfirmed",
             "group_reap_unconfirmed",
            "protocol_failure",
            "python_identity_failed",
            "source_identity_failed",
            "supervisor_deadline",
            "supervisor_output_limit",
        }
        self.code = code if code in allowed else "supervisor_failure"
        super().__init__(self.code)


def write_packet(payload: bytes) -> None:
    if len(payload) > MAX_FRAME_BYTES:
        raise SupervisorFailure("protocol_failure")
    encoded = struct.pack(">I", len(payload)) + payload
    with WRITE_LOCK:
        sys.stdout.buffer.write(encoded)
        sys.stdout.buffer.flush()


def read_packet_from(stream: BinaryIO) -> bytes | None:
    header = read_exact(stream, 4)
    if header is None:
        return None
    length = struct.unpack(">I", header)[0]
    if length > MAX_CONTROL_BYTES:
        raise SupervisorFailure("protocol_failure")
    payload = read_exact(stream, length)
    if payload is None:
        raise SupervisorFailure("protocol_failure")
    return payload


def read_packet() -> bytes | None:
    return read_packet_from(sys.stdin.buffer)


def read_exact(stream: BinaryIO, length: int) -> bytes | None:
    chunks: list[bytes] = []
    remaining = length
    while remaining:
        chunk = stream.read(remaining)
        if not chunk:
            if not chunks:
                return None
            raise SupervisorFailure("protocol_failure")
        chunks.append(chunk)
        remaining -= len(chunk)
    return b"".join(chunks)


def file_identity(info: os.stat_result) -> tuple[int, int, int, int, int, int, int]:
    """Identity fields stable across path/handle reads (atime excluded).

    CPython's Windows path stat and descriptor fstat expose different ctime
    semantics/precision for the same file.  Device+inode, size, mode, mtime,
    and link count remain bound there; POSIX also binds ctime.
    """
    return (
        0 if os.name == "nt" else info.st_mode,
        info.st_size,
        info.st_mtime_ns,
        0 if os.name == "nt" else info.st_ctime_ns,
        info.st_nlink,
        info.st_dev,
        info.st_ino,
    )


def path_has_reparse_point(info: os.stat_result) -> bool:
    attributes = int(getattr(info, "st_file_attributes", 0))
    reparse = int(getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400))
    return bool(attributes & reparse)


def verified_regular_path(path: Path) -> os.stat_result:
    """Traverse every component without accepting a link or reparse point."""
    parts = path.parts
    if not parts:
        raise SupervisorFailure("source_identity_failed")
    current = Path(parts[0])
    final_info: os.stat_result | None = None
    for index, part in enumerate(parts):
        if index:
            current = current / part
        try:
            info = os.lstat(current)
        except OSError as exc:
            raise SupervisorFailure("source_identity_failed") from exc
        if stat.S_ISLNK(info.st_mode) or path_has_reparse_point(info):
            raise SupervisorFailure("source_identity_failed")
        final = index == len(parts) - 1
        if final:
            if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
                raise SupervisorFailure("source_identity_failed")
            final_info = info
        elif not stat.S_ISDIR(info.st_mode):
            raise SupervisorFailure("source_identity_failed")
    if final_info is None:
        raise SupervisorFailure("source_identity_failed")
    return final_info


def verified_file_digest(
    path_value: str,
    maximum: int,
    after_open: Callable[[], None] | None = None,
) -> str:
    """Hash one regular, single-link file while rejecting path replacement."""
    if not isinstance(path_value, str) or not path_value or "\0" in path_value:
        raise SupervisorFailure("source_identity_failed")
    if not isinstance(maximum, int) or isinstance(maximum, bool) or maximum < 0:
        raise SupervisorFailure("source_identity_failed")
    path = Path(os.path.abspath(path_value))
    initial = verified_regular_path(path)
    if initial.st_size < 0 or initial.st_size > maximum:
        raise SupervisorFailure("source_identity_failed")
    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_CLOEXEC", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise SupervisorFailure("source_identity_failed") from exc
    digest = hashlib.sha256()
    total = 0
    try:
        opened = os.fstat(descriptor)
        if (
            not stat.S_ISREG(opened.st_mode)
            or opened.st_nlink != 1
            or file_identity(opened) != file_identity(initial)
        ):
            raise SupervisorFailure("source_identity_failed")
        if after_open is not None:
            after_open()
        while True:
            chunk = os.read(descriptor, min(65_536, maximum - total + 1))
            if not chunk:
                break
            total += len(chunk)
            if total > maximum:
                raise SupervisorFailure("source_identity_failed")
            digest.update(chunk)
        finished = os.fstat(descriptor)
    except OSError as exc:
        raise SupervisorFailure("source_identity_failed") from exc
    finally:
        try:
            os.close(descriptor)
        except OSError:
            raise SupervisorFailure("source_identity_failed")
    final_info = verified_regular_path(path)
    if (
        total != initial.st_size
        or file_identity(opened) != file_identity(finished)
        or file_identity(finished) != file_identity(final_info)
    ):
        raise SupervisorFailure("source_identity_failed")
    return digest.hexdigest()


def source_digest() -> str:
    return verified_file_digest(__file__, 131_072)


def python_executable_digest() -> str:
    return verified_file_digest(sys.executable, 134_217_728)


def normalized_status(returncode: int) -> int:
    if returncode < 0:
        return min(255, 128 + abs(returncode))
    return min(255, returncode)


def windows_abnormal_exit_category(returncode: int) -> str | None:
    """Map an NTSTATUS exit to a finite, non-sensitive diagnosis."""
    if returncode <= 255:
        return None
    return {
        0xC0000005: "child_access_violation",
        0xC0000008: "child_invalid_handle",
        0xC000000D: "child_invalid_parameter",
        0xC0000017: "child_no_memory",
        0xC000001D: "child_illegal_instruction",
        0xC0000022: "child_access_denied",
        0xC000007B: "child_invalid_image",
        0xC00000FD: "child_stack_overflow",
        0xC000012F: "child_invalid_image",
        0xC0000135: "child_dependency_missing",
        0xC0000139: "child_entrypoint_missing",
        0xC000013A: "child_controlled_interrupt",
        0xC0000142: "child_initialization_failed",
        0xC0000374: "child_heap_corruption",
        0xC0000409: "child_fast_fail",
        0xC0000417: "child_invalid_crt_parameter",
        0xC0000420: "child_assertion_failure",
        0x40000015: "child_fatal_application_exit",
        0xFFFFFFFF: "child_runtime_abort",
    }.get(returncode & 0xFFFFFFFF, "child_abnormal_exit")


def wait_until(predicate: Callable[[], bool], seconds: float) -> bool:
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        if predicate():
            return True
        time.sleep(0.01)
    return predicate()


def owned_popen(
    argv: Sequence[str], *, supervisor_root: bool = False, **options: object
) -> subprocess.Popen[bytes]:
    """The repository's single native launch primitive.

    Windows children inherit the verified ConPTY owned by the supervisor.
    Other authored Python callers inherit the already-owned Job/group.
    """
    if options.get("shell") is True:
        raise SupervisorFailure("protocol_failure")
    options["close_fds"] = True
    if os.name == "nt":
        requested = int(options.pop("creationflags", 0))
        if requested != 0:
            raise SupervisorFailure("protocol_failure")
        # This helper may run only inside the ConPTY root created below.
        # A second CREATE_NO_WINDOW would detach the child from that headless console and allow a console-subsystem grandchild to allocate a real window.
        # Inheriting the verified current console closes that gap.
        if supervisor_root or not windows_console_attached():
            raise SupervisorFailure("console_isolation_unconfirmed")
        options["creationflags"] = requested
        options.pop("start_new_session", None)
    else:
        options.pop("creationflags", None)
        options["start_new_session"] = supervisor_root
    return subprocess.Popen(list(argv), **options)  # type: ignore[arg-type]


def owned_operation_deadline(timeout: float | None) -> float:
    seconds: float | int = (
        MAX_DURATION_MILLISECONDS / 1000.0 if timeout is None else timeout
    )
    if (
        type(seconds) not in (int, float)
        or not 0 <= seconds <= MAX_DURATION_MILLISECONDS / 1000.0
    ):
        raise SupervisorFailure("protocol_failure")
    return time.monotonic() + float(seconds)


def owned_remaining(deadline: float) -> float:
    return max(0.0, deadline - time.monotonic())


def owned_close_stream(stream: BinaryIO | None) -> bool:
    if stream is None:
        return True
    try:
        if stream.closed:
            return True
        stream.close()
        return stream.closed
    except BaseException:
        return bool(getattr(stream, "closed", False))


def owned_close_streams(streams: Sequence[BinaryIO | None]) -> bool:
    results = [owned_close_stream(stream) for stream in streams]
    return all(results)


def owned_record_failure(
    state: list[tuple[float, str] | None],
    lock: threading.Lock,
    code: str,
    occurred_at: float | None = None,
) -> None:
    timestamp = time.monotonic() if occurred_at is None else occurred_at
    priority = {
        "supervisor_deadline": 0,
        "supervisor_output_limit": 1,
        "child_wait_failed": 2,
    }[code]
    with lock:
        current = state[0]
        if current is None or (timestamp, priority) < (
            current[0], {
                "supervisor_deadline": 0,
                "supervisor_output_limit": 1,
                "child_wait_failed": 2,
            }[current[1]]
        ):
            state[0] = (timestamp, code)


def owned_observed_failure(
    state: list[tuple[float, str] | None], lock: threading.Lock
) -> str | None:
    with lock:
        return state[0][1] if state[0] is not None else None


def owned_capture_pipe(
    stream: BinaryIO,
    index: int,
    captures: list[bytearray],
    captured_total: list[int],
    capture_lock: threading.Lock,
    failure_state: list[tuple[float, str] | None],
    failure_lock: threading.Lock,
    abort: threading.Event,
    maximum: int,
) -> None:
    try:
        while not abort.is_set():
            chunk = stream.read(OWNED_RUN_CHUNK_BYTES)
            if not chunk:
                return
            if not isinstance(chunk, bytes):
                owned_record_failure(
                    failure_state, failure_lock, "child_wait_failed"
                )
                return
            with capture_lock:
                remaining = maximum - captured_total[0]
                accepted = min(len(chunk), max(0, remaining))
                if accepted:
                    captures[index].extend(chunk[:accepted])
                    captured_total[0] += accepted
                if accepted != len(chunk):
                    owned_record_failure(
                        failure_state, failure_lock,
                        "supervisor_output_limit",
                    )
            if owned_observed_failure(failure_state, failure_lock) is not None:
                return
    except (OSError, ValueError):
        if not abort.is_set():
            owned_record_failure(
                failure_state, failure_lock, "child_wait_failed"
            )
    except BaseException:
        owned_record_failure(failure_state, failure_lock, "child_wait_failed")
    finally:
        if not owned_close_stream(stream) and not abort.is_set():
            owned_record_failure(
                failure_state, failure_lock, "child_wait_failed"
            )


def owned_input_closed_early(error: OSError) -> bool:
    return isinstance(error, BrokenPipeError) or (
        os.name == "nt"
        and (
            getattr(error, "errno", None) == errno.EINVAL
            or getattr(error, "winerror", None) == 232
        )
    )


def owned_write_input(
    stream: BinaryIO,
    payload: bytes,
    failure_state: list[tuple[float, str] | None],
    failure_lock: threading.Lock,
    abort: threading.Event,
) -> None:
    try:
        offset = 0
        while offset < len(payload) and not abort.is_set():
            written = stream.write(payload[offset:offset + OWNED_RUN_CHUNK_BYTES])
            if not isinstance(written, int) or written <= 0:
                owned_record_failure(
                    failure_state, failure_lock, "child_wait_failed"
                )
                return
            offset += written
        if not abort.is_set():
            stream.flush()
    except OSError as error:
        if (
            not abort.is_set() and not owned_input_closed_early(error)
        ):
            owned_record_failure(
                failure_state, failure_lock, "child_wait_failed"
            )
    except ValueError:
        if not abort.is_set():
            owned_record_failure(
                failure_state, failure_lock, "child_wait_failed"
            )
    except BaseException:
        owned_record_failure(failure_state, failure_lock, "child_wait_failed")
    finally:
        if not owned_close_stream(stream) and not abort.is_set():
            owned_record_failure(
                failure_state, failure_lock, "child_wait_failed"
            )


def owned_join_workers(
    workers: list[threading.Thread], deadline: float, reserve: float = 0.0
) -> bool:
    try:
        while True:
            worker = next((item for item in workers if item.is_alive()), None)
            if worker is None:
                return True
            remaining = owned_remaining(deadline) - reserve
            if remaining <= 0:
                return False
            worker.join(timeout=min(OWNED_RUN_POLL_SECONDS, remaining))
    except BaseException:
        return False


def owned_run(
    argv: Sequence[str], *, timeout: float | None = None, check: bool = False,
    input: bytes | None = None, max_output_bytes: int = MAX_OUTPUT_BYTES,
    **options: object
) -> subprocess.CompletedProcess[bytes]:
    """Run one child inside the already-established native tree boundary.

    Popen exposes only the direct child identity.  Descendant ownership remains
    with the enclosing Job/process group.  If the root or an inherited pipe
    cannot be joined, this process exits so that enclosing owner reaps the full
    tree instead of allowing an unverifiable result to escape.
    """
    operation_deadline = owned_operation_deadline(timeout)
    if type(argv) in (str, bytes):
        raise SupervisorFailure("protocol_failure")
    try:
        bounded_argv = list(argv)
    except BaseException:
        raise SupervisorFailure("protocol_failure") from None
    if (
        type(max_output_bytes) is not int
        or not 0 <= max_output_bytes <= MAX_OUTPUT_BYTES
        or not bounded_argv
        or any(type(argument) is not str or "\0" in argument
               for argument in bounded_argv)
        or (input is not None and type(input) is not bytes)
        or any(name in options for name in (
            "encoding", "errors", "text", "universal_newlines"
        ))
        or (input is not None and "stdin" in options)
    ):
        raise SupervisorFailure("protocol_failure")
    if input is not None:
        options["stdin"] = subprocess.PIPE
    captures_stdout = options.get("stdout") is subprocess.PIPE
    captures_stderr = options.get("stderr") is subprocess.PIPE
    if captures_stdout or captures_stderr or options.get("stdin") is subprocess.PIPE:
        if "bufsize" in options and options["bufsize"] != 0:
            raise SupervisorFailure("protocol_failure")
        options["bufsize"] = 0
    try:
        child = owned_popen(bounded_argv, **options)
    except SupervisorFailure:
        raise
    except BaseException:
        raise SupervisorFailure("child_start_failed") from None

    captures = [bytearray(), bytearray()]
    captured_total = [0]
    capture_lock = threading.Lock()
    failure_state: list[tuple[float, str] | None] = [None]
    failure_lock = threading.Lock()
    abort = threading.Event()
    workers: list[threading.Thread] = []
    failure: str | None = None
    try:
        candidates: list[threading.Thread] = []
        if captures_stdout and child.stdout is not None:
            candidates.append(threading.Thread(
                target=owned_capture_pipe,
                args=(child.stdout, 0, captures, captured_total, capture_lock,
                      failure_state, failure_lock, abort, max_output_bytes),
                name="http-owned-capture",
                daemon=True,
            ))
        if captures_stderr and child.stderr is not None:
            candidates.append(threading.Thread(
                target=owned_capture_pipe,
                args=(child.stderr, 1, captures, captured_total, capture_lock,
                      failure_state, failure_lock, abort, max_output_bytes),
                name="http-owned-capture",
                daemon=True,
            ))
        if child.stdin is not None:
            candidates.append(threading.Thread(
                target=owned_write_input,
                args=(child.stdin, input or b"", failure_state, failure_lock,
                      abort),
                name="http-owned-input",
                daemon=True,
            ))
        for worker in candidates:
            workers.append(worker)
            worker.start()
        while failure is None:
            now = time.monotonic()
            if now >= operation_deadline:
                owned_record_failure(
                    failure_state, failure_lock, "supervisor_deadline",
                    operation_deadline,
                )
            failure = owned_observed_failure(failure_state, failure_lock)
            if failure is not None:
                break
            if child.poll() is not None:
                break
            time.sleep(min(
                OWNED_RUN_POLL_SECONDS, owned_remaining(operation_deadline)
            ))
    except BaseException:
        owned_record_failure(
            failure_state, failure_lock, "child_wait_failed"
        )
        failure = owned_observed_failure(failure_state, failure_lock)

    cleanup_deadline = time.monotonic() + TREE_JOIN_SECONDS
    if failure is not None:
        abort.set()
        try:
            child.kill()
        except BaseException:
            pass
    root_reaped = False
    try:
        child.wait(timeout=owned_remaining(cleanup_deadline))
        root_reaped = child.returncode is not None
    except BaseException:
        try:
            child.kill()
        except BaseException:
            pass
        try:
            child.wait(timeout=owned_remaining(cleanup_deadline))
            root_reaped = child.returncode is not None
        except BaseException:
            root_reaped = False

    streams = [child.stdin, child.stdout, child.stderr]
    streams_closed = True
    if failure is not None or not root_reaped:
        abort.set()
        streams_closed = owned_close_streams(streams)
    workers_joined = owned_join_workers(
        workers, cleanup_deadline, OWNED_RUN_CLOSE_RESERVE_SECONDS
    )
    if not workers_joined:
        abort.set()
        streams_closed = owned_close_streams(streams) and streams_closed
        workers_joined = owned_join_workers(workers, cleanup_deadline)
    streams_closed = owned_close_streams(streams) and streams_closed

    if not root_reaped or not workers_joined:
        # Returning would let an unconfirmed root or pipe owner escape the enclosing Job/process-group boundary.
        # Exiting makes that owner tear down the complete native tree before it can attest completion.
        os._exit(127)
    if not streams_closed:
        owned_record_failure(
            failure_state, failure_lock, "child_wait_failed"
        )
    if failure is None:
        failure = owned_observed_failure(failure_state, failure_lock)
    if failure is not None:
        raise SupervisorFailure(failure)

    try:
        stdout = bytes(captures[0]) if captures_stdout else None
        stderr = bytes(captures[1]) if captures_stderr else None
        result = subprocess.CompletedProcess(
            bounded_argv, child.returncode, stdout, stderr
        )
        if check and result.returncode:
            category = windows_abnormal_exit_category(result.returncode)
            raise SupervisorFailure(category or "child_abnormal_exit")
        return result
    except SupervisorFailure:
        raise
    except BaseException:
        raise SupervisorFailure("child_wait_failed") from None


def owned_check_output(argv: Sequence[str], *, timeout: float | None = None,
                       max_output_bytes: int = MAX_OUTPUT_BYTES,
                       **options: object) -> bytes:
    options["stdout"] = subprocess.PIPE
    options["stderr"] = subprocess.PIPE
    return owned_run(
        argv, timeout=timeout, check=True,
        max_output_bytes=max_output_bytes, **options
    ).stdout or b""


def output_relay(
    stream: BinaryIO,
    output_limited: threading.Event,
    protocol_failed: threading.Event,
    limit: int,
) -> None:
    count = 0
    forwarding = True
    try:
        while True:
            chunk = stream.read(65_536)
            if not chunk:
                return
            count = min(limit + 1, count + len(chunk))
            if count > limit:
                output_limited.set()
                forwarding = False
            if forwarding:
                try:
                    write_packet(b"O" + chunk)
                except (BrokenPipeError, OSError, SupervisorFailure):
                    protocol_failed.set()
                    forwarding = False
    except Exception:
        protocol_failed.set()


def settled_relay_reason(
    reason: str | None,
    output_limited: threading.Event,
    protocol_failed: threading.Event,
) -> str | None:
    """Resolve relay outcomes after the root and its output have both settled.

    A short-lived root can exit before its relay publishes an output-limit or
    protocol event.  Protocol failure has priority because a missing output
    frame invalidates the observation channel itself.  A late output-limit only
    replaces an otherwise successful result; an already-observed deadline or
    parent cancellation remains the earlier cause.
    """
    if protocol_failed.is_set():
        return "protocol_failure"
    if reason is None and output_limited.is_set():
        return "output_limit"
    return reason


def poll_control() -> object | bytes | None:
    if os.name == "nt":
        return poll_windows_control()
    import select

    ready, _, _ = select.select([sys.stdin.buffer], [], [], 0)
    if not ready:
        return parse_control_buffer(False)
    chunk = os.read(sys.stdin.fileno(), 20)
    if not chunk:
        return parse_control_buffer(True)
    CONTROL_BUFFER.extend(chunk)
    return parse_control_buffer(False)


def parse_control_buffer(eof: bool) -> object | bytes | None:
    if len(CONTROL_BUFFER) < 4:
        if eof:
            if CONTROL_BUFFER:
                raise SupervisorFailure("protocol_failure")
            return None
        return CONTROL_IDLE
    length = struct.unpack(">I", CONTROL_BUFFER[:4])[0]
    if length > MAX_CONTROL_BYTES:
        raise SupervisorFailure("protocol_failure")
    total = 4 + length
    if len(CONTROL_BUFFER) < total:
        if eof:
            raise SupervisorFailure("protocol_failure")
        return CONTROL_IDLE
    payload = bytes(CONTROL_BUFFER[4:total])
    del CONTROL_BUFFER[:total]
    return payload


def control_reason() -> str | None:
    try:
        command = poll_control()
        if command is CONTROL_IDLE:
            return None
        if command is None:
            return "parent_eof"
        if command == b"STOP":
            return "parent_stop"
        return "protocol_failure"
    except (OSError, SupervisorFailure):
        return "protocol_failure"


def requested_status(reason: str | None, returncode: int) -> int:
    if reason in {"deadline", "parent_stop", "parent_eof"}:
        return 124
    if reason == "output_limit":
        return 125
    if reason == "protocol_failure":
        return 127
    return normalized_status(returncode)


def posix_group_exists(group: int) -> bool:
    try:
        os.killpg(group, 0)
        return True
    except ProcessLookupError:
        return False
    except PermissionError:
        raise SupervisorFailure("group_query_failed")


def terminate_posix_group(group: int) -> None:
    try:
        os.killpg(group, signal.SIGKILL)
    except ProcessLookupError:
        return
    except PermissionError as exc:
        raise SupervisorFailure("group_termination_failed") from exc


def supervise_posix(
    argv: Sequence[str], deadline: float, output_limit: int
) -> tuple[int, bool, bool, bool, bool]:
    child: subprocess.Popen[bytes] | None = None
    relay: threading.Thread | None = None
    tree_empty = False
    root_reaped = False
    try:
        try:
            child = owned_popen(
                argv,
                supervisor_root=True,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                bufsize=0,
            )
        except OSError as exc:
            # This is the only OSError converted to child_start_failed: Popen has not returned, so no repository process group exists.
            raise SupervisorFailure("child_start_failed") from exc
        assert child.stdout is not None
        output_limited = threading.Event()
        protocol_failed = threading.Event()
        relay = threading.Thread(
            target=output_relay,
            args=(child.stdout, output_limited, protocol_failed, output_limit),
            daemon=True,
        )
        relay.start()
        reason: str | None = None
        while child.poll() is None and reason is None:
            if time.monotonic() >= deadline:
                reason = "deadline"
                break
            if output_limited.is_set():
                reason = "output_limit"
                break
            if protocol_failed.is_set():
                reason = "protocol_failure"
                break
            reason = control_reason()
            time.sleep(0.01)
        requested = reason is not None
        if requested and child.poll() is None:
            terminate_posix_group(child.pid)
        try:
            returncode = child.wait(timeout=TREE_JOIN_SECONDS)
            root_reaped = True
        except subprocess.TimeoutExpired as exc:
            terminate_posix_group(child.pid)
            raise SupervisorFailure("child_wait_failed") from exc
        outlived = posix_group_exists(child.pid)
        if outlived:
            terminate_posix_group(child.pid)
        tree_empty = wait_until(
            lambda: not posix_group_exists(child.pid), TREE_JOIN_SECONDS
        )
        relay.join(timeout=TREE_JOIN_SECONDS)
        if relay.is_alive():
            # The workload group is already absent.
            # A blocked parent output pipe must not retain this supervisor indefinitely.
            if tree_empty:
                os._exit(127)
            raise SupervisorFailure("group_reap_unconfirmed")
        reason = settled_relay_reason(reason, output_limited, protocol_failed)
        requested = reason is not None
        status = requested_status(reason, returncode)
        abnormal_exit = (
            windows_abnormal_exit_category(returncode)
            if reason is None else None
        )
        if outlived and not requested:
            status = 126
        if not tree_empty:
            status = 127
        if reason == "deadline":
            write_packet(b"E|supervisor_deadline")
        elif reason == "output_limit":
            write_packet(b"E|supervisor_output_limit")
        elif reason == "protocol_failure":
            write_packet(b"E|protocol_failure")
        return status, tree_empty, outlived, requested, True
    finally:
        if child is not None:
            cleanup_confirmed = True
            try:
                if posix_group_exists(child.pid):
                    terminate_posix_group(child.pid)
            except SupervisorFailure:
                cleanup_confirmed = False
            try:
                child.wait(timeout=TREE_JOIN_SECONDS)
                root_reaped = True
            except (OSError, subprocess.TimeoutExpired):
                cleanup_confirmed = False
            try:
                if posix_group_exists(child.pid):
                    terminate_posix_group(child.pid)
                tree_empty = wait_until(
                    lambda: not posix_group_exists(child.pid), TREE_JOIN_SECONDS
                )
            except SupervisorFailure:
                tree_empty = False
            cleanup_confirmed = cleanup_confirmed and root_reaped and tree_empty
            if relay is not None:
                relay.join(timeout=TREE_JOIN_SECONDS)
                if relay.is_alive():
                    # A relay blocked on the parent protocol pipe may own WRITE_LOCK.
                    # Exiting here avoids a second write attempt in the top-level failure handler after group teardown.
                    os._exit(127)
            try:
                if child.stdout is not None:
                    child.stdout.close()
            except OSError:
                cleanup_confirmed = False
            if not cleanup_confirmed:
                raise SupervisorFailure("group_reap_unconfirmed")


if os.name == "nt":
    import ctypes
    import msvcrt
    from ctypes import wintypes

    JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE = 0x00002000
    JOB_OBJECT_EXTENDED_LIMIT_INFORMATION_CLASS = 9
    JOB_OBJECT_BASIC_ACCOUNTING_INFORMATION_CLASS = 1
    CREATE_SUSPENDED = WINDOWS_CREATE_SUSPENDED
    CREATE_UNICODE_ENVIRONMENT = 0x00000400
    EXTENDED_STARTUPINFO_PRESENT = 0x00080000
    PROC_THREAD_ATTRIBUTE_PSEUDOCONSOLE = 0x00020016
    STARTF_USESTDHANDLES = 0x00000100
    STD_INPUT_HANDLE = ctypes.c_ulong(-10).value
    STD_OUTPUT_HANDLE = ctypes.c_ulong(-11).value
    STD_ERROR_HANDLE = ctypes.c_ulong(-12).value
    WAIT_OBJECT_0 = 0x00000000
    WAIT_TIMEOUT = 0x00000102
    STILL_ACTIVE = 259
    ERROR_BROKEN_PIPE = 109

    class COORD(ctypes.Structure):
        _fields_ = [("X", ctypes.c_short), ("Y", ctypes.c_short)]

    class SECURITY_ATTRIBUTES(ctypes.Structure):
        _fields_ = [
            ("nLength", wintypes.DWORD),
            ("lpSecurityDescriptor", ctypes.c_void_p),
            ("bInheritHandle", wintypes.BOOL),
        ]

    class STARTUPINFO(ctypes.Structure):
        _fields_ = [
            ("cb", wintypes.DWORD),
            ("lpReserved", wintypes.LPWSTR),
            ("lpDesktop", wintypes.LPWSTR),
            ("lpTitle", wintypes.LPWSTR),
            ("dwX", wintypes.DWORD),
            ("dwY", wintypes.DWORD),
            ("dwXSize", wintypes.DWORD),
            ("dwYSize", wintypes.DWORD),
            ("dwXCountChars", wintypes.DWORD),
            ("dwYCountChars", wintypes.DWORD),
            ("dwFillAttribute", wintypes.DWORD),
            ("dwFlags", wintypes.DWORD),
            ("wShowWindow", wintypes.WORD),
            ("cbReserved2", wintypes.WORD),
            ("lpReserved2", ctypes.POINTER(ctypes.c_ubyte)),
            ("hStdInput", wintypes.HANDLE),
            ("hStdOutput", wintypes.HANDLE),
            ("hStdError", wintypes.HANDLE),
        ]

    class STARTUPINFOEX(ctypes.Structure):
        _fields_ = [
            ("StartupInfo", STARTUPINFO),
            ("lpAttributeList", ctypes.c_void_p),
        ]

    class PROCESS_INFORMATION(ctypes.Structure):
        _fields_ = [
            ("hProcess", wintypes.HANDLE),
            ("hThread", wintypes.HANDLE),
            ("dwProcessId", wintypes.DWORD),
            ("dwThreadId", wintypes.DWORD),
        ]

    class IO_COUNTERS(ctypes.Structure):
        _fields_ = [
            ("ReadOperationCount", ctypes.c_uint64),
            ("WriteOperationCount", ctypes.c_uint64),
            ("OtherOperationCount", ctypes.c_uint64),
            ("ReadTransferCount", ctypes.c_uint64),
            ("WriteTransferCount", ctypes.c_uint64),
            ("OtherTransferCount", ctypes.c_uint64),
        ]

    class JOBOBJECT_BASIC_LIMIT_INFORMATION(ctypes.Structure):
        _fields_ = [
            ("PerProcessUserTimeLimit", ctypes.c_int64),
            ("PerJobUserTimeLimit", ctypes.c_int64),
            ("LimitFlags", wintypes.DWORD),
            ("MinimumWorkingSetSize", ctypes.c_size_t),
            ("MaximumWorkingSetSize", ctypes.c_size_t),
            ("ActiveProcessLimit", wintypes.DWORD),
            ("Affinity", ctypes.c_size_t),
            ("PriorityClass", wintypes.DWORD),
            ("SchedulingClass", wintypes.DWORD),
        ]

    class JOBOBJECT_EXTENDED_LIMIT_INFORMATION(ctypes.Structure):
        _fields_ = [
            ("BasicLimitInformation", JOBOBJECT_BASIC_LIMIT_INFORMATION),
            ("IoInfo", IO_COUNTERS),
            ("ProcessMemoryLimit", ctypes.c_size_t),
            ("JobMemoryLimit", ctypes.c_size_t),
            ("PeakProcessMemoryUsed", ctypes.c_size_t),
            ("PeakJobMemoryUsed", ctypes.c_size_t),
        ]

    class JOBOBJECT_BASIC_ACCOUNTING_INFORMATION(ctypes.Structure):
        _fields_ = [
            ("TotalUserTime", ctypes.c_int64),
            ("TotalKernelTime", ctypes.c_int64),
            ("ThisPeriodTotalUserTime", ctypes.c_int64),
            ("ThisPeriodTotalKernelTime", ctypes.c_int64),
            ("TotalPageFaultCount", wintypes.DWORD),
            ("TotalProcesses", wintypes.DWORD),
            ("ActiveProcesses", wintypes.DWORD),
            ("TotalTerminatedProcesses", wintypes.DWORD),
        ]

    KERNEL32 = ctypes.WinDLL("kernel32", use_last_error=True)
    KERNEL32.CreateJobObjectW.argtypes = [ctypes.c_void_p, wintypes.LPCWSTR]
    KERNEL32.CreateJobObjectW.restype = wintypes.HANDLE
    KERNEL32.SetInformationJobObject.argtypes = [
        wintypes.HANDLE,
        ctypes.c_int,
        ctypes.c_void_p,
        wintypes.DWORD,
    ]
    KERNEL32.SetInformationJobObject.restype = wintypes.BOOL
    KERNEL32.AssignProcessToJobObject.argtypes = [wintypes.HANDLE, wintypes.HANDLE]
    KERNEL32.AssignProcessToJobObject.restype = wintypes.BOOL
    KERNEL32.QueryInformationJobObject.argtypes = [
        wintypes.HANDLE,
        ctypes.c_int,
        ctypes.c_void_p,
        wintypes.DWORD,
        ctypes.c_void_p,
    ]
    KERNEL32.QueryInformationJobObject.restype = wintypes.BOOL
    KERNEL32.TerminateJobObject.argtypes = [wintypes.HANDLE, wintypes.UINT]
    KERNEL32.TerminateJobObject.restype = wintypes.BOOL
    KERNEL32.GetCurrentProcess.argtypes = []
    KERNEL32.GetCurrentProcess.restype = wintypes.HANDLE
    KERNEL32.GetStdHandle.argtypes = [wintypes.DWORD]
    KERNEL32.GetStdHandle.restype = wintypes.HANDLE
    KERNEL32.SetStdHandle.argtypes = [wintypes.DWORD, wintypes.HANDLE]
    KERNEL32.SetStdHandle.restype = wintypes.BOOL
    KERNEL32.IsProcessInJob.argtypes = [
        wintypes.HANDLE, wintypes.HANDLE, ctypes.POINTER(wintypes.BOOL)
    ]
    KERNEL32.IsProcessInJob.restype = wintypes.BOOL
    KERNEL32.ResumeThread.argtypes = [wintypes.HANDLE]
    KERNEL32.ResumeThread.restype = wintypes.DWORD
    KERNEL32.CloseHandle.argtypes = [wintypes.HANDLE]
    KERNEL32.CloseHandle.restype = wintypes.BOOL
    KERNEL32.PeekNamedPipe.argtypes = [
        wintypes.HANDLE,
        ctypes.c_void_p,
        wintypes.DWORD,
        ctypes.c_void_p,
        ctypes.POINTER(wintypes.DWORD),
        ctypes.c_void_p,
    ]
    KERNEL32.PeekNamedPipe.restype = wintypes.BOOL
    KERNEL32.CreatePipe.argtypes = [
        ctypes.POINTER(wintypes.HANDLE),
        ctypes.POINTER(wintypes.HANDLE),
        ctypes.POINTER(SECURITY_ATTRIBUTES),
        wintypes.DWORD,
    ]
    KERNEL32.CreatePipe.restype = wintypes.BOOL
    CREATE_PSEUDO_CONSOLE = getattr(KERNEL32, "CreatePseudoConsole", None)
    CLOSE_PSEUDO_CONSOLE = getattr(KERNEL32, "ClosePseudoConsole", None)
    if CREATE_PSEUDO_CONSOLE is not None:
        CREATE_PSEUDO_CONSOLE.argtypes = [
            COORD,
            wintypes.HANDLE,
            wintypes.HANDLE,
            wintypes.DWORD,
            ctypes.POINTER(wintypes.HANDLE),
        ]
        CREATE_PSEUDO_CONSOLE.restype = ctypes.c_long
    if CLOSE_PSEUDO_CONSOLE is not None:
        CLOSE_PSEUDO_CONSOLE.argtypes = [wintypes.HANDLE]
        CLOSE_PSEUDO_CONSOLE.restype = None
    KERNEL32.InitializeProcThreadAttributeList.argtypes = [
        ctypes.c_void_p,
        wintypes.DWORD,
        wintypes.DWORD,
        ctypes.POINTER(ctypes.c_size_t),
    ]
    KERNEL32.InitializeProcThreadAttributeList.restype = wintypes.BOOL
    KERNEL32.UpdateProcThreadAttribute.argtypes = [
        ctypes.c_void_p,
        wintypes.DWORD,
        ctypes.c_size_t,
        ctypes.c_void_p,
        ctypes.c_size_t,
        ctypes.c_void_p,
        ctypes.c_void_p,
    ]
    KERNEL32.UpdateProcThreadAttribute.restype = wintypes.BOOL
    KERNEL32.DeleteProcThreadAttributeList.argtypes = [ctypes.c_void_p]
    KERNEL32.DeleteProcThreadAttributeList.restype = None
    KERNEL32.CreateProcessW.argtypes = [
        wintypes.LPCWSTR,
        wintypes.LPWSTR,
        ctypes.c_void_p,
        ctypes.c_void_p,
        wintypes.BOOL,
        wintypes.DWORD,
        ctypes.c_void_p,
        wintypes.LPCWSTR,
        ctypes.POINTER(STARTUPINFO),
        ctypes.POINTER(PROCESS_INFORMATION),
    ]
    KERNEL32.CreateProcessW.restype = wintypes.BOOL
    KERNEL32.GetExitCodeProcess.argtypes = [
        wintypes.HANDLE,
        ctypes.POINTER(wintypes.DWORD),
    ]
    KERNEL32.GetExitCodeProcess.restype = wintypes.BOOL
    KERNEL32.WaitForSingleObject.argtypes = [wintypes.HANDLE, wintypes.DWORD]
    KERNEL32.WaitForSingleObject.restype = wintypes.DWORD
    KERNEL32.TerminateProcess.argtypes = [wintypes.HANDLE, wintypes.UINT]
    KERNEL32.TerminateProcess.restype = wintypes.BOOL
    KERNEL32.GetConsoleOutputCP.argtypes = []
    KERNEL32.GetConsoleOutputCP.restype = wintypes.UINT


def windows_console_attached() -> bool:
    if not KERNEL32.GetConsoleOutputCP():
        return False
    in_job = wintypes.BOOL()
    if not KERNEL32.IsProcessInJob(
        KERNEL32.GetCurrentProcess(), None, ctypes.byref(in_job)
    ) or not in_job.value:
        return False
    limits = JOBOBJECT_EXTENDED_LIMIT_INFORMATION()
    if not KERNEL32.QueryInformationJobObject(
        None,
        JOB_OBJECT_EXTENDED_LIMIT_INFORMATION_CLASS,
        ctypes.byref(limits),
        ctypes.sizeof(limits),
        None,
    ):
        return False
    return bool(
        limits.BasicLimitInformation.LimitFlags
        & JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
    )


def poll_windows_control() -> object | bytes | None:
    handle = wintypes.HANDLE(msvcrt.get_osfhandle(sys.stdin.fileno()))
    available = wintypes.DWORD()
    if not KERNEL32.PeekNamedPipe(
        handle, None, 0, None, ctypes.byref(available), None
    ):
        if ctypes.get_last_error() == ERROR_BROKEN_PIPE:
            return parse_control_buffer(True)
        raise SupervisorFailure("protocol_failure")
    if available.value == 0:
        return parse_control_buffer(False)
    chunk = os.read(sys.stdin.fileno(), min(int(available.value), 20))
    if not chunk:
        return parse_control_buffer(True)
    CONTROL_BUFFER.extend(chunk)
    return parse_control_buffer(False)


def close_windows_handle(handle: int | None) -> bool:
    if not handle:
        return True
    return bool(KERNEL32.CloseHandle(wintypes.HANDLE(handle)))


class WindowsPseudoConsoleChild:
    """Suspended root process attached to a headless pseudoconsole.

    The object owns every process, thread, pseudoconsole, and host-pipe handle.
    No handle value or command-line value is exposed through the supervisor
    protocol.
    """

    def __init__(
        self,
        argv: Sequence[str],
        process: PROCESS_INFORMATION,
        pseudoconsole: int,
        input_write: int,
        output_stream: BinaryIO,
    ) -> None:
        self.args = list(argv)
        self._handle = int(process.hProcess)
        self._thread = int(process.hThread)
        self.pid = int(process.dwProcessId)
        self._pseudoconsole = pseudoconsole
        self._input_write = input_write
        self.stdout = output_stream
        self._process_handles_closed = False
        self._console_closed = False
        self._console_close_started = False
        self._console_close_completed = threading.Event()
        self._resumed = False

    def poll(self) -> int | None:
        state = KERNEL32.WaitForSingleObject(wintypes.HANDLE(self._handle), 0)
        if state == WAIT_TIMEOUT:
            return None
        if state != WAIT_OBJECT_0:
            raise SupervisorFailure("child_wait_failed")
        status = wintypes.DWORD()
        if not KERNEL32.GetExitCodeProcess(
            wintypes.HANDLE(self._handle), ctypes.byref(status)
        ):
            raise SupervisorFailure("child_wait_failed")
        return int(status.value)

    def wait(self, timeout: float) -> int:
        milliseconds = max(0, min(0xFFFFFFFE, int(timeout * 1000)))
        state = KERNEL32.WaitForSingleObject(
            wintypes.HANDLE(self._handle), milliseconds
        )
        if state == WAIT_TIMEOUT:
            raise subprocess.TimeoutExpired(self.args, timeout)
        if state != WAIT_OBJECT_0:
            raise SupervisorFailure("child_wait_failed")
        result = self.poll()
        if result is None:
            raise SupervisorFailure("child_wait_failed")
        return result

    def kill(self) -> None:
        if self.poll() is None and not KERNEL32.TerminateProcess(
            wintypes.HANDLE(self._handle), 127
        ):
            raise SupervisorFailure("job_termination_failed")

    def resume(self) -> None:
        if not self._thread:
            raise SupervisorFailure("job_resume_failed")
        result = KERNEL32.ResumeThread(wintypes.HANDLE(self._thread))
        if result == 0xFFFFFFFF:
            raise SupervisorFailure("job_resume_failed")
        self._resumed = True
        thread_closed = close_windows_handle(self._thread)
        if thread_closed:
            self._thread = 0
        # Keep the host input writer alive until the client exits.
        # Closing the last writer while an attached process is running makes ConPTY deliver a console-close condition, which Windows reports as 0xC000013A.
        if not thread_closed:
            raise SupervisorFailure("console_prestart_cleanup_failed")

    def close_console_while_draining(
        self, relay: threading.Thread
    ) -> bool:
        """Close ConPTY while its output reader remains active.

        Microsoft documents that ClosePseudoConsole can block when output is
        not drained.  The relay is therefore started before the workload and
        remains active during close.  Both operations must finish before the
        completion attestation can be emitted.
        """
        input_closed = close_windows_handle(self._input_write)
        if input_closed:
            self._input_write = 0
        if not self._console_close_started:
            self._console_close_started = True

            def close_console() -> None:
                try:
                    if CLOSE_PSEUDO_CONSOLE is not None:
                        CLOSE_PSEUDO_CONSOLE(
                            wintypes.HANDLE(self._pseudoconsole)
                        )
                        self._pseudoconsole = 0
                        self._console_closed = True
                except Exception:
                    self._console_closed = False
                finally:
                    self._console_close_completed.set()

            closer = threading.Thread(target=close_console, daemon=True)
            closer.start()
        relay.join(timeout=TREE_JOIN_SECONDS)
        self._console_close_completed.wait(timeout=TREE_JOIN_SECONDS)
        complete = input_closed and self._console_closed and not relay.is_alive()
        if complete:
            try:
                self.stdout.close()
            except OSError:
                complete = False
        return complete

    def close_console_before_resume(self) -> bool:
        """Close a ConPTY whose suspended client never executed user code.

        The no-drain close is restricted to this state: no client instruction
        ran, so it cannot have produced pending pseudoconsole output.  Once
        ResumeThread succeeds every cleanup path must use the concurrent drain
        in close_console_while_draining instead.
        """
        if self._resumed or self._console_close_started:
            return False
        self._console_close_started = True
        closed = close_windows_handle(self._input_write)
        if closed:
            self._input_write = 0
        try:
            if CLOSE_PSEUDO_CONSOLE is not None and self._pseudoconsole:
                CLOSE_PSEUDO_CONSOLE(wintypes.HANDLE(self._pseudoconsole))
                self._pseudoconsole = 0
                self._console_closed = True
        except Exception:
            self._console_closed = False
        try:
            self.stdout.close()
        except OSError:
            closed = False
        self._console_close_completed.set()
        return closed and self._console_closed

    def close_process_handles(self) -> bool:
        if self._process_handles_closed:
            return True
        for attribute in ("_thread", "_handle", "_input_write"):
            handle = int(getattr(self, attribute))
            if handle and close_windows_handle(handle):
                setattr(self, attribute, 0)
        self._process_handles_closed = not any(
            (self._thread, self._handle, self._input_write)
        )
        return self._process_handles_closed


def create_windows_pseudoconsole_child(
    argv: Sequence[str], job: int, *, fault: str | None = None,
) -> WindowsPseudoConsoleChild:
    """Create a suspended process with an inherited headless console session."""
    if not argv or any((not isinstance(value, str) or "\0" in value)
                       for value in argv):
        raise SupervisorFailure("protocol_failure")
    if fault not in {None, "fdopen", "assign", "postassign"}:
        raise SupervisorFailure("protocol_failure")
    if CREATE_PSEUDO_CONSOLE is None or CLOSE_PSEUDO_CONSOLE is None:
        raise SupervisorFailure("console_create_failed")

    input_read = wintypes.HANDLE()
    input_write = wintypes.HANDLE()
    output_read = wintypes.HANDLE()
    output_write = wintypes.HANDLE()
    pseudoconsole = wintypes.HANDLE()
    output_stream: BinaryIO | None = None
    process = PROCESS_INFORMATION()
    attribute_buffer: ctypes.Array[ctypes.c_char] | None = None
    attribute_list: ctypes.c_void_p | None = None
    attribute_initialized = False
    descriptor = -1
    created = False
    assigned = False
    prestart_reap_confirmed = True
    cleanup_failed = False
    security = SECURITY_ATTRIBUTES(ctypes.sizeof(SECURITY_ATTRIBUTES), None,
                                   False)
    try:
        if not KERNEL32.CreatePipe(
            ctypes.byref(input_read), ctypes.byref(input_write),
            ctypes.byref(security), 0
        ):
            raise SupervisorFailure("console_pipe_failed")
        if not KERNEL32.CreatePipe(
            ctypes.byref(output_read), ctypes.byref(output_write),
            ctypes.byref(security), 0
        ):
            raise SupervisorFailure("console_pipe_failed")
        result = CREATE_PSEUDO_CONSOLE(
            COORD(240, 80), input_read, output_write, 0,
            ctypes.byref(pseudoconsole)
        )
        if result < 0 or not pseudoconsole:
            raise SupervisorFailure("console_create_failed")

        # Convert the host output handle before a process exists.
        # A descriptor allocation failure therefore cannot strand a suspended root between CreateProcess and Job assignment.
        if not close_windows_handle(int(input_read.value or 0)):
            raise SupervisorFailure("console_prestart_cleanup_failed")
        input_read = wintypes.HANDLE()
        if not close_windows_handle(int(output_write.value or 0)):
            raise SupervisorFailure("console_prestart_cleanup_failed")
        output_write = wintypes.HANDLE()
        descriptor = msvcrt.open_osfhandle(
            int(output_read.value), os.O_RDONLY | os.O_BINARY
        )
        output_read = wintypes.HANDLE()
        if fault == "fdopen":
            raise OSError
        output_stream = os.fdopen(descriptor, "rb", buffering=0)
        descriptor = -1

        size = ctypes.c_size_t()
        KERNEL32.InitializeProcThreadAttributeList(None, 1, 0,
                                                   ctypes.byref(size))
        if not size.value:
            raise SupervisorFailure("console_attribute_failed")
        attribute_buffer = ctypes.create_string_buffer(size.value)
        attribute_list = ctypes.cast(attribute_buffer, ctypes.c_void_p)
        if not KERNEL32.InitializeProcThreadAttributeList(
            attribute_list, 1, 0, ctypes.byref(size)
        ):
            raise SupervisorFailure("console_attribute_failed")
        attribute_initialized = True
        if not KERNEL32.UpdateProcThreadAttribute(
            attribute_list, 0, PROC_THREAD_ATTRIBUTE_PSEUDOCONSOLE,
            ctypes.c_void_p(int(pseudoconsole.value)),
            ctypes.sizeof(ctypes.c_void_p),
            None, None
        ):
            raise SupervisorFailure("console_attribute_failed")

        startup = STARTUPINFOEX()
        startup.StartupInfo.cb = ctypes.sizeof(startup)
        startup.lpAttributeList = attribute_list
        command_line = ctypes.create_unicode_buffer(
            subprocess.list2cmdline(list(argv))
        )
        # ConPTY fills only empty standard-handle slots in the child process.
        # This supervisor's slots name its private Erlang protocol pipes; the numeric values are meaningless in a non-inheriting child and can crash the runtime before user code starts.
        # No relay thread exists yet, so temporarily clearing these process-global slots is bounded to this single CreateProcess call.
        # Every cleared slot is restored before control leaves this block.
        standard_handle_ids = (
            STD_INPUT_HANDLE, STD_OUTPUT_HANDLE, STD_ERROR_HANDLE
        )
        saved_standard_handles: list[int | None] = []
        cleared_standard_handles = 0
        restore_failed = False
        try:
            for standard_handle_id in standard_handle_ids:
                saved_standard_handles.append(
                    KERNEL32.GetStdHandle(standard_handle_id)
                )
                if not KERNEL32.SetStdHandle(
                    standard_handle_id, wintypes.HANDLE()
                ):
                    raise SupervisorFailure("console_prestart_setup_failed")
                cleared_standard_handles += 1
            created = bool(KERNEL32.CreateProcessW(
                argv[0], command_line, None, None, False,
                EXTENDED_STARTUPINFO_PRESENT | CREATE_UNICODE_ENVIRONMENT
                | CREATE_SUSPENDED,
                None, None, ctypes.byref(startup.StartupInfo),
                ctypes.byref(process)
            ))
        finally:
            for index in range(cleared_standard_handles):
                restored = saved_standard_handles[index]
                if not KERNEL32.SetStdHandle(
                    standard_handle_ids[index],
                    wintypes.HANDLE(restored or 0),
                ):
                    restore_failed = True
        if restore_failed:
            raise SupervisorFailure("console_prestart_setup_failed")
        if not created:
            raise SupervisorFailure("console_child_start_failed")
        # From this point until explicit ownership transfer, every exceptional path must prove the suspended root was reaped.
        # A missing/invalid process handle therefore cannot inherit the optimistic initial value.
        prestart_reap_confirmed = False
        assigned_ok = False if fault == "assign" else bool(
            KERNEL32.AssignProcessToJobObject(job, process.hProcess)
        )
        if not assigned_ok:
            raise SupervisorFailure("job_assign_failed")
        assigned = True
        if fault == "postassign":
            raise OSError
        child = WindowsPseudoConsoleChild(
            argv, process, int(pseudoconsole.value),
            int(input_write.value), output_stream
        )
        process = PROCESS_INFORMATION()
        pseudoconsole = wintypes.HANDLE()
        input_write = wintypes.HANDLE()
        output_stream = None
        # The returned object now owns all live handles and the assigned Job.
        # Disable this function's pre-start cleanup branch before returning.
        created = False
        return child
    except SupervisorFailure:
        raise
    except (OSError, ValueError) as exc:
        code = ("console_prestart_setup_failed" if created else
                "console_output_setup_failed")
        raise SupervisorFailure(code) from exc
    finally:
        if attribute_list and attribute_initialized:
            try:
                KERNEL32.DeleteProcThreadAttributeList(attribute_list)
            except Exception:
                cleanup_failed = True
        cleanup_failed = not close_windows_handle(
            int(input_read.value or 0)) or cleanup_failed
        cleanup_failed = not close_windows_handle(
            int(input_write.value or 0)) or cleanup_failed
        cleanup_failed = not close_windows_handle(
            int(output_read.value or 0)) or cleanup_failed
        cleanup_failed = not close_windows_handle(
            int(output_write.value or 0)) or cleanup_failed
        if descriptor >= 0:
            try:
                os.close(descriptor)
            except OSError:
                cleanup_failed = True
        cleanup_failed = not close_windows_handle(
            int(process.hThread or 0)) or cleanup_failed
        if process.hProcess:
            if created:
                if assigned:
                    if not KERNEL32.TerminateJobObject(job, 127):
                        cleanup_failed = True
                else:
                    if not KERNEL32.TerminateProcess(process.hProcess, 127):
                        cleanup_failed = True
                prestart_reap_confirmed = KERNEL32.WaitForSingleObject(
                    process.hProcess, 5000
                ) == WAIT_OBJECT_0
                if assigned:
                    try:
                        prestart_reap_confirmed = (
                            prestart_reap_confirmed and wait_until(
                                lambda: windows_active_processes(job) == 0,
                                TREE_JOIN_SECONDS,
                            )
                        )
                    except SupervisorFailure:
                        prestart_reap_confirmed = False
            cleanup_failed = not close_windows_handle(
                int(process.hProcess)) or cleanup_failed
        if pseudoconsole:
            try:
                CLOSE_PSEUDO_CONSOLE(pseudoconsole)
            except Exception:
                cleanup_failed = True
        if output_stream is not None:
            try:
                output_stream.close()
            except OSError:
                cleanup_failed = True
        if created and not prestart_reap_confirmed:
            raise SupervisorFailure("prestart_reap_unconfirmed")
        if cleanup_failed:
            raise SupervisorFailure("console_prestart_cleanup_failed")


def windows_job() -> int:
    job = KERNEL32.CreateJobObjectW(None, None)
    if not job:
        raise SupervisorFailure("job_create_failed")
    limits = JOBOBJECT_EXTENDED_LIMIT_INFORMATION()
    limits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
    if not KERNEL32.SetInformationJobObject(
        job,
        JOB_OBJECT_EXTENDED_LIMIT_INFORMATION_CLASS,
        ctypes.byref(limits),
        ctypes.sizeof(limits),
    ):
        KERNEL32.CloseHandle(job)
        raise SupervisorFailure("job_set_limits_failed")
    return job


def windows_active_processes(job: int) -> int:
    accounting = JOBOBJECT_BASIC_ACCOUNTING_INFORMATION()
    if not KERNEL32.QueryInformationJobObject(
        job,
        JOB_OBJECT_BASIC_ACCOUNTING_INFORMATION_CLASS,
        ctypes.byref(accounting),
        ctypes.sizeof(accounting),
        None,
    ):
        raise SupervisorFailure("job_query_failed")
    return int(accounting.ActiveProcesses)


def supervise_windows(
    argv: Sequence[str], deadline: float, output_limit: int
) -> tuple[int, bool, bool, bool, bool]:
    job = windows_job()
    child: WindowsPseudoConsoleChild | None = None
    relay: threading.Thread | None = None
    cleanup_confirmed = True
    try:
        child = create_windows_pseudoconsole_child(argv, job)
        assert child.stdout is not None
        output_limited = threading.Event()
        protocol_failed = threading.Event()
        relay_candidate = threading.Thread(
            target=output_relay,
            args=(child.stdout, output_limited, protocol_failed, output_limit),
            daemon=True,
        )
        relay_candidate.start()
        relay = relay_candidate
        child.resume()
        reason: str | None = None
        while child.poll() is None and reason is None:
            if time.monotonic() >= deadline:
                reason = "deadline"
                break
            if output_limited.is_set():
                reason = "output_limit"
                break
            if protocol_failed.is_set():
                reason = "protocol_failure"
                break
            reason = control_reason()
            time.sleep(0.01)
        requested = reason is not None
        if requested and windows_active_processes(job) > 0:
            if not KERNEL32.TerminateJobObject(job, 124):
                raise SupervisorFailure("job_termination_failed")
        try:
            returncode = child.wait(timeout=TREE_JOIN_SECONDS)
        except subprocess.TimeoutExpired as exc:
            KERNEL32.TerminateJobObject(job, 127)
            raise SupervisorFailure("child_wait_failed") from exc
        root_only_cleared = wait_until(
            lambda: windows_active_processes(job) == 0, 0.1
        )
        outlived = not root_only_cleared
        if outlived:
            if not KERNEL32.TerminateJobObject(job, 126):
                raise SupervisorFailure("job_termination_failed")
        tree_empty = wait_until(lambda: windows_active_processes(job) == 0,
                                TREE_JOIN_SECONDS)
        console_closed = child.close_console_while_draining(relay)
        reason = settled_relay_reason(reason, output_limited, protocol_failed)
        requested = reason is not None
        status = requested_status(reason, returncode)
        abnormal_exit = (
            windows_abnormal_exit_category(returncode)
            if reason is None else None
        )
        if outlived and not requested:
            status = 126
        if not tree_empty:
            status = 127
        if not console_closed:
            # The relay may be blocked in the parent protocol pipe while the parent remains alive but is not scheduled.
            # Writing another packet could then deadlock behind WRITE_LOCK.
            # Immediate process exit closes the Job and ConPTY handles; the parent classifies the deliberately absent final frame as a fixed final_missing error.
            os._exit(127)
        if reason == "deadline":
            write_packet(b"E|supervisor_deadline")
        elif reason == "output_limit":
            write_packet(b"E|supervisor_output_limit")
        elif reason == "protocol_failure":
            write_packet(b"E|protocol_failure")
        elif abnormal_exit is not None:
            write_packet(b"E|" + abnormal_exit.encode("ascii"))
        return status, tree_empty, outlived, requested, console_closed
    finally:
        try:
            if child is not None:
                try:
                    running = child.poll() is None
                except SupervisorFailure:
                    running = True
                    cleanup_confirmed = False
                if running:
                    if not KERNEL32.TerminateJobObject(job, 127):
                        cleanup_confirmed = False
                    try:
                        child.wait(timeout=TREE_JOIN_SECONDS)
                    except (subprocess.TimeoutExpired, SupervisorFailure):
                        cleanup_confirmed = False
                try:
                    try:
                        cleanup_confirmed = (
                            wait_until(
                                lambda: windows_active_processes(job) == 0,
                                TREE_JOIN_SECONDS,
                            ) and cleanup_confirmed
                        )
                    except SupervisorFailure:
                        cleanup_confirmed = False
                    if not child._console_closed:
                        if relay is not None:
                            cleanup_confirmed = (
                                child.close_console_while_draining(relay)
                                and cleanup_confirmed
                            )
                        else:
                            cleanup_confirmed = (
                                child.close_console_before_resume()
                                and cleanup_confirmed
                            )
                finally:
                    cleanup_confirmed = (
                        child.close_process_handles() and cleanup_confirmed
                    )
            else:
                try:
                    if windows_active_processes(job) > 0:
                        if not KERNEL32.TerminateJobObject(job, 127):
                            cleanup_confirmed = False
                    cleanup_confirmed = (
                        wait_until(
                            lambda: windows_active_processes(job) == 0,
                            TREE_JOIN_SECONDS,
                        ) and cleanup_confirmed
                    )
                except SupervisorFailure:
                    cleanup_confirmed = False
        finally:
            cleanup_confirmed = close_windows_handle(job) and cleanup_confirmed
        if not cleanup_confirmed:
            # Never publish a final frame after a cleanup path that failed to prove root exit, Job emptiness, ConPTY close, and relay join.
            os._exit(127)


def arguments() -> tuple[str, str, int, int, list[str]]:
    if (
        len(sys.argv) < 11
        or sys.argv[1] != "--expected-sha256"
        or sys.argv[3] != "--expected-python-sha256"
        or sys.argv[5] != "--deadline-ms"
        or sys.argv[7] != "--output-limit-bytes"
        or sys.argv[9] != "--"
    ):
        raise SupervisorFailure("protocol_failure")
    expected = sys.argv[2]
    expected_python = sys.argv[4]
    if len(expected) != 64 or any(c not in "0123456789abcdef" for c in expected):
        raise SupervisorFailure("protocol_failure")
    if len(expected_python) != 64 or any(
        c not in "0123456789abcdef" for c in expected_python
    ):
        raise SupervisorFailure("protocol_failure")
    try:
        duration = int(sys.argv[6], 10)
        output_limit = int(sys.argv[8], 10)
    except ValueError as exc:
        raise SupervisorFailure("protocol_failure") from exc
    if not 1 <= duration <= MAX_DURATION_MILLISECONDS:
        raise SupervisorFailure("protocol_failure")
    if not 1 <= output_limit <= MAX_OUTPUT_BYTES:
        raise SupervisorFailure("protocol_failure")
    if not sys.argv[10:]:
        raise SupervisorFailure("protocol_failure")
    return expected, expected_python, duration, output_limit, sys.argv[10:]


def wait_for_start(deadline: float) -> str:
    while time.monotonic() < deadline:
        command = poll_control()
        if command is CONTROL_IDLE:
            time.sleep(0.01)
            continue
        if command == b"START":
            return "start"
        if command in {None, b"STOP"}:
            # No child exists before this transition.
            # A closed parent pipe or cancellation packet therefore has an exact no-child final state.
            return "cancel"
        raise SupervisorFailure("protocol_failure")
    return "deadline"


def late_relay_settlement_self_test() -> None:
    """Drive the platform supervisor through a root-before-relay race."""
    saved: dict[str, object] = {}
    names = ["output_relay", "write_packet"]
    if os.name == "nt":
        names.extend([
            "windows_job", "create_windows_pseudoconsole_child",
            "windows_active_processes", "close_windows_handle",
        ])
    else:
        names.extend(["owned_popen", "posix_group_exists"])
    for name in names:
        saved[name] = globals()[name]

    class FinishedChild:
        def __init__(self) -> None:
            self.args = ["fixed-child"]
            self.pid = 1
            self.stdout = io.BytesIO(b"")
            self._console_closed = True
            self.resume = lambda: None
            self.poll = lambda: 0
            self.wait = lambda timeout: 0
            self.close_process_handles = lambda: True

            def settle_console(relay: threading.Thread) -> bool:
                relay.join(timeout=2.0)
                return not relay.is_alive()

            self.close_console_while_draining = settle_console

    try:
        if os.name == "nt":
            globals()["windows_job"] = lambda: 1
            globals()["create_windows_pseudoconsole_child"] = (
                lambda _argv, _job: FinishedChild()
            )
            globals()["windows_active_processes"] = lambda _job: 0
            globals()["close_windows_handle"] = lambda _handle: True
            supervise = supervise_windows
        else:
            globals()["owned_popen"] = lambda _argv, **_options: FinishedChild()
            globals()["posix_group_exists"] = lambda _group: False
            supervise = supervise_posix

        for selected, expected_status, expected_packet in (
            ("output_limit", 125, "E|supervisor_output_limit"),
            ("protocol_failure", 127, "E|protocol_failure"),
        ):
            packets: list[str] = []

            def delayed_relay(
                _stream: BinaryIO,
                output_limited: threading.Event,
                protocol_failed: threading.Event,
                _limit: int,
            ) -> None:
                time.sleep(0.05)
                event = (
                    output_limited
                    if selected == "output_limit"
                    else protocol_failed
                )
                event.set()

            globals()["output_relay"] = delayed_relay
            globals()["write_packet"] = (
                lambda packet: packets.append(packet.decode("ascii"))
            )
            observed = supervise(
                ["fixed-child"], time.monotonic() + 2.0, 1
            )
            assert observed == (expected_status, True, False, True, True)
            assert packets == [expected_packet]

        empty_output = threading.Event()
        empty_protocol = threading.Event()
        assert settled_relay_reason(None, empty_output, empty_protocol) is None
        late_output = threading.Event()
        late_output.set()
        assert settled_relay_reason(
            "deadline", late_output, empty_protocol
        ) == "deadline"
        late_protocol = threading.Event()
        late_protocol.set()
        assert settled_relay_reason(
            "output_limit", late_output, late_protocol
        ) == "protocol_failure"
    finally:
        for name, value in saved.items():
            globals()[name] = value


def expect_owned_run_failure(
    expected: str, argv: Sequence[str], **options: object
) -> None:
    try:
        owned_run(argv, **options)
    except SupervisorFailure as failure:
        assert failure.code == expected
        assert str(failure) == expected
    else:
        raise AssertionError("owned run failure was accepted")


def owned_run_self_test() -> None:
    python = [sys.executable, "-I", "-B", "-c"]
    exact = owned_run(
        python + ["import sys;sys.stdout.buffer.write(b'abcd')"],
        timeout=10.0,
        max_output_bytes=4,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=True,
    )
    assert exact.stdout == b"abcd" and exact.stderr == b""

    expect_owned_run_failure(
        "supervisor_output_limit",
        python + ["import sys;sys.stdout.buffer.write(b'abcde')"],
        timeout=10.0,
        max_output_bytes=4,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=True,
    )

    combined = owned_run(
        python + [
            "import sys;sys.stdout.buffer.write(b'ab');"
            "sys.stderr.buffer.write(b'cd')"
        ],
        timeout=10.0,
        max_output_bytes=4,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=True,
    )
    assert combined.stdout == b"ab" and combined.stderr == b"cd"

    for _ in range(8):
        expect_owned_run_failure(
            "supervisor_output_limit",
            python + [
                "import sys,threading\n"
                "a=threading.Thread(target=lambda:"
                "(sys.stdout.buffer.write(b'ab'),sys.stdout.buffer.flush()))\n"
                "b=threading.Thread(target=lambda:"
                "(sys.stderr.buffer.write(b'cd'),sys.stderr.buffer.flush()))\n"
                "a.start();b.start();a.join();b.join()"
            ],
            timeout=10.0,
            max_output_bytes=1,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=True,
        )

    started = time.monotonic()
    expect_owned_run_failure(
        "supervisor_deadline",
        python + [
            "import sys,time\n"
            "while True:\n"
            " sys.stdout.buffer.write(b'x');sys.stdout.buffer.flush();time.sleep(.002)"
        ],
        timeout=0.08,
        max_output_bytes=4096,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=True,
    )
    assert time.monotonic() - started < TREE_JOIN_SECONDS + 2.0

    expect_owned_run_failure(
        "supervisor_deadline",
        python + ["import time;time.sleep(30)"],
        timeout=0.05,
        max_output_bytes=0,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        check=True,
    )

    echoed = owned_run(
        python + ["import sys;sys.stdout.buffer.write(sys.stdin.buffer.read())"],
        input=b"input!",
        timeout=10.0,
        max_output_bytes=6,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=True,
    )
    assert echoed.stdout == b"input!" and echoed.stderr == b""

    private = "owned-run-private-marker"
    try:
        owned_run(
            python + [
                "import sys;sys.stderr.write('owned-run-private-marker');"
                "raise SystemExit(7)"
            ],
            timeout=10.0,
            max_output_bytes=64,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=True,
        )
    except SupervisorFailure as failure:
        assert failure.code == "child_abnormal_exit"
        assert private not in str(failure) and private not in repr(failure)
    else:
        raise AssertionError("nonzero owned run was accepted")
    try:
        owned_check_output(
            python + [
                "import sys;sys.stderr.write('owned-run-private-marker');"
                "raise SystemExit(9)"
            ],
            timeout=10.0,
            max_output_bytes=64,
        )
    except SupervisorFailure as failure:
        assert failure.code == "child_abnormal_exit"
        assert private not in str(failure) and private not in repr(failure)
    else:
        raise AssertionError("nonzero owned check output was accepted")
    assert not any(
        worker.is_alive() and worker.name.startswith("http-owned-")
        for worker in threading.enumerate()
    )
    default_remaining = owned_operation_deadline(None) - time.monotonic()
    assert MAX_DURATION_MILLISECONDS / 1000.0 - 0.1 <= default_remaining
    assert default_remaining <= MAX_DURATION_MILLISECONDS / 1000.0
    first_cause: list[tuple[float, str] | None] = [None]
    first_cause_lock = threading.Lock()
    owned_record_failure(
        first_cause, first_cause_lock, "supervisor_deadline", 10.0
    )
    owned_record_failure(
        first_cause, first_cause_lock, "supervisor_output_limit", 20.0
    )
    owned_record_failure(
        first_cause, first_cause_lock, "child_wait_failed", 30.0
    )
    assert owned_observed_failure(first_cause, first_cause_lock) == (
        "supervisor_deadline"
    )
    assert owned_input_closed_early(BrokenPipeError())
    if os.name == "nt":
        assert owned_input_closed_early(OSError(errno.EINVAL, "redacted"))
    assert not owned_input_closed_early(OSError(errno.EIO, "redacted"))


def self_test() -> int:
    original_argv = sys.argv
    try:
        prefix = [
            original_argv[0],
            "--expected-sha256",
            "0" * 64,
            "--expected-python-sha256",
            "1" * 64,
            "--deadline-ms",
            str(MAX_DURATION_MILLISECONDS),
            "--output-limit-bytes",
            "1",
            "--",
            "child",
        ]
        sys.argv = prefix
        assert arguments()[2] == MAX_DURATION_MILLISECONDS
        sys.argv = [*prefix]
        sys.argv[6] = str(MAX_DURATION_MILLISECONDS + 1)
        try:
            arguments()
        except SupervisorFailure as failure:
            assert failure.code == "protocol_failure"
        else:
            raise AssertionError("oversize deadline accepted")
    finally:
        sys.argv = original_argv
    link_capability = "unavailable"
    with tempfile.TemporaryDirectory(prefix="http-process-identity-") as temporary:
        root = Path(temporary)
        original = root / "original.bin"
        original.write_bytes(b"verified bytes")
        assert verified_file_digest(str(original), 64) == hashlib.sha256(
            b"verified bytes"
        ).hexdigest()
        alias = root / "alias.bin"
        os.link(original, alias)
        try:
            verified_file_digest(str(alias), 64)
        except SupervisorFailure as failure:
            assert failure.code == "source_identity_failed"
        else:
            raise AssertionError("hardlink accepted")
        alias.unlink()
        mutation = root / "mutation.bin"
        mutation.write_bytes(b"before")

        def mutate_open_file() -> None:
            mutation.write_bytes(b"after mutation")

        try:
            verified_file_digest(str(mutation), 64, mutate_open_file)
        except SupervisorFailure as failure:
            assert failure.code == "source_identity_failed"
        else:
            raise AssertionError("open file mutation accepted")
        target = root / "target"
        target.mkdir()
        linked_parent = root / "linked-parent"
        try:
            os.symlink(target, linked_parent, target_is_directory=True)
        except (OSError, NotImplementedError):
            link_capability = "unavailable"
        else:
            linked_input = linked_parent / "input.bin"
            (target / "input.bin").write_bytes(b"linked")
            try:
                verified_file_digest(str(linked_input), 64)
            except SupervisorFailure as failure:
                assert failure.code == "source_identity_failed"
                link_capability = "verified"
            else:
                raise AssertionError("linked parent accepted")
    external_parent = os.environ.get("HTTP_PROCESS_SUPERVISOR_PARENT_PATH", "")
    if external_parent:
        if not os.path.isabs(external_parent) or len(external_parent) > 4096:
            raise AssertionError("parent link fixture path invalid")
        try:
            verified_file_digest(external_parent, 64)
        except SupervisorFailure as failure:
            assert failure.code == "source_identity_failed"
            link_capability = "verified"
        else:
            raise AssertionError("external linked parent accepted")
    assert windows_abnormal_exit_category(0) is None
    assert windows_abnormal_exit_category(255) is None
    for status, category in (
        (0xC0000005, "child_access_violation"),
        (0xC0000008, "child_invalid_handle"),
        (0xC000000D, "child_invalid_parameter"),
        (0xC0000017, "child_no_memory"),
        (0xC000001D, "child_illegal_instruction"),
        (0xC0000022, "child_access_denied"),
        (0xC000007B, "child_invalid_image"),
        (0xC00000FD, "child_stack_overflow"),
        (0xC000012F, "child_invalid_image"),
        (0xC0000135, "child_dependency_missing"),
        (0xC0000139, "child_entrypoint_missing"),
        (0xC000013A, "child_controlled_interrupt"),
        (0xC0000142, "child_initialization_failed"),
        (0xC0000374, "child_heap_corruption"),
        (0xC0000409, "child_fast_fail"),
        (0xC0000417, "child_invalid_crt_parameter"),
        (0xC0000420, "child_assertion_failure"),
        (0x40000015, "child_fatal_application_exit"),
        (0xFFFFFFFF, "child_runtime_abort"),
        (0xC0001234, "child_abnormal_exit"),
    ):
        assert windows_abnormal_exit_category(status) == category
    assert read_exact(io.BytesIO(b""), 4) is None
    for partial in (b"x", b"xxx"):
        try:
            read_exact(io.BytesIO(partial), 4)
        except SupervisorFailure as failure:
            assert failure.code == "protocol_failure"
        else:
            raise AssertionError("partial control accepted")
    for framed in (struct.pack(">I", 17), struct.pack(">I", 4) + b"ST"):
        try:
            read_packet_from(io.BytesIO(framed))
        except SupervisorFailure as failure:
            assert failure.code == "protocol_failure"
        else:
            raise AssertionError("invalid control accepted")
    for partial in (b"x", struct.pack(">I", 4) + b"ST"):
        CONTROL_BUFFER.clear()
        CONTROL_BUFFER.extend(partial)
        try:
            parse_control_buffer(True)
        except SupervisorFailure as failure:
            assert failure.code == "protocol_failure"
        else:
            raise AssertionError("truncated buffered control accepted")
    CONTROL_BUFFER.clear()
    CONTROL_BUFFER.extend(struct.pack(">I", 17))
    try:
        parse_control_buffer(False)
    except SupervisorFailure as failure:
        assert failure.code == "protocol_failure"
    else:
        raise AssertionError("oversize buffered control accepted")
    CONTROL_BUFFER.clear()
    CONTROL_BUFFER.extend(struct.pack(">I", 4) + b"STOP")
    assert parse_control_buffer(False) == b"STOP"
    assert not CONTROL_BUFFER
    original_writer = globals()["write_packet"]
    try:
        forwarded: list[bytes] = []
        globals()["write_packet"] = forwarded.append
        limited_stream = io.BytesIO(b"x" * 200_000)
        limited = threading.Event()
        protocol = threading.Event()
        output_relay(limited_stream, limited, protocol, 65_536)
        assert limited.is_set() and not protocol.is_set()
        assert limited_stream.tell() == 200_000
        assert sum(len(packet) - 1 for packet in forwarded) <= 65_536

        writes = 0

        def blocked_writer(_packet: bytes) -> None:
            nonlocal writes
            writes += 1
            raise BrokenPipeError

        globals()["write_packet"] = blocked_writer
        blocked_stream = io.BytesIO(b"x" * 200_000)
        limited = threading.Event()
        protocol = threading.Event()
        output_relay(blocked_stream, limited, protocol, 500_000)
        assert writes == 1 and protocol.is_set() and not limited.is_set()
        assert blocked_stream.tell() == 200_000
    finally:
        globals()["write_packet"] = original_writer
    late_relay_settlement_self_test()
    original_poller = globals()["poll_control"]
    try:
        for control, expected in (
            (b"START", "start"), (b"STOP", "cancel"), (None, "cancel")
        ):
            globals()["poll_control"] = lambda value=control: value
            assert wait_for_start(time.monotonic() + 1.0) == expected
        globals()["poll_control"] = lambda: CONTROL_IDLE
        assert wait_for_start(time.monotonic()) == "deadline"
    finally:
        globals()["poll_control"] = original_poller
    owned_run_self_test()
    print(
        "process_supervisor_self_test passed=true controls=60 relay_settlement=verified "
        "owned_run=verified "
        f"parent_link={link_capability} hardlink=verified mutation=verified"
    )
    return 0


def windows_fault_self_test() -> int:
    """Exercise pre-start ConPTY cleanup without exposing fault details."""
    if os.name != "nt":
        print("process_supervisor_windows_fault_test passed=true controls=0")
        return 0
    child_argv = [
        sys.executable, "-I", "-B", "-c",
        "import time; time.sleep(30)",
    ]
    controls = [
        ("fdopen", "console_output_setup_failed"),
        ("assign", "job_assign_failed"),
        ("postassign", "console_prestart_setup_failed"),
    ]
    for fault, expected in controls:
        job = windows_job()
        try:
            try:
                create_windows_pseudoconsole_child(
                    child_argv, job, fault=fault
                )
            except SupervisorFailure as failure:
                if failure.code != expected:
                    raise AssertionError("unexpected_fault_classification")
            else:
                raise AssertionError("fault_was_not_injected")
            if windows_active_processes(job) != 0:
                raise AssertionError("fault_left_native_process")
        finally:
            cleanup_confirmed = False
            try:
                if windows_active_processes(job) > 0:
                    KERNEL32.TerminateJobObject(job, 127)
                cleanup_confirmed = wait_until(
                    lambda: windows_active_processes(job) == 0,
                    TREE_JOIN_SECONDS,
                )
            finally:
                cleanup_confirmed = close_windows_handle(job) and cleanup_confirmed
            if not cleanup_confirmed:
                os._exit(127)
    print("process_supervisor_windows_fault_test passed=true controls=3")
    return 0


def main() -> int:
    global START_ACCEPTED
    expected, expected_python, duration, output_limit, child_argv = arguments()
    deadline = time.monotonic() + duration / 1000.0
    actual = source_digest()
    if actual != expected:
        raise SupervisorFailure("source_identity_failed")
    try:
        actual_python = python_executable_digest()
    except SupervisorFailure as exc:
        raise SupervisorFailure("python_identity_failed") from exc
    if actual_python != expected_python:
        raise SupervisorFailure("python_identity_failed")
    runtime = platform.python_implementation()
    version = f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}"
    if runtime not in {"CPython"} or len(version) > 16:
        raise SupervisorFailure("source_identity_failed")
    test_fault = os.environ.get("HTTP_PROCESS_SUPERVISOR_TEST_FAULT", "")
    if test_fault not in {"", "handshake_invalid", "protocol_after_start"}:
        raise SupervisorFailure("protocol_failure")
    if test_fault == "handshake_invalid":
        write_packet(b"invalid-handshake")
    else:
        write_packet(
            (f"H|{actual}|{actual_python}|{runtime}|{version}|{duration}|"
             f"{output_limit}|"
             f"{'conpty-v1' if os.name == 'nt' else 'session-v1'}").encode("ascii")
        )
    start_outcome = wait_for_start(deadline)
    if start_outcome != "start":
        # START is the sole child-creation transition.
        # STOP/clean EOF while waiting has a fully known empty tree and no console to tear down.
        if start_outcome == "deadline":
            write_packet(b"E|supervisor_deadline")
        write_packet(b"F|124|1|0|1|1")
        return 124
    START_ACCEPTED = True
    if test_fault == "protocol_after_start":
        write_packet(b"invalid-protocol-frame")
    try:
        if os.name == "nt":
            status, tree_empty, outlived, requested, console_isolated = supervise_windows(
                child_argv, deadline, output_limit
            )
        else:
            status, tree_empty, outlived, requested, console_isolated = supervise_posix(
                child_argv, deadline, output_limit
            )
    except SupervisorFailure as failure:
        # Only exact pre-child failures may publish a final tree-empty frame.
        # Every post-create failure leaves the final absent so the parent fails closed even after the local cleanup path reports a fixed error.
        if failure.code not in {"child_start_failed", "console_child_start_failed"}:
            raise
        write_packet(b"E|" + failure.code.encode("ascii"))
        status, tree_empty, outlived, requested, console_isolated = (
            127, True, False, False, True
        )
    final = (f"F|{status}|{int(tree_empty)}|{int(outlived)}|"
             f"{int(requested)}|{int(console_isolated)}")
    write_packet(final.encode("ascii"))
    return status


if __name__ == "__main__":
    try:
        if sys.argv[1:] == ["--self-test"]:
            raise SystemExit(self_test())
        if sys.argv[1:] == ["--windows-fault-self-test"]:
            raise SystemExit(windows_fault_self_test())
        if sys.argv[1:] == ["--exception-self-test"]:
            raise ValueError("supervisor-private-exception-marker")
        raise SystemExit(main())
    except SupervisorFailure as failure:
        try:
            write_packet(b"E|" + failure.code.encode("ascii"))
            if not START_ACCEPTED:
                # No START transition means no workload or descendant could have been created.
                # Pair the fixed error with an exact empty lifecycle attestation so the parent can finish containment.
                write_packet(b"F|127|1|0|0|1")
        except (BrokenPipeError, OSError, SupervisorFailure):
            pass
        raise SystemExit(127)
    except BrokenPipeError:
        raise SystemExit(127)
    except Exception:
        # Never let Python render a traceback containing paths, argv,
        # exception values, handles, or implementation details.
        try:
            write_packet(b"E|supervisor_failure")
            if not START_ACCEPTED:
                write_packet(b"F|127|1|0|0|1")
        except (BrokenPipeError, OSError, SupervisorFailure):
            pass
        raise SystemExit(127)

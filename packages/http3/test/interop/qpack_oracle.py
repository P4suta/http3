#!/usr/bin/env python3
# Copyright (c) 2026 the http contributors
# SPDX-FileCopyrightText: 2026 the http contributors
# SPDX-License-Identifier: MIT OR Apache-2.0
"""Pinned pylsqpack half of the bidirectional QPACK differential gate."""

from __future__ import annotations

import hashlib
import importlib
import io
import json
import os
import secrets
import stat
import sys
import tempfile
import threading
from contextlib import contextmanager, suppress
from contextvars import ContextVar
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING

import pylsqpack

if TYPE_CHECKING:
    from collections.abc import Iterator
    from types import ModuleType
    from typing import Never, TypeGuard

__all__ = ("main", "run_cli")

type JsonValue = bool | int | str | list[JsonValue] | dict[str, JsonValue] | None

sys.dont_write_bytecode = True


EXPECTED_VERSION = "1.0.0"
SCHEMA = 2
CAPACITY = 512
BLOCKED_STREAMS = 8
MAX_INPUT_BYTES = 2 * 1024 * 1024
MAX_OUTPUT_BYTES = 2 * 1024 * 1024
MAX_JSON_DEPTH = 64
MAX_JSON_NODES = 100_000
MAX_CONTAINER_ITEMS = 4096
MAX_JSON_INTEGER_TOKEN_BYTES = 32
MAX_STEPS = 1024
MAX_HEADERS_PER_STEP = 64
MAX_TOTAL_FIELDS = 65_536
MAX_PREFIX_BYTES = 1024 * 1024
MAX_STEP_BYTES = 1024 * 1024
MAX_TOTAL_ENCODED_BYTES = 2 * 1024 * 1024
MAX_HEADER_NAME_BYTES = 65_536
MAX_HEADER_VALUE_BYTES = 1024 * 1024
MAX_STEP_ID_BYTES = 128
RUN_ID_HEX_BYTES = 32
LOCK_SUFFIX = ".qpack-lock"
OWNER_FILE = "owner.json"
MAX_PROCESS_EXIT_STATUS = 255
MAX_JSON_KEY_BYTES = 256
MAX_PYTHON_IDENTITY_BYTES = 64
MAX_PYTHON_VERSION_BYTES = 32
PYTHON_VERSION_COMPONENTS = 3
MAX_PYTHON_VERSION_COMPONENT_BYTES = 8
SHA256_BYTES = 32
MAX_ORACLE_MODULES = 4
MAX_ORACLE_ROLE_BYTES = 32
MIN_DIFFERENTIAL_CASES = 2
_FAILURE_CANARY = "private-canary"


@dataclass(frozen=True)
class VerifiedBytes:
    data: bytes
    sha256: str
    size: int


@dataclass
class PublicationState:
    destination: Path
    expected: VerifiedBytes | None = None


_ACTIVE_PUBLICATION: ContextVar[PublicationState | None] = ContextVar(
    "qpack_active_publication",
    default=None,
)


def repository_root() -> Path:
    return Path(__file__).resolve().parents[4]


def _reject(message: str) -> Never:
    raise RuntimeError(message) from None


def require(*, condition: bool, message: str) -> None:
    if not condition:
        _reject(message)


def failure_exit_status(error: BaseException) -> int:
    if type(error) is SystemExit:
        code = error.code
        if type(code) is int and 1 <= code <= MAX_PROCESS_EXIT_STATUS:
            return code
    if type(error) is KeyboardInterrupt:
        return 130
    return 1


def safe_stderr_line(message: str) -> None:
    sink = sys.stderr

    def emit() -> None:
        with suppress(BaseException):
            sink.write(message + "\n")
            sink.flush()

    worker = threading.Thread(target=emit, name="qpack-safe-stderr", daemon=True)
    with suppress(BaseException):
        worker.start()
        worker.join(0.1)


def _absolute_path(path: Path) -> Path:
    return Path(os.path.normpath(path.absolute()))


def _has_reparse_point(metadata: os.stat_result) -> bool:
    return bool(
        getattr(metadata, "st_file_attributes", 0)
        & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400),
    )


def _file_identity(
    metadata: os.stat_result,
    *,
    same_handle_domain: bool = False,
) -> tuple[int, ...]:
    identity = (
        metadata.st_dev,
        metadata.st_ino,
        stat.S_IFMT(metadata.st_mode),
        metadata.st_nlink,
        metadata.st_size,
        getattr(metadata, "st_mtime_ns", int(metadata.st_mtime * 1_000_000_000)),
    )
    # An NTFS replacement can expose different ctimes through a handle and path.
    # Compare ctimes between handles and across both domains on POSIX.
    if os.name != "nt" or same_handle_domain:
        identity += (
            getattr(metadata, "st_ctime_ns", int(metadata.st_ctime * 1_000_000_000)),
        )
    return identity


def _plain_directory(
    path: Path,
    *,
    create: bool = False,
) -> tuple[Path, os.stat_result]:
    absolute = _absolute_path(path)
    metadata: os.stat_result | None = None
    for component in [*reversed(absolute.parents), absolute]:
        try:
            metadata = os.lstat(component)
        except FileNotFoundError:
            require(condition=create, message="missing directory")
            try:
                component.mkdir()
            except FileExistsError:
                pass
            except OSError:
                _reject("directory creation failed")
            try:
                metadata = os.lstat(component)
            except OSError:
                _reject("directory inspection failed")
        except OSError:
            _reject("directory inspection failed")
        require(
            condition=stat.S_ISDIR(metadata.st_mode)
            and not stat.S_ISLNK(metadata.st_mode)
            and not _has_reparse_point(metadata),
            message="unsafe directory",
        )
    require(condition=metadata is not None, message="unsafe directory")
    return absolute, metadata


def _plain_file_metadata(
    path: Path,
    *,
    missing: str = "input missing",
) -> os.stat_result:
    try:
        metadata = os.lstat(path)
    except FileNotFoundError:
        _reject(missing)
    except OSError:
        _reject("input inspection failed")
    require(
        condition=stat.S_ISREG(metadata.st_mode)
        and not stat.S_ISLNK(metadata.st_mode)
        and not _has_reparse_point(metadata),
        message="unsafe file",
    )
    require(condition=metadata.st_nlink == 1, message="hard-linked file rejected")
    return metadata


def _lock_path(path: Path) -> Path:
    return path.with_name(path.name + LOCK_SUFFIX)


def _require_lock_absent(path: Path) -> None:
    try:
        os.lstat(_lock_path(path))
    except FileNotFoundError:
        return
    except OSError:
        _reject("publication lock inspection failed")
    _reject("active or abandoned publication")


def read_verified(
    path: Path,
    limit: int = MAX_INPUT_BYTES,
    *,
    allow_held_lock: bool = False,
) -> VerifiedBytes:
    require(
        condition=type(limit) is int and 0 <= limit <= MAX_INPUT_BYTES,
        message="invalid input limit",
    )
    absolute = _absolute_path(path)
    _plain_directory(absolute.parent)
    if not allow_held_lock:
        _require_lock_absent(absolute)
    initial = _plain_file_metadata(absolute)
    require(
        condition=0 <= initial.st_size <= limit,
        message="input byte limit exceeded",
    )
    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(absolute, flags)
    except OSError:
        _reject("input open failed")
    chunks: list[bytes] = []
    observed = 0
    try:
        opened = os.fstat(descriptor)
        require(
            condition=stat.S_ISREG(opened.st_mode)
            and not _has_reparse_point(opened)
            and opened.st_nlink == 1
            and _file_identity(initial) == _file_identity(opened),
            message="input changed while opening",
        )
        while True:
            request = min(65_536, limit + 1 - observed)
            chunk = os.read(descriptor, request)
            if not chunk:
                break
            chunks.append(chunk)
            observed += len(chunk)
            require(condition=observed <= limit, message="input byte limit exceeded")
        finished = os.fstat(descriptor)
        require(
            condition=_file_identity(opened, same_handle_domain=True)
            == _file_identity(finished, same_handle_domain=True),
            message="input changed while reading",
        )
    finally:
        os.close(descriptor)
    final = _plain_file_metadata(absolute)
    require(
        condition=_file_identity(finished) == _file_identity(final),
        message="input changed while reading",
    )
    _plain_directory(absolute.parent)
    if not allow_held_lock:
        _require_lock_absent(absolute)
    data = b"".join(chunks)
    require(
        condition=len(data) == initial.st_size,
        message="input changed while reading",
    )
    return VerifiedBytes(data, hashlib.sha256(data).hexdigest(), len(data))


def read_bounded(path: Path, limit: int = MAX_INPUT_BYTES) -> bytes:
    return read_verified(path, limit).data


def unique_object(pairs: list[tuple[str, JsonValue]]) -> dict[str, JsonValue]:
    result: dict[str, JsonValue] = {}
    for key, value in pairs:
        require(condition=key not in result, message="duplicate JSON key")
        result[key] = value
    return result


def _json_string_state(byte: int, *, escaped: bool) -> tuple[bool, bool]:
    if escaped:
        return True, False
    if byte == ord("\\"):
        return True, True
    return byte != ord('"'), False


def preflight_json_bytes(data: bytes) -> None:
    depth = 0
    structural_tokens = 0
    integer_token_bytes = 0
    in_string = False
    escaped = False
    for byte in data:
        if in_string:
            in_string, escaped = _json_string_state(byte, escaped=escaped)
            continue
        if byte == ord('"'):
            in_string = True
            integer_token_bytes = 0
        elif byte in b"{[":
            depth += 1
            structural_tokens += 1
            integer_token_bytes = 0
            require(
                condition=depth <= MAX_JSON_DEPTH + 1,
                message="JSON depth limit exceeded",
            )
            require(
                condition=structural_tokens <= MAX_JSON_NODES,
                message="JSON node limit exceeded",
            )
        elif byte in b"}]":
            depth -= 1
            integer_token_bytes = 0
            require(condition=depth >= 0, message="invalid JSON")
        elif byte == ord(","):
            structural_tokens += 1
            integer_token_bytes = 0
            require(
                condition=structural_tokens <= MAX_JSON_NODES,
                message="JSON node limit exceeded",
            )
        elif byte in b"-+0123456789.eE":
            integer_token_bytes += 1
            require(
                condition=integer_token_bytes <= MAX_JSON_INTEGER_TOKEN_BYTES,
                message="JSON integer token limit exceeded",
            )
        else:
            integer_token_bytes = 0


def validate_json_shape(value: object) -> TypeGuard[JsonValue]:
    pending: list[tuple[object, int]] = [(value, 0)]
    nodes = 0
    while pending:
        current, depth = pending.pop()
        nodes += 1
        require(condition=nodes <= MAX_JSON_NODES, message="JSON node limit exceeded")
        require(condition=depth <= MAX_JSON_DEPTH, message="JSON depth limit exceeded")
        if type(current) is dict:
            require(
                condition=len(current) <= MAX_CONTAINER_ITEMS,
                message="JSON object limit exceeded",
            )
            for key, member in current.items():
                require(condition=type(key) is str, message="invalid JSON key")
                require(
                    condition=len(key.encode("utf-8")) <= MAX_JSON_KEY_BYTES,
                    message="JSON key limit exceeded",
                )
                pending.append((member, depth + 1))
        elif type(current) is list:
            require(
                condition=len(current) <= MAX_CONTAINER_ITEMS,
                message="JSON array limit exceeded",
            )
            pending.extend((member, depth + 1) for member in current)
        elif type(current) is str:
            require(
                condition=len(current.encode("utf-8")) <= MAX_INPUT_BYTES,
                message="JSON string limit exceeded",
            )
        elif type(current) is int:
            require(
                condition=-(1 << 63) <= current <= (1 << 63) - 1,
                message="JSON integer limit exceeded",
            )
        else:
            require(
                condition=current is None or type(current) is bool,
                message="invalid JSON scalar",
            )

    return True


def load_json(path: Path) -> tuple[JsonValue, VerifiedBytes]:
    verified = read_verified(path)
    preflight_json_bytes(verified.data)
    try:
        value: object = json.loads(
            verified.data.decode("utf-8"),
            object_pairs_hook=unique_object,
        )
    except (UnicodeError, json.JSONDecodeError):
        _reject("invalid JSON")
    if validate_json_shape(value):
        return value, verified
    _reject("invalid JSON")


def sha256(path: Path) -> str:
    return read_verified(path).sha256


def require_exact_keys(
    value: JsonValue,
    keys: set[str],
    message: str,
) -> dict[str, JsonValue]:
    require(condition=type(value) is dict and set(value) == keys, message=message)
    return value


def require_hex(
    value: JsonValue,
    maximum_bytes: int,
    message: str,
    *,
    allow_empty: bool = True,
) -> bytes:
    require(condition=type(value) is str, message=message)
    require(
        condition=len(value) % 2 == 0 and len(value) <= maximum_bytes * 2,
        message=message,
    )
    require(condition=bool(value) or allow_empty, message=message)
    require(
        condition=all(character in "0123456789abcdef" for character in value),
        message=message,
    )
    try:
        return bytes.fromhex(value)
    except ValueError:
        _reject(message)


def require_run_id(value: JsonValue) -> str:
    require(condition=type(value) is str, message="invalid oracle run ID")
    require_hex(value, RUN_ID_HEX_BYTES, "invalid oracle run ID", allow_empty=False)
    require(
        condition=len(value) == RUN_ID_HEX_BYTES * 2,
        message="invalid oracle run ID",
    )
    return value


def header_json(headers: list[tuple[bytes, bytes]]) -> list[dict[str, str]]:
    return [{"name": name.hex(), "value": value.hex()} for name, value in headers]


def headers_from_json(values: JsonValue) -> list[tuple[bytes, bytes]]:
    require(condition=type(values) is list, message="invalid headers")
    require(
        condition=0 < len(values) <= MAX_HEADERS_PER_STEP,
        message="invalid headers",
    )
    headers: list[tuple[bytes, bytes]] = []
    for value in values:
        header = require_exact_keys(value, {"name", "value"}, "invalid header")
        name = require_hex(
            header["name"],
            MAX_HEADER_NAME_BYTES,
            "invalid header name",
            allow_empty=False,
        )
        field_value = require_hex(
            header["value"],
            MAX_HEADER_VALUE_BYTES,
            "invalid header value",
        )
        headers.append((name, field_value))
    return headers


def _directory_identity(metadata: os.stat_result) -> tuple[int, ...]:
    return (
        metadata.st_dev,
        metadata.st_ino,
        stat.S_IFMT(metadata.st_mode),
        getattr(metadata, "st_uid", 0),
        getattr(metadata, "st_gid", 0),
    )


def _write_all(descriptor: int, data: bytes) -> None:
    offset = 0
    while offset < len(data):
        try:
            written = os.write(descriptor, data[offset:])
        except OSError:
            _reject("output write failed")
        require(condition=written > 0, message="output write failed")
        offset += written


def _invalidate_failed_publication(destination: Path) -> None:
    invalidated = False
    try:
        _invalidate_output_locked(destination)
        invalidated = True
    finally:
        if not invalidated:
            # Retain the owned lock when output invalidation fails.
            _reject("publication lock release failed")


def _release_publication_lock(
    state: PublicationState,
    parent: Path,
    lock: Path,
    owner_bytes: bytes,
    *,
    body_completed: bool,
) -> None:
    owner = lock / OWNER_FILE
    lock_removed = False
    released = False
    try:
        require(
            condition=read_verified(owner).data == owner_bytes,
            message="publication lock changed",
        )
        require(
            condition=tuple(lock.iterdir()) == (owner,),
            message="publication lock contaminated",
        )
        if body_completed:
            _require_bound_publication(state, allow_held_lock=True)
        owner.unlink()
        if body_completed:
            _require_bound_publication(state, allow_held_lock=True)
        lock.rmdir()
        lock_removed = True
        _plain_directory(parent)
        if body_completed:
            _require_bound_publication(state, allow_held_lock=False)
        released = True
    finally:
        if not released:
            if lock_removed:
                _quarantine_unlocked_publication(state.destination, lock)
            _reject("publication lock release failed")


@contextmanager
def publication_lock(destination: Path) -> Iterator[Path]:
    destination = _absolute_path(destination)
    parent, _ = _plain_directory(destination.parent, create=True)
    lock = _lock_path(destination)
    try:
        lock.mkdir()
    except FileExistsError:
        # An active or abandoned lease makes every prior Ready document ineligible.
        # Removing the designated output can only fail closed.
        _invalidate_output_locked(destination)
        _reject("active or abandoned publication")
    except OSError:
        _reject("publication lock failed")
    token = secrets.token_hex(32)
    owner = lock / OWNER_FILE
    owner_bytes = (
        json.dumps(
            {
                "kind": "qpack-oracle-publication",
                "schema": 1,
                "status": "Writing",
                "token": token,
            },
            sort_keys=True,
            separators=(",", ":"),
        )
        + "\n"
    ).encode("utf-8")
    descriptor: int | None = None
    body_completed = False
    state = PublicationState(destination)
    context_token = _ACTIVE_PUBLICATION.set(state)
    try:
        flags = (
            os.O_WRONLY
            | os.O_CREAT
            | os.O_EXCL
            | getattr(os, "O_BINARY", 0)
            | getattr(os, "O_NOFOLLOW", 0)
        )
        try:
            descriptor = os.open(owner, flags, 0o600)
        except OSError:
            _reject("publication lock failed")
        _write_all(descriptor, owner_bytes)
        os.fsync(descriptor)
        os.close(descriptor)
        descriptor = None
        require(
            condition=read_verified(owner).data == owner_bytes,
            message="publication lock changed",
        )
        _plain_directory(lock)
        yield destination
        _require_bound_publication(state, allow_held_lock=True)
        body_completed = True
    finally:
        try:
            if descriptor is not None:
                os.close(descriptor)
            if not body_completed:
                _invalidate_failed_publication(destination)
            _release_publication_lock(
                state,
                parent,
                lock,
                owner_bytes,
                body_completed=body_completed,
            )
        finally:
            _ACTIVE_PUBLICATION.reset(context_token)


def _require_bound_publication(
    state: PublicationState,
    *,
    allow_held_lock: bool,
) -> None:
    if state.expected is None:
        require(
            condition=not os.path.lexists(state.destination),
            message="unbound publication output",
        )
        return
    current = read_verified(
        state.destination,
        MAX_OUTPUT_BYTES,
        allow_held_lock=allow_held_lock,
    )
    require(
        condition=current.data == state.expected.data
        and current.sha256 == state.expected.sha256
        and current.size == state.expected.size,
        message="published output changed",
    )


def _quarantine_unlocked_publication(destination: Path, lock: Path) -> None:
    with suppress(OSError):
        lock.mkdir()
    with suppress(BaseException):
        _invalidate_output_locked(destination)


def _invalidate_output_locked(path: Path) -> None:
    try:
        os.lstat(path)
    except FileNotFoundError:
        return
    except OSError:
        _reject("output inspection failed")
    _ = read_verified(path, MAX_OUTPUT_BYTES, allow_held_lock=True)
    try:
        path.unlink()
    except OSError:
        _reject("prior output invalidation failed")
    require(
        condition=not os.path.lexists(path),
        message="prior output invalidation failed",
    )


def _publish_bytes_locked(path: Path, encoded: bytes) -> VerifiedBytes:
    require(
        condition=0 < len(encoded) <= MAX_OUTPUT_BYTES,
        message="output byte limit exceeded",
    )
    path = _absolute_path(path)
    parent, initial_parent = _plain_directory(path.parent)
    temporary = parent / f".{path.name}.{secrets.token_hex(32)}.pending"
    descriptor: int | None = None
    try:
        flags = (
            os.O_WRONLY
            | os.O_CREAT
            | os.O_EXCL
            | getattr(os, "O_BINARY", 0)
            | getattr(os, "O_NOFOLLOW", 0)
        )
        try:
            descriptor = os.open(temporary, flags, 0o600)
        except OSError:
            _reject("output temporary creation failed")
        _write_all(descriptor, encoded)
        os.fsync(descriptor)
        os.close(descriptor)
        descriptor = None
        require(
            condition=read_verified(temporary, MAX_OUTPUT_BYTES).data == encoded,
            message="output temporary changed",
        )
        _, current_parent = _plain_directory(parent)
        require(
            condition=_directory_identity(initial_parent)
            == _directory_identity(current_parent),
            message="output directory changed",
        )
        # The caller invalidated the old output while holding the sibling lock.
        # A no-replace hard link commits the output.
        # A contender can make the commit fail but cannot overwrite another output.
        require(
            condition=not os.path.lexists(path),
            message="concurrent output publication",
        )
        try:
            os.link(temporary, path, follow_symlinks=False)
        except (FileExistsError, OSError):
            _reject("concurrent output publication")
        temporary.unlink()
        published = read_verified(path, MAX_OUTPUT_BYTES, allow_held_lock=True)
        require(condition=published.data == encoded, message="published output changed")
        if hasattr(os, "O_DIRECTORY"):
            directory_descriptor = os.open(parent, os.O_RDONLY | os.O_DIRECTORY)
            try:
                os.fsync(directory_descriptor)
            finally:
                os.close(directory_descriptor)
        _, final_parent = _plain_directory(parent)
        require(
            condition=_directory_identity(initial_parent)
            == _directory_identity(final_parent),
            message="output directory changed",
        )
        state = _ACTIVE_PUBLICATION.get()
        require(
            condition=state is not None and state.destination == path,
            message="publication lock missing",
        )
        state.expected = published
        return published
    finally:
        if descriptor is not None:
            os.close(descriptor)
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass
        except OSError:
            _reject("output temporary cleanup failed")


def _write_json_locked(path: Path, value: dict[str, JsonValue]) -> VerifiedBytes:
    validate_json_shape(value)
    encoded = (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode(
        "utf-8",
    )
    return _publish_bytes_locked(path, encoded)


def write_json(path: Path, value: dict[str, JsonValue]) -> VerifiedBytes:
    with publication_lock(path) as locked_path:
        _invalidate_output_locked(locked_path)
        return _write_json_locked(locked_path, value)


def oracle_header_sets() -> list[tuple[str, list[tuple[bytes, bytes]]]]:
    return [
        (
            "static-request",
            [
                (b":method", b"GET"),
                (b":scheme", b"https"),
                (b":authority", b"example.com"),
                (b":path", b"/"),
                (b"accept-encoding", b"gzip, deflate, br"),
            ],
        ),
        (
            "literal-huffman",
            [
                (b"x-qpack-differential", b"alpha.example.test/one"),
                (b"cache-control", b"no-cache"),
            ],
        ),
        (
            "repeat-alpha-seed",
            [(b"x-repeat", b"alpha"), (b"cache-control", b"no-cache")],
        ),
        (
            "repeat-alpha-dynamic",
            [(b"x-repeat", b"alpha"), (b"cache-control", b"no-cache")],
        ),
        (
            "repeat-alpha-known",
            [(b"x-repeat", b"alpha"), (b"cache-control", b"no-cache")],
        ),
        (
            "repeat-beta-seed",
            [(b"x-repeat", b"alpha"), (b"x-other", b"beta")],
        ),
        (
            "repeat-beta-dynamic",
            [(b"x-repeat", b"alpha"), (b"x-other", b"beta")],
        ),
        (
            "binary-literal",
            [(b"x-binary", bytes([0, 255, 127, 1])), (b":method", b"POST")],
        ),
        (
            "long-value-seed",
            [(b"x-long", b"0123456789abcdef" * 12)],
        ),
        (
            "long-value-dynamic",
            [(b"x-long", b"0123456789abcdef" * 12)],
        ),
    ]


def _module_file_identity(role: str, module: ModuleType) -> dict[str, JsonValue]:
    location = getattr(module, "__file__", None)
    require(
        condition=type(location) is str and bool(location),
        message="oracle module identity unavailable",
    )
    verified = read_verified(Path(location))
    return {
        "role": role,
        "sha256": verified.sha256,
        "bytes": verified.size,
    }


def _python_runtime_identity() -> dict[str, str]:
    implementation = sys.implementation.name
    cache_tag = sys.implementation.cache_tag
    version = ".".join(str(component) for component in sys.version_info[:3])
    require(
        condition=implementation == "cpython"
        and type(cache_tag) is str
        and 0 < len(cache_tag) <= MAX_PYTHON_IDENTITY_BYTES,
        message="python runtime identity unavailable",
    )
    return {
        "implementation": implementation,
        "version": version,
        "cache_tag": cache_tag,
    }


def _validate_python_runtime_identity(value: JsonValue) -> dict[str, str]:
    runtime = require_exact_keys(
        value,
        {"implementation", "version", "cache_tag"},
        "invalid python runtime identity",
    )
    require(
        condition=runtime["implementation"] == "cpython",
        message="invalid python implementation",
    )
    version = runtime["version"]
    version_parts = version.split(".") if type(version) is str else []
    require(
        condition=type(version) is str
        and 0 < len(version) <= MAX_PYTHON_VERSION_BYTES
        and len(version_parts) == PYTHON_VERSION_COMPONENTS
        and all(
            0 < len(part) <= MAX_PYTHON_VERSION_COMPONENT_BYTES
            and all("0" <= character <= "9" for character in part)
            for part in version_parts
        ),
        message="invalid python version",
    )
    cache_tag = runtime["cache_tag"]
    require(
        condition=type(cache_tag) is str
        and 0 < len(cache_tag) <= MAX_PYTHON_IDENTITY_BYTES
        and all(
            character in "abcdefghijklmnopqrstuvwxyz0123456789-_"
            for character in cache_tag
        ),
        message="invalid python cache tag",
    )
    return runtime


def current_oracle_identity() -> dict[str, JsonValue]:
    require(
        condition=type(getattr(pylsqpack, "__version__", None)) is str
        and pylsqpack.__version__ == EXPECTED_VERSION,
        message="unexpected pylsqpack version",
    )
    driver = read_verified(Path(__file__))
    lock_path = repository_root() / "packages/http3/test/interop/requirements.txt"
    lock = read_verified(lock_path)
    binding_name = getattr(getattr(pylsqpack, "Encoder", None), "__module__", None)
    require(
        condition=type(binding_name) is str and bool(binding_name),
        message="oracle module identity unavailable",
    )
    binding = importlib.import_module(binding_name)
    identities = [_module_file_identity("package", pylsqpack)]
    binding_identity = _module_file_identity("binding", binding)
    if binding_identity["sha256"] != identities[0]["sha256"]:
        identities.append(binding_identity)
    return {
        "name": "pylsqpack",
        "version": EXPECTED_VERSION,
        "requirements_lock": "packages/http3/test/interop/requirements.txt",
        "requirements_lock_sha256": lock.sha256,
        "driver_sha256": driver.sha256,
        "python_runtime": _python_runtime_identity(),
        "module_files": identities,
    }


def validate_oracle_identity(
    value: JsonValue,
    *,
    require_current: bool,
) -> dict[str, JsonValue]:
    identity = require_exact_keys(
        value,
        {
            "name",
            "version",
            "requirements_lock",
            "requirements_lock_sha256",
            "driver_sha256",
            "python_runtime",
            "module_files",
        },
        "invalid oracle identity",
    )
    require(condition=identity["name"] == "pylsqpack", message="invalid oracle name")
    require(
        condition=identity["version"] == EXPECTED_VERSION,
        message="invalid oracle version",
    )
    require(
        condition=identity["requirements_lock"]
        == "packages/http3/test/interop/requirements.txt",
        message="invalid oracle lock path",
    )
    require_hex(
        identity["requirements_lock_sha256"],
        SHA256_BYTES,
        "invalid oracle lock digest",
        allow_empty=False,
    )
    require(
        condition=len(identity["requirements_lock_sha256"]) == SHA256_BYTES * 2,
        message="invalid oracle lock digest",
    )
    require_hex(
        identity["driver_sha256"],
        SHA256_BYTES,
        "invalid oracle driver digest",
        allow_empty=False,
    )
    require(
        condition=len(identity["driver_sha256"]) == SHA256_BYTES * 2,
        message="invalid oracle driver digest",
    )
    _validate_python_runtime_identity(identity["python_runtime"])
    modules = identity["module_files"]
    require(
        condition=type(modules) is list and 1 <= len(modules) <= MAX_ORACLE_MODULES,
        message="invalid oracle modules",
    )
    roles: set[str] = set()
    for module_value in modules:
        module = require_exact_keys(
            module_value,
            {"role", "sha256", "bytes"},
            "invalid oracle module",
        )
        role = module["role"]
        require(
            condition=type(role) is str
            and 0 < len(role) <= MAX_ORACLE_ROLE_BYTES
            and all(character in "abcdefghijklmnopqrstuvwxyz-_" for character in role),
            message="invalid oracle module role",
        )
        require(condition=role not in roles, message="duplicate oracle module role")
        roles.add(role)
        require_hex(
            module["sha256"],
            SHA256_BYTES,
            "invalid oracle module digest",
            allow_empty=False,
        )
        require(
            condition=len(module["sha256"]) == SHA256_BYTES * 2,
            message="invalid oracle module digest",
        )
        require(
            condition=type(module["bytes"]) is int
            and 0 < module["bytes"] <= MAX_INPUT_BYTES,
            message="invalid oracle module size",
        )
    if require_current:
        require(
            condition=identity == current_oracle_identity(),
            message="stale oracle identity",
        )
    return identity


def validate_transcript(document: JsonValue, expected_direction: str) -> dict[str, int]:
    require(
        condition=expected_direction in {"pylsqpack-to-http3", "http3-to-pylsqpack"},
        message="invalid expected direction",
    )
    expected_keys = {
        "schema",
        "direction",
        "oracle",
        "configuration",
        "oracle_run_id",
        "steps",
    }
    if expected_direction == "pylsqpack-to-http3":
        expected_keys.add("encoder_stream_prefix")
    transcript = require_exact_keys(
        document,
        expected_keys,
        "invalid transcript fields",
    )
    require(
        condition=type(transcript["schema"]) is int and transcript["schema"] == SCHEMA,
        message="invalid transcript schema",
    )
    require(
        condition=transcript["direction"] == expected_direction,
        message="invalid transcript direction",
    )
    validate_oracle_identity(transcript["oracle"], require_current=True)
    require_run_id(transcript["oracle_run_id"])
    configuration = require_exact_keys(
        transcript["configuration"],
        {"maximum_table_capacity", "maximum_blocked_streams"},
        "invalid configuration",
    )
    require(
        condition=type(configuration["maximum_table_capacity"]) is int
        and configuration["maximum_table_capacity"] == CAPACITY,
        message="capacity drift",
    )
    require(
        condition=type(configuration["maximum_blocked_streams"]) is int
        and configuration["maximum_blocked_streams"] == BLOCKED_STREAMS,
        message="blocked-stream drift",
    )
    prefix_bytes = 0
    if expected_direction == "pylsqpack-to-http3":
        prefix_bytes = len(
            require_hex(
                transcript["encoder_stream_prefix"],
                MAX_PREFIX_BYTES,
                "invalid encoder stream prefix",
            ),
        )
    steps = transcript["steps"]
    require(
        condition=type(steps) is list and 0 < len(steps) <= MAX_STEPS,
        message="invalid steps",
    )
    streams: set[int] = set()
    fields = 0
    blocked_cases = 0
    encoded_bytes = prefix_bytes
    for value in steps:
        step_keys = {
            "id",
            "stream_id",
            "delivery",
            "encoder_stream",
            "field_section",
            "headers",
        }
        if expected_direction == "pylsqpack-to-http3":
            step_keys.add("decoder_stream")
        step = require_exact_keys(value, step_keys, "invalid step")
        case_id = step["id"]
        require(
            condition=type(case_id) is str
            and 0 < len(case_id.encode("utf-8")) <= MAX_STEP_ID_BYTES,
            message="invalid step ID",
        )
        stream_id = step["stream_id"]
        require(
            condition=type(stream_id) is int and 0 <= stream_id <= (1 << 62) - 1,
            message="invalid stream ID",
        )
        require(condition=stream_id not in streams, message="duplicate stream ID")
        streams.add(stream_id)
        allowed = {"encoder_first", "header_first"}
        if expected_direction == "pylsqpack-to-http3":
            allowed.add("header_before_encoder_unblocked")
        require(condition=step["delivery"] in allowed, message="invalid delivery mode")
        encoder_stream = require_hex(
            step["encoder_stream"],
            MAX_STEP_BYTES,
            "invalid encoder stream",
        )
        field_section = require_hex(
            step["field_section"],
            MAX_STEP_BYTES,
            "invalid field section",
            allow_empty=False,
        )
        decoder_stream = b""
        if expected_direction == "pylsqpack-to-http3":
            decoder_stream = require_hex(
                step["decoder_stream"],
                MAX_STEP_BYTES,
                "invalid decoder stream",
            )
        step_bytes = len(encoder_stream) + len(field_section) + len(decoder_stream)
        require(
            condition=step_bytes <= MAX_STEP_BYTES,
            message="step byte limit exceeded",
        )
        decoded_headers = headers_from_json(step["headers"])
        fields += len(decoded_headers)
        encoded_bytes += step_bytes + sum(
            len(name) + len(field_value) for name, field_value in decoded_headers
        )
        require(
            condition=fields <= MAX_TOTAL_FIELDS,
            message="field count limit exceeded",
        )
        require(
            condition=encoded_bytes <= MAX_TOTAL_ENCODED_BYTES,
            message="transcript byte limit exceeded",
        )
        if step["delivery"] == "header_first":
            blocked_cases += 1
    return {
        "cases": len(steps),
        "fields": fields,
        "blocked_cases": blocked_cases,
        "encoded_bytes": encoded_bytes,
    }


def generate(path: Path) -> None:
    with publication_lock(path) as locked_path:
        _invalidate_output_locked(locked_path)
        oracle_identity = current_oracle_identity()
        oracle_run_id = secrets.token_hex(RUN_ID_HEX_BYTES)
        encoder = pylsqpack.Encoder()
        decoder = pylsqpack.Decoder(CAPACITY, BLOCKED_STREAMS)
        prefix = encoder.apply_settings(CAPACITY, BLOCKED_STREAMS)
        require(
            condition=len(prefix) <= MAX_PREFIX_BYTES,
            message="encoder prefix limit exceeded",
        )
        require(
            condition=decoder.feed_encoder(prefix) == [],
            message="settings unblocked a stream",
        )

        steps: list[dict[str, JsonValue]] = []
        blocked_cases = 0
        dynamic_steps = 0
        for index, (case_id, headers) in enumerate(oracle_header_sets()):
            stream_id = index * 4
            encoder_stream, field_section = encoder.encode(stream_id, headers)
            require(
                condition=len(encoder_stream) + len(field_section) <= MAX_STEP_BYTES,
                message="generated step byte limit exceeded",
            )
            if encoder_stream:
                dynamic_steps += 1
                try:
                    control, decoded = decoder.feed_header(stream_id, field_section)
                except pylsqpack.StreamBlocked:
                    delivery = "header_first"
                    blocked_cases += 1
                    unblocked = decoder.feed_encoder(encoder_stream)
                    require(
                        condition=stream_id in unblocked,
                        message="stream was not unblocked",
                    )
                    control, decoded = decoder.resume_header(stream_id)
                else:
                    delivery = "header_before_encoder_unblocked"
                    require(
                        condition=decoder.feed_encoder(encoder_stream) == [],
                        message="unexpected unblocked stream",
                    )
            else:
                delivery = "encoder_first"
                control, decoded = decoder.feed_header(stream_id, field_section)

            require(
                condition=decoded == headers,
                message="pylsqpack self-round-trip mismatch",
            )
            require(
                condition=len(control) <= MAX_STEP_BYTES,
                message="decoder stream limit exceeded",
            )
            if control:
                encoder.feed_decoder(control)
            steps.append(
                {
                    "id": case_id,
                    "stream_id": stream_id,
                    "delivery": delivery,
                    "encoder_stream": encoder_stream.hex(),
                    "field_section": field_section.hex(),
                    "decoder_stream": control.hex(),
                    "headers": header_json(headers),
                },
            )

        require(
            condition=blocked_cases >= MIN_DIFFERENTIAL_CASES,
            message="oracle corpus lost blocked-stream coverage",
        )
        require(
            condition=dynamic_steps >= MIN_DIFFERENTIAL_CASES,
            message="oracle corpus lost dynamic-table coverage",
        )
        document = {
            "schema": SCHEMA,
            "direction": "pylsqpack-to-http3",
            "oracle": oracle_identity,
            "oracle_run_id": oracle_run_id,
            "configuration": {
                "maximum_table_capacity": CAPACITY,
                "maximum_blocked_streams": BLOCKED_STREAMS,
            },
            "encoder_stream_prefix": prefix.hex(),
            "steps": steps,
        }
        _ = validate_transcript(document, "pylsqpack-to-http3")
        _write_json_locked(locked_path, document)
        require(
            condition=oracle_identity == current_oracle_identity(),
            message="oracle identity changed during generation",
        )


def verify(source: Path, report: Path) -> None:
    with publication_lock(report) as locked_report:
        _invalidate_output_locked(locked_report)
        document, source_verified = load_json(source)
        summary = validate_transcript(document, "http3-to-pylsqpack")
        configuration = document["configuration"]
        capacity = configuration["maximum_table_capacity"]
        blocked_streams = configuration["maximum_blocked_streams"]
        decoder = pylsqpack.Decoder(capacity, blocked_streams)

        blocked_cases = 0
        fields = 0
        control_bytes = 0
        for step in document["steps"]:
            stream_id = step["stream_id"]
            encoder_stream = require_hex(
                step["encoder_stream"],
                MAX_STEP_BYTES,
                "invalid encoder stream",
            )
            field_section = require_hex(
                step["field_section"],
                MAX_STEP_BYTES,
                "invalid field section",
                allow_empty=False,
            )
            expected = headers_from_json(step["headers"])
            delivery = step["delivery"]
            if delivery == "header_first":
                try:
                    decoder.feed_header(stream_id, field_section)
                except pylsqpack.StreamBlocked:
                    blocked_cases += 1
                else:
                    _reject("expected StreamBlocked")
                unblocked = decoder.feed_encoder(encoder_stream)
                require(
                    condition=stream_id in unblocked,
                    message="stream not unblocked",
                )
                control, decoded = decoder.resume_header(stream_id)
            elif delivery == "encoder_first":
                require(
                    condition=decoder.feed_encoder(encoder_stream) == [],
                    message="unexpected unblocked stream",
                )
                control, decoded = decoder.feed_header(stream_id, field_section)
            else:
                _reject("invalid delivery mode")
            require(condition=decoded == expected, message="header mismatch")
            fields += len(decoded)
            control_bytes += len(control)
            require(
                condition=control_bytes <= MAX_TOTAL_ENCODED_BYTES,
                message="decoder control byte limit exceeded",
            )

        require(
            condition=blocked_cases >= MIN_DIFFERENTIAL_CASES,
            message="implementation corpus lost blocked coverage",
        )
        require(
            condition=blocked_cases == summary["blocked_cases"],
            message="blocked count drift",
        )
        require(condition=fields == summary["fields"], message="field count drift")
        report_value = {
            "schema": SCHEMA,
            "status": "Ready",
            "direction": "http3-to-pylsqpack",
            "oracle": document["oracle"],
            "oracle_run_id": document["oracle_run_id"],
            "cases": summary["cases"],
            "fields": fields,
            "blocked_cases": blocked_cases,
            "decoder_control_bytes": control_bytes,
            "implementation_bytes": source_verified.size,
            "implementation_sha256": source_verified.sha256,
        }
        _write_json_locked(locked_report, report_value)
        current_source = read_verified(source)
        require(
            condition=current_source.data == source_verified.data
            and current_source.sha256 == source_verified.sha256
            and current_source.size == source_verified.size,
            message="implementation changed during verification",
        )
        require(
            condition=document["oracle"] == current_oracle_identity(),
            message="oracle identity changed during verification",
        )


def _self_test_roundtrip(directory: Path) -> None:
    path = directory / "oracle.json"
    generate(path)
    document, _document_bytes = load_json(path)
    require(condition=document["schema"] == SCHEMA, message="self-test schema mismatch")
    require(
        condition=len(document["steps"]) == len(oracle_header_sets()),
        message="case loss",
    )
    require(
        condition=sum(step["delivery"] == "header_first" for step in document["steps"])
        >= MIN_DIFFERENTIAL_CASES,
        message="blocked self-test coverage lost",
    )
    require(
        condition=not list(directory.glob(".oracle.json.*.pending")),
        message="temporary output retained",
    )
    require(
        condition=not os.path.lexists(_lock_path(path)),
        message="publication lock retained",
    )


def _self_test_json_rejections(directory: Path) -> None:
    duplicate = directory / "duplicate.json"
    duplicate.write_bytes(b'{"key":1,"key":2}')
    try:
        load_json(duplicate)
    except RuntimeError as error:
        require(
            condition=str(error) == "duplicate JSON key",
            message="wrong duplicate-key failure",
        )
    else:
        _reject("duplicate JSON key accepted")
    oversized = directory / "oversized.json"
    oversized.write_bytes(b"x" * (MAX_INPUT_BYTES + 1))
    try:
        read_bounded(oversized)
    except RuntimeError as error:
        require(
            condition=str(error) == "input byte limit exceeded",
            message="wrong input-limit failure",
        )
    else:
        _reject("oversized input accepted")
    verified = directory / "verified.json"
    verified.write_bytes(b'{"schema":1}')
    _verified_document, verified_bytes = load_json(verified)
    verified.write_bytes(b'{"schema":2}')
    require(
        condition=verified_bytes.sha256 != sha256(verified),
        message="verified-byte digest was not retained",
    )
    nested: JsonValue = None
    for _ in range(MAX_JSON_DEPTH + 1):
        nested = [nested]
    try:
        validate_json_shape(nested)
    except RuntimeError as error:
        require(
            condition=str(error) == "JSON depth limit exceeded",
            message="wrong depth failure",
        )
    else:
        _reject("excessive JSON depth accepted")
    try:
        validate_json_shape([[None] * 1000 for _ in range(101)])
    except RuntimeError as error:
        require(
            condition=str(error) == "JSON node limit exceeded",
            message="wrong node failure",
        )
    else:
        _reject("excessive JSON node count accepted")


def _self_test_cli_failures() -> None:
    captured = io.StringIO()
    previous_stderr = sys.stderr
    try:
        sys.stderr = captured
        require(
            condition=run_cli(["private-canary"]) == 1,
            message="failure status changed",
        )
    finally:
        sys.stderr = previous_stderr
    require(
        condition=captured.getvalue() == "qpack oracle failed\n",
        message="failure details escaped",
    )

    class BrokenSink:
        def write(self, _value: str) -> int:
            raise OSError(_FAILURE_CANARY)

        def flush(self) -> None:
            raise OSError(_FAILURE_CANARY)

    previous_stderr = sys.stderr
    try:
        sys.stderr = BrokenSink()
        require(
            condition=run_cli(["private-canary"]) == 1,
            message="broken sink changed failure status",
        )
    finally:
        sys.stderr = previous_stderr

    class HostileSystemExit(SystemExit):
        def __getattribute__(self, _name: str) -> Never:
            _reject("private-canary")

    class HostileKeyboardInterrupt(KeyboardInterrupt):
        def __getattribute__(self, _name: str) -> Never:
            _reject("private-canary")

    require(
        condition=failure_exit_status(HostileSystemExit()) == 1,
        message="hostile SystemExit escaped",
    )
    require(
        condition=failure_exit_status(HostileKeyboardInterrupt()) == 1,
        message="hostile KeyboardInterrupt escaped",
    )


def self_test() -> None:
    require(
        condition=pylsqpack.__version__ == EXPECTED_VERSION,
        message="unexpected pylsqpack version",
    )
    with tempfile.TemporaryDirectory(prefix="qpack-oracle-self-test-") as temporary:
        directory = Path(temporary)
        _self_test_roundtrip(directory)
        _self_test_json_rejections(directory)
    _self_test_cli_failures()


def main(arguments: list[str]) -> None:
    """Run one bounded oracle operation or raise its validation failure."""
    match arguments:
        case ["--self-test"]:
            self_test()
        case ["generate", output]:
            generate(Path(output))
        case ["verify", source, report]:
            verify(Path(source), Path(report))
        case _:
            _reject(
                "usage: qpack_oracle.py --self-test | generate OUTPUT | "
                "verify INPUT REPORT",
            )


def run_cli(arguments: list[str]) -> int:
    """Convert every operation failure into fixed output and an exit status."""
    try:
        main(arguments)
    except BaseException as error:  # noqa: BLE001
        # The CLI contains hostile BaseException subclasses and emits only fixed text.
        safe_stderr_line("qpack oracle failed")
        return failure_exit_status(error)
    else:
        return 0


if __name__ == "__main__":
    raise SystemExit(run_cli(sys.argv[1:]))

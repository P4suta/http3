#!/usr/bin/env python3

# SPDX-FileCopyrightText: 2026 the http contributors
# SPDX-License-Identifier: MIT OR Apache-2.0

"""Fail-closed filesystem state machines for the RFC 9114 v4 audit."""

from __future__ import annotations

import errno
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat
import sys
import tempfile
from typing import Any, Callable


MAX_BYTES = 32 * 1024 * 1024
MAX_DIRECTORY_ENTRIES = 4096
RUN_ID = re.compile(r"^[0-9a-f]{32}$")
SAFE_CATEGORY = re.compile(r"^[a-z0-9_]{1,120}$")
Hook = Callable[[str, Path], None]


class Rejected(ValueError):
    pass


class SimulatedCrash(BaseException):
    """A test-only abrupt-stop signal which production handlers must not catch."""


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def safe_category(value: str) -> str:
    return value if SAFE_CATEGORY.fullmatch(value) else "typed_rejection"


def invoke(hook: Hook | None, boundary: str, path: Path) -> None:
    if hook is not None:
        hook(boundary, path)


def fsync_parent(path: Path) -> None:
    if os.name != "posix":
        return
    descriptor = None
    try:
        descriptor = os.open(path.parent, os.O_RDONLY)
        os.fsync(descriptor)
    except OSError as error:
        raise Rejected("directory_sync_failed") from error
    finally:
        if descriptor is not None:
            os.close(descriptor)


def is_reparse(metadata: os.stat_result) -> bool:
    attributes = getattr(metadata, "st_file_attributes", 0)
    marker = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
    return bool(attributes & marker)


def same_identity(left: os.stat_result, right: os.stat_result) -> bool:
    return (left.st_dev, left.st_ino) == (right.st_dev, right.st_ino)


def identity_token(metadata: os.stat_result, run_id: str) -> str:
    return digest(
        f"{run_id}:{metadata.st_dev}:{metadata.st_ino}".encode("ascii", "strict")
    )


def assert_plain_directory(path: Path, category: str) -> None:
    try:
        metadata = os.stat(path, follow_symlinks=False)
    except OSError as error:
        raise Rejected(category) from error
    if (
        not stat.S_ISDIR(metadata.st_mode)
        or stat.S_ISLNK(metadata.st_mode)
        or is_reparse(metadata)
    ):
        raise Rejected(category)


def bounded_directory_entries(
    directory: Path,
    category: str,
    *,
    limit: int = MAX_DIRECTORY_ENTRIES,
) -> list[Path]:
    """Return a deterministically ordered, explicitly finite directory view."""

    entries: list[Path] = []
    try:
        with os.scandir(directory) as scanner:
            for entry in scanner:
                if len(entries) >= limit:
                    raise Rejected(category)
                entries.append(Path(entry.path))
    except Rejected:
        raise
    except OSError as error:
        raise Rejected(category) from error
    entries.sort(key=lambda item: item.name)
    return entries


def checked_relative_path(root: Path, relative: str) -> Path:
    parsed = PurePosixPath(relative)
    if (
        parsed.is_absolute()
        or not parsed.parts
        or any(part in {"", ".", ".."} for part in parsed.parts)
        or "\\" in relative
    ):
        raise Rejected("input_path_invalid")
    current = root
    root_metadata = os.stat(root, follow_symlinks=False)
    if not stat.S_ISDIR(root_metadata.st_mode) or is_reparse(root_metadata):
        raise Rejected("input_root_alias_rejected")
    for part in parsed.parts[:-1]:
        current = current / part
        try:
            metadata = os.stat(current, follow_symlinks=False)
        except OSError as error:
            raise Rejected("input_component_missing") from error
        if (
            not stat.S_ISDIR(metadata.st_mode)
            or stat.S_ISLNK(metadata.st_mode)
            or is_reparse(metadata)
        ):
            raise Rejected("input_alias_rejected")
    return root.joinpath(*parsed.parts)


def strict_read_path(
    path: Path,
    *,
    hook: Hook | None = None,
    max_bytes: int = MAX_BYTES,
    require_single_link: bool = True,
    with_metadata: bool = False,
) -> bytes | tuple[bytes, os.stat_result]:
    """Read one unaliased inode and reject name or content swaps during the read."""

    descriptor = None
    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0)
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        before_name = os.stat(path, follow_symlinks=False)
        if (
            not stat.S_ISREG(before_name.st_mode)
            or stat.S_ISLNK(before_name.st_mode)
            or is_reparse(before_name)
            or (require_single_link and before_name.st_nlink != 1)
        ):
            raise Rejected("input_alias_rejected")
        descriptor = os.open(path, flags)
        before_fd = os.fstat(descriptor)
        if (
            not stat.S_ISREG(before_fd.st_mode)
            or is_reparse(before_fd)
            or (require_single_link and before_fd.st_nlink != 1)
            or not same_identity(before_name, before_fd)
        ):
            raise Rejected("input_alias_rejected")
        invoke(hook, "after_open", path)
        chunks: list[bytes] = []
        size = 0
        while True:
            chunk = os.read(descriptor, min(65536, max_bytes + 1 - size))
            if not chunk:
                break
            chunks.append(chunk)
            size += len(chunk)
            if size > max_bytes:
                raise Rejected("input_too_large")
        after_fd = os.fstat(descriptor)
        after_name = os.stat(path, follow_symlinks=False)
        stable_metadata = (
            same_identity(before_fd, after_fd)
            and same_identity(after_fd, after_name)
            and before_fd.st_size == after_fd.st_size
            and before_fd.st_mtime_ns == after_fd.st_mtime_ns
            and before_fd.st_ctime_ns == after_fd.st_ctime_ns
            and before_fd.st_nlink == after_fd.st_nlink
            and after_fd.st_nlink == after_name.st_nlink
            and (not require_single_link or after_fd.st_nlink == 1)
            and not is_reparse(after_name)
        )
        if not stable_metadata:
            raise Rejected("input_changed_during_read")
        data = b"".join(chunks)
        return (data, after_fd) if with_metadata else data
    except Rejected:
        raise
    except FileNotFoundError as error:
        raise Rejected("input_missing") from error
    except OSError as error:
        raise Rejected("input_read_failed") from error
    finally:
        if descriptor is not None:
            os.close(descriptor)


def strict_read(root: Path, relative: str, *, hook: Hook | None = None) -> bytes:
    return strict_read_path(checked_relative_path(root, relative), hook=hook)


def optional_strict_digest(path: Path) -> str | None:
    try:
        metadata = os.stat(path, follow_symlinks=False)
    except FileNotFoundError:
        return None
    except OSError as error:
        raise Rejected("transaction_artifact_unreadable") from error
    if (
        not stat.S_ISREG(metadata.st_mode)
        or stat.S_ISLNK(metadata.st_mode)
        or is_reparse(metadata)
        or metadata.st_nlink != 1
    ):
        raise Rejected("transaction_artifact_alias_rejected")
    return digest(strict_read_path(path))


def generated_read(path: Path, max_bytes: int = MAX_BYTES) -> bytes:
    try:
        with path.open("rb") as handle:
            data = handle.read(max_bytes + 1)
            if len(data) > max_bytes or handle.read(1):
                raise Rejected("generated_input_too_large")
            return data
    except Rejected:
        raise
    except FileNotFoundError as error:
        raise Rejected("generated_input_missing") from error
    except OSError as error:
        raise Rejected("generated_input_read_failed") from error


def durable_new_file(path: Path, data: bytes, mode: int = 0o600) -> None:
    descriptor = None
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, mode)
        with os.fdopen(descriptor, "wb") as handle:
            descriptor = None
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        fsync_parent(path)
    except FileExistsError as error:
        raise Rejected("exclusive_create_conflict") from error
    except Rejected:
        raise
    except OSError as error:
        raise Rejected("exclusive_create_failed") from error
    finally:
        if descriptor is not None:
            os.close(descriptor)


def atomic_write(
    path: Path,
    data: bytes,
    *,
    hook: Hook | None = None,
    prefix: str,
    pre_replace: Callable[[], None] | None = None,
    replace_is_commit: bool = False,
) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{path.name}.", suffix=".tmp", dir=path.parent
    )
    temporary = Path(temporary_name)
    replaced = False
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        invoke(hook, f"{prefix}_after_stage", path)
        invoke(hook, f"{prefix}_before_replace", path)
        if pre_replace is not None:
            pre_replace()
        os.replace(temporary, path)
        replaced = True
        # A final canonical pointer is the transaction's linearization point.
        # Its immutable report, per-mode pointer, Done marker, and intent journal are already durable.
        # Once replace succeeds, no later hook,
        # readback, or fallible operation may turn that Final into a reported failure.
        # A crash leaves either the prior Running pointer or this fully consumable Final pointer.
        if replace_is_commit:
            # Persist the directory entry when the platform exposes directory fsync.
            # Once replace has succeeded the Final pointer is authoritative, so a later durability API failure cannot be reported as a rejected publication; recovery/consumption will still validate the exact immutable pair under both locks.
            try:
                fsync_parent(path)
            except Rejected:
                pass
            invoke(hook, f"{prefix}_after_commit", path)
            return
        fsync_parent(path)
        invoke(hook, f"{prefix}_after_replace", path)
        if generated_read(path) != data:
            raise Rejected("generated_write_readback_mismatch")
    except (Rejected, SimulatedCrash):
        raise
    except OSError as error:
        raise Rejected("generated_write_failed") from error
    finally:
        if not replaced:
            try:
                temporary.unlink(missing_ok=True)
            except OSError:
                pass


def exclusive_rename(source: Path, destination: Path) -> None:
    """Atomically move ``source`` without ever replacing ``destination``."""

    if destination.exists():
        raise Rejected("transaction_claim_conflict")
    try:
        if os.name == "nt":
            # Windows rename is exclusive when the destination exists.
            os.rename(source, destination)
        elif sys.platform.startswith("linux"):
            import ctypes

            libc = ctypes.CDLL(None, use_errno=True)
            renameat2 = getattr(libc, "renameat2", None)
            if renameat2 is None:
                raise Rejected("exclusive_rename_unsupported")
            renameat2.argtypes = [
                ctypes.c_int,
                ctypes.c_char_p,
                ctypes.c_int,
                ctypes.c_char_p,
                ctypes.c_uint,
            ]
            renameat2.restype = ctypes.c_int
            result = renameat2(
                -100,
                os.fsencode(source),
                -100,
                os.fsencode(destination),
                1,
            )
            if result != 0:
                error_number = ctypes.get_errno()
                if error_number == errno.EEXIST:
                    raise Rejected("transaction_claim_conflict")
                raise OSError(error_number, "renameat2")
        elif sys.platform == "darwin":
            import ctypes

            libc = ctypes.CDLL(None, use_errno=True)
            renamex_np = getattr(libc, "renamex_np", None)
            if renamex_np is None:
                raise Rejected("exclusive_rename_unsupported")
            renamex_np.argtypes = [ctypes.c_char_p, ctypes.c_char_p, ctypes.c_uint]
            renamex_np.restype = ctypes.c_int
            result = renamex_np(os.fsencode(source), os.fsencode(destination), 0x4)
            if result != 0:
                error_number = ctypes.get_errno()
                if error_number == errno.EEXIST:
                    raise Rejected("transaction_claim_conflict")
                raise OSError(error_number, "renamex_np")
        else:
            raise Rejected("exclusive_rename_unsupported")
        fsync_parent(source)
        if source.parent != destination.parent:
            fsync_parent(destination)
    except Rejected:
        raise
    except FileExistsError as error:
        raise Rejected("transaction_claim_conflict") from error
    except OSError as error:
        raise Rejected("transaction_claim_failed") from error


def json_bytes(value: dict[str, Any]) -> bytes:
    return (json.dumps(value, indent=2, sort_keys=True) + "\n").encode("utf-8")


def json_object(data: bytes, category: str) -> dict[str, Any]:
    def closed_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        value: dict[str, Any] = {}
        for key, item in pairs:
            if key in value:
                raise Rejected(f"{category}_duplicate_key")
            value[key] = item
        return value

    try:
        value = json.loads(data, object_pairs_hook=closed_pairs)
    except Rejected:
        raise
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise Rejected(f"{category}_invalid") from error
    if not isinstance(value, dict):
        raise Rejected(f"{category}_not_object")
    return value


class ProcessFileLock:
    """A nonblocking process-owned lock released by the OS after a crash."""

    def __init__(self, path: Path):
        self.path = path
        self.descriptor: int | None = None

    def acquire(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        parent_metadata = os.stat(self.path.parent, follow_symlinks=False)
        if (
            not stat.S_ISDIR(parent_metadata.st_mode)
            or stat.S_ISLNK(parent_metadata.st_mode)
            or is_reparse(parent_metadata)
        ):
            raise Rejected("exclusive_lock_alias_rejected")
        flags = os.O_RDWR | os.O_CREAT | getattr(os, "O_BINARY", 0)
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        descriptor = os.open(self.path, flags, 0o600)
        try:
            descriptor_metadata = os.fstat(descriptor)
            name_metadata = os.stat(self.path, follow_symlinks=False)
            if (
                not stat.S_ISREG(descriptor_metadata.st_mode)
                or not stat.S_ISREG(name_metadata.st_mode)
                or stat.S_ISLNK(name_metadata.st_mode)
                or is_reparse(descriptor_metadata)
                or is_reparse(name_metadata)
                or descriptor_metadata.st_nlink != 1
                or name_metadata.st_nlink != 1
                or not same_identity(descriptor_metadata, name_metadata)
            ):
                raise Rejected("exclusive_lock_alias_rejected")
            if descriptor_metadata.st_size == 0:
                os.write(descriptor, b"\0")
                os.fsync(descriptor)
            elif descriptor_metadata.st_size != 1:
                raise Rejected("exclusive_lock_identity_invalid")
            os.lseek(descriptor, 0, os.SEEK_SET)
            if os.read(descriptor, 1) != b"\0":
                raise Rejected("exclusive_lock_identity_invalid")
            os.lseek(descriptor, 0, os.SEEK_SET)
            if os.name == "nt":
                import msvcrt

                msvcrt.locking(descriptor, msvcrt.LK_NBLCK, 1)
            else:
                import fcntl

                fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
            after_lock = os.stat(self.path, follow_symlinks=False)
            if not same_identity(os.fstat(descriptor), after_lock):
                raise Rejected("exclusive_lock_name_changed")
        except Rejected:
            os.close(descriptor)
            raise
        except OSError as error:
            os.close(descriptor)
            raise Rejected("exclusive_lock_busy") from error
        self.descriptor = descriptor

    def assert_owned(self) -> None:
        descriptor = self.descriptor
        if descriptor is None:
            raise Rejected("exclusive_lock_not_owned")
        try:
            descriptor_metadata = os.fstat(descriptor)
            name_metadata = os.stat(self.path, follow_symlinks=False)
        except OSError as error:
            raise Rejected("exclusive_lock_name_changed") from error
        if (
            not stat.S_ISREG(name_metadata.st_mode)
            or stat.S_ISLNK(name_metadata.st_mode)
            or is_reparse(name_metadata)
            or descriptor_metadata.st_nlink != 1
            or name_metadata.st_nlink != 1
            or not same_identity(descriptor_metadata, name_metadata)
        ):
            raise Rejected("exclusive_lock_name_changed")

    def release(self) -> None:
        descriptor = self.descriptor
        if descriptor is None:
            return
        try:
            os.lseek(descriptor, 0, os.SEEK_SET)
            if os.name == "nt":
                import msvcrt

                msvcrt.locking(descriptor, msvcrt.LK_UNLCK, 1)
            else:
                import fcntl

                fcntl.flock(descriptor, fcntl.LOCK_UN)
        except OSError as error:
            raise Rejected("exclusive_lock_release_failed") from error
        finally:
            os.close(descriptor)
            self.descriptor = None


def publish_exclusive_copy(data: bytes, target: Path, stage: Path, mode: int) -> None:
    durable_new_file(stage, data, mode)
    try:
        os.link(stage, target)
        fsync_parent(target)
    except FileExistsError as error:
        raise Rejected("transaction_publish_conflict") from error
    except OSError as error:
        raise Rejected("transaction_publish_failed") from error
    finally:
        try:
            stage.unlink(missing_ok=True)
            fsync_parent(stage)
        except OSError as error:
            raise Rejected("transaction_stage_release_failed") from error


class TargetTransaction:
    TERMINAL = {"Committed", "RecoveredCommitted", "RecoveredOriginal", "Rejected"}
    STATES = TERMINAL | {
        "Pending",
        "Validated",
        "Claimed",
        "StageCreating",
        "PublishPrepared",
        "Linked",
        "Published",
    }

    def __init__(
        self,
        target: Path,
        expected: bytes,
        intended: bytes,
        recovery_root: Path,
        run_id: str,
        *,
        hook: Hook | None = None,
    ):
        if not RUN_ID.fullmatch(run_id):
            raise Rejected("transaction_run_id_invalid")
        self.target = target
        self.expected = expected
        self.intended = intended
        self.root = recovery_root
        self.run_id = run_id
        self.directory = recovery_root / f"run-{run_id}"
        self.original = self.directory / "original.bin"
        self.intended_copy = self.directory / "intended.bin"
        self.claimed = self.directory / "claimed.bin"
        self.published = self.directory / "published.bin"
        self.concurrent = self.directory / "concurrent.bin"
        self.journal_path = self.directory / "transaction.json"
        self.abandoned_preparation = recovery_root / f"abandoned-preparation-{run_id}"
        self.stage = target.parent / f".rfc9114-v4-{run_id}.stage"
        self.lock = ProcessFileLock(recovery_root / "target.lock")
        self.hook = hook
        self.mode = 0o600
        self.state = "New"
        self.target_identity: str | None = None
        self.journal_sha256: str | None = None
        self.locked = False

    def journal_value(self, state: str, category: str | None = None) -> dict[str, Any]:
        artifacts: dict[str, str | None] = {}
        for name, path in (
            ("original", self.original),
            ("intended", self.intended_copy),
            ("claimed", self.claimed),
            ("published", self.published),
            ("concurrent", self.concurrent),
        ):
            artifacts[name] = optional_strict_digest(path)
        return {
            "schema": 4,
            "journal_kind": "rfc9114_v4_target_transaction",
            "run_id": self.run_id,
            "state": state,
            "failure_category": category,
            "expected_sha256": digest(self.expected),
            "intended_sha256": digest(self.intended),
            "target_identity_token": self.target_identity,
            "artifacts": artifacts,
        }

    def write_journal(self, state: str, category: str | None = None) -> None:
        data = json_bytes(
            self.journal_value(state, safe_category(category) if category else None)
        )
        atomic_write(
            self.journal_path,
            data,
            prefix="transaction_journal",
            replace_is_commit=state in self.TERMINAL,
        )
        self.journal_sha256 = digest(data)
        self.state = state

    @staticmethod
    def _load_transaction(target: Path, recovery_root: Path, directory: Path) -> "TargetTransaction":
        journal_data = strict_read_path(directory / "transaction.json")
        journal = json_object(journal_data, "transaction_journal")
        artifacts = journal.get("artifacts")
        run_id = journal.get("run_id")
        state = journal.get("state")
        failure = journal.get("failure_category")
        token = journal.get("target_identity_token")
        if (
            set(journal)
            != {
                "schema",
                "journal_kind",
                "run_id",
                "state",
                "failure_category",
                "expected_sha256",
                "intended_sha256",
                "target_identity_token",
                "artifacts",
            }
            or journal.get("schema") != 4
            or journal.get("journal_kind")
            != "rfc9114_v4_target_transaction"
            or not isinstance(run_id, str)
            or not RUN_ID.fullmatch(run_id)
            or directory.name != f"run-{run_id}"
            or state not in TargetTransaction.STATES
            or not isinstance(journal.get("expected_sha256"), str)
            or not re.fullmatch(r"[0-9a-f]{64}", journal["expected_sha256"])
            or not isinstance(journal.get("intended_sha256"), str)
            or not re.fullmatch(r"[0-9a-f]{64}", journal["intended_sha256"])
            or (
                failure is not None
                and (not isinstance(failure, str) or not SAFE_CATEGORY.fullmatch(failure))
            )
            or (state == "Rejected") != (failure is not None)
            or (token is not None and (not isinstance(token, str) or not re.fullmatch(r"[0-9a-f]{64}", token)))
            or not isinstance(artifacts, dict)
            or set(artifacts)
            != {"original", "intended", "claimed", "published", "concurrent"}
            or any(
                value is not None
                and (not isinstance(value, str) or not re.fullmatch(r"[0-9a-f]{64}", value))
                for value in artifacts.values()
            )
        ):
            raise Rejected("transaction_journal_invalid")
        expected_hash = journal.get("expected_sha256")
        intended_hash = journal.get("intended_sha256")
        original = strict_read_path(directory / "original.bin")
        intended = strict_read_path(directory / "intended.bin")
        if digest(original) != expected_hash or digest(intended) != intended_hash:
            raise Rejected("transaction_recovery_identity_mismatch")
        item = TargetTransaction(target, original, intended, recovery_root, run_id)
        item.state = state
        item.journal_sha256 = digest(journal_data)
        item.target_identity = token if isinstance(token, str) else None
        observed_artifacts: dict[str, str | None] = {}
        for name, path in (
            ("original", item.original),
            ("intended", item.intended_copy),
            ("claimed", item.claimed),
            ("published", item.published),
            ("concurrent", item.concurrent),
        ):
            observed = optional_strict_digest(path)
            observed_artifacts[name] = observed
            recorded = artifacts[name]
            if recorded is not None and observed != recorded:
                raise Rejected("transaction_recovery_identity_mismatch")
        # A durable data operation intentionally precedes the journal update at each crash boundary.
        # Recovery therefore accepts only the exact one-step-ahead artifacts that the state machine can have produced.
        # Already-recorded hashes always remain exact, and every other unexpected artifact fails closed.
        allowed_unrecorded: set[str] = set()
        if state == "Validated":
            allowed_unrecorded.add("claimed")
        if state in {"PublishPrepared", "Linked"}:
            allowed_unrecorded.add("published")
        if state not in TargetTransaction.TERMINAL:
            # Reconciliation preserves an independently-created target before publishing its terminal journal entry.
            allowed_unrecorded.add("concurrent")
        for name, observed in observed_artifacts.items():
            if artifacts[name] is None and observed is not None:
                if name not in allowed_unrecorded:
                    raise Rejected("transaction_recovery_identity_mismatch")
                if name == "published" and observed != intended_hash:
                    raise Rejected("transaction_recovery_identity_mismatch")
        required_artifacts = {"original", "intended"}
        if state in {
            "Claimed",
            "StageCreating",
            "PublishPrepared",
            "Linked",
            "Published",
            "Committed",
            "RecoveredCommitted",
            "RecoveredOriginal",
        }:
            required_artifacts.add("claimed")
        if state in {"Published", "Committed", "RecoveredCommitted"}:
            required_artifacts.add("published")
        if any(
            artifacts[name] is None or observed_artifacts[name] is None
            for name in required_artifacts
        ):
            raise Rejected("transaction_recovery_identity_mismatch")
        if state in {
            "PublishPrepared",
            "Linked",
            "Published",
            "Committed",
            "RecoveredCommitted",
        } and token is None:
            raise Rejected("transaction_recovery_identity_mismatch")
        return item

    @classmethod
    def reconcile_unjournaled_preparation(
        cls,
        target: Path,
        recovery_root: Path,
        directory: Path,
    ) -> dict[str, str]:
        """Quarantine a crash that happened before the first journal commit.

        Preparation runs only while ``target.lock`` is held and before the
        target is inspected or moved.  Therefore an unjournaled run directory
        can contain only independent preparation bytes and a journal staging
        file.  Preserve every such byte under a terminal name; anything else
        fails closed because it could have crossed the claim boundary.
        """

        run_id = directory.name.removeprefix("run-")
        if not RUN_ID.fullmatch(run_id):
            raise Rejected("transaction_recovery_identity_mismatch")
        stage = target.parent / f".rfc9114-v4-{run_id}.stage"
        restore = target.parent / f".rfc9114-v4-{run_id}.restore"
        if os.path.lexists(stage) or os.path.lexists(restore):
            raise Rejected("transaction_unjournaled_mutation_detected")
        children = bounded_directory_entries(
            directory, "transaction_recovery_artifact_unreadable"
        )
        preparation_marker = directory / "preparation-rejected.json"
        artifact_hashes: dict[str, str | None] = {
            "original": None,
            "intended": None,
        }
        journal_stages: list[str] = []
        for child in children:
            if child == preparation_marker:
                continue
            if child.name == "original.bin":
                role = "original"
            elif child.name == "intended.bin":
                role = "intended"
            elif re.fullmatch(r"\.transaction\.json\.[A-Za-z0-9_-]+\.tmp", child.name):
                role = "journal_stage"
            else:
                raise Rejected("transaction_unjournaled_artifact_invalid")
            metadata = os.stat(child, follow_symlinks=False)
            if (
                not stat.S_ISREG(metadata.st_mode)
                or stat.S_ISLNK(metadata.st_mode)
                or is_reparse(metadata)
                or metadata.st_nlink != 1
            ):
                raise Rejected("transaction_recovery_alias_rejected")
            observed = digest(strict_read_path(child))
            if role == "journal_stage":
                journal_stages.append(observed)
            else:
                artifact_hashes[role] = observed
        marker = json_bytes(
            {
                "schema": 4,
                "journal_kind": "rfc9114_v4_transaction_preparation",
                "run_id": run_id,
                "state": "Rejected",
                "failure_category": "transaction_preparation_incomplete",
                "artifact_sha256": artifact_hashes,
                "journal_stage_count": len(journal_stages),
                "journal_stage_aggregate_sha256": digest(
                    "".join(sorted(journal_stages)).encode("ascii")
                ),
            }
        )
        if os.path.lexists(preparation_marker):
            if strict_read_path(preparation_marker) != marker:
                raise Rejected("transaction_preparation_marker_mismatch")
        else:
            durable_new_file(preparation_marker, marker)
        abandoned = recovery_root / f"abandoned-preparation-{run_id}"
        exclusive_rename(directory, abandoned)
        return {
            "run_id": run_id,
            "state": "Rejected",
            "journal_sha256": digest(strict_read_path(abandoned / preparation_marker.name)),
        }

    @classmethod
    def reconcile_all(
        cls,
        target: Path,
        recovery_root: Path,
        lock: ProcessFileLock,
        *,
        exclude_run_id: str | None = None,
    ) -> list[dict[str, str]]:
        if not isinstance(lock, ProcessFileLock):
            raise Rejected("exclusive_lock_not_owned")
        lock.assert_owned()
        outcomes: list[dict[str, str]] = []
        if not os.path.lexists(recovery_root):
            return outcomes
        root_metadata = os.stat(recovery_root, follow_symlinks=False)
        if (
            not stat.S_ISDIR(root_metadata.st_mode)
            or stat.S_ISLNK(root_metadata.st_mode)
            or is_reparse(root_metadata)
        ):
            raise Rejected("transaction_recovery_alias_rejected")
        for directory in bounded_directory_entries(
            recovery_root, "transaction_recovery_inventory_exceeded"
        ):
            if not directory.name.startswith("run-"):
                continue
            lock.assert_owned()
            if directory.name == f"run-{exclude_run_id}":
                continue
            metadata = os.stat(directory, follow_symlinks=False)
            if (
                not stat.S_ISDIR(metadata.st_mode)
                or stat.S_ISLNK(metadata.st_mode)
                or is_reparse(metadata)
            ):
                raise Rejected("transaction_recovery_alias_rejected")
            journal_path = directory / "transaction.json"
            try:
                journal_metadata = os.stat(journal_path, follow_symlinks=False)
            except FileNotFoundError:
                outcomes.append(
                    cls.reconcile_unjournaled_preparation(
                        target, recovery_root, directory
                    )
                )
                continue
            if (
                not stat.S_ISREG(journal_metadata.st_mode)
                or stat.S_ISLNK(journal_metadata.st_mode)
                or is_reparse(journal_metadata)
                or journal_metadata.st_nlink != 1
            ):
                raise Rejected("transaction_recovery_alias_rejected")
            item = cls._load_transaction(target, recovery_root, directory)
            if item.state in cls.TERMINAL:
                continue
            state = item.reconcile_one()
            outcomes.append(
                {
                    "run_id": item.run_id,
                    "state": state,
                    "journal_sha256": digest(strict_read_path(item.journal_path)),
                }
            )
        lock.assert_owned()
        return outcomes

    def reconcile_one(self) -> str:
        target_exists = os.path.lexists(self.target)
        stage_exists = os.path.lexists(self.stage)
        restore_stage = self.target.parent / f".rfc9114-v4-{self.run_id}.restore"
        restore_exists = os.path.lexists(restore_stage)
        if restore_exists:
            try:
                restore_metadata = os.stat(restore_stage, follow_symlinks=False)
                if (
                    not stat.S_ISREG(restore_metadata.st_mode)
                    or stat.S_ISLNK(restore_metadata.st_mode)
                    or is_reparse(restore_metadata)
                    or restore_metadata.st_nlink not in {1, 2}
                    or not os.path.lexists(self.claimed)
                ):
                    raise Rejected("transaction_recovery_restore_alias")
                claimed_for_restore = strict_read_path(self.claimed)
                target_is_restore = False
                if target_exists:
                    target_metadata = os.stat(self.target, follow_symlinks=False)
                    if (
                        not stat.S_ISREG(target_metadata.st_mode)
                        or stat.S_ISLNK(target_metadata.st_mode)
                        or is_reparse(target_metadata)
                    ):
                        raise Rejected("transaction_recovery_restore_alias")
                    target_is_restore = same_identity(
                        target_metadata, restore_metadata
                    )
                expected_links = 2 if target_is_restore else 1
                if (
                    restore_metadata.st_nlink != expected_links
                    or strict_read_path(
                        restore_stage, require_single_link=not target_is_restore
                    )
                    != claimed_for_restore
                ):
                    raise Rejected("transaction_recovery_restore_identity_mismatch")
                restore_stage.unlink()
                fsync_parent(restore_stage)
                target_exists = os.path.lexists(self.target)
            except Rejected as error:
                self.write_journal("Rejected", safe_category(str(error)))
                return self.state
            except OSError:
                self.write_journal("Rejected", "transaction_recovery_restore_failed")
                return self.state
        owned_stage = False
        if stage_exists and self.target_identity is not None:
            try:
                stage_metadata = os.stat(self.stage, follow_symlinks=False)
                owned_stage = (
                    stat.S_ISREG(stage_metadata.st_mode)
                    and not stat.S_ISLNK(stage_metadata.st_mode)
                    and not is_reparse(stage_metadata)
                    and identity_token(stage_metadata, self.run_id)
                    == self.target_identity
                )
            except OSError:
                owned_stage = False
        if stage_exists and not owned_stage and self.state == "StageCreating":
            try:
                stage_metadata = os.stat(self.stage, follow_symlinks=False)
                owned_stage = (
                    stat.S_ISREG(stage_metadata.st_mode)
                    and not stat.S_ISLNK(stage_metadata.st_mode)
                    and not is_reparse(stage_metadata)
                    and stage_metadata.st_nlink == 1
                    and strict_read_path(self.stage) == self.intended
                )
            except (OSError, Rejected):
                owned_stage = False
        owns_target = False
        current: bytes | None = None
        if target_exists:
            try:
                metadata = os.stat(self.target, follow_symlinks=False)
                if (
                    not stat.S_ISREG(metadata.st_mode)
                    or stat.S_ISLNK(metadata.st_mode)
                    or is_reparse(metadata)
                ):
                    raise Rejected("input_alias_rejected")
                stage_alias = owned_stage and os.path.samefile(self.target, self.stage)
                if metadata.st_nlink != 1 and not stage_alias:
                    raise Rejected("input_alias_rejected")
                current = strict_read_path(
                    self.target, require_single_link=not stage_alias
                )
                owns_target = (
                    stage_alias
                    or (
                        self.target_identity is not None
                        and identity_token(metadata, self.run_id) == self.target_identity
                    )
                )
            except Rejected:
                self.write_journal("Rejected", "transaction_recovery_target_alias")
                return self.state
        if owns_target and current == self.intended:
            published_hash = optional_strict_digest(self.published)
            if published_hash is None:
                durable_new_file(self.published, self.intended)
            elif published_hash != digest(self.intended):
                raise Rejected("transaction_recovery_identity_mismatch")
            if stage_exists:
                self.stage.unlink(missing_ok=True)
                fsync_parent(self.stage)
            self.write_journal("RecoveredCommitted")
            return self.state
        if owns_target and current is not None:
            # A writer may keep the published handle open and modify that inode in place.
            # Record those bytes independently even if they happen to equal the original content.
            self.preserve_concurrent(current)
            if owned_stage:
                self.stage.unlink(missing_ok=True)
                fsync_parent(self.stage)
            self.write_journal("Rejected", "transaction_concurrent_target_preserved")
            return self.state
        # Once a claim artifact exists, any independently-created target belongs to a concurrent writer.
        # Its bytes must survive even when they happen to equal the pre-transaction bytes; equality is not ownership.
        if target_exists and os.path.lexists(self.claimed) and not owns_target:
            if current is not None:
                self.preserve_concurrent(current)
            if owned_stage:
                self.stage.unlink(missing_ok=True)
                fsync_parent(self.stage)
            self.write_journal("Rejected", "transaction_concurrent_target_preserved")
            return self.state
        if target_exists and current != self.expected:
            if current is not None:
                self.preserve_concurrent(current)
            if owned_stage:
                self.stage.unlink(missing_ok=True)
                fsync_parent(self.stage)
            self.write_journal("Rejected", "transaction_concurrent_target_preserved")
            return self.state
        if not target_exists and os.path.lexists(self.claimed):
            claimed = strict_read_path(self.claimed)
            if owned_stage:
                self.stage.unlink(missing_ok=True)
                fsync_parent(self.stage)
            restore_stage = self.target.parent / f".rfc9114-v4-{self.run_id}.restore"
            if claimed != self.expected:
                self.preserve_concurrent(claimed)
                publish_exclusive_copy(claimed, self.target, restore_stage, self.mode)
                self.write_journal("Rejected", "transaction_claimed_concurrent_preserved")
                return self.state
            publish_exclusive_copy(claimed, self.target, restore_stage, self.mode)
            self.write_journal("RecoveredOriginal")
            return self.state
        self.write_journal("Rejected", "transaction_abandoned_before_claim")
        return self.state

    def preserve_concurrent(self, value: bytes) -> None:
        if os.path.lexists(self.concurrent):
            if strict_read_path(self.concurrent) != value:
                raise Rejected("transaction_recovery_identity_mismatch")
            return
        durable_new_file(self.concurrent, value)

    def begin(self) -> list[dict[str, str]]:
        self.root.mkdir(parents=True, exist_ok=True)
        assert_plain_directory(self.root, "transaction_recovery_alias_rejected")
        self.lock.acquire()
        self.locked = True
        self.lock.assert_owned()
        invoke(self.hook, "after_lock_acquired", self.target)
        # No attempt becomes visible until this process owns the same OS-released lock used by reconciliation.
        # Otherwise a second owner can observe a live contender's Pending directory, mark it abandoned,
        # and race that contender's later journal writes.
        os.mkdir(self.directory)
        assert_plain_directory(self.directory, "transaction_recovery_alias_rejected")
        invoke(self.hook, "after_attempt_directory", self.directory)
        durable_new_file(self.original, self.expected)
        invoke(self.hook, "after_original_copy", self.original)
        durable_new_file(self.intended_copy, self.intended)
        invoke(self.hook, "after_intended_copy", self.intended_copy)
        invoke(self.hook, "before_pending_journal", self.journal_path)
        self.write_journal("Pending")
        invoke(self.hook, "after_pending_journal", self.journal_path)
        invoke(self.hook, "after_lock", self.target)
        self.lock.assert_owned()
        recovered = self.reconcile_all(
            self.target,
            self.root,
            self.lock,
            exclude_run_id=self.run_id,
        )
        self.lock.assert_owned()
        observed = strict_read_path(self.target)
        metadata = os.stat(self.target, follow_symlinks=False)
        self.mode = stat.S_IMODE(metadata.st_mode)
        if observed != self.expected:
            raise Rejected("transaction_target_identity_mismatch")
        self.write_journal("Validated")
        invoke(self.hook, "before_claim", self.target)
        self.lock.assert_owned()
        exclusive_rename(self.target, self.claimed)
        invoke(self.hook, "after_claim_move_before_journal", self.claimed)
        self.write_journal("Claimed")
        invoke(self.hook, "after_claim", self.target)
        if generated_read(self.claimed) != self.expected:
            raise Rejected("transaction_claimed_identity_mismatch")
        self.write_journal("StageCreating")
        durable_new_file(self.stage, self.intended, self.mode)
        invoke(self.hook, "after_stage_create_before_journal", self.stage)
        stage_metadata = os.stat(self.stage, follow_symlinks=False)
        self.target_identity = identity_token(stage_metadata, self.run_id)
        self.write_journal("PublishPrepared")
        invoke(self.hook, "before_publish", self.target)
        self.lock.assert_owned()
        try:
            os.link(self.stage, self.target)
            fsync_parent(self.target)
        except FileExistsError as error:
            raise Rejected("transaction_publish_conflict") from error
        except OSError as error:
            raise Rejected("transaction_publish_failed") from error
        invoke(self.hook, "after_target_link_before_journal", self.target)
        self.lock.assert_owned()
        metadata = os.stat(self.target, follow_symlinks=False)
        if identity_token(metadata, self.run_id) != self.target_identity:
            raise Rejected("transaction_publish_identity_mismatch")
        self.write_journal("Linked")
        invoke(self.hook, "after_publish", self.target)
        if strict_read_path(self.target, require_single_link=False) != self.intended:
            raise Rejected("transaction_published_identity_mismatch")
        durable_new_file(self.published, self.intended)
        invoke(self.hook, "after_published_copy_before_stage_release", self.published)
        self.stage.unlink(missing_ok=True)
        fsync_parent(self.stage)
        invoke(self.hook, "after_stage_release_before_journal", self.target)
        if strict_read_path(self.target) != self.intended:
            raise Rejected("transaction_published_identity_mismatch")
        self.write_journal("Published")
        invoke(self.hook, "after_published_journal", self.target)
        self.assert_independent_recovery()
        return recovered

    def assert_independent_recovery(self) -> None:
        paths = [self.original, self.intended_copy, self.claimed, self.published, self.target]
        metadata = [os.stat(path, follow_symlinks=False) for path in paths]
        if any(item.st_nlink != 1 for item in metadata):
            raise Rejected("transaction_recovery_alias_detected")
        identities = {(item.st_dev, item.st_ino) for item in metadata}
        if len(identities) != len(metadata):
            raise Rejected("transaction_recovery_alias_detected")

    def assert_owned_target(self) -> None:
        if self.target_identity is None:
            raise Rejected("transaction_target_ownership_mismatch")
        metadata = os.stat(self.target, follow_symlinks=False)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or stat.S_ISLNK(metadata.st_mode)
            or is_reparse(metadata)
            or metadata.st_nlink != 1
            or identity_token(metadata, self.run_id) != self.target_identity
        ):
            raise Rejected("transaction_target_ownership_mismatch")

    def commit(self) -> None:
        self.lock.assert_owned()
        self.assert_owned_target()
        if self.state != "Published" or strict_read_path(self.target) != self.intended:
            raise Rejected("transaction_commit_identity_mismatch")
        self.assert_independent_recovery()
        self.write_journal("Committed")
        invoke(self.hook, "after_committed_journal", self.target)
        try:
            try:
                self.lock.release()
            except (Rejected, OSError):
                # Committed is the transaction's durable linearization point.
                # ProcessFileLock closes its descriptor while reporting an explicit unlock failure, and process exit is the final release boundary.
                # Do not reinterpret committed bytes as a failed application.
                pass
        finally:
            self.locked = False

    def reject(self, category: str) -> None:
        if not self.locked:
            return
        try:
            # Failure to acquire the lock, or failure while creating the attempt under that lock, cannot have moved the target.
            # In the latter case a partial directory is deliberately left as fail-closed crash evidence; do not manufacture a terminal journal whose required recovery bytes do not exist.
            if self.state == "New":
                return
            if self.state not in self.TERMINAL:
                self.lock.assert_owned()
                self.reconcile_one()
                if self.state not in self.TERMINAL:
                    self.write_journal("Rejected", category)
        finally:
            try:
                self.lock.release()
            finally:
                self.locked = False

    def abandon_for_test(self) -> None:
        try:
            self.lock.release()
        finally:
            self.locked = False


def pointer_bytes(mode: str, run_id: str, state: str, report_sha256: str | None) -> bytes:
    if mode not in {"red", "self-test", "apply"} or not RUN_ID.fullmatch(run_id):
        raise Rejected("report_pointer_invalid")
    if state not in {"Running", "Final"}:
        raise Rejected("report_pointer_invalid")
    if (state == "Running") != (report_sha256 is None):
        raise Rejected("report_pointer_invalid")
    return json_bytes(
        {
            "schema": 4,
            "pointer_kind": "rfc9114_v4_report_pointer",
            "mode": mode,
            "run_id": run_id,
            "state": state,
            "report_sha256": report_sha256,
        }
    )


class ReportStore:
    """Publish an immutable report and advance canonical pointers only at the end."""

    def __init__(
        self,
        directory: Path,
        mode: str,
        run_id: str,
        validate: Callable[[bytes, str, str], None],
        *,
        hook: Hook | None = None,
    ):
        if (
            mode not in {"red", "self-test", "apply"}
            or not RUN_ID.fullmatch(run_id)
            or not callable(validate)
        ):
            raise Rejected("report_invocation_invalid")
        self.directory = directory
        self.mode = mode
        self.run_id = run_id
        self.attempt = directory / "attempts" / f"run-{run_id}"
        self.pending = self.attempt / "pending.json"
        self.done = self.attempt / "done.json"
        self.abandoned = self.attempt / "abandoned.json"
        self.publication_failure = self.attempt / "publication-failure.json"
        self.journal = self.attempt / "journal.json"
        self.reports = self.attempt / "reports"
        self.intent_lock = ProcessFileLock(directory / "report-intent.lock")
        self.lock = ProcessFileLock(directory / "report.lock")
        self.validate = validate
        self.hook = hook
        self.locked = False
        self.intent_locked = False
        self.started = False
        self.committed = False
        self.report_sha256: str | None = None

    def marker(self, kind: str) -> bytes:
        marker: dict[str, Any] = {
            "schema": 4,
            "marker_kind": kind,
            "mode": self.mode,
            "run_id": self.run_id,
        }
        if kind == "Done":
            if self.report_sha256 is None:
                raise Rejected("report_attempt_contract_mismatch")
            marker["report_sha256"] = self.report_sha256
        elif kind != "Pending":
            raise Rejected("report_attempt_contract_mismatch")
        return json_bytes(marker)

    def write_journal(self, state: str) -> None:
        report_sha256 = self.report_sha256
        if state in {"Pending", "Locked", "Running"}:
            if report_sha256 is not None:
                raise Rejected("report_attempt_contract_mismatch")
        elif state in {"ImmutableReport", "ModePointer", "ReadyPrepared"}:
            if report_sha256 is None:
                raise Rejected("report_attempt_contract_mismatch")
        else:
            raise Rejected("report_attempt_contract_mismatch")
        atomic_write(
            self.journal,
            json_bytes(
                {
                    "schema": 4,
                    "journal_kind": "rfc9114_v4_report_attempt",
                    "mode": self.mode,
                    "run_id": self.run_id,
                    "state": state,
                    "report_sha256": report_sha256,
                }
            ),
            prefix="report_journal",
        )

    def reconcile_attempts(self) -> list[str]:
        recovered: list[str] = []
        attempts = self.directory / "attempts"
        if not os.path.lexists(attempts):
            return recovered
        assert_plain_directory(attempts, "report_attempt_alias_rejected")
        for item in bounded_directory_entries(
            attempts, "report_attempt_inventory_exceeded"
        ):
            if not item.name.startswith("run-"):
                raise Rejected("report_attempt_identity_invalid")
            self.lock.assert_owned()
            self.intent_lock.assert_owned()
            if item == self.attempt:
                continue
            metadata = os.stat(item, follow_symlinks=False)
            if (
                not stat.S_ISDIR(metadata.st_mode)
                or stat.S_ISLNK(metadata.st_mode)
                or is_reparse(metadata)
            ):
                raise Rejected("report_attempt_alias_rejected")
            run_id = item.name.removeprefix("run-")
            if not RUN_ID.fullmatch(run_id):
                raise Rejected("report_attempt_identity_invalid")
            try:
                kind = closed_attempt_kind(item, run_id, self.validate)
            except Rejected:
                if not os.path.lexists(item / "done.json"):
                    raise
                reconcile_done_before_journal(item, run_id, self.validate)
                kind = closed_attempt_kind(item, run_id, self.validate)
            if kind is not None:
                continue
            self.lock.assert_owned()
            self.intent_lock.assert_owned()
            durable_new_file(
                item / "abandoned.json",
                json_bytes({"schema": 4, "marker_kind": "Abandoned", "run_id": run_id}),
            )
            recovered.append(run_id)
        self.lock.assert_owned()
        self.intent_lock.assert_owned()
        return recovered

    def begin(self) -> list[str]:
        self.directory.mkdir(parents=True, exist_ok=True)
        assert_plain_directory(self.directory, "report_directory_alias_rejected")
        (self.directory / "attempts").mkdir(parents=True, exist_ok=True)
        assert_plain_directory(
            self.directory / "attempts", "report_attempt_alias_rejected"
        )
        self.intent_lock.acquire()
        self.intent_locked = True
        try:
            os.mkdir(self.attempt)
            assert_plain_directory(self.attempt, "report_attempt_alias_rejected")
            invoke(self.hook, "report_after_attempt_directory", self.attempt)
            durable_new_file(self.pending, self.marker("Pending"))
            invoke(self.hook, "report_pending_before_journal", self.pending)
            self.write_journal("Pending")
            invoke(self.hook, "report_after_pending", self.pending)
            self.lock.acquire()
            self.locked = True
        except BaseException:
            self.intent_lock.release()
            self.intent_locked = False
            raise
        self.lock.assert_owned()
        self.intent_lock.assert_owned()
        invoke(self.hook, "report_after_lock", self.pending)
        self.lock.assert_owned()
        self.intent_lock.assert_owned()
        recovered = self.reconcile_attempts()
        self.write_journal("Locked")
        invoke(self.hook, "report_before_running", self.directory / "report.json")
        atomic_write(
            self.directory / "report.json",
            pointer_bytes(self.mode, self.run_id, "Running", None),
            hook=self.hook,
            prefix="running_pointer",
        )
        invoke(
            self.hook,
            "report_running_pointer_before_journal",
            self.directory / "report.json",
        )
        self.write_journal("Running")
        self.started = True
        invoke(self.hook, "report_after_running", self.directory / "report.json")
        return recovered

    def publish(
        self,
        report: bytes,
        validate: Callable[[bytes, str, str], None],
        *,
        pre_final: Callable[[], None] | None = None,
    ) -> str:
        if not self.locked or not self.intent_locked:
            raise Rejected("exclusive_lock_not_owned")
        if validate is not self.validate:
            raise Rejected("report_validator_identity_mismatch")
        self.lock.assert_owned()
        self.intent_lock.assert_owned()
        validate(report, self.mode, self.run_id)
        report_sha = digest(report)
        self.report_sha256 = report_sha
        report_path = self.reports / f"{report_sha}.json"
        invoke(self.hook, "report_before_immutable", report_path)
        durable_new_file(report_path, report)
        invoke(self.hook, "report_immutable_before_journal", report_path)
        self.write_journal("ImmutableReport")
        invoke(self.hook, "report_after_immutable", report_path)
        final_pointer = pointer_bytes(self.mode, self.run_id, "Final", report_sha)
        atomic_write(
            self.directory / f"report-{self.mode}.json",
            final_pointer,
            hook=self.hook,
            prefix="mode_pointer",
        )
        self.lock.assert_owned()
        invoke(
            self.hook,
            "report_mode_pointer_before_journal",
            self.directory / f"report-{self.mode}.json",
        )
        self.write_journal("ModePointer")
        invoke(self.hook, "report_before_ready", self.directory / "report.json")
        durable_new_file(self.done, self.marker("Done"))
        invoke(self.hook, "report_done_before_journal", self.done)
        self.write_journal("ReadyPrepared")
        invoke(
            self.hook,
            "report_before_canonical_final",
            self.directory / "report.json",
        )

        def validate_final_publication() -> None:
            self.lock.assert_owned()
            self.intent_lock.assert_owned()
            if pre_final is not None:
                pre_final()

        atomic_write(
            self.directory / "report.json",
            final_pointer,
            hook=self.hook,
            prefix="canonical_pointer",
            pre_replace=validate_final_publication,
            replace_is_commit=True,
        )
        # No validation, diagnostic output, or other fallible publication work may follow this assignment.
        # The canonical replace above is the linearization point; callers use this flag only to avoid turning a later best-effort lock-release error into a contradictory rejection.
        self.committed = True
        return report_sha

    def record_publication_failure(self, category: str) -> str:
        """Persist a typed pre-commit failure without advancing canonical."""

        self.lock.assert_owned()
        self.intent_lock.assert_owned()
        if not os.path.lexists(self.done) or self.report_sha256 is None:
            raise Rejected("publication_failure_state_invalid")
        failure = json_bytes(
            {
                "schema": 4,
                "marker_kind": "PublicationFailure",
                "mode": self.mode,
                "run_id": self.run_id,
                "report_sha256": self.report_sha256,
                "failure_category": safe_category(category),
            }
        )
        if os.path.lexists(self.publication_failure):
            if strict_read_path(self.publication_failure) != failure:
                raise Rejected("publication_failure_marker_mismatch")
        else:
            durable_new_file(self.publication_failure, failure)
        return digest(failure)

    def close(self) -> None:
        try:
            if self.locked:
                self.lock.release()
                self.locked = False
        finally:
            if self.intent_locked:
                self.intent_lock.release()
                self.intent_locked = False

    def abandon_for_test(self) -> None:
        self.close()


def unresolved_attempts(
    directory: Path, validate: Callable[[bytes, str, str], None]
) -> list[str]:
    attempts = directory / "attempts"
    if not os.path.lexists(attempts):
        return []
    assert_plain_directory(attempts, "report_attempt_alias_rejected")
    unresolved: list[str] = []
    for item in bounded_directory_entries(
        attempts, "report_attempt_inventory_exceeded"
    ):
        if not item.name.startswith("run-"):
            raise Rejected("report_attempt_identity_invalid")
        metadata = os.stat(item, follow_symlinks=False)
        if (
            not stat.S_ISDIR(metadata.st_mode)
            or stat.S_ISLNK(metadata.st_mode)
            or is_reparse(metadata)
        ):
            raise Rejected("report_attempt_alias_rejected")
        run_id = item.name.removeprefix("run-")
        if not RUN_ID.fullmatch(run_id):
            raise Rejected("report_attempt_identity_invalid")
        if closed_attempt_kind(item, run_id, validate) is None:
            unresolved.append(run_id)
    return unresolved


def validated_attempt_reports(
    attempt: Path,
    mode: str,
    run_id: str,
    selected_sha256: str,
    validate: Callable[[bytes, str, str], None],
) -> None:
    reports = attempt / "reports"
    assert_plain_directory(reports, "report_attempt_contract_mismatch")
    entries = bounded_directory_entries(
        reports, "report_attempt_contract_mismatch", limit=5
    )
    selected_seen = False
    if not entries or len(entries) > 4:
        raise Rejected("report_attempt_contract_mismatch")
    for report_path in entries:
        match = re.fullmatch(r"([0-9a-f]{64})\.json", report_path.name)
        if match is None:
            raise Rejected("report_attempt_contract_mismatch")
        try:
            report = strict_read_path(report_path)
            if digest(report) != match.group(1):
                raise Rejected("report_attempt_contract_mismatch")
            validate(report, mode, run_id)
        except Rejected:
            raise
        except Exception as error:
            raise Rejected("report_attempt_contract_mismatch") from error
        if match.group(1) == selected_sha256:
            selected_seen = True
    if not selected_seen:
        raise Rejected("report_attempt_contract_mismatch")


def closed_attempt_kind(
    attempt: Path,
    run_id: str,
    validate: Callable[[bytes, str, str], None],
) -> str | None:
    done = attempt / "done.json"
    abandoned = attempt / "abandoned.json"
    done_exists = os.path.lexists(done)
    abandoned_exists = os.path.lexists(abandoned)
    publication_failure = attempt / "publication-failure.json"
    publication_failure_exists = os.path.lexists(publication_failure)
    if done_exists and abandoned_exists:
        raise Rejected("report_attempt_contract_mismatch")
    if publication_failure_exists and not done_exists:
        raise Rejected("report_attempt_contract_mismatch")
    if abandoned_exists:
        marker = json_object(strict_read_path(abandoned), "report_marker")
        if marker != {
            "schema": 4,
            "marker_kind": "Abandoned",
            "run_id": run_id,
        }:
            raise Rejected("report_attempt_contract_mismatch")
        return "Abandoned"
    if done_exists:
        marker = json_object(strict_read_path(done), "report_marker")
        mode = marker.get("mode")
        report_sha256 = marker.get("report_sha256")
        if marker != {
            "schema": 4,
            "marker_kind": "Done",
            "mode": mode,
            "run_id": run_id,
            "report_sha256": report_sha256,
        } or mode not in {"red", "self-test", "apply"} or not isinstance(
            report_sha256, str
        ) or not re.fullmatch(r"[0-9a-f]{64}", report_sha256):
            raise Rejected("report_attempt_contract_mismatch")
        pending = json_object(
            strict_read_path(attempt / "pending.json"), "report_marker"
        )
        if pending != {
            "schema": 4,
            "marker_kind": "Pending",
            "mode": mode,
            "run_id": run_id,
        }:
            raise Rejected("report_attempt_contract_mismatch")
        journal = json_object(
            strict_read_path(attempt / "journal.json"), "report_journal"
        )
        if journal != {
            "schema": 4,
            "journal_kind": "rfc9114_v4_report_attempt",
            "mode": mode,
            "run_id": run_id,
            "state": "ReadyPrepared",
            "report_sha256": report_sha256,
        }:
            raise Rejected("report_attempt_contract_mismatch")
        validated_attempt_reports(
            attempt, mode, run_id, report_sha256, validate
        )
        if publication_failure_exists:
            failure = json_object(
                strict_read_path(publication_failure), "publication_failure"
            )
            failure_category = failure.get("failure_category")
            if failure != {
                "schema": 4,
                "marker_kind": "PublicationFailure",
                "mode": mode,
                "run_id": run_id,
                "report_sha256": report_sha256,
                "failure_category": failure_category,
            } or not isinstance(failure_category, str) or not SAFE_CATEGORY.fullmatch(
                failure_category
            ):
                raise Rejected("report_attempt_contract_mismatch")
            # The attempt is durably closed so successors do not wait on it,
            # but it can never authorize a canonical Final pointer.
            # This distinction prevents an exact-looking pointer pair from resurrecting a run whose final identity validation failed.
            return "PublicationFailed"
        return "Done"
    return None


def reconcile_done_before_journal(
    attempt: Path,
    run_id: str,
    validate: Callable[[bytes, str, str], None],
) -> None:
    done = json_object(strict_read_path(attempt / "done.json"), "report_marker")
    mode = done.get("mode")
    report_sha256 = done.get("report_sha256")
    if done != {
        "schema": 4,
        "marker_kind": "Done",
        "mode": mode,
        "run_id": run_id,
        "report_sha256": report_sha256,
    } or mode not in {"red", "self-test", "apply"} or not isinstance(
        report_sha256, str
    ) or not re.fullmatch(r"[0-9a-f]{64}", report_sha256):
        raise Rejected("report_attempt_contract_mismatch")
    pending = json_object(
        strict_read_path(attempt / "pending.json"), "report_marker"
    )
    journal = json_object(
        strict_read_path(attempt / "journal.json"), "report_journal"
    )
    if (
        pending
        != {
            "schema": 4,
            "marker_kind": "Pending",
            "mode": mode,
            "run_id": run_id,
        }
        or journal
        != {
            "schema": 4,
            "journal_kind": "rfc9114_v4_report_attempt",
            "mode": mode,
            "run_id": run_id,
            "state": "ModePointer",
            "report_sha256": report_sha256,
        }
    ):
        raise Rejected("report_attempt_contract_mismatch")
    validated_attempt_reports(attempt, mode, run_id, report_sha256, validate)
    expected_pointer = pointer_bytes(mode, run_id, "Final", report_sha256)
    if strict_read_path(attempt.parent.parent / f"report-{mode}.json") != expected_pointer:
        raise Rejected("report_attempt_contract_mismatch")
    atomic_write(
        attempt / "journal.json",
        json_bytes(
            {
                "schema": 4,
                "journal_kind": "rfc9114_v4_report_attempt",
                "mode": mode,
                "run_id": run_id,
                "state": "ReadyPrepared",
                "report_sha256": report_sha256,
            }
        ),
        prefix="report_recovery_journal",
    )


def validate_completed_attempt(
    directory: Path,
    mode: str,
    run_id: str,
    expected_report_sha256: str,
    validate: Callable[[bytes, str, str], None],
) -> None:
    attempt = directory / "attempts" / f"run-{run_id}"
    try:
        metadata = os.stat(attempt, follow_symlinks=False)
    except OSError as error:
        raise Rejected("report_attempt_contract_mismatch") from error
    if (
        not stat.S_ISDIR(metadata.st_mode)
        or stat.S_ISLNK(metadata.st_mode)
        or is_reparse(metadata)
        or os.path.lexists(attempt / "abandoned.json")
        or closed_attempt_kind(attempt, run_id, validate) != "Done"
    ):
        raise Rejected("report_attempt_contract_mismatch")
    for path, marker_kind in (
        (attempt / "pending.json", "Pending"),
        (attempt / "done.json", "Done"),
    ):
        marker = json_object(strict_read_path(path), "report_marker")
        if marker != {
            "schema": 4,
            "marker_kind": marker_kind,
            "mode": mode,
            "run_id": run_id,
            **(
                {"report_sha256": expected_report_sha256}
                if marker_kind == "Done"
                else {}
            ),
        }:
            raise Rejected("report_attempt_contract_mismatch")
    journal = json_object(
        strict_read_path(attempt / "journal.json"), "report_journal"
    )
    if journal != {
        "schema": 4,
        "journal_kind": "rfc9114_v4_report_attempt",
        "mode": mode,
        "run_id": run_id,
        "state": "ReadyPrepared",
        "report_sha256": expected_report_sha256,
    }:
        raise Rejected("report_attempt_contract_mismatch")


def consume_pointer_pair(
    directory: Path,
    mode: str,
    expected_run_id: str | None,
    validate: Callable[[bytes, str, str], None],
) -> bytes:
    if mode not in {"red", "self-test", "apply"}:
        raise Rejected("report_mode_invalid")
    if expected_run_id is None:
        raise Rejected("expected_run_id_required")
    if not RUN_ID.fullmatch(expected_run_id):
        raise Rejected("expected_run_id_invalid")
    intent_lock = ProcessFileLock(directory / "report-intent.lock")
    lock = ProcessFileLock(directory / "report.lock")
    intent_lock.acquire()
    try:
        intent_lock.assert_owned()
        lock.acquire()
        try:
            lock.assert_owned()
            if unresolved_attempts(directory, validate):
                raise Rejected("report_attempt_incomplete")
            canonical = strict_read_path(directory / "report.json")
            per_mode = strict_read_path(directory / f"report-{mode}.json")
            if canonical != per_mode:
                raise Rejected("report_pointer_pair_mismatch")
            pointer = json_object(canonical, "report_pointer")
            if set(pointer) != {"schema", "pointer_kind", "mode", "run_id", "state", "report_sha256"}:
                raise Rejected("report_pointer_schema_mismatch")
            if (
                pointer.get("schema") != 4
                or pointer.get("pointer_kind") != "rfc9114_v4_report_pointer"
                or pointer.get("mode") != mode
                or pointer.get("state") != "Final"
                or pointer.get("run_id") != expected_run_id
                or not isinstance(pointer.get("report_sha256"), str)
                or not re.fullmatch(r"[0-9a-f]{64}", pointer["report_sha256"])
            ):
                if pointer.get("run_id") != expected_run_id:
                    raise Rejected("report_run_id_mismatch")
                raise Rejected("report_pointer_contract_mismatch")
            validate_completed_attempt(
                directory,
                mode,
                expected_run_id,
                pointer["report_sha256"],
                validate,
            )
            report_path = directory / "attempts" / f"run-{expected_run_id}" / "reports" / f"{pointer['report_sha256']}.json"
            report = strict_read_path(report_path)
            if digest(report) != pointer["report_sha256"]:
                raise Rejected("immutable_report_identity_mismatch")
            validate(report, mode, expected_run_id)
            lock.assert_owned()
            intent_lock.assert_owned()
            return report
        finally:
            lock.release()
    finally:
        intent_lock.release()

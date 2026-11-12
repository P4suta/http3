#!/usr/bin/env python3

# SPDX-FileCopyrightText: 2026 the http contributors
# SPDX-License-Identifier: MIT OR Apache-2.0

"""Externally frozen bootstrap for the RFC 9114 v4 source-tree anchor."""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import platform
import re
import stat
import sys
import tempfile
from typing import Any


BOOTSTRAP_PATH = Path(os.path.abspath(__file__))
BOOTSTRAP_METADATA = os.stat(BOOTSTRAP_PATH, follow_symlinks=False)
if (
    not stat.S_ISREG(BOOTSTRAP_METADATA.st_mode)
    or stat.S_ISLNK(BOOTSTRAP_METADATA.st_mode)
    or getattr(BOOTSTRAP_METADATA, "st_file_attributes", 0)
    & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
    or BOOTSTRAP_METADATA.st_nlink != 1
):
    raise RuntimeError("bootstrap_alias_rejected")
ROOT = BOOTSTRAP_PATH.parents[2]
for bootstrap_directory in (
    ROOT,
    ROOT / "standards",
    ROOT / "standards" / "audits",
):
    directory_metadata = os.stat(bootstrap_directory, follow_symlinks=False)
    if (
        not stat.S_ISDIR(directory_metadata.st_mode)
        or stat.S_ISLNK(directory_metadata.st_mode)
        or getattr(directory_metadata, "st_file_attributes", 0)
        & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
    ):
        raise RuntimeError("bootstrap_parent_alias_rejected")
ANCHOR_PATH = ROOT / "standards/audit-anchors/rfc9114-v4.json"
LAUNCHER_PATH = "standards/audits/rfc9114/v4/launcher.py"
GATE_PATH = "standards/audits/rfc9114/v4/evidence_gate.py"
MISE_PATH = ".mise.toml"
EXPECTED_ANCHOR_SHA256 = "PENDING_EXTERNAL_FREEZE"
MAX_BYTES = 32 * 1024 * 1024


class Rejected(ValueError):
    pass


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def safe_exception_category(error: BaseException) -> str:
    if error.__class__.__name__ not in {"Rejected", "SchemaRejected"}:
        return "bootstrap_rejected"
    if len(error.args) != 1 or not isinstance(error.args[0], str):
        return "bootstrap_rejected"
    category = error.args[0]
    return (
        category
        if re.fullmatch(r"[a-z0-9_]{1,120}", category)
        else "bootstrap_rejected"
    )


def safe_stdout_line(value: str) -> None:
    try:
        print(value, flush=True)
    except BaseException:
        # Diagnostics are best effort.
        # A closed or failing output sink must not alter the verified result or expose a secondary traceback.
        pass


def checked_path(relative: str) -> Path:
    parsed = PurePosixPath(relative)
    if (
        parsed.is_absolute()
        or not parsed.parts
        or any(part in {"", ".", ".."} for part in parsed.parts)
        or "\\" in relative
    ):
        raise Rejected("anchor_member_path_invalid")
    current = ROOT
    for part in parsed.parts[:-1]:
        current = current / part
        metadata = os.stat(current, follow_symlinks=False)
        attributes = getattr(metadata, "st_file_attributes", 0)
        if (
            not stat.S_ISDIR(metadata.st_mode)
            or stat.S_ISLNK(metadata.st_mode)
            or attributes & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
        ):
            raise Rejected("input_alias_rejected")
    return ROOT.joinpath(*parsed.parts)


def strict_read(path: Path) -> bytes:
    descriptor = None
    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0)
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        before_name = os.stat(path, follow_symlinks=False)
        attributes = getattr(before_name, "st_file_attributes", 0)
        if (
            not stat.S_ISREG(before_name.st_mode)
            or stat.S_ISLNK(before_name.st_mode)
            or attributes & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
            or before_name.st_nlink != 1
        ):
            raise Rejected("input_alias_rejected")
        descriptor = os.open(path, flags)
        before_fd = os.fstat(descriptor)
        if (
            (before_fd.st_dev, before_fd.st_ino)
            != (before_name.st_dev, before_name.st_ino)
            or before_fd.st_nlink != 1
        ):
            raise Rejected("input_alias_rejected")
        chunks: list[bytes] = []
        size = 0
        while True:
            chunk = os.read(descriptor, min(65536, MAX_BYTES + 1 - size))
            if not chunk:
                break
            chunks.append(chunk)
            size += len(chunk)
            if size > MAX_BYTES:
                raise Rejected("input_too_large")
        after_fd = os.fstat(descriptor)
        after_name = os.stat(path, follow_symlinks=False)
        if (
            (before_fd.st_dev, before_fd.st_ino, before_fd.st_size, before_fd.st_mtime_ns, before_fd.st_ctime_ns)
            != (after_fd.st_dev, after_fd.st_ino, after_fd.st_size, after_fd.st_mtime_ns, after_fd.st_ctime_ns)
            or (after_fd.st_dev, after_fd.st_ino) != (after_name.st_dev, after_name.st_ino)
            or after_fd.st_nlink != 1
            or after_name.st_nlink != 1
            or not stat.S_ISREG(after_name.st_mode)
            or stat.S_ISLNK(after_name.st_mode)
            or getattr(after_name, "st_file_attributes", 0)
            & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
        ):
            raise Rejected("input_changed_during_read")
        return b"".join(chunks)
    except Rejected:
        raise
    except FileNotFoundError as error:
        raise Rejected("input_missing") from error
    except OSError as error:
        raise Rejected("input_read_failed") from error
    finally:
        if descriptor is not None:
            os.close(descriptor)


def object_from(data: bytes, category: str) -> dict[str, Any]:
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


def load_anchor() -> tuple[dict[str, Any], dict[str, bytes], bytes]:
    anchor_bytes = strict_read(ANCHOR_PATH)
    if digest(anchor_bytes) != EXPECTED_ANCHOR_SHA256:
        raise Rejected("external_anchor_identity_mismatch")
    anchor = object_from(anchor_bytes, "anchor")
    expected_keys = {
        "schema",
        "anchor_kind",
        "generation",
        "members",
        "requirements_policy",
        "python_policy",
        "independent_audit",
    }
    members = anchor.get("members")
    if (
        set(anchor) != expected_keys
        or anchor.get("schema") != 4
        or anchor.get("anchor_kind") != "rfc9114_v4_external_source_tree"
        or anchor.get("generation") != 4
        or not isinstance(members, dict)
        or not 0 < len(members) <= 1024
    ):
        raise Rejected("anchor_schema_mismatch")
    snapshots: dict[str, bytes] = {}
    normalized_members: set[str] = set()
    for relative, expected in members.items():
        if (
            not isinstance(relative, str)
            or not isinstance(expected, str)
            or not re.fullmatch(r"[0-9a-f]{64}", expected)
        ):
            raise Rejected("anchor_member_entry_invalid")
        normalized = os.path.normcase(
            os.path.normpath(relative.replace("/", os.sep))
        )
        if normalized in normalized_members:
            raise Rejected("anchor_member_alias_rejected")
        normalized_members.add(normalized)
        snapshot = strict_read(checked_path(relative))
        if digest(snapshot) != expected:
            raise Rejected("anchor_member_identity_mismatch")
        snapshots[relative] = snapshot
    anchor["anchor_sha256"] = EXPECTED_ANCHOR_SHA256
    return anchor, snapshots, anchor_bytes


def executable_path() -> Path:
    # mise commonly exposes ``bin/python`` as a symlink on Unix.
    # Bind the canonical resolved executable path and bytes, rather than authorizing a mutable alias or rejecting every legitimate Unix installation.
    path = Path(os.path.realpath(os.path.abspath(sys.executable)))
    if not path.is_absolute():
        raise Rejected("python_executable_path_invalid")
    current = Path(path.anchor)
    for part in path.parts[1:-1]:
        current = current / part
        metadata = os.stat(current, follow_symlinks=False)
        attributes = getattr(metadata, "st_file_attributes", 0)
        if (
            not stat.S_ISDIR(metadata.st_mode)
            or stat.S_ISLNK(metadata.st_mode)
            or attributes & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
        ):
            raise Rejected("python_executable_alias_rejected")
    return path


def executable_path_sha256(path: Path) -> str:
    normalized = os.path.normcase(os.path.normpath(os.fspath(path)))
    return digest(os.fsencode(normalized))


def executable_identity_material(path: Path) -> tuple[bytes, int]:
    """Read the exact executable while permitting its recorded platform hardlink."""

    descriptor = None
    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0)
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        before_name = os.stat(path, follow_symlinks=False)
        attributes = getattr(before_name, "st_file_attributes", 0)
        if (
            not stat.S_ISREG(before_name.st_mode)
            or stat.S_ISLNK(before_name.st_mode)
            or attributes & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
        ):
            raise Rejected("python_executable_alias_rejected")
        descriptor = os.open(path, flags)
        before_fd = os.fstat(descriptor)
        if (before_fd.st_dev, before_fd.st_ino) != (
            before_name.st_dev,
            before_name.st_ino,
        ):
            raise Rejected("python_executable_changed")
        chunks: list[bytes] = []
        size = 0
        while True:
            chunk = os.read(descriptor, min(65536, MAX_BYTES + 1 - size))
            if not chunk:
                break
            chunks.append(chunk)
            size += len(chunk)
            if size > MAX_BYTES:
                raise Rejected("python_executable_too_large")
        after_fd = os.fstat(descriptor)
        after_name = os.stat(path, follow_symlinks=False)
        if (
            (
                before_fd.st_dev,
                before_fd.st_ino,
                before_fd.st_size,
                before_fd.st_mtime_ns,
                before_fd.st_ctime_ns,
                before_fd.st_nlink,
            )
            != (
                after_fd.st_dev,
                after_fd.st_ino,
                after_fd.st_size,
                after_fd.st_mtime_ns,
                after_fd.st_ctime_ns,
                after_fd.st_nlink,
            )
            or (after_fd.st_dev, after_fd.st_ino)
            != (after_name.st_dev, after_name.st_ino)
            or after_fd.st_nlink != after_name.st_nlink
            or not stat.S_ISREG(after_name.st_mode)
            or stat.S_ISLNK(after_name.st_mode)
            or getattr(after_name, "st_file_attributes", 0)
            & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
        ):
            raise Rejected("python_executable_changed")
        return b"".join(chunks), after_fd.st_nlink
    except Rejected:
        raise
    except OSError as error:
        raise Rejected("python_executable_identity_unreadable") from error
    finally:
        if descriptor is not None:
            os.close(descriptor)


def observed_python_identity(anchor: dict[str, Any]) -> dict[str, str]:
    if (
        sys.flags.isolated != 1
        or sys.flags.dont_write_bytecode != 1
        or sys.flags.optimize != 0
    ):
        raise Rejected("python_flags_mismatch")
    policy = anchor.get("python_policy")
    if (
        not isinstance(policy, dict)
        or set(policy)
        != {"allowed", "configured_version", "resolution", "mise_config_sha256"}
        or policy.get("resolution") != "mise"
        or policy.get("mise_config_sha256") != anchor["members"].get(MISE_PATH)
        or not isinstance(policy.get("configured_version"), str)
        or not isinstance(policy.get("allowed"), list)
        or not 0 < len(policy["allowed"]) <= 16
    ):
        raise Rejected("python_policy_invalid")
    identity_keys = {
        "implementation",
        "version",
        "executable_sha256",
        "executable_path_sha256",
        "executable_link_count",
        "os",
        "architecture",
        "mise_config_sha256",
        "identity_kind",
    }
    normalized: list[tuple[tuple[str, Any], ...]] = []
    for item in policy["allowed"]:
        if (
            not isinstance(item, dict)
            or set(item) != identity_keys
            or item.get("implementation") != "cpython"
            or item.get("version") != policy["configured_version"]
            or not isinstance(item.get("executable_sha256"), str)
            or not re.fullmatch(r"[0-9a-f]{64}", item["executable_sha256"])
            or not isinstance(item.get("executable_path_sha256"), str)
            or not re.fullmatch(r"[0-9a-f]{64}", item["executable_path_sha256"])
            or not isinstance(item.get("executable_link_count"), int)
            or isinstance(item["executable_link_count"], bool)
            or not 1 <= item["executable_link_count"] <= 64
            or item.get("os") not in {"windows", "linux", "darwin"}
            or not isinstance(item.get("architecture"), str)
            or not re.fullmatch(r"[a-z0-9_.-]{1,64}", item["architecture"])
            or item.get("mise_config_sha256") != policy["mise_config_sha256"]
            or item.get("identity_kind") != "mise_resolved_cpython"
        ):
            raise Rejected("python_policy_invalid")
        normalized.append(tuple(sorted(item.items())))
    if len(set(normalized)) != len(normalized):
        raise Rejected("python_policy_invalid")
    path = executable_path()
    executable, link_count = executable_identity_material(path)
    observed = {
        "implementation": sys.implementation.name,
        "version": ".".join(str(value) for value in sys.version_info[:3]),
        "executable_sha256": digest(executable),
        "executable_path_sha256": executable_path_sha256(path),
        "executable_link_count": link_count,
        "os": platform.system().lower(),
        "architecture": platform.machine().lower(),
        "mise_config_sha256": anchor["members"].get(MISE_PATH),
        "identity_kind": "mise_resolved_cpython",
    }
    if observed["version"] != policy["configured_version"]:
        raise Rejected("python_version_config_mismatch")
    return observed


def python_identity(anchor: dict[str, Any]) -> dict[str, str]:
    observed = observed_python_identity(anchor)
    allowed = anchor["python_policy"]["allowed"]
    matches = [
        item
        for item in allowed
        if isinstance(item, dict)
        and item == observed
        and set(item) == set(observed)
    ]
    if len(matches) != 1:
        raise Rejected("python_identity_not_allowed")
    return matches[0]


def atomic_generated_write(path: Path, data: bytes) -> None:
    try:
        relative_parent = path.parent.relative_to(ROOT)
    except ValueError as error:
        raise Rejected("identity_capture_path_invalid") from error
    current = ROOT
    for part in relative_parent.parts:
        current = current / part
        if not os.path.lexists(current):
            try:
                os.mkdir(current)
            except FileExistsError:
                pass
        metadata = os.stat(current, follow_symlinks=False)
        if (
            not stat.S_ISDIR(metadata.st_mode)
            or stat.S_ISLNK(metadata.st_mode)
            or getattr(metadata, "st_file_attributes", 0)
            & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
        ):
            raise Rejected("identity_capture_path_alias_rejected")
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
        os.replace(temporary, path)
        replaced = True
        if os.name == "posix":
            directory = os.open(path.parent, os.O_RDONLY)
            try:
                os.fsync(directory)
            finally:
                os.close(directory)
    except OSError as error:
        raise Rejected("identity_capture_write_failed") from error
    finally:
        if not replaced:
            temporary.unlink(missing_ok=True)
    if strict_read(path) != data:
        raise Rejected("identity_capture_readback_mismatch")


def identity_capture_report(
    anchor: dict[str, Any], identity: dict[str, str], approved: bool
) -> bytes:
    report = {
        "schema": 4,
        "report_kind": "rfc9114_v4_python_identity_capture",
        "status": "ApprovedIdentity" if approved else "UnapprovedIdentity",
        "shareable": True,
        "anchor_sha256": anchor["anchor_sha256"],
        "mise_config_sha256": anchor["members"][MISE_PATH],
        "identity": identity,
        "requires_explicit_refreeze": not approved,
    }
    expected_identity_keys = {
        "implementation",
        "version",
        "executable_sha256",
        "executable_path_sha256",
        "executable_link_count",
        "os",
        "architecture",
        "mise_config_sha256",
        "identity_kind",
    }
    if (
        set(report)
        != {
            "schema",
            "report_kind",
            "status",
            "shareable",
            "anchor_sha256",
            "mise_config_sha256",
            "identity",
            "requires_explicit_refreeze",
        }
        or set(identity) != expected_identity_keys
        or report["schema"] != 4
        or report["report_kind"] != "rfc9114_v4_python_identity_capture"
        or report["shareable"] is not True
        or report["status"] not in {"ApprovedIdentity", "UnapprovedIdentity"}
        or report["requires_explicit_refreeze"] is approved
        or report["mise_config_sha256"] != identity["mise_config_sha256"]
    ):
        raise Rejected("identity_capture_schema_mismatch")
    return (json.dumps(report, indent=2, sort_keys=True) + "\n").encode("utf-8")


def run_identity_capture() -> int:
    anchor, _snapshots, anchor_snapshot = load_anchor()
    identity = observed_python_identity(anchor)
    approved = identity in anchor["python_policy"]["allowed"]
    data = identity_capture_report(anchor, identity, approved)
    atomic_generated_write(
        ROOT / "build/root-validation/rfc9114-v4/python-identity-capture.json", data
    )
    final_anchor, _final_snapshots, final_anchor_snapshot = load_anchor()
    if (
        final_anchor_snapshot != anchor_snapshot
        or observed_python_identity(final_anchor) != identity
    ):
        raise Rejected("identity_capture_publication_drift")
    safe_stdout_line(
        "rfc9114_v4_identity status="
        + ("ApprovedIdentity" if approved else "UnapprovedIdentity")
    )
    return 0 if approved else 2


def binding() -> dict[str, Any]:
    anchor, snapshots, anchor_snapshot = load_anchor()
    identity = python_identity(anchor)
    launcher_snapshot = snapshots.get(LAUNCHER_PATH)
    if not isinstance(launcher_snapshot, bytes):
        raise Rejected("launcher_snapshot_missing")
    return {
        "schema": 4,
        "root": str(ROOT),
        "anchor": anchor,
        "anchor_relative": ANCHOR_PATH.relative_to(ROOT).as_posix(),
        "anchor_snapshot": anchor_snapshot,
        "anchor_sha256": EXPECTED_ANCHOR_SHA256,
        "snapshots": snapshots,
        "python_identity": identity,
        "launcher_snapshot": launcher_snapshot,
        "launcher_sha256": digest(launcher_snapshot),
    }


def execute_snapshot(snapshot: bytes, name: str, launch_binding: dict[str, Any]) -> dict[str, Any]:
    namespace = {
        "__name__": name,
        "__file__": f"<{name}-snapshot>",
        "__package__": None,
        "__builtins__": __builtins__,
        "__rfc9114_v4_binding__": launch_binding,
    }
    exec(compile(snapshot, f"<{name}-snapshot>", "exec"), namespace, namespace)
    return namespace


def run_cycle(mode: str) -> int:
    if mode not in {"red", "self-test", "apply"}:
        raise Rejected("invalid_mode")
    launch_binding = binding()
    run_id = digest(os.urandom(32))[:32]
    launcher = execute_snapshot(
        launch_binding["launcher_snapshot"], "rfc9114_v4_launcher", launch_binding
    )
    launch = launcher.get("launch")
    if not callable(launch):
        raise Rejected("launcher_entry_missing")
    application_exit = launch(mode, run_id)
    gate = execute_snapshot(
        launch_binding["snapshots"][GATE_PATH], "rfc9114_v4_gate", launch_binding
    )
    consume = gate.get("consume")
    if not callable(consume):
        raise Rejected("gate_consumer_missing")
    report = consume(mode, run_id)
    safe_stdout_line(
        f"rfc9114_v4_cycle status={report['status']} mode={mode} "
        f"run_id={run_id} application_exit={application_exit}"
    )
    return application_exit


def run_gate_self_test() -> int:
    launch_binding = binding()
    gate = execute_snapshot(
        launch_binding["snapshots"][GATE_PATH], "rfc9114_v4_gate", launch_binding
    )
    publish = gate.get("publish_gate_self_test")
    if not callable(publish):
        raise Rejected("gate_self_test_entry_missing")
    report = object_from(publish(), "gate_report")
    safe_stdout_line(
        f"rfc9114_v4_gate status={report['status']} "
        f"controls={report['controls_completed']}"
    )
    return 0


def run_tracked_gate() -> int:
    launch_binding = binding()
    gate = execute_snapshot(
        launch_binding["snapshots"][GATE_PATH], "rfc9114_v4_gate", launch_binding
    )
    tracked = gate.get("tracked_gate")
    if not callable(tracked):
        raise Rejected("tracked_gate_entry_missing")
    tracked()
    safe_stdout_line(
        "rfc9114_v4_gate status=Validated scope=tracked_source "
        f"independent_audit={launch_binding['anchor']['independent_audit']['status']}"
    )
    return 0


def run_consumer(mode: str, run_id: str | None) -> int:
    launch_binding = binding()
    gate = execute_snapshot(
        launch_binding["snapshots"][GATE_PATH], "rfc9114_v4_gate", launch_binding
    )
    consume = gate.get("consume")
    if not callable(consume):
        raise Rejected("gate_consumer_missing")
    report = consume(mode, run_id)
    safe_stdout_line(
        f"rfc9114_v4_consumer status={report['status']} mode={mode} run_id={run_id}"
    )
    return 0


def main(arguments: list[str]) -> int:
    if arguments == ["identity-capture"]:
        return run_identity_capture()
    if arguments == ["tracked"]:
        return run_tracked_gate()
    if arguments == ["gate-self-test"]:
        return run_gate_self_test()
    if len(arguments) == 2 and arguments[0] == "cycle":
        return run_cycle(arguments[1])
    if len(arguments) in {2, 3} and arguments[0] == "consume":
        return run_consumer(arguments[1], arguments[2] if len(arguments) == 3 else None)
    raise Rejected("invalid_arguments")


if __name__ == "__main__":
    try:
        raise SystemExit(main(sys.argv[1:]))
    except SystemExit:
        raise
    except BaseException as error:
        category = safe_exception_category(error)
        safe_stdout_line(
            f"rfc9114_v4_bootstrap status=Rejected category={category}"
        )
        raise SystemExit(1)

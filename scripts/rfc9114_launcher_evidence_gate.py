#!/usr/bin/env python3

# SPDX-FileCopyrightText: 2026 the http contributors
# SPDX-License-Identifier: MIT OR Apache-2.0

"""Consume the RFC 9114 launcher evidence without starting the native stack.

The gate is intentionally a read-only consumer.  It binds the two PowerShell
engine reports to an exact source inventory, an exact 88-mutant inventory, and
the immutable per-run reports behind the canonical pointers.  ``--self-test``
uses an in-memory bundle and publishes only a bounded gate-test report.
"""

from __future__ import annotations

import argparse
import copy
import ctypes
from ctypes import wintypes
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat
import struct
import sys
import tempfile
import time
import uuid
from typing import Any, Callable, Iterable, Mapping


LOCK_PATH = "standards/audits/rfc9114-launcher/evidence-lock.json"
GATE_PATH = "scripts/rfc9114_launcher_evidence_gate.py"
MUTATION_ROOT = "build/root-validation/rfc9114-peer-error-mapping/mutations"
MUTANT_ROOT = f"{MUTATION_ROOT}/launcher-structural-mutants-v4"
SUMMARY_PATH = f"{MUTANT_ROOT}/summary.json"
INVALIDATION_PATH = (
    "standards/audits/rfc9114-launcher/legacy-evidence-invalidations.json"
)
INTEGRATION_PATH = "standards/audits/rfc9114-launcher/integration-candidate.json"
GATE_CONTROLS_PATH = "standards/audits/rfc9114-launcher/gate-controls.json"
FIX_MATRIX_PATH = "standards/audits/rfc9114-launcher/fix-matrix.json"
MISE_PATH = ".mise.toml"
CI_PATH = ".github/workflows/ci.yml"

MAX_LOCK_BYTES = 1_048_576
MAX_ARTIFACT_BYTES = 4_194_304
MAX_EVIDENCE_BYTES = 4_194_304
MAX_JSON_DEPTH = 32
ABSOLUTE_GATE_SECONDS = 60.0
HASH_RE = re.compile(r"^[0-9a-f]{64}$")
RUN_RE = re.compile(r"^[0-9a-f]{32}$")
IDENT_RE = re.compile(r"^[a-z0-9][a-z0-9_.-]{0,119}$")
CONTROL_RE = re.compile(r"^[a-z0-9][a-z0-9_]{0,119}$")
VERSION_RE = re.compile(r"^[0-9]+(?:\.[0-9]+){1,3}$")
NATIVE_PROCESS_NAMES = {"erl", "werl", "beam.smp", "escript", "gleam"}
SHELL_PROCESS_NAMES = {
    "cmd",
    "conhost",
    "openconsole",
    "windowsterminal",
    "powershell",
    "pwsh",
}

TRACKED_ROOTS = (
    ".mise.toml",
    "packages/http3/gleam.toml",
    "packages/http3/manifest.toml",
    "packages/http3/src",
    "packages/http3/test",
    "packages/quic_core/gleam.toml",
    "packages/quic_core/manifest.toml",
    "packages/quic_core/src",
    "packages/quic_core/test",
)

REQUIRED_ARTIFACTS = {
    "launcher": f"{MUTATION_ROOT}/run_hidden_mutation.ps1",
    "supervisor_client": f"{MUTATION_ROOT}/supervisor_packet_client.ps1",
    "process_supervisor": "scripts/process_supervisor.py",
    "contract_checker": f"{MUTATION_ROOT}/launcher_contract_check.ps1",
    "supervisor_client_test": (
        f"{MUTATION_ROOT}/supervisor_packet_client_contract_test.ps1"
    ),
    "mutant_preparer": f"{MUTATION_ROOT}/prepare_launcher_contract_mutants_v4.ps1",
    "mutant_auditor": f"{MUTATION_ROOT}/audit_launcher_contract_mutants_v4.ps1",
    "mutant_summary": SUMMARY_PATH,
    "mutation_probe": f"{MUTATION_ROOT}/mutation_probe.escript",
    "outer_runner": f"{MUTATION_ROOT}/outer_mutation_runner.escript",
    "supervised_runner": "scripts/supervised_gleam.escript",
    "process_runner": "scripts/process_runner.escript",
    "command_capture": "scripts/command_capture.hrl",
    "native_mutant_preparer": f"{MUTATION_ROOT}/prepare_mutations.ps1",
    "native_static_summary": f"{MUTATION_ROOT}/static-summary.json",
    "evidence_gate": GATE_PATH,
    "lock_builder": "scripts/rfc9114_launcher_evidence_lock.py",
    "gate_controls": GATE_CONTROLS_PATH,
    "fix_matrix": FIX_MATRIX_PATH,
    "legacy_invalidation": INVALIDATION_PATH,
    "integration_candidate": INTEGRATION_PATH,
}

EVIDENCE_PATHS = {
    "ps5.1": f"{MUTATION_ROOT}/launcher-structural-audit-v4-ps5.1.json",
    "ps7.6": f"{MUTATION_ROOT}/launcher-structural-audit-v4-ps7.6.json",
}

MUTATION_IDS = (
    "running-after-relative-self-check",
    "comment-decoy-supervisor-call",
    "string-decoy-supervisor-call",
    "dead-code-decoy-supervisor-call",
    "active-file-poll-cap",
    "owned-exit-removed-from-ready",
    "compatibility-drift-self-compared",
    "toolchain-drift-unconditional",
    "freeze-after-check-removed",
    "host-after-gate-removed",
    "private-helper-after-check-removed",
    "source-lock-ready-gate-removed",
    "boundary-lock-ready-gate-removed",
    "compatibility-result-unconditional",
    "toolchain-result-unconditional",
    "identity-map-fail-open",
    "freeze-comparison-decoy",
    "host-identity-self-compared",
    "tool-identity-self-compared",
    "source-identity-self-compared",
    "atomic-replace-null-backup",
    "atomic-replace-downgraded-to-copy",
    "ordinal-sort-replaced-by-culture-sort",
    "utf8-frame-path-removed",
    "raw-output-clear-removed",
    "mode-exclusivity-disabled",
    "contract-checker-after-self-compared",
    "unrelated-supervisor-result-receiver",
    "direct-escript-root-process",
    "wrong-process-kill-receiver",
    "abort-parent-eof-removed",
    "dead-parent-eof-decoy",
    "supervisor-output-cap-bypassed",
    "wrong-process-start-receiver",
    "visible-supervisor-window",
    "unbounded-stderr-reader",
    "window-style-normal",
    "output-cap-variable-decoy",
    "startinfo-arguments-decoupled",
    "wrong-supervisor-working-directory",
    "process-dispose-removed",
    "exit-observation-forced",
    "protocol-cap-guard-disabled",
    "stderr-cap-guard-disabled",
    "process-startinfo-decoupled",
    "parent-eof-classification-removed",
    "parent-eof-job-termination-removed",
    "parent-eof-tree-convergence-removed",
    "atomic-writer-early-return",
    "atomic-writer-early-throw",
    "atomic-writer-indirect-dead-path",
    "atomic-readback-bypassed",
    "atomic-readback-unbounded",
    "atomic-flush-not-durable",
    "atomic-write-through-disabled",
    "running-receipt-gate-disabled",
    "running-receipt-result-ignored",
    "hashmap-type-equality-disabled",
    "hashmap-key-comparison-case-insensitive",
    "hashmap-observed-type-check-disabled",
    "hashmap-null-check-disabled",
    "hidden-flags-indirect-dead-branch",
    "hidden-flags-after-process-start",
    "hidden-assignment-moved-after-start",
    "direct-ampersand-escript",
    "direct-dot-escript",
    "direct-ampersand-python",
    "direct-ampersand-gleam",
    "direct-ampersand-outer-runner",
    "extra-process-start",
    "static-process-start",
    "start-process-command",
    "invoke-command-launch",
    "cmd-launch",
    "powershell-launch",
    "pwsh-launch",
    "iex-launch",
    "lease-acquisition-disabled",
    "lease-ready-gate-disabled",
    "failure-canonical-lease-guard-disabled",
    "canonical-evidence-delete-on-failure",
    "canonical-terminal-published-before-per-run",
    "lease-released-before-canonical-terminal",
    "per-run-hash-pointer-removed",
    "per-run-hash-pointer-forged",
    "shared-per-run-evidence-path",
    "canonical-running-publish-removed",
    "lease-wait-made-unbounded",
)

BLOCKER_IDS = (
    "live_inventory_drift",
    "ready_freeze_absent",
    "checker_allows_unsupervised_invocation",
    "checker_allows_disabled_atomic_writer",
    "checker_allows_disabled_hidden_flags",
    "hash_map_not_strict",
    "evidence_has_no_consumer_gate",
    "shared_evidence_path_race",
)

FALSE_GREEN_IDS = (
    "atomic_writer_early_return",
    "atomic_writer_early_throw",
    "atomic_writer_indirect_dead_branch",
    "hidden_flags_indirect_false",
    "direct_call_before_supervisor",
)

LEGACY_EVIDENCE = (
    (
        "launcher_freeze_v2",
        f"{MUTATION_ROOT}/launcher-freeze.json",
        "2c7467569d7debbc788400aaec5b583fcfa2a50382bfba4ed9178b90fa9c385e",
    ),
    (
        "structural_v3_ps5",
        f"{MUTATION_ROOT}/launcher-structural-audit-v3-ps5.1.json",
        "226d97a0009d4b37b01dbd4103433018a118e0d6517dcaa896a776a9a1ec6446",
    ),
    (
        "structural_v3_ps7",
        f"{MUTATION_ROOT}/launcher-structural-audit-v3-ps7.6.json",
        "fa8608696dc87f9a03d654ddb9d4e4689e0788ca095ccc4b991000c17ecd8332",
    ),
    (
        "structural_v3_independent_ps5",
        f"{MUTATION_ROOT}/launcher-structural-audit-v3-independent-ps5.1.json",
        "107f5c63212d6a5ab9edf1f614978ca289fda653f73d603226df983955aa898e",
    ),
    (
        "structural_v2_ps5",
        f"{MUTATION_ROOT}/launcher-structural-audit-ps5.1.json",
        "670e08facafa45e4da802e691e4655ee55a7ce998870bd7ff4500ef341b4089c",
    ),
    (
        "structural_v2_ps7",
        f"{MUTATION_ROOT}/launcher-structural-audit-ps7.6.json",
        "265c879e915e8ce8bb8b4163eff5fe4dee95fb455fc29a00df0d50c15a6dce9f",
    ),
    (
        "compatibility_v2",
        f"{MUTATION_ROOT}/launcher-compatibility.evidence.json",
        "09f0fbe91c8cab0380fd4d4a3864022ec53aeacebe4c98e9d22729a315de2df7",
    ),
    (
        "hardening_v2",
        f"{MUTATION_ROOT}/launcher-hardening.evidence.json",
        "a58454db09ab4a5923aaf97a3fc75d54daa78283b83bcebe5874668838bd626f",
    ),
    (
        "mutant_summary_v3",
        f"{MUTATION_ROOT}/launcher-structural-mutants-v3/summary.json",
        "7029b285c8cf3d46c91b737eecfc7a0fffea9c97f2f0497d9622efadd5b0971c",
    ),
    (
        "launcher_static_red",
        f"{MUTATION_ROOT}/launcher-static-red.evidence.json",
        "26ffcc193bb242ed81fb770847993447a02964afcef1f84f8951cfd916f3514c",
    ),
    (
        "independent_launcher_audit_report",
        (
            "build/root-validation/rfc9114-peer-error-mapping/"
            "independent-launcher-audit/independent-audit-report.json"
        ),
        "15b54017c152dfa1e6357f070d301ec48828a46e8707c23f28f5a70691fbeda9",
    ),
)

IDENTITY_KEYS = {
    "launcher",
    "supervisor_client",
    "process_supervisor",
    "checker",
    "preparer",
    "summary",
}
EVIDENCE_KEYS = {
    "schema",
    "report_kind",
    "run_id",
    "status",
    "shareable",
    "engine",
    "production_controls_passed",
    "mutation_set_expected",
    "mutation_count",
    "mutations_detected",
    "mutation_ids_unique",
    "mutant_hashes_unique",
    "manifest_hashes_unique",
    "results",
    "identities_before",
    "identities_after",
    "source_fresh",
    "absolute_deadline_ms",
    "elapsed_ms",
    "native_started",
    "native_residual_count",
    "new_visible_shell_count",
    "raw_output_retained",
    "exclusive_lease_held_at_terminal_publish",
    "running_canonical_published",
    "running_per_run_published",
    "canonical_evidence",
    "per_run_evidence_file",
    "per_run_evidence_sha256",
}


class Rejected(ValueError):
    """A deliberately safe, finite failure classification."""


def reject(code: str) -> None:
    if not CONTROL_RE.fullmatch(code):
        code = "unexpected_gate_failure"
    raise Rejected(code)


ACTIVE_DEADLINE = float("inf")


def check_deadline() -> None:
    if time.monotonic() > ACTIVE_DEADLINE:
        reject("gate_absolute_deadline")


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def canonical_json(value: Any) -> bytes:
    return json.dumps(
        value, ensure_ascii=False, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")


def pretty_json(value: Any) -> bytes:
    return (json.dumps(value, ensure_ascii=False, indent=2) + "\n").encode("utf-8")


def duplicate_rejecting_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            reject("json_duplicate_key")
        result[key] = value
    return result


def json_depth(value: Any, depth: int = 0) -> int:
    if depth > MAX_JSON_DEPTH:
        reject("json_depth_rejected")
    if isinstance(value, dict):
        for key, item in value.items():
            if type(key) is not str:
                reject("json_key_type_rejected")
            json_depth(item, depth + 1)
    elif isinstance(value, list):
        for item in value:
            json_depth(item, depth + 1)
    return depth


def parse_json(data: bytes, category: str) -> dict[str, Any]:
    try:
        text = data.decode("utf-8", errors="strict")
        value = json.loads(
            text,
            object_pairs_hook=duplicate_rejecting_object,
            parse_constant=lambda _value: reject("json_constant_rejected"),
        )
    except Rejected:
        raise
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise Rejected(f"{category}_invalid_json") from error
    json_depth(value)
    if type(value) is not dict:
        reject(f"{category}_not_object")
    return value


def exact_keys(value: Any, expected: set[str], code: str) -> dict[str, Any]:
    if type(value) is not dict or set(value) != expected:
        reject(code)
    return value


def exact_bool(value: Any, expected: bool, code: str) -> None:
    if type(value) is not bool or value is not expected:
        reject(code)


def exact_int(value: Any, minimum: int, maximum: int, code: str) -> None:
    if type(value) is not int or not minimum <= value <= maximum:
        reject(code)


def hash_value(value: Any, code: str) -> str:
    if type(value) is not str or not HASH_RE.fullmatch(value):
        reject(code)
    return value


def run_value(value: Any, code: str) -> str:
    if type(value) is not str or not RUN_RE.fullmatch(value):
        reject(code)
    return value


def normalized_relative(value: Any, code: str = "path_rejected") -> str:
    if type(value) is not str or not value or "\\" in value or "\x00" in value:
        reject(code)
    path = PurePosixPath(value)
    if path.is_absolute() or any(part in {"", ".", ".."} for part in path.parts):
        reject(code)
    if ":" in path.parts[0]:
        reject(code)
    normalized = path.as_posix()
    if normalized != value:
        reject(code)
    return normalized


def normalized_process_name(value: str) -> str:
    name = Path(value).name.lower()
    return name[:-4] if name.endswith(".exe") else name


def process_snapshot() -> tuple[dict[int, str], set[int]]:
    """Return process names and visible-window PIDs without a child process."""
    if os.name != "nt":
        processes: dict[int, str] = {}
        proc = Path("/proc")
        if proc.is_dir():
            for entry in proc.iterdir():
                if not entry.name.isdigit():
                    continue
                try:
                    name = (entry / "comm").read_text(encoding="utf-8").strip()
                except (OSError, UnicodeError):
                    continue
                processes[int(entry.name)] = normalized_process_name(name)
        return processes, set()

    class ProcessEntry32W(ctypes.Structure):
        _fields_ = [
            ("dwSize", wintypes.DWORD),
            ("cntUsage", wintypes.DWORD),
            ("th32ProcessID", wintypes.DWORD),
            ("th32DefaultHeapID", ctypes.c_size_t),
            ("th32ModuleID", wintypes.DWORD),
            ("cntThreads", wintypes.DWORD),
            ("th32ParentProcessID", wintypes.DWORD),
            ("pcPriClassBase", wintypes.LONG),
            ("dwFlags", wintypes.DWORD),
            ("szExeFile", wintypes.WCHAR * 260),
        ]

    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel32.CreateToolhelp32Snapshot.argtypes = (wintypes.DWORD, wintypes.DWORD)
    kernel32.CreateToolhelp32Snapshot.restype = wintypes.HANDLE
    kernel32.Process32FirstW.argtypes = (wintypes.HANDLE, ctypes.POINTER(ProcessEntry32W))
    kernel32.Process32FirstW.restype = wintypes.BOOL
    kernel32.Process32NextW.argtypes = (wintypes.HANDLE, ctypes.POINTER(ProcessEntry32W))
    kernel32.Process32NextW.restype = wintypes.BOOL
    kernel32.CloseHandle.argtypes = (wintypes.HANDLE,)
    kernel32.CloseHandle.restype = wintypes.BOOL
    snapshot = kernel32.CreateToolhelp32Snapshot(0x00000002, 0)
    invalid_handle = ctypes.c_void_p(-1).value
    if snapshot == invalid_handle:
        reject("process_snapshot_rejected")
    entry = ProcessEntry32W()
    entry.dwSize = ctypes.sizeof(entry)
    processes = {}
    try:
        present = bool(kernel32.Process32FirstW(snapshot, ctypes.byref(entry)))
        while present:
            processes[int(entry.th32ProcessID)] = normalized_process_name(entry.szExeFile)
            present = bool(kernel32.Process32NextW(snapshot, ctypes.byref(entry)))
    finally:
        kernel32.CloseHandle(snapshot)

    visible: set[int] = set()
    user32 = ctypes.WinDLL("user32", use_last_error=True)
    callback_type = ctypes.WINFUNCTYPE(wintypes.BOOL, wintypes.HWND, wintypes.LPARAM)

    @callback_type
    def collect(window: int, _parameter: int) -> bool:
        if user32.IsWindowVisible(window):
            process_id = wintypes.DWORD()
            user32.GetWindowThreadProcessId(window, ctypes.byref(process_id))
            if process_id.value:
                visible.add(int(process_id.value))
        return True

    user32.EnumWindows.argtypes = (callback_type, wintypes.LPARAM)
    user32.EnumWindows.restype = wintypes.BOOL
    user32.IsWindowVisible.argtypes = (wintypes.HWND,)
    user32.IsWindowVisible.restype = wintypes.BOOL
    user32.GetWindowThreadProcessId.argtypes = (
        wintypes.HWND,
        ctypes.POINTER(wintypes.DWORD),
    )
    user32.GetWindowThreadProcessId.restype = wintypes.DWORD
    if not user32.EnumWindows(collect, 0):
        reject("window_snapshot_rejected")
    return processes, visible


def process_postconditions(
    before: tuple[dict[int, str], set[int]],
    after: tuple[dict[int, str], set[int]],
) -> tuple[bool, int, int]:
    before_processes, before_visible = before
    after_processes, after_visible = after
    new_native = {
        pid
        for pid, name in after_processes.items()
        if name in NATIVE_PROCESS_NAMES and pid not in before_processes
    }
    native_residual = sum(
        1 for name in after_processes.values() if name in NATIVE_PROCESS_NAMES
    )
    new_visible_shell = sum(
        1
        for pid in after_visible - before_visible
        if after_processes.get(pid, "") in SHELL_PROCESS_NAMES
    )
    return bool(new_native), native_residual, new_visible_shell


class Store:
    def read(self, relative: str, maximum: int) -> bytes:
        raise NotImplementedError

    def list_files(self, relative: str) -> list[str]:
        raise NotImplementedError


class DiskStore(Store):
    def __init__(self, root: Path):
        self.root = root.resolve(strict=True)

    def _path(self, relative: str) -> Path:
        safe = normalized_relative(relative)
        candidate = self.root.joinpath(*PurePosixPath(safe).parts)
        absolute = candidate.absolute()
        try:
            if os.path.commonpath((str(self.root), str(absolute))) != str(self.root):
                reject("path_outside_repository")
        except ValueError:
            reject("path_outside_repository")
        current = self.root
        for part in PurePosixPath(safe).parts:
            current = current / part
            try:
                value = os.lstat(current)
            except FileNotFoundError:
                break
            attributes = getattr(value, "st_file_attributes", 0)
            reparse = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
            if stat.S_ISLNK(value.st_mode) or attributes & reparse:
                reject("input_alias_rejected")
        return absolute

    @staticmethod
    def _identity(value: os.stat_result) -> tuple[int, int, int, int, int]:
        return (
            int(value.st_dev),
            int(value.st_ino),
            int(value.st_size),
            int(value.st_mtime_ns),
            int(value.st_nlink),
        )

    @staticmethod
    def _regular_identity(value: os.stat_result) -> bool:
        if not stat.S_ISREG(value.st_mode) or value.st_nlink != 1:
            return False
        attributes = getattr(value, "st_file_attributes", 0)
        reparse = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
        return not bool(attributes & reparse)

    def read(self, relative: str, maximum: int) -> bytes:
        check_deadline()
        path = self._path(relative)
        try:
            before = os.lstat(path)
        except OSError as error:
            raise Rejected("input_missing") from error
        if not self._regular_identity(before) or before.st_size <= 0 or before.st_size > maximum:
            reject("input_identity_or_size_rejected")
        flags = os.O_RDONLY | getattr(os, "O_BINARY", 0)
        flags |= getattr(os, "O_NOFOLLOW", 0)
        try:
            descriptor = os.open(path, flags)
        except OSError as error:
            raise Rejected("input_open_rejected") from error
        try:
            opened = os.fstat(descriptor)
            if self._identity(opened) != self._identity(before):
                reject("input_identity_drift")
            chunks: list[bytes] = []
            remaining = maximum + 1
            while remaining > 0:
                check_deadline()
                chunk = os.read(descriptor, min(65_536, remaining))
                if not chunk:
                    break
                chunks.append(chunk)
                remaining -= len(chunk)
            data = b"".join(chunks)
            after = os.fstat(descriptor)
            if (
                len(data) != before.st_size
                or len(data) > maximum
                or self._identity(after) != self._identity(before)
            ):
                reject("input_identity_drift")
            return data
        finally:
            os.close(descriptor)

    def list_files(self, relative: str) -> list[str]:
        check_deadline()
        root = self._path(relative)
        try:
            root_stat = os.lstat(root)
        except OSError as error:
            raise Rejected("tracked_root_missing") from error
        if stat.S_ISREG(root_stat.st_mode):
            return [normalized_relative(relative)]
        if not stat.S_ISDIR(root_stat.st_mode):
            reject("tracked_root_identity_rejected")
        paths: list[str] = []
        for directory, names, files in os.walk(root, followlinks=False):
            check_deadline()
            names.sort()
            files.sort()
            for name in names:
                item = Path(directory) / name
                value = os.lstat(item)
                attributes = getattr(value, "st_file_attributes", 0)
                reparse = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
                if stat.S_ISLNK(value.st_mode) or attributes & reparse:
                    reject("tracked_root_alias_rejected")
            for name in files:
                item = Path(directory) / name
                relative_path = item.relative_to(self.root).as_posix()
                paths.append(normalized_relative(relative_path))
        return sorted(paths)


class MemoryStore(Store):
    def __init__(self, files: Mapping[str, bytes]):
        self.files = {normalized_relative(key): bytes(value) for key, value in files.items()}

    def clone(self) -> "MemoryStore":
        return MemoryStore(self.files)

    def read(self, relative: str, maximum: int) -> bytes:
        check_deadline()
        safe = normalized_relative(relative)
        if safe not in self.files:
            reject("input_missing")
        data = self.files[safe]
        if not data or len(data) > maximum:
            reject("input_identity_or_size_rejected")
        return data

    def list_files(self, relative: str) -> list[str]:
        check_deadline()
        safe = normalized_relative(relative)
        if safe in self.files:
            return [safe]
        prefix = safe.rstrip("/") + "/"
        values = sorted(path for path in self.files if path.startswith(prefix))
        if not values:
            reject("tracked_root_missing")
        return values


def records_identity(records: Iterable[tuple[str, int, str]]) -> str:
    framed = bytearray()
    for path, size, digest in records:
        for value in (path, str(size), digest):
            field = value.encode("utf-8")
            framed.extend(struct.pack(">I", len(field)))
            framed.extend(field)
    return sha256(bytes(framed))


def source_identity(store: Store) -> dict[str, Any]:
    discovered: set[str] = set()
    records: list[tuple[str, int, str]] = []
    for root in TRACKED_ROOTS:
        check_deadline()
        for relative in store.list_files(root):
            if relative in discovered:
                reject("source_inventory_duplicate_path")
            discovered.add(relative)
            data = store.read(relative, MAX_ARTIFACT_BYTES)
            records.append((relative, len(data), sha256(data)))
    records.sort(key=lambda item: item[0])
    return {
        "tracked_roots": list(TRACKED_ROOTS),
        "file_count": len(records),
        "framed_sha256": records_identity(records),
        "mise_sha256": sha256(store.read(MISE_PATH, MAX_ARTIFACT_BYTES)),
        "ci_sha256": sha256(store.read(CI_PATH, MAX_ARTIFACT_BYTES)),
    }


def validate_source_epoch(value: Any, store: Store) -> None:
    exact_keys(
        value,
        {"tracked_roots", "file_count", "framed_sha256", "mise_sha256", "ci_sha256"},
        "source_epoch_schema_mismatch",
    )
    if value.get("tracked_roots") != list(TRACKED_ROOTS):
        reject("source_root_inventory_mismatch")
    exact_int(value.get("file_count"), 1, 100_000, "source_file_count_rejected")
    for key in ("framed_sha256", "mise_sha256", "ci_sha256"):
        hash_value(value.get(key), "source_epoch_hash_rejected")
    if value != source_identity(store):
        reject("source_identity_stale")


def artifact_map(value: Any, store: Store) -> dict[str, str]:
    if type(value) is not list or len(value) != len(REQUIRED_ARTIFACTS):
        reject("artifact_inventory_count_mismatch")
    observed: dict[str, str] = {}
    expected_roles = list(REQUIRED_ARTIFACTS)
    for index, item in enumerate(value):
        exact_keys(item, {"role", "path", "sha256"}, "artifact_entry_schema_mismatch")
        role = item.get("role")
        if type(role) is not str or role != expected_roles[index] or role in observed:
            reject("artifact_role_inventory_mismatch")
        path = normalized_relative(item.get("path"), "artifact_path_rejected")
        if path != REQUIRED_ARTIFACTS[role]:
            reject("artifact_path_rejected")
        expected_hash = hash_value(item.get("sha256"), "artifact_hash_rejected")
        if sha256(store.read(path, MAX_ARTIFACT_BYTES)) != expected_hash:
            reject("artifact_identity_drift")
        observed[role] = expected_hash
    return observed


def validate_policy(value: Any) -> dict[str, int]:
    exact_keys(
        value,
        {
            "production_controls",
            "mutation_count",
            "absolute_deadline_ms",
            "maximum_artifact_bytes",
            "maximum_evidence_bytes",
        },
        "policy_schema_mismatch",
    )
    expected = {
        "production_controls": 55,
        "mutation_count": len(MUTATION_IDS),
        "absolute_deadline_ms": 1_200_000,
        "maximum_artifact_bytes": MAX_ARTIFACT_BYTES,
        "maximum_evidence_bytes": MAX_EVIDENCE_BYTES,
    }
    if value != expected:
        reject("policy_value_mismatch")
    return expected


def validate_invalidation(value: Any) -> None:
    exact_keys(
        value,
        {
            "schema",
            "invalidation_kind",
            "status",
            "shareable",
            "current_generation",
            "invalidated",
            "replacement",
            "reason_codes",
        },
        "invalidation_schema_mismatch",
    )
    if (
        type(value.get("schema")) is not int
        or type(value.get("current_generation")) is not int
        or value.get("schema") != 1
        or value.get("invalidation_kind")
        != "rfc9114_launcher_evidence_invalidation_chain"
        or value.get("status") != "Active"
        or value.get("shareable") is not True
        or value.get("current_generation") != 4
    ):
        reject("invalidation_identity_mismatch")
    invalidated = value.get("invalidated")
    if type(invalidated) is not list or len(invalidated) != len(LEGACY_EVIDENCE):
        reject("invalidation_inventory_count_mismatch")
    expected_reasons = [
        "source_inventory_drift",
        "atomic_writer_contract_not_live",
        "hidden_process_contract_not_live",
        "identity_map_structure_not_strict",
        "external_invocation_allowlist_incomplete",
        "consumer_gate_absent",
        "shared_evidence_path_race",
        "independent_reaudit_required",
    ]
    for index, item in enumerate(invalidated):
        check_deadline()
        exact_keys(
            item,
            {"id", "path", "sha256", "generation", "status", "reason_codes"},
            "invalidation_entry_schema_mismatch",
        )
        legacy_id, path, digest = LEGACY_EVIDENCE[index]
        if item != {
            "id": legacy_id,
            "path": path,
            "sha256": digest,
            "generation": 3 if "v3" in legacy_id else 2,
            "status": "Rejected",
            "reason_codes": expected_reasons,
        }:
            reject("invalidation_entry_mismatch")
    replacement = exact_keys(
        value.get("replacement"),
        {"lock_path", "status", "independent_audit_required"},
        "invalidation_replacement_schema_mismatch",
    )
    if replacement != {
        "lock_path": LOCK_PATH,
        "status": "Pending",
        "independent_audit_required": True,
    }:
        reject("invalidation_replacement_mismatch")
    if value.get("reason_codes") != expected_reasons:
        reject("invalidation_reason_inventory_mismatch")


def validate_integration(value: Any, store: Store) -> None:
    exact_keys(
        value,
        {"schema", "integration_kind", "status", "mise", "ci", "constraints"},
        "integration_schema_mismatch",
    )
    if (
        type(value.get("schema")) is not int
        or value.get("schema") != 1
        or value.get("integration_kind") != "rfc9114_launcher_gate_integration"
        or value.get("status") not in {"Staged", "Wired"}
    ):
        reject("integration_identity_mismatch")
    mise = exact_keys(
        value.get("mise"),
        {"task", "command", "wired"},
        "integration_mise_schema_mismatch",
    )
    ci = exact_keys(
        value.get("ci"),
        {"workflow", "job", "command", "artifact_paths", "wired"},
        "integration_ci_schema_mismatch",
    )
    command = (
        "python -I -B scripts/rfc9114_launcher_evidence_gate.py "
        "--lock standards/audits/rfc9114-launcher/evidence-lock.json"
    )
    if (
        mise.get("task") != "rfc9114-launcher-evidence-gate"
        or mise.get("command") != command
        or type(mise.get("wired")) is not bool
        or ci.get("workflow") != CI_PATH
        or ci.get("job") != "rfc9114-launcher-evidence-gate"
        or ci.get("command") != command
        or type(ci.get("wired")) is not bool
        or ci.get("artifact_paths")
        != [
            EVIDENCE_PATHS["ps5.1"],
            EVIDENCE_PATHS["ps7.6"],
            (
                "build/root-validation/rfc9114-peer-error-mapping/mutations/"
                "launcher-structural-audit-v4-ps*.json"
            ),
        ]
        or value.get("constraints")
        != {
            "native_execution": "forbidden",
            "independent_audit_before_ready": True,
            "canonical_source_required": True,
        }
    ):
        reject("integration_value_mismatch")
    expected_status = "Wired" if mise["wired"] and ci["wired"] else "Staged"
    if value["status"] != expected_status:
        reject("integration_status_mismatch")
    # Force both tracked configuration inputs through the same bounded reader.
    store.read(MISE_PATH, MAX_ARTIFACT_BYTES)
    store.read(CI_PATH, MAX_ARTIFACT_BYTES)


def validate_summary(
    value: Any, store: Store, artifacts: Mapping[str, str]
) -> list[dict[str, Any]]:
    exact_keys(
        value,
        {
            "schema",
            "report_kind",
            "status",
            "shareable",
            "source_hashes",
            "mutation_count",
            "mutations",
        },
        "summary_schema_mismatch",
    )
    if (
        type(value.get("schema")) is not int
        or type(value.get("mutation_count")) is not int
        or value.get("schema") != 2
        or value.get("report_kind")
        != "rfc9114_launcher_structural_contract_mutations_v4"
        or value.get("status") != "Prepared"
        or value.get("shareable") is not True
        or value.get("mutation_count") != len(MUTATION_IDS)
    ):
        reject("summary_identity_mismatch")
    source_hashes = exact_keys(
        value.get("source_hashes"),
        {"launcher", "supervisor_client", "process_supervisor"},
        "summary_source_schema_mismatch",
    )
    if source_hashes != {
        "launcher": artifacts["launcher"],
        "supervisor_client": artifacts["supervisor_client"],
        "process_supervisor": artifacts["process_supervisor"],
    }:
        reject("summary_source_identity_mismatch")
    mutations = value.get("mutations")
    if type(mutations) is not list or len(mutations) != len(MUTATION_IDS):
        reject("summary_mutation_count_mismatch")
    mutant_hashes: set[str] = set()
    manifest_hashes: set[str] = set()
    for index, item in enumerate(mutations):
        check_deadline()
        exact_keys(
            item,
            {"mutation_id", "target", "mutated_sha256", "manifest_sha256"},
            "summary_mutation_schema_mismatch",
        )
        mutation_id = item.get("mutation_id")
        if mutation_id != MUTATION_IDS[index]:
            reject("summary_mutation_id_inventory_mismatch")
        target = item.get("target")
        if target not in {"launcher", "supervisor_client", "process_supervisor"}:
            reject("summary_mutation_target_rejected")
        mutant_hash = hash_value(item.get("mutated_sha256"), "summary_mutant_hash_rejected")
        manifest_hash = hash_value(
            item.get("manifest_sha256"), "summary_manifest_hash_rejected"
        )
        if mutant_hash in mutant_hashes or manifest_hash in manifest_hashes:
            reject("summary_mutation_hash_duplicate")
        mutant_hashes.add(mutant_hash)
        manifest_hashes.add(manifest_hash)
        directory = f"{MUTANT_ROOT}/{mutation_id}"
        source_name = {
            "launcher": "run_hidden_mutation.ps1",
            "supervisor_client": "supervisor_packet_client.ps1",
            "process_supervisor": "process_supervisor.py",
        }[target]
        expected_files = sorted([f"{directory}/mutation.json", f"{directory}/{source_name}"])
        if store.list_files(directory) != expected_files:
            reject("mutation_file_inventory_mismatch")
        manifest_bytes = store.read(f"{directory}/mutation.json", MAX_ARTIFACT_BYTES)
        if sha256(manifest_bytes) != manifest_hash:
            reject("mutation_manifest_identity_mismatch")
        manifest = parse_json(manifest_bytes, "mutation_manifest")
        exact_keys(
            manifest,
            {
                "schema",
                "mutation_id",
                "status",
                "shareable",
                "target",
                "changed_file_count",
                "contiguous_edit_count",
                "replacement_count",
                "original_sha256",
                "mutated_sha256",
                "reverse_restored_sha256",
            },
            "mutation_manifest_schema_mismatch",
        )
        for numeric_key in (
            "schema",
            "changed_file_count",
            "contiguous_edit_count",
            "replacement_count",
        ):
            if type(manifest.get(numeric_key)) is not int:
                reject("mutation_manifest_type_mismatch")
        original_role = target
        if manifest != {
            "schema": 2,
            "mutation_id": mutation_id,
            "status": "Prepared",
            "shareable": True,
            "target": target,
            "changed_file_count": 1,
            "contiguous_edit_count": 1,
            "replacement_count": 1,
            "original_sha256": artifacts[original_role],
            "mutated_sha256": mutant_hash,
            "reverse_restored_sha256": artifacts[original_role],
        }:
            reject("mutation_manifest_value_mismatch")
        if sha256(store.read(f"{directory}/{source_name}", MAX_ARTIFACT_BYTES)) != mutant_hash:
            reject("mutated_source_identity_mismatch")
    return mutations


def validate_engine(value: Any, expected_label: str) -> str:
    exact_keys(
        value,
        {
            "label",
            "powershell_version",
            "powershell_edition",
            "executable_name",
            "executable_sha256",
            "os_platform",
            "os_version",
            "os_is_64_bit",
        },
        "engine_schema_mismatch",
    )
    if value.get("label") != expected_label or value.get("os_platform") != "Win32NT":
        reject("engine_identity_mismatch")
    exact_bool(value.get("os_is_64_bit"), True, "engine_identity_mismatch")
    if type(value.get("os_version")) is not str or not VERSION_RE.fullmatch(value["os_version"]):
        reject("engine_os_version_rejected")
    version = value.get("powershell_version")
    if type(version) is not str or not VERSION_RE.fullmatch(version):
        reject("engine_version_rejected")
    if expected_label == "ps5.1":
        if (
            not version.startswith("5.1.")
            or value.get("powershell_edition") != "Desktop"
            or value.get("executable_name") != "powershell.exe"
        ):
            reject("engine_identity_mismatch")
    elif (
        not version.startswith("7.6.")
        or value.get("powershell_edition") != "Core"
        or value.get("executable_name") != "pwsh.exe"
    ):
        reject("engine_identity_mismatch")
    return hash_value(value.get("executable_sha256"), "engine_executable_hash_rejected")


def validate_result(
    value: Any, expected: Mapping[str, Any], mutation_id: str
) -> None:
    exact_keys(
        value,
        {
            "mutation_id",
            "target",
            "detected",
            "failed_control_count",
            "failed_controls",
            "mutated_sha256",
            "manifest_sha256",
        },
        "result_schema_mismatch",
    )
    if (
        value.get("mutation_id") != mutation_id
        or value.get("target") != expected["target"]
        or value.get("mutated_sha256") != expected["mutated_sha256"]
        or value.get("manifest_sha256") != expected["manifest_sha256"]
    ):
        reject("result_identity_mismatch")
    exact_bool(value.get("detected"), True, "result_not_detected")
    controls = value.get("failed_controls")
    count = value.get("failed_control_count")
    if (
        type(controls) is not list
        or type(count) is not int
        or not 1 <= count <= 55
        or len(controls) != count
        or len(set(controls)) != len(controls)
        or any(type(item) is not str or not CONTROL_RE.fullmatch(item) for item in controls)
    ):
        reject("result_control_inventory_mismatch")


def expected_identity_map(artifacts: Mapping[str, str]) -> dict[str, str]:
    return {
        "launcher": artifacts["launcher"],
        "supervisor_client": artifacts["supervisor_client"],
        "process_supervisor": artifacts["process_supervisor"],
        "checker": artifacts["contract_checker"],
        "preparer": artifacts["mutant_preparer"],
        "summary": artifacts["mutant_summary"],
    }


def validate_evidence_shape(
    value: Any,
    label: str,
    canonical: bool,
    policy: Mapping[str, int],
    summary: list[dict[str, Any]],
    identities: Mapping[str, str],
) -> str:
    exact_keys(value, EVIDENCE_KEYS, "evidence_schema_mismatch")
    if (
        type(value.get("schema")) is not int
        or value.get("schema") != 3
        or value.get("report_kind")
        != "rfc9114_launcher_structural_contract_audit_v4"
        or value.get("status") != "StaticReady"
        or value.get("shareable") is not True
    ):
        reject("evidence_identity_mismatch")
    run_id = run_value(value.get("run_id"), "evidence_run_id_rejected")
    validate_engine(value.get("engine"), label)
    exact_int(
        value.get("production_controls_passed"),
        policy["production_controls"],
        policy["production_controls"],
        "production_control_count_mismatch",
    )
    for key in ("mutation_set_expected", "mutation_count", "mutations_detected"):
        exact_int(
            value.get(key),
            policy["mutation_count"],
            policy["mutation_count"],
            "evidence_mutation_count_mismatch",
        )
    for key in (
        "mutation_ids_unique",
        "mutant_hashes_unique",
        "manifest_hashes_unique",
        "source_fresh",
        "exclusive_lease_held_at_terminal_publish",
        "running_canonical_published",
        "running_per_run_published",
    ):
        exact_bool(value.get(key), True, "evidence_required_predicate_false")
    exact_bool(value.get("native_started"), False, "native_started_rejected")
    exact_int(value.get("native_residual_count"), 0, 0, "native_residual_rejected")
    exact_int(value.get("new_visible_shell_count"), 0, 0, "visible_shell_rejected")
    exact_bool(value.get("raw_output_retained"), False, "raw_output_retained_rejected")
    exact_bool(value.get("canonical_evidence"), canonical, "canonical_flag_mismatch")
    exact_int(
        value.get("absolute_deadline_ms"),
        policy["absolute_deadline_ms"],
        policy["absolute_deadline_ms"],
        "deadline_policy_mismatch",
    )
    exact_int(
        value.get("elapsed_ms"), 0, policy["absolute_deadline_ms"], "elapsed_time_rejected"
    )
    before = exact_keys(
        value.get("identities_before"), IDENTITY_KEYS, "identity_map_schema_mismatch"
    )
    after = exact_keys(
        value.get("identities_after"), IDENTITY_KEYS, "identity_map_schema_mismatch"
    )
    if before != identities or after != identities or before != after:
        reject("evidence_source_identity_mismatch")
    results = value.get("results")
    if type(results) is not list or len(results) != len(MUTATION_IDS):
        reject("result_inventory_count_mismatch")
    for index, result in enumerate(results):
        check_deadline()
        validate_result(result, summary[index], MUTATION_IDS[index])
    expected_name = f"launcher-structural-audit-v4-{label}-{run_id}.json"
    if value.get("per_run_evidence_file") != expected_name:
        reject("per_run_evidence_name_mismatch")
    pointer = value.get("per_run_evidence_sha256")
    if canonical:
        hash_value(pointer, "per_run_evidence_hash_rejected")
    elif pointer is not None:
        reject("per_run_evidence_hash_rejected")
    return run_id


def validate_evidence_pair(
    store: Store,
    entry: Any,
    label: str,
    policy: Mapping[str, int],
    summary: list[dict[str, Any]],
    artifacts: Mapping[str, str],
) -> tuple[str, str]:
    exact_keys(
        entry,
        {"label", "canonical_path", "canonical_sha256", "run_id", "engine_sha256"},
        "evidence_lock_entry_schema_mismatch",
    )
    canonical_path = normalized_relative(
        entry.get("canonical_path"), "evidence_canonical_path_rejected"
    )
    if entry.get("label") != label or canonical_path != EVIDENCE_PATHS[label]:
        reject("evidence_lock_identity_mismatch")
    expected_hash = hash_value(entry.get("canonical_sha256"), "evidence_lock_hash_rejected")
    expected_run = run_value(entry.get("run_id"), "evidence_lock_run_id_rejected")
    expected_engine = hash_value(entry.get("engine_sha256"), "engine_executable_hash_rejected")
    canonical_bytes = store.read(canonical_path, policy["maximum_evidence_bytes"])
    if sha256(canonical_bytes) != expected_hash:
        reject("canonical_evidence_identity_drift")
    canonical = parse_json(canonical_bytes, "canonical_evidence")
    identities = expected_identity_map(artifacts)
    run_id = validate_evidence_shape(
        canonical, label, True, policy, summary, identities
    )
    if run_id != expected_run or canonical["engine"]["executable_sha256"] != expected_engine:
        reject("evidence_lock_identity_mismatch")
    per_run_path = f"{MUTATION_ROOT}/{canonical['per_run_evidence_file']}"
    per_run_bytes = store.read(per_run_path, policy["maximum_evidence_bytes"])
    if sha256(per_run_bytes) != canonical["per_run_evidence_sha256"]:
        reject("per_run_evidence_identity_drift")
    per_run = parse_json(per_run_bytes, "per_run_evidence")
    validate_evidence_shape(per_run, label, False, policy, summary, identities)
    expected_per_run = copy.deepcopy(canonical)
    expected_per_run["canonical_evidence"] = False
    expected_per_run["per_run_evidence_sha256"] = None
    if per_run != expected_per_run:
        reject("canonical_per_run_content_mismatch")
    return run_id, expected_engine


def mutation_ids_sha256() -> str:
    return sha256(("\n".join(MUTATION_IDS) + "\n").encode("utf-8"))


def subject_object(lock: Mapping[str, Any]) -> dict[str, Any]:
    return {
        key: lock[key]
        for key in (
            "schema",
            "lock_kind",
            "generation",
            "shareable",
            "implementer_id",
            "source_epoch",
            "policy",
            "artifacts",
            "mutation_set",
            "evidence",
            "integration",
        )
    }


def validate_independent_audit(
    value: Any, store: Store, lock_status: str, implementer_id: str, subject: str
) -> None:
    exact_keys(
        value,
        {"status", "reviewer_kind", "reviewer_id", "report_path", "report_sha256"},
        "independent_audit_schema_mismatch",
    )
    if value.get("reviewer_kind") != "different_agent":
        reject("independent_reviewer_kind_rejected")
    if lock_status == "StaticReady":
        if value != {
            "status": "Pending",
            "reviewer_kind": "different_agent",
            "reviewer_id": None,
            "report_path": None,
            "report_sha256": None,
        }:
            reject("independent_audit_pending_mismatch")
        return
    if lock_status != "Ready" or value.get("status") != "Green":
        reject("independent_audit_status_rejected")
    reviewer = value.get("reviewer_id")
    if (
        type(reviewer) is not str
        or not IDENT_RE.fullmatch(reviewer)
        or reviewer == implementer_id
    ):
        reject("independent_reviewer_identity_rejected")
    report_path = normalized_relative(
        value.get("report_path"), "independent_report_path_rejected"
    )
    report_hash = hash_value(
        value.get("report_sha256"), "independent_report_hash_rejected"
    )
    report_bytes = store.read(report_path, MAX_EVIDENCE_BYTES)
    if sha256(report_bytes) != report_hash:
        reject("independent_report_identity_drift")
    report = parse_json(report_bytes, "independent_report")
    exact_keys(
        report,
        {
            "schema",
            "report_kind",
            "status",
            "shareable",
            "reviewer_id",
            "subject_sha256",
            "launcher_sha256",
            "checker_sha256",
            "ps5_evidence_sha256",
            "ps7_evidence_sha256",
            "mutation_count",
            "findings",
            "native_started",
            "native_residual_count",
            "new_visible_shell_count",
            "rerun_command",
        },
        "independent_report_schema_mismatch",
    )
    if (
        report.get("schema") != 1
        or report.get("report_kind") != "rfc9114_launcher_independent_reaudit"
        or report.get("status") != "Green"
        or report.get("shareable") is not True
        or report.get("reviewer_id") != reviewer
        or report.get("subject_sha256") != subject
        or report.get("mutation_count") != len(MUTATION_IDS)
        or report.get("findings") != []
        or report.get("native_started") is not False
        or report.get("native_residual_count") != 0
        or report.get("new_visible_shell_count") != 0
        or type(report.get("rerun_command")) is not str
        or not report["rerun_command"].startswith("python -I -B ")
    ):
        reject("independent_report_value_mismatch")
    if type(report.get("schema")) is not int:
        reject("independent_report_type_mismatch")
    exact_int(
        report.get("mutation_count"),
        len(MUTATION_IDS),
        len(MUTATION_IDS),
        "independent_report_type_mismatch",
    )
    exact_bool(
        report.get("native_started"), False, "independent_report_type_mismatch"
    )
    exact_int(
        report.get("native_residual_count"),
        0,
        0,
        "independent_report_type_mismatch",
    )
    exact_int(
        report.get("new_visible_shell_count"),
        0,
        0,
        "independent_report_type_mismatch",
    )
    if report.get("rerun_command") != (
        "python -I -B scripts/rfc9114_launcher_evidence_gate.py --require-ready"
    ):
        reject("independent_report_rerun_mismatch")


def validate_lock(store: Store, lock: Any, require_ready: bool) -> str:
    exact_keys(
        lock,
        {
            "schema",
            "lock_kind",
            "generation",
            "status",
            "shareable",
            "implementer_id",
            "source_epoch",
            "policy",
            "artifacts",
            "mutation_set",
            "evidence",
            "integration",
            "independent_audit",
            "subject_sha256",
        },
        "lock_schema_mismatch",
    )
    status_value = lock.get("status")
    if (
        type(lock.get("schema")) is not int
        or type(lock.get("generation")) is not int
        or lock.get("schema") != 1
        or lock.get("lock_kind") != "rfc9114_launcher_evidence_lock"
        or lock.get("generation") != 4
        or status_value not in {"StaticReady", "Ready"}
        or lock.get("shareable") is not True
        or type(lock.get("implementer_id")) is not str
        or not IDENT_RE.fullmatch(lock["implementer_id"])
    ):
        reject("lock_identity_mismatch")
    validate_source_epoch(lock.get("source_epoch"), store)
    policy = validate_policy(lock.get("policy"))
    artifacts = artifact_map(lock.get("artifacts"), store)
    gate_controls = parse_json(
        store.read(GATE_CONTROLS_PATH, MAX_ARTIFACT_BYTES), "gate_controls"
    )
    validate_gate_controls_manifest(gate_controls)
    matrix = parse_json(store.read(FIX_MATRIX_PATH, MAX_ARTIFACT_BYTES), "fix_matrix")
    validate_fix_matrix(matrix, True)
    invalidation = parse_json(
        store.read(INVALIDATION_PATH, MAX_ARTIFACT_BYTES), "invalidation"
    )
    validate_invalidation(invalidation)
    integration = parse_json(
        store.read(INTEGRATION_PATH, MAX_ARTIFACT_BYTES), "integration"
    )
    validate_integration(integration, store)
    integration_lock = exact_keys(
        lock.get("integration"),
        {"candidate_path", "candidate_sha256", "mise_wired", "ci_wired"},
        "integration_lock_schema_mismatch",
    )
    if (
        integration_lock.get("candidate_path") != INTEGRATION_PATH
        or integration_lock.get("candidate_sha256")
        != artifacts["integration_candidate"]
        or type(integration_lock.get("mise_wired")) is not bool
        or type(integration_lock.get("ci_wired")) is not bool
        or integration_lock["mise_wired"] is not integration["mise"]["wired"]
        or integration_lock["ci_wired"] is not integration["ci"]["wired"]
    ):
        reject("integration_lock_value_mismatch")
    if status_value in {"StaticReady", "Ready"} and (
        integration_lock["mise_wired"] is not True
        or integration_lock["ci_wired"] is not True
    ):
        reject("consumer_gate_not_wired")
    mutation_set = exact_keys(
        lock.get("mutation_set"),
        {"summary_path", "summary_sha256", "count", "ids_sha256"},
        "mutation_set_schema_mismatch",
    )
    if (
        mutation_set.get("summary_path") != SUMMARY_PATH
        or mutation_set.get("summary_sha256") != artifacts["mutant_summary"]
        or mutation_set.get("count") != len(MUTATION_IDS)
        or mutation_set.get("ids_sha256") != mutation_ids_sha256()
    ):
        reject("mutation_set_identity_mismatch")
    summary = parse_json(store.read(SUMMARY_PATH, MAX_ARTIFACT_BYTES), "summary")
    summary_mutations = validate_summary(summary, store, artifacts)
    evidence = lock.get("evidence")
    if type(evidence) is not list or len(evidence) != 2:
        reject("evidence_lock_inventory_count_mismatch")
    expected_labels = list(EVIDENCE_PATHS)
    engine_hashes: list[str] = []
    run_ids: set[str] = set()
    for index, item in enumerate(evidence):
        check_deadline()
        if type(item) is not dict or item.get("label") != expected_labels[index]:
            reject("evidence_lock_label_inventory_mismatch")
        run_id, engine_hash = validate_evidence_pair(
            store, item, expected_labels[index], policy, summary_mutations, artifacts
        )
        if run_id in run_ids:
            reject("evidence_run_id_duplicate")
        run_ids.add(run_id)
        engine_hashes.append(engine_hash)
    if len(set(engine_hashes)) != 2:
        reject("engine_executable_identity_collision")
    subject = hash_value(lock.get("subject_sha256"), "subject_hash_rejected")
    if sha256(canonical_json(subject_object(lock))) != subject:
        reject("subject_identity_mismatch")
    validate_independent_audit(
        lock.get("independent_audit"),
        store,
        status_value,
        lock["implementer_id"],
        subject,
    )
    if status_value == "Ready":
        report = parse_json(
            store.read(lock["independent_audit"]["report_path"], MAX_EVIDENCE_BYTES),
            "independent_report",
        )
        by_label = {item["label"]: item for item in evidence}
        if (
            report.get("launcher_sha256") != artifacts["launcher"]
            or report.get("checker_sha256") != artifacts["contract_checker"]
            or report.get("ps5_evidence_sha256") != by_label["ps5.1"]["canonical_sha256"]
            or report.get("ps7_evidence_sha256") != by_label["ps7.6"]["canonical_sha256"]
        ):
            reject("independent_report_subject_detail_mismatch")
    # Re-read every mutable input after the semantic checks.
    # A report is consumable only when source, helper, mutant, and evidence identities are unchanged across the whole gate transaction.
    validate_source_epoch(lock.get("source_epoch"), store)
    artifacts_after = artifact_map(lock.get("artifacts"), store)
    if artifacts_after != artifacts:
        reject("artifact_identity_drift")
    summary_after = parse_json(
        store.read(SUMMARY_PATH, MAX_ARTIFACT_BYTES), "summary"
    )
    summary_mutations_after = validate_summary(summary_after, store, artifacts_after)
    engine_hashes_after: list[str] = []
    run_ids_after: set[str] = set()
    for index, item in enumerate(evidence):
        check_deadline()
        run_id, engine_hash = validate_evidence_pair(
            store,
            item,
            expected_labels[index],
            policy,
            summary_mutations_after,
            artifacts_after,
        )
        if run_id in run_ids_after:
            reject("evidence_run_id_duplicate")
        run_ids_after.add(run_id)
        engine_hashes_after.append(engine_hash)
    if run_ids_after != run_ids or engine_hashes_after != engine_hashes:
        reject("evidence_identity_drift")
    validate_independent_audit(
        lock.get("independent_audit"),
        store,
        status_value,
        lock["implementer_id"],
        subject,
    )
    if require_ready and status_value != "Ready":
        reject("independent_audit_pending")
    return status_value


def consume(root: Path, lock_relative: str, require_ready: bool) -> str:
    store = DiskStore(root)
    lock = parse_json(store.read(lock_relative, MAX_LOCK_BYTES), "lock")
    return validate_lock(store, lock, require_ready)


def legacy_manifest() -> dict[str, Any]:
    reasons = [
        "source_inventory_drift",
        "atomic_writer_contract_not_live",
        "hidden_process_contract_not_live",
        "identity_map_structure_not_strict",
        "external_invocation_allowlist_incomplete",
        "consumer_gate_absent",
        "shared_evidence_path_race",
        "independent_reaudit_required",
    ]
    return {
        "schema": 1,
        "invalidation_kind": "rfc9114_launcher_evidence_invalidation_chain",
        "status": "Active",
        "shareable": True,
        "current_generation": 4,
        "invalidated": [
            {
                "id": legacy_id,
                "path": path,
                "sha256": digest,
                "generation": 3 if "v3" in legacy_id else 2,
                "status": "Rejected",
                "reason_codes": reasons,
            }
            for legacy_id, path, digest in LEGACY_EVIDENCE
        ],
        "replacement": {
            "lock_path": LOCK_PATH,
            "status": "Pending",
            "independent_audit_required": True,
        },
        "reason_codes": reasons,
    }


def integration_manifest(wired: bool = True) -> dict[str, Any]:
    command = (
        "python -I -B scripts/rfc9114_launcher_evidence_gate.py "
        "--lock standards/audits/rfc9114-launcher/evidence-lock.json"
    )
    return {
        "schema": 1,
        "integration_kind": "rfc9114_launcher_gate_integration",
        "status": "Wired" if wired else "Staged",
        "mise": {
            "task": "rfc9114-launcher-evidence-gate",
            "command": command,
            "wired": wired,
        },
        "ci": {
            "workflow": CI_PATH,
            "job": "rfc9114-launcher-evidence-gate",
            "command": command,
            "artifact_paths": [
                EVIDENCE_PATHS["ps5.1"],
                EVIDENCE_PATHS["ps7.6"],
                (
                    "build/root-validation/rfc9114-peer-error-mapping/mutations/"
                    "launcher-structural-audit-v4-ps*.json"
                ),
            ],
            "wired": wired,
        },
        "constraints": {
            "native_execution": "forbidden",
            "independent_audit_before_ready": True,
            "canonical_source_required": True,
        },
    }


def gate_controls_manifest() -> dict[str, Any]:
    return {
        "schema": 1,
        "manifest_kind": "rfc9114_launcher_gate_self_test_controls",
        "generation": 4,
        "count": len(SELF_TEST_EXPECTED),
        "result_shape": ["name", "observed"],
        "controls": [
            {"name": name, "observed": observed}
            for name, observed in SELF_TEST_EXPECTED.items()
        ],
    }


def validate_gate_controls_manifest(
    value: Any, observed: list[dict[str, str]] | None = None
) -> None:
    exact_keys(
        value,
        {
            "schema",
            "manifest_kind",
            "generation",
            "count",
            "result_shape",
            "controls",
        },
        "gate_control_manifest_schema_mismatch",
    )
    expected = gate_controls_manifest()
    if value != expected:
        reject("gate_control_manifest_value_mismatch")
    if observed is not None and observed != expected["controls"]:
        reject("gate_control_result_mismatch")


def fix_matrix(final: bool) -> dict[str, Any]:
    state = {
        "live_inventory_drift": "Fixed" if final else "PendingRefreeze",
        "ready_freeze_absent": "PendingIndependentAudit",
        "checker_allows_unsupervised_invocation": "Fixed",
        "checker_allows_disabled_atomic_writer": "Fixed",
        "checker_allows_disabled_hidden_flags": "Fixed",
        "hash_map_not_strict": "Fixed",
        "evidence_has_no_consumer_gate": "Fixed" if final else "PendingIntegration",
        "shared_evidence_path_race": "Fixed",
    }
    evidence = {
        "live_inventory_drift": ["source_epoch", "source_identity_stale"],
        "ready_freeze_absent": ["independent_audit", "independent_audit_pending"],
        "checker_allows_unsupervised_invocation": [
            "external_invocation_surface_is_exact"
        ],
        "checker_allows_disabled_atomic_writer": [
            "atomic_writer_contract_is_executable"
        ],
        "checker_allows_disabled_hidden_flags": ["hidden_stdio_same_live_try_dataflow"],
        "hash_map_not_strict": ["identity_map_comparison_fails_closed"],
        "evidence_has_no_consumer_gate": ["gate_controls", "valid_static_bundle"],
        "shared_evidence_path_race": ["per_run_evidence_path_is_unique"],
    }
    false_green_controls = {
        "atomic_writer_early_return": "atomic-writer-early-return",
        "atomic_writer_early_throw": "atomic-writer-early-throw",
        "atomic_writer_indirect_dead_branch": "atomic-writer-indirect-dead-path",
        "hidden_flags_indirect_false": "hidden-flags-indirect-dead-branch",
        "direct_call_before_supervisor": "direct-ampersand-outer-runner",
    }
    return {
        "schema": 1,
        "matrix_kind": "rfc9114_launcher_independent_audit_fix_matrix",
        "generation": 4,
        "status": "StaticReady" if final else "ImplementedAwaitingRefreeze",
        "shareable": True,
        "source_audit_sha256": (
            "15b54017c152dfa1e6357f070d301ec48828a46e8707c23f28f5a70691fbeda9"
        ),
        "blocker_count": len(BLOCKER_IDS),
        "blockers": [
            {"id": blocker_id, "state": state[blocker_id], "evidence": evidence[blocker_id]}
            for blocker_id in BLOCKER_IDS
        ],
        "false_green_count": len(FALSE_GREEN_IDS),
        "false_greens": [
            {
                "id": false_green_id,
                "state": "Detected",
                "replacement_mutation_id": false_green_controls[false_green_id],
            }
            for false_green_id in FALSE_GREEN_IDS
        ],
        "remaining": (
            ["independent_reaudit"]
            if final
            else ["config_integration", "source_refreeze", "dual_engine_rerun", "independent_reaudit"]
        ),
    }


def validate_fix_matrix(value: Any, final: bool) -> None:
    exact_keys(
        value,
        {
            "schema",
            "matrix_kind",
            "generation",
            "status",
            "shareable",
            "source_audit_sha256",
            "blocker_count",
            "blockers",
            "false_green_count",
            "false_greens",
            "remaining",
        },
        "fix_matrix_schema_mismatch",
    )
    if value != fix_matrix(final):
        reject("fix_matrix_value_mismatch")


def synthetic_bundle() -> tuple[MemoryStore, dict[str, Any]]:
    files: dict[str, bytes] = {}
    for index, path in enumerate(REQUIRED_ARTIFACTS.values()):
        files[path] = f"artifact-{index}\n".encode()
    files[INVALIDATION_PATH] = pretty_json(legacy_manifest())
    files[INTEGRATION_PATH] = pretty_json(integration_manifest(True))
    files[GATE_CONTROLS_PATH] = pretty_json(gate_controls_manifest())
    files[FIX_MATRIX_PATH] = pretty_json(fix_matrix(True))
    files[MISE_PATH] = b"[tools]\npython = '3.13.7'\n"
    files[CI_PATH] = b"jobs:\n  rfc9114-launcher-evidence-gate: {}\n"
    source_seed = {
        "packages/http3/gleam.toml": b"name = 'http3'\n",
        "packages/http3/manifest.toml": b"packages = []\n",
        "packages/http3/src/synthetic.gleam": b"pub fn source() { Nil }\n",
        "packages/http3/test/synthetic_test.gleam": b"pub fn test() { Nil }\n",
        "packages/quic_core/gleam.toml": b"name = 'quic_core'\n",
        "packages/quic_core/manifest.toml": b"packages = []\n",
        "packages/quic_core/src/synthetic.gleam": b"pub fn source() { Nil }\n",
        "packages/quic_core/test/synthetic_test.gleam": b"pub fn test() { Nil }\n",
    }
    files.update(source_seed)
    initial_artifacts = {
        role: sha256(files[path]) for role, path in REQUIRED_ARTIFACTS.items()
    }
    mutations: list[dict[str, Any]] = []
    targets = ("launcher", "supervisor_client", "process_supervisor")
    source_names = {
        "launcher": "run_hidden_mutation.ps1",
        "supervisor_client": "supervisor_packet_client.ps1",
        "process_supervisor": "process_supervisor.py",
    }
    for index, mutation_id in enumerate(MUTATION_IDS):
        target = targets[index % len(targets)]
        mutant = f"mutant:{mutation_id}\n".encode()
        mutant_hash = sha256(mutant)
        manifest = {
            "schema": 2,
            "mutation_id": mutation_id,
            "status": "Prepared",
            "shareable": True,
            "target": target,
            "changed_file_count": 1,
            "contiguous_edit_count": 1,
            "replacement_count": 1,
            "original_sha256": initial_artifacts[target],
            "mutated_sha256": mutant_hash,
            "reverse_restored_sha256": initial_artifacts[target],
        }
        directory = f"{MUTANT_ROOT}/{mutation_id}"
        manifest_bytes = pretty_json(manifest)
        files[f"{directory}/mutation.json"] = manifest_bytes
        files[f"{directory}/{source_names[target]}"] = mutant
        mutations.append(
            {
                "mutation_id": mutation_id,
                "target": target,
                "mutated_sha256": mutant_hash,
                "manifest_sha256": sha256(manifest_bytes),
            }
        )
    summary = {
        "schema": 2,
        "report_kind": "rfc9114_launcher_structural_contract_mutations_v4",
        "status": "Prepared",
        "shareable": True,
        "source_hashes": {
            role: initial_artifacts[role]
            for role in ("launcher", "supervisor_client", "process_supervisor")
        },
        "mutation_count": len(MUTATION_IDS),
        "mutations": mutations,
    }
    files[SUMMARY_PATH] = pretty_json(summary)
    artifact_hashes = {
        role: sha256(files[path]) for role, path in REQUIRED_ARTIFACTS.items()
    }
    identities = expected_identity_map(artifact_hashes)
    policy = {
        "production_controls": 55,
        "mutation_count": len(MUTATION_IDS),
        "absolute_deadline_ms": 1_200_000,
        "maximum_artifact_bytes": MAX_ARTIFACT_BYTES,
        "maximum_evidence_bytes": MAX_EVIDENCE_BYTES,
    }
    evidence_entries: list[dict[str, Any]] = []
    for index, label in enumerate(EVIDENCE_PATHS):
        run_id = str(index + 1) * 32
        engine_hash = ("a" if label == "ps5.1" else "b") * 64
        engine = {
            "label": label,
            "powershell_version": "5.1.26100.1" if label == "ps5.1" else "7.6.5",
            "powershell_edition": "Desktop" if label == "ps5.1" else "Core",
            "executable_name": "powershell.exe" if label == "ps5.1" else "pwsh.exe",
            "executable_sha256": engine_hash,
            "os_platform": "Win32NT",
            "os_version": "10.0.26200.0",
            "os_is_64_bit": True,
        }
        results = [
            {
                "mutation_id": item["mutation_id"],
                "target": item["target"],
                "detected": True,
                "failed_control_count": 1,
                "failed_controls": ["synthetic_control"],
                "mutated_sha256": item["mutated_sha256"],
                "manifest_sha256": item["manifest_sha256"],
            }
            for item in mutations
        ]
        leaf = f"launcher-structural-audit-v4-{label}-{run_id}.json"
        per_run = {
            "schema": 3,
            "report_kind": "rfc9114_launcher_structural_contract_audit_v4",
            "run_id": run_id,
            "status": "StaticReady",
            "shareable": True,
            "engine": engine,
            "production_controls_passed": 55,
            "mutation_set_expected": len(MUTATION_IDS),
            "mutation_count": len(MUTATION_IDS),
            "mutations_detected": len(MUTATION_IDS),
            "mutation_ids_unique": True,
            "mutant_hashes_unique": True,
            "manifest_hashes_unique": True,
            "results": results,
            "identities_before": identities,
            "identities_after": identities,
            "source_fresh": True,
            "absolute_deadline_ms": 1_200_000,
            "elapsed_ms": 1,
            "native_started": False,
            "native_residual_count": 0,
            "new_visible_shell_count": 0,
            "raw_output_retained": False,
            "exclusive_lease_held_at_terminal_publish": True,
            "running_canonical_published": True,
            "running_per_run_published": True,
            "canonical_evidence": False,
            "per_run_evidence_file": leaf,
            "per_run_evidence_sha256": None,
        }
        per_run_bytes = pretty_json(per_run)
        files[f"{MUTATION_ROOT}/{leaf}"] = per_run_bytes
        canonical = copy.deepcopy(per_run)
        canonical["canonical_evidence"] = True
        canonical["per_run_evidence_sha256"] = sha256(per_run_bytes)
        canonical_bytes = pretty_json(canonical)
        files[EVIDENCE_PATHS[label]] = canonical_bytes
        evidence_entries.append(
            {
                "label": label,
                "canonical_path": EVIDENCE_PATHS[label],
                "canonical_sha256": sha256(canonical_bytes),
                "run_id": run_id,
                "engine_sha256": engine_hash,
            }
        )
    store = MemoryStore(files)
    lock: dict[str, Any] = {
        "schema": 1,
        "lock_kind": "rfc9114_launcher_evidence_lock",
        "generation": 4,
        "status": "StaticReady",
        "shareable": True,
        "implementer_id": "http3_launcher_independent_audit",
        "source_epoch": source_identity(store),
        "policy": policy,
        "artifacts": [
            {"role": role, "path": path, "sha256": artifact_hashes[role]}
            for role, path in REQUIRED_ARTIFACTS.items()
        ],
        "mutation_set": {
            "summary_path": SUMMARY_PATH,
            "summary_sha256": artifact_hashes["mutant_summary"],
            "count": len(MUTATION_IDS),
            "ids_sha256": mutation_ids_sha256(),
        },
        "evidence": evidence_entries,
        "integration": {
            "candidate_path": INTEGRATION_PATH,
            "candidate_sha256": artifact_hashes["integration_candidate"],
            "mise_wired": True,
            "ci_wired": True,
        },
        "independent_audit": {
            "status": "Pending",
            "reviewer_kind": "different_agent",
            "reviewer_id": None,
            "report_path": None,
            "report_sha256": None,
        },
        "subject_sha256": "0" * 64,
    }
    lock["subject_sha256"] = sha256(canonical_json(subject_object(lock)))
    store.files[LOCK_PATH] = pretty_json(lock)
    return store, lock


def rebind_artifact(store: MemoryStore, lock: dict[str, Any], role: str) -> None:
    path = REQUIRED_ARTIFACTS[role]
    digest = sha256(store.files[path])
    for item in lock["artifacts"]:
        if item["role"] == role:
            item["sha256"] = digest
    if role == "mutant_summary":
        lock["mutation_set"]["summary_sha256"] = digest
    if role == "integration_candidate":
        lock["integration"]["candidate_sha256"] = digest
    lock["subject_sha256"] = sha256(canonical_json(subject_object(lock)))


def rebind_evidence(store: MemoryStore, lock: dict[str, Any], label: str) -> None:
    canonical_path = EVIDENCE_PATHS[label]
    canonical = parse_json(store.files[canonical_path], "self_test_evidence")
    per_run_path = f"{MUTATION_ROOT}/{canonical['per_run_evidence_file']}"
    per_run = copy.deepcopy(canonical)
    per_run["canonical_evidence"] = False
    per_run["per_run_evidence_sha256"] = None
    per_run_bytes = pretty_json(per_run)
    store.files[per_run_path] = per_run_bytes
    canonical["canonical_evidence"] = True
    canonical["per_run_evidence_sha256"] = sha256(per_run_bytes)
    canonical_bytes = pretty_json(canonical)
    store.files[canonical_path] = canonical_bytes
    for item in lock["evidence"]:
        if item["label"] == label:
            item["canonical_sha256"] = sha256(canonical_bytes)
            item["run_id"] = canonical["run_id"]
            item["engine_sha256"] = canonical["engine"]["executable_sha256"]
    lock["subject_sha256"] = sha256(canonical_json(subject_object(lock)))


SELF_TEST_EXPECTED = {
    "valid_static_bundle": "StaticReady",
    "lock_extra_key": "lock_schema_mismatch",
    "lock_missing_key": "lock_schema_mismatch",
    "lock_schema_type_confusion": "lock_identity_mismatch",
    "artifact_missing": "input_missing",
    "artifact_tampered": "artifact_identity_drift",
    "artifact_duplicate_role": "artifact_role_inventory_mismatch",
    "artifact_path_traversal": "artifact_path_rejected",
    "source_stale": "source_identity_stale",
    "summary_duplicate_mutation_id": "summary_mutation_id_inventory_mismatch",
    "summary_missing_mutation_id": "summary_identity_mismatch",
    "summary_duplicate_mutant_hash": "summary_mutation_hash_duplicate",
    "mutation_manifest_tampered": "mutation_manifest_identity_mismatch",
    "mutation_source_tampered": "mutated_source_identity_mismatch",
    "mutation_extra_file": "mutation_file_inventory_mismatch",
    "old_v3_evidence_substitution": "evidence_schema_mismatch",
    "canonical_evidence_tampered": "canonical_evidence_identity_drift",
    "evidence_extra_key": "evidence_schema_mismatch",
    "evidence_missing_key": "evidence_schema_mismatch",
    "evidence_count_type_confusion": "production_control_count_mismatch",
    "evidence_duplicate_result_id": "result_identity_mismatch",
    "evidence_missing_result": "result_inventory_count_mismatch",
    "evidence_result_hash_mismatch": "result_identity_mismatch",
    "evidence_duplicate_failed_control": "result_control_inventory_mismatch",
    "evidence_source_fresh_false": "evidence_required_predicate_false",
    "evidence_native_started": "native_started_rejected",
    "evidence_native_residual": "native_residual_rejected",
    "evidence_visible_shell": "visible_shell_rejected",
    "evidence_raw_output_retained": "raw_output_retained_rejected",
    "evidence_canonical_flag_false": "canonical_flag_mismatch",
    "evidence_stale_run_id": "evidence_lock_identity_mismatch",
    "per_run_evidence_missing": "input_missing",
    "per_run_pointer_tampered": "per_run_evidence_identity_drift",
    "per_run_content_mismatch": "canonical_per_run_content_mismatch",
    "engine_substitution": "engine_identity_mismatch",
    "engine_identity_collision": "engine_executable_identity_collision",
    "evidence_duplicate_run_id": "evidence_run_id_duplicate",
    "invalidation_missing_entry": "invalidation_inventory_count_mismatch",
    "invalidation_coordinated_tamper": "invalidation_entry_mismatch",
    "integration_not_wired": "consumer_gate_not_wired",
    "integration_command_tamper": "integration_value_mismatch",
    "ready_requires_independent_audit": "independent_audit_pending",
    "valid_ready_bundle": "Ready",
    "same_agent_review_rejected": "independent_reviewer_identity_rejected",
    "independent_report_missing": "input_missing",
    "independent_report_tampered": "independent_report_identity_drift",
    "independent_report_stale_subject": "independent_report_value_mismatch",
    "json_duplicate_key": "json_duplicate_key",
    "oversized_input": "input_identity_or_size_rejected",
}
SELF_TEST_CONTROLS = tuple(SELF_TEST_EXPECTED)


def self_test() -> list[dict[str, str]]:
    controls: list[dict[str, str]] = []

    def accepted(name: str) -> None:
        store, lock = synthetic_bundle()
        if validate_lock(store, lock, False) != "StaticReady":
            reject("self_test_valid_fixture_rejected")
        controls.append({"name": name, "observed": "StaticReady"})

    def rejected(
        name: str,
        code: str,
        mutate: Callable[[MemoryStore, dict[str, Any]], None],
        *,
        ready: bool = False,
    ) -> None:
        store, lock = synthetic_bundle()
        mutate(store, lock)
        try:
            validate_lock(store, lock, ready)
        except Rejected as error:
            if str(error) != code:
                raise Rejected("self_test_wrong_rejection") from error
        else:
            reject("self_test_mutant_accepted")
        controls.append({"name": name, "observed": code})

    accepted("valid_static_bundle")
    rejected(
        "lock_extra_key",
        "lock_schema_mismatch",
        lambda _s, lock: lock.__setitem__("decoy", True),
    )
    rejected(
        "lock_missing_key",
        "lock_schema_mismatch",
        lambda _s, lock: lock.pop("source_epoch"),
    )
    rejected(
        "lock_schema_type_confusion",
        "lock_identity_mismatch",
        lambda _s, lock: lock.__setitem__("schema", True),
    )
    rejected(
        "artifact_missing",
        "input_missing",
        lambda store, _lock: store.files.pop(REQUIRED_ARTIFACTS["contract_checker"]),
    )
    rejected(
        "artifact_tampered",
        "artifact_identity_drift",
        lambda store, _lock: store.files.__setitem__(
            REQUIRED_ARTIFACTS["contract_checker"], b"tampered\n"
        ),
    )
    rejected(
        "artifact_duplicate_role",
        "artifact_role_inventory_mismatch",
        lambda _store, lock: lock["artifacts"][1].__setitem__(
            "role", lock["artifacts"][0]["role"]
        ),
    )
    rejected(
        "artifact_path_traversal",
        "artifact_path_rejected",
        lambda _store, lock: lock["artifacts"][0].__setitem__(
            "path", "../decoy.ps1"
        ),
    )
    rejected(
        "source_stale",
        "source_identity_stale",
        lambda store, _lock: store.files.__setitem__(MISE_PATH, b"changed\n"),
    )

    def duplicate_summary_id(store: MemoryStore, lock: dict[str, Any]) -> None:
        value = parse_json(store.files[SUMMARY_PATH], "summary")
        value["mutations"][1]["mutation_id"] = value["mutations"][0]["mutation_id"]
        store.files[SUMMARY_PATH] = pretty_json(value)
        rebind_artifact(store, lock, "mutant_summary")

    rejected(
        "summary_duplicate_mutation_id",
        "summary_mutation_id_inventory_mismatch",
        duplicate_summary_id,
    )

    def missing_summary_id(store: MemoryStore, lock: dict[str, Any]) -> None:
        value = parse_json(store.files[SUMMARY_PATH], "summary")
        value["mutations"].pop()
        value["mutation_count"] -= 1
        store.files[SUMMARY_PATH] = pretty_json(value)
        rebind_artifact(store, lock, "mutant_summary")

    rejected(
        "summary_missing_mutation_id",
        "summary_identity_mismatch",
        missing_summary_id,
    )

    def duplicate_mutant_hash(store: MemoryStore, lock: dict[str, Any]) -> None:
        value = parse_json(store.files[SUMMARY_PATH], "summary")
        value["mutations"][1]["mutated_sha256"] = value["mutations"][0][
            "mutated_sha256"
        ]
        store.files[SUMMARY_PATH] = pretty_json(value)
        rebind_artifact(store, lock, "mutant_summary")

    rejected(
        "summary_duplicate_mutant_hash",
        "summary_mutation_hash_duplicate",
        duplicate_mutant_hash,
    )
    rejected(
        "mutation_manifest_tampered",
        "mutation_manifest_identity_mismatch",
        lambda store, _lock: store.files.__setitem__(
            f"{MUTANT_ROOT}/{MUTATION_IDS[0]}/mutation.json", b"{}\n"
        ),
    )
    rejected(
        "mutation_source_tampered",
        "mutated_source_identity_mismatch",
        lambda store, _lock: store.files.__setitem__(
            f"{MUTANT_ROOT}/{MUTATION_IDS[0]}/run_hidden_mutation.ps1", b"changed\n"
        ),
    )
    rejected(
        "mutation_extra_file",
        "mutation_file_inventory_mismatch",
        lambda store, _lock: store.files.__setitem__(
            f"{MUTANT_ROOT}/{MUTATION_IDS[0]}/decoy.txt", b"decoy\n"
        ),
    )

    def old_v3(store: MemoryStore, lock: dict[str, Any]) -> None:
        store.files[EVIDENCE_PATHS["ps5.1"]] = pretty_json(
            {"schema": 3, "report_kind": "rfc9114_launcher_structural_contract_audit_v3"}
        )
        for item in lock["evidence"]:
            if item["label"] == "ps5.1":
                item["canonical_sha256"] = sha256(store.files[EVIDENCE_PATHS["ps5.1"]])
        lock["subject_sha256"] = sha256(canonical_json(subject_object(lock)))

    rejected("old_v3_evidence_substitution", "evidence_schema_mismatch", old_v3)
    rejected(
        "canonical_evidence_tampered",
        "canonical_evidence_identity_drift",
        lambda store, _lock: store.files.__setitem__(
            EVIDENCE_PATHS["ps5.1"], b"tampered\n"
        ),
    )

    def evidence_change(
        transform: Callable[[dict[str, Any]], None]
    ) -> Callable[[MemoryStore, dict[str, Any]], None]:
        def apply(store: MemoryStore, lock: dict[str, Any]) -> None:
            value = parse_json(store.files[EVIDENCE_PATHS["ps5.1"]], "evidence")
            transform(value)
            store.files[EVIDENCE_PATHS["ps5.1"]] = pretty_json(value)
            rebind_evidence(store, lock, "ps5.1")

        return apply

    rejected(
        "evidence_extra_key",
        "evidence_schema_mismatch",
        evidence_change(lambda value: value.__setitem__("secret", "redacted")),
    )
    rejected(
        "evidence_missing_key",
        "evidence_schema_mismatch",
        evidence_change(lambda value: value.pop("source_fresh")),
    )
    rejected(
        "evidence_count_type_confusion",
        "production_control_count_mismatch",
        evidence_change(
            lambda value: value.__setitem__("production_controls_passed", 55.0)
        ),
    )
    rejected(
        "evidence_duplicate_result_id",
        "result_identity_mismatch",
        evidence_change(
            lambda value: value["results"][1].__setitem__(
                "mutation_id", value["results"][0]["mutation_id"]
            )
        ),
    )
    rejected(
        "evidence_missing_result",
        "result_inventory_count_mismatch",
        evidence_change(lambda value: value["results"].pop()),
    )
    rejected(
        "evidence_result_hash_mismatch",
        "result_identity_mismatch",
        evidence_change(
            lambda value: value["results"][0].__setitem__("mutated_sha256", "f" * 64)
        ),
    )
    rejected(
        "evidence_duplicate_failed_control",
        "result_control_inventory_mismatch",
        evidence_change(
            lambda value: value["results"][0].update(
                {
                    "failed_control_count": 2,
                    "failed_controls": ["synthetic_control", "synthetic_control"],
                }
            )
        ),
    )
    rejected(
        "evidence_source_fresh_false",
        "evidence_required_predicate_false",
        evidence_change(lambda value: value.__setitem__("source_fresh", False)),
    )
    rejected(
        "evidence_native_started",
        "native_started_rejected",
        evidence_change(lambda value: value.__setitem__("native_started", True)),
    )
    rejected(
        "evidence_native_residual",
        "native_residual_rejected",
        evidence_change(lambda value: value.__setitem__("native_residual_count", 1)),
    )
    rejected(
        "evidence_visible_shell",
        "visible_shell_rejected",
        evidence_change(lambda value: value.__setitem__("new_visible_shell_count", 1)),
    )
    rejected(
        "evidence_raw_output_retained",
        "raw_output_retained_rejected",
        evidence_change(lambda value: value.__setitem__("raw_output_retained", True)),
    )
    def canonical_flag_false(store: MemoryStore, lock: dict[str, Any]) -> None:
        path = EVIDENCE_PATHS["ps5.1"]
        value = parse_json(store.files[path], "evidence")
        value["canonical_evidence"] = False
        store.files[path] = pretty_json(value)
        for item in lock["evidence"]:
            if item["label"] == "ps5.1":
                item["canonical_sha256"] = sha256(store.files[path])
        lock["subject_sha256"] = sha256(canonical_json(subject_object(lock)))

    rejected(
        "evidence_canonical_flag_false",
        "canonical_flag_mismatch",
        canonical_flag_false,
    )

    def stale_run(store: MemoryStore, lock: dict[str, Any]) -> None:
        canonical_path = EVIDENCE_PATHS["ps5.1"]
        value = parse_json(store.files[canonical_path], "evidence")
        value["run_id"] = "9" * 32
        value["per_run_evidence_file"] = (
            "launcher-structural-audit-v4-ps5.1-" + "9" * 32 + ".json"
        )
        per_run = copy.deepcopy(value)
        per_run["canonical_evidence"] = False
        per_run["per_run_evidence_sha256"] = None
        per_run_bytes = pretty_json(per_run)
        store.files[f"{MUTATION_ROOT}/{value['per_run_evidence_file']}"] = per_run_bytes
        value["canonical_evidence"] = True
        value["per_run_evidence_sha256"] = sha256(per_run_bytes)
        store.files[canonical_path] = pretty_json(value)
        for item in lock["evidence"]:
            if item["label"] == "ps5.1":
                item["canonical_sha256"] = sha256(store.files[canonical_path])
        lock["subject_sha256"] = sha256(canonical_json(subject_object(lock)))

    rejected(
        "evidence_stale_run_id",
        "evidence_lock_identity_mismatch",
        stale_run,
    )

    def remove_per_run(store: MemoryStore, _lock: dict[str, Any]) -> None:
        canonical = parse_json(store.files[EVIDENCE_PATHS["ps5.1"]], "evidence")
        store.files.pop(f"{MUTATION_ROOT}/{canonical['per_run_evidence_file']}")

    rejected("per_run_evidence_missing", "input_missing", remove_per_run)

    def bad_pointer(store: MemoryStore, lock: dict[str, Any]) -> None:
        value = parse_json(store.files[EVIDENCE_PATHS["ps5.1"]], "evidence")
        value["per_run_evidence_sha256"] = "f" * 64
        store.files[EVIDENCE_PATHS["ps5.1"]] = pretty_json(value)
        for item in lock["evidence"]:
            if item["label"] == "ps5.1":
                item["canonical_sha256"] = sha256(store.files[EVIDENCE_PATHS["ps5.1"]])
        lock["subject_sha256"] = sha256(canonical_json(subject_object(lock)))

    rejected("per_run_pointer_tampered", "per_run_evidence_identity_drift", bad_pointer)

    def per_run_content(store: MemoryStore, lock: dict[str, Any]) -> None:
        canonical = parse_json(store.files[EVIDENCE_PATHS["ps5.1"]], "evidence")
        path = f"{MUTATION_ROOT}/{canonical['per_run_evidence_file']}"
        value = parse_json(store.files[path], "evidence")
        value["elapsed_ms"] = 2
        store.files[path] = pretty_json(value)
        canonical["per_run_evidence_sha256"] = sha256(store.files[path])
        store.files[EVIDENCE_PATHS["ps5.1"]] = pretty_json(canonical)
        for item in lock["evidence"]:
            if item["label"] == "ps5.1":
                item["canonical_sha256"] = sha256(
                    store.files[EVIDENCE_PATHS["ps5.1"]]
                )
        lock["subject_sha256"] = sha256(canonical_json(subject_object(lock)))

    rejected(
        "per_run_content_mismatch",
        "canonical_per_run_content_mismatch",
        per_run_content,
    )

    def substitute_engine(value: dict[str, Any]) -> None:
        value["engine"]["powershell_edition"] = "Core"

    rejected(
        "engine_substitution",
        "engine_identity_mismatch",
        evidence_change(substitute_engine),
    )

    def collide_engines(store: MemoryStore, lock: dict[str, Any]) -> None:
        ps5 = parse_json(store.files[EVIDENCE_PATHS["ps5.1"]], "evidence")
        ps7 = parse_json(store.files[EVIDENCE_PATHS["ps7.6"]], "evidence")
        ps7["engine"]["executable_sha256"] = ps5["engine"]["executable_sha256"]
        store.files[EVIDENCE_PATHS["ps7.6"]] = pretty_json(ps7)
        rebind_evidence(store, lock, "ps7.6")

    rejected(
        "engine_identity_collision",
        "engine_executable_identity_collision",
        collide_engines,
    )

    def duplicate_run_id(store: MemoryStore, lock: dict[str, Any]) -> None:
        ps5 = parse_json(store.files[EVIDENCE_PATHS["ps5.1"]], "evidence")
        ps7 = parse_json(store.files[EVIDENCE_PATHS["ps7.6"]], "evidence")
        ps7["run_id"] = ps5["run_id"]
        ps7["per_run_evidence_file"] = (
            "launcher-structural-audit-v4-ps7.6-" + ps5["run_id"] + ".json"
        )
        store.files[EVIDENCE_PATHS["ps7.6"]] = pretty_json(ps7)
        rebind_evidence(store, lock, "ps7.6")

    rejected(
        "evidence_duplicate_run_id",
        "evidence_run_id_duplicate",
        duplicate_run_id,
    )

    def invalidation_missing(store: MemoryStore, lock: dict[str, Any]) -> None:
        value = parse_json(store.files[INVALIDATION_PATH], "invalidation")
        value["invalidated"].pop()
        store.files[INVALIDATION_PATH] = pretty_json(value)
        rebind_artifact(store, lock, "legacy_invalidation")

    rejected(
        "invalidation_missing_entry",
        "invalidation_inventory_count_mismatch",
        invalidation_missing,
    )

    def invalidation_tamper(store: MemoryStore, lock: dict[str, Any]) -> None:
        value = parse_json(store.files[INVALIDATION_PATH], "invalidation")
        value["invalidated"][0]["sha256"] = "f" * 64
        store.files[INVALIDATION_PATH] = pretty_json(value)
        rebind_artifact(store, lock, "legacy_invalidation")

    rejected(
        "invalidation_coordinated_tamper",
        "invalidation_entry_mismatch",
        invalidation_tamper,
    )

    def integration_unwired(store: MemoryStore, lock: dict[str, Any]) -> None:
        store.files[INTEGRATION_PATH] = pretty_json(integration_manifest(False))
        rebind_artifact(store, lock, "integration_candidate")
        lock["integration"]["mise_wired"] = False
        lock["integration"]["ci_wired"] = False
        lock["subject_sha256"] = sha256(canonical_json(subject_object(lock)))

    rejected("integration_not_wired", "consumer_gate_not_wired", integration_unwired)

    def integration_command_tamper(store: MemoryStore, lock: dict[str, Any]) -> None:
        value = parse_json(store.files[INTEGRATION_PATH], "integration")
        value["mise"]["command"] = "python decoy.py"
        store.files[INTEGRATION_PATH] = pretty_json(value)
        rebind_artifact(store, lock, "integration_candidate")

    rejected(
        "integration_command_tamper",
        "integration_value_mismatch",
        integration_command_tamper,
    )
    rejected(
        "ready_requires_independent_audit",
        "independent_audit_pending",
        lambda _store, _lock: None,
        ready=True,
    )

    def make_ready(
        store: MemoryStore,
        lock: dict[str, Any],
        reviewer: str = "independent_reviewer",
        subject_override: str | None = None,
    ) -> None:
        lock["status"] = "Ready"
        subject = lock["subject_sha256"] if subject_override is None else subject_override
        by_label = {item["label"]: item for item in lock["evidence"]}
        artifacts = {item["role"]: item["sha256"] for item in lock["artifacts"]}
        report = {
            "schema": 1,
            "report_kind": "rfc9114_launcher_independent_reaudit",
            "status": "Green",
            "shareable": True,
            "reviewer_id": reviewer,
            "subject_sha256": subject,
            "launcher_sha256": artifacts["launcher"],
            "checker_sha256": artifacts["contract_checker"],
            "ps5_evidence_sha256": by_label["ps5.1"]["canonical_sha256"],
            "ps7_evidence_sha256": by_label["ps7.6"]["canonical_sha256"],
            "mutation_count": len(MUTATION_IDS),
            "findings": [],
            "native_started": False,
            "native_residual_count": 0,
            "new_visible_shell_count": 0,
            "rerun_command": (
                "python -I -B scripts/rfc9114_launcher_evidence_gate.py "
                "--require-ready"
            ),
        }
        report_path = "standards/audits/rfc9114-launcher/independent-review.json"
        report_bytes = pretty_json(report)
        store.files[report_path] = report_bytes
        lock["independent_audit"] = {
            "status": "Green",
            "reviewer_kind": "different_agent",
            "reviewer_id": reviewer,
            "report_path": report_path,
            "report_sha256": sha256(report_bytes),
        }

    ready_store, ready_lock = synthetic_bundle()
    make_ready(ready_store, ready_lock)
    if validate_lock(ready_store, ready_lock, True) != "Ready":
        reject("self_test_valid_ready_fixture_rejected")
    controls.append({"name": "valid_ready_bundle", "observed": "Ready"})

    rejected(
        "same_agent_review_rejected",
        "independent_reviewer_identity_rejected",
        lambda store, lock: make_ready(store, lock, lock["implementer_id"]),
    )

    def missing_review(_store: MemoryStore, lock: dict[str, Any]) -> None:
        lock["status"] = "Ready"
        lock["independent_audit"] = {
            "status": "Green",
            "reviewer_kind": "different_agent",
            "reviewer_id": "independent_reviewer",
            "report_path": "standards/audits/rfc9114-launcher/missing.json",
            "report_sha256": "a" * 64,
        }

    rejected("independent_report_missing", "input_missing", missing_review)

    def tamper_review(store: MemoryStore, lock: dict[str, Any]) -> None:
        make_ready(store, lock)
        path = lock["independent_audit"]["report_path"]
        store.files[path] += b" "

    rejected(
        "independent_report_tampered",
        "independent_report_identity_drift",
        tamper_review,
    )
    rejected(
        "independent_report_stale_subject",
        "independent_report_value_mismatch",
        lambda store, lock: make_ready(store, lock, subject_override="f" * 64),
    )

    def duplicate_json(store: MemoryStore, _lock: dict[str, Any]) -> None:
        store.files[LOCK_PATH] = b'{"schema":1,"schema":1}\n'

    # This control exercises the byte consumer rather than validate_lock's parsed input.
    store, _lock = synthetic_bundle()
    duplicate_json(store, _lock)
    try:
        parse_json(store.read(LOCK_PATH, MAX_LOCK_BYTES), "lock")
    except Rejected as error:
        if str(error) != "json_duplicate_key":
            raise Rejected("self_test_wrong_rejection") from error
    else:
        reject("self_test_mutant_accepted")
    controls.append({"name": "json_duplicate_key", "observed": "json_duplicate_key"})

    store, _lock = synthetic_bundle()
    store.files[LOCK_PATH] = b"x" * (MAX_LOCK_BYTES + 1)
    try:
        store.read(LOCK_PATH, MAX_LOCK_BYTES)
    except Rejected as error:
        if str(error) != "input_identity_or_size_rejected":
            raise Rejected("self_test_wrong_rejection") from error
    else:
        reject("self_test_mutant_accepted")
    controls.append(
        {"name": "oversized_input", "observed": "input_identity_or_size_rejected"}
    )
    if [item["name"] for item in controls] != list(SELF_TEST_CONTROLS):
        reject("self_test_control_inventory_mismatch")
    return controls


def bounded_local_read(path: Path, maximum: int) -> bytes:
    try:
        size = path.stat().st_size
    except OSError as error:
        raise Rejected("atomic_output_readback_rejected") from error
    if size <= 0 or size > maximum:
        reject("atomic_output_readback_rejected")
    with open(path, "rb", buffering=0) as stream:
        data = stream.read(maximum + 1)
    if len(data) != size or len(data) > maximum:
        reject("atomic_output_readback_rejected")
    return data


def atomic_write(path: Path, data: bytes, maximum: int) -> str:
    if not data or len(data) > maximum:
        reject("atomic_output_size_rejected")
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.parent / f".{path.name}.{uuid.uuid4().hex}.tmp"
    descriptor = os.open(
        temporary,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0),
        0o600,
    )
    try:
        offset = 0
        while offset < len(data):
            written = os.write(descriptor, data[offset:])
            if written <= 0:
                reject("atomic_output_write_rejected")
            offset += written
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    try:
        os.replace(temporary, path)
        if os.name != "nt":
            directory = os.open(path.parent, os.O_RDONLY)
            try:
                os.fsync(directory)
            finally:
                os.close(directory)
    finally:
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass
    observed = bounded_local_read(path, maximum)
    if observed != data:
        reject("atomic_output_readback_rejected")
    return sha256(observed)


class Lease:
    def __init__(self, path: Path, timeout_seconds: float = 5.0):
        self.path = path
        self.timeout_seconds = timeout_seconds
        self.stream: Any = None

    def __enter__(self) -> "Lease":
        self.path.parent.mkdir(parents=True, exist_ok=True)
        deadline = time.monotonic() + self.timeout_seconds
        while True:
            stream = open(self.path, "a+b", buffering=0)
            try:
                stream.seek(0, os.SEEK_END)
                if stream.tell() == 0:
                    stream.write(b"0")
                    stream.flush()
                    os.fsync(stream.fileno())
                stream.seek(0)
                if os.name == "nt":
                    import msvcrt

                    msvcrt.locking(stream.fileno(), msvcrt.LK_NBLCK, 1)
                else:
                    import fcntl

                    fcntl.flock(stream.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
                self.stream = stream
                return self
            except (OSError, BlockingIOError):
                stream.close()
                if time.monotonic() >= deadline:
                    reject("gate_evidence_lease_unavailable")
                time.sleep(0.025)

    def __exit__(self, _type: Any, _value: Any, _traceback: Any) -> None:
        if self.stream is None:
            return
        try:
            self.stream.seek(0)
            if os.name == "nt":
                import msvcrt

                msvcrt.locking(self.stream.fileno(), msvcrt.LK_UNLCK, 1)
            else:
                import fcntl

                fcntl.flock(self.stream.fileno(), fcntl.LOCK_UN)
        finally:
            self.stream.close()
            self.stream = None


def publish_self_test(root: Path) -> tuple[int, str]:
    output = root / "build/root-validation/rfc9114-launcher-gate"
    canonical = output / "gate-self-test.json"
    lease_path = output / "gate-self-test.lease"
    run_id = uuid.uuid4().hex
    per_run = output / f"gate-self-test-{run_id}.json"
    started = time.monotonic()
    process_before = process_snapshot()
    with Lease(lease_path):
        running = {
            "schema": 1,
            "report_kind": "rfc9114_launcher_gate_self_test",
            "status": "Running",
            "run_id": run_id,
            "shareable": True,
            "canonical_evidence": True,
            "per_run_evidence_file": per_run.name,
            "per_run_evidence_sha256": None,
            "controls_expected": len(SELF_TEST_CONTROLS),
            "controls_completed": 0,
            "controls": [],
            "native_started": False,
            "raw_output_retained": False,
        }
        atomic_write(canonical, pretty_json(running), MAX_EVIDENCE_BYTES)
        running["canonical_evidence"] = False
        atomic_write(per_run, pretty_json(running), MAX_EVIDENCE_BYTES)
        controls: list[dict[str, str]] = []
        try:
            controls = self_test()
            tracked_store = DiskStore(root)
            control_manifest = parse_json(
                tracked_store.read(GATE_CONTROLS_PATH, MAX_ARTIFACT_BYTES),
                "gate_controls",
            )
            validate_gate_controls_manifest(control_manifest, controls)
            validate_invalidation(
                parse_json(
                    tracked_store.read(INVALIDATION_PATH, MAX_ARTIFACT_BYTES),
                    "invalidation",
                )
            )
            validate_integration(
                parse_json(
                    tracked_store.read(INTEGRATION_PATH, MAX_ARTIFACT_BYTES),
                    "integration",
                ),
                tracked_store,
            )
            validate_fix_matrix(
                parse_json(
                    tracked_store.read(FIX_MATRIX_PATH, MAX_ARTIFACT_BYTES),
                    "fix_matrix",
                ),
                False,
            )
            check_deadline()
            native_started, native_residual, visible_shell = process_postconditions(
                process_before, process_snapshot()
            )
            if native_started or native_residual != 0:
                reject("native_process_postcondition_rejected")
            if visible_shell != 0:
                reject("visible_shell_postcondition_rejected")
            terminal = {
                "schema": 1,
                "report_kind": "rfc9114_launcher_gate_self_test",
                "status": "StaticReady",
                "run_id": run_id,
                "shareable": True,
                "canonical_evidence": False,
                "per_run_evidence_file": per_run.name,
                "per_run_evidence_sha256": None,
                "controls_expected": len(SELF_TEST_CONTROLS),
                "controls_completed": len(controls),
                "controls": controls,
                "elapsed_ms": int((time.monotonic() - started) * 1000),
                "absolute_deadline_ms": int(ABSOLUTE_GATE_SECONDS * 1000),
                "native_started": native_started,
                "native_residual_count": native_residual,
                "new_visible_shell_count": visible_shell,
                "raw_output_retained": False,
                "running_canonical_published": True,
                "running_per_run_published": True,
                "exclusive_lease_held_at_terminal_publish": True,
                "rerun_command": (
                    "python -I -B scripts/rfc9114_launcher_evidence_gate.py --self-test"
                ),
            }
            per_run_hash = atomic_write(
                per_run, pretty_json(terminal), MAX_EVIDENCE_BYTES
            )
            terminal["canonical_evidence"] = True
            terminal["per_run_evidence_sha256"] = per_run_hash
            report_hash = atomic_write(
                canonical, pretty_json(terminal), MAX_EVIDENCE_BYTES
            )
        except Rejected as error:
            try:
                native_started, native_residual, visible_shell = process_postconditions(
                    process_before, process_snapshot()
                )
                failed = {
                    "schema": 1,
                    "report_kind": "rfc9114_launcher_gate_self_test",
                    "status": "Failed",
                    "run_id": run_id,
                    "shareable": True,
                    "failure_code": str(error),
                    "canonical_evidence": False,
                    "per_run_evidence_file": per_run.name,
                    "per_run_evidence_sha256": None,
                    "controls_expected": len(SELF_TEST_CONTROLS),
                    "controls_completed": len(controls),
                    "elapsed_ms": int((time.monotonic() - started) * 1000),
                    "absolute_deadline_ms": int(ABSOLUTE_GATE_SECONDS * 1000),
                    "native_started": native_started,
                    "native_residual_count": native_residual,
                    "new_visible_shell_count": visible_shell,
                    "raw_output_retained": False,
                    "running_canonical_published": True,
                    "running_per_run_published": True,
                    "exclusive_lease_held_at_terminal_publish": True,
                }
                failed_hash = atomic_write(
                    per_run, pretty_json(failed), MAX_EVIDENCE_BYTES
                )
                failed["canonical_evidence"] = True
                failed["per_run_evidence_sha256"] = failed_hash
                atomic_write(canonical, pretty_json(failed), MAX_EVIDENCE_BYTES)
            except Exception:
                pass
            raise
    return len(controls), report_hash


def repository_root() -> Path:
    return Path(__file__).resolve(strict=True).parent.parent


class SafeArgumentParser(argparse.ArgumentParser):
    def error(self, _message: str) -> None:
        reject("argument_rejected")


def parser() -> argparse.ArgumentParser:
    value = SafeArgumentParser(add_help=True)
    value.add_argument("--lock", default=LOCK_PATH)
    value.add_argument("--require-ready", action="store_true")
    value.add_argument("--self-test", action="store_true")
    return value


def main() -> int:
    global ACTIVE_DEADLINE
    ACTIVE_DEADLINE = time.monotonic() + ABSOLUTE_GATE_SECONDS
    try:
        arguments = parser().parse_args()
        root = repository_root()
        if arguments.lock != LOCK_PATH or (
            arguments.self_test and arguments.require_ready
        ):
            reject("argument_rejected")
        if arguments.self_test:
            completed, report_hash = publish_self_test(root)
            print(
                "rfc9114_launcher_gate_self_test=StaticReady "
                f"controls={completed} report_sha256={report_hash} native_started=false"
            )
            return 0
        lock_relative = normalized_relative(arguments.lock, "lock_path_rejected")
        status_value = consume(root, lock_relative, arguments.require_ready)
        print(
            f"rfc9114_launcher_evidence_gate={status_value} "
            f"mutations={len(MUTATION_IDS)} native_started=false"
        )
        return 0
    except Rejected as error:
        print(
            "rfc9114_launcher_evidence_gate=Rejected "
            f"failure={str(error)} native_started=false"
        )
        return 1
    except Exception:
        print(
            "rfc9114_launcher_evidence_gate=Rejected "
            "failure=unexpected_gate_failure native_started=false"
        )
        return 1


if __name__ == "__main__":
    raise SystemExit(main())

#!/usr/bin/env python3
"""Bounded identity and adversarial gate for the spawn-monitor scanner."""

from __future__ import annotations

import hashlib
import importlib.util
import json
import os
from pathlib import Path
import stat
import sys


ROOT = Path(__file__).resolve().parents[2]
SCANNER = ROOT / "scripts/spawn_monitor_contract_audit.py"
MAXIMUM_SOURCE_BYTES = 4 * 1024 * 1024
MAXIMUM_TOOL_BYTES = 64 * 1024 * 1024
MAXIMUM_REPORT_BYTES = 1024 * 1024
EXPECTED_SOURCE_PATHS = (
    "packages/quic_core/src/quic_core/internal/tls/replay_guard.gleam",
    "packages/quic_core/src/quic_core_process_ffi.erl",
    "src/http/internal/http1/server.gleam",
    "src/http/internal/http3/server.gleam",
    "src/http_server_ffi.erl",
)
EXPECTED_CONTROLS = {
    "generic_atomic_good",
    "generic_spawn_monitor_gap",
    "generic_erlang_atomic_good",
    "delegated_good",
    "dead_scope_wrong_receiver_composite",
    "dead_owner_scope",
    "dead_state_scope",
    "dead_down_scope",
    "wrong_external_module",
    "wrong_external_function",
    "unused_exact_call",
    "different_ok_binding",
    "await_in_different_case_branch",
    "different_guardian_spawn",
    "boot_outside_guardian_closure",
    "unrelated_handler_spawn_opt",
    "old_non_atomic",
    "different_monitor_return",
    "owner_monitor_not_forwarded",
    "handler_monitor_not_stored",
    "handler_down_uses_other_monitor",
    "down_call_in_different_clause",
    "lexical_decoys",
    "source_drift_rejected",
    "scanner_drift_rejected",
    "atomic_report_readback",
}


def safe_read_bytes(path: Path, maximum: int) -> tuple[bytes, str]:
    absolute = Path(os.path.abspath(path))
    before_path = os.lstat(absolute)
    reparse_flag = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0)
    attributes = getattr(before_path, "st_file_attributes", 0)
    if stat.S_ISLNK(before_path.st_mode) or (
        reparse_flag and attributes & reparse_flag
    ):
        raise ValueError("identity_rejected")
    if not stat.S_ISREG(before_path.st_mode):
        raise ValueError("type_rejected")
    if before_path.st_size <= 0 or before_path.st_size > maximum:
        raise ValueError("size_rejected")
    chunks: list[bytes] = []
    consumed = 0
    with absolute.open("rb") as handle:
        before_handle = os.fstat(handle.fileno())
        while True:
            chunk = handle.read(min(1024 * 1024, maximum - consumed + 1))
            if not chunk:
                break
            consumed += len(chunk)
            if consumed > maximum:
                raise ValueError("size_rejected")
            chunks.append(chunk)
        after_handle = os.fstat(handle.fileno())
    after_path = os.lstat(absolute)
    identity = lambda value: (
        value.st_dev,
        value.st_ino,
        value.st_size,
        value.st_mtime_ns,
    )
    if not (
        identity(before_path)
        == identity(before_handle)
        == identity(after_handle)
        == identity(after_path)
    ):
        raise ValueError("changed_during_read")
    data = b"".join(chunks)
    if len(data) != before_path.st_size:
        raise ValueError("partial_read_rejected")
    return data, hashlib.sha256(data).hexdigest()


def safe_hash(path: Path, maximum: int = MAXIMUM_SOURCE_BYTES) -> str:
    return safe_read_bytes(path, maximum)[1]


def source_snapshot() -> tuple[dict[str, str], int, str]:
    hashes: dict[str, str] = {}
    total = 0
    aggregate = hashlib.sha256()
    for relative in EXPECTED_SOURCE_PATHS:
        data, digest = safe_read_bytes(ROOT / relative, MAXIMUM_SOURCE_BYTES)
        hashes[relative] = digest
        total += len(data)
        aggregate.update(relative.encode("utf-8") + b"\0" + data + b"\0")
    return hashes, total, aggregate.hexdigest()


def load_scanner() -> object:
    specification = importlib.util.spec_from_file_location(
        "spawn_monitor_contract_audit_contract_check", SCANNER
    )
    if specification is None or specification.loader is None:
        raise ValueError("scanner_load_rejected")
    module = importlib.util.module_from_spec(specification)
    sys.modules[specification.name] = module
    specification.loader.exec_module(module)
    return module


def validate_report(
    report: object,
    kind: str,
    expected_scanner_hash: str,
    expected_sources: dict[str, str] | None,
    expected_runtime_hash: str,
    expected_aggregate: str | None = None,
    expected_source_bytes: int | None = None,
) -> list[str]:
    """Compare identity values exactly; field presence is never sufficient."""
    if not isinstance(report, dict):
        return [f"{kind}_report_not_map"]
    failures: list[str] = []
    if report.get("schema") != 2 or report.get("kind") != kind:
        failures.append(f"{kind}_schema_invalid")
    if report.get("status") != "Ready" or report.get("classification") != "passed":
        failures.append(f"{kind}_status_invalid")
    if report.get("scanner_sha256_pre") != expected_scanner_hash:
        failures.append(f"{kind}_scanner_pre_identity_mismatch")
    if report.get("scanner_sha256_post") != expected_scanner_hash:
        failures.append(f"{kind}_scanner_post_identity_mismatch")
    if report.get("scanner_stable") is not True:
        failures.append(f"{kind}_scanner_stability_invalid")
    runtime = report.get("runtime")
    if (
        not isinstance(runtime, dict)
        or runtime.get("executable_sha256") != expected_runtime_hash
    ):
        failures.append(f"{kind}_runtime_identity_mismatch")
    if not isinstance(report.get("rerun_command"), str):
        failures.append(f"{kind}_rerun_missing")

    if kind == "self_test":
        controls = report.get("controls")
        if not isinstance(controls, list):
            failures.append("self_test_controls_invalid")
        else:
            names = [
                control.get("name")
                for control in controls
                if isinstance(control, dict)
            ]
            if (
                len(names) != len(controls)
                or len(set(names)) != len(names)
                or set(names) != EXPECTED_CONTROLS
                or report.get("completed_controls") != len(EXPECTED_CONTROLS)
            ):
                failures.append("self_test_control_inventory_mismatch")
            if any(
                not isinstance(control, dict)
                or not isinstance(control.get("expected"), list)
                or not isinstance(control.get("observed"), list)
                or control.get("expected") != control.get("observed")
                or control.get("passed") is not True
                for control in controls
            ):
                failures.append("self_test_control_result_invalid")
    elif kind == "audit":
        if expected_sources is None:
            failures.append("audit_expected_sources_missing")
        else:
            if report.get("source_sha256_pre") != expected_sources:
                failures.append("audit_source_pre_identity_mismatch")
            if report.get("source_sha256_post") != expected_sources:
                failures.append("audit_source_post_identity_mismatch")
            if report.get("source_stable") is not True:
                failures.append("audit_source_stability_invalid")
            if report.get("source_files") != len(expected_sources):
                failures.append("audit_source_inventory_mismatch")
        if expected_aggregate is not None:
            if report.get("source_aggregate_sha256_pre") != expected_aggregate:
                failures.append("audit_aggregate_pre_identity_mismatch")
            if report.get("source_aggregate_sha256_post") != expected_aggregate:
                failures.append("audit_aggregate_post_identity_mismatch")
        if (
            expected_source_bytes is not None
            and report.get("source_bytes") != expected_source_bytes
        ):
            failures.append("audit_source_bytes_mismatch")
        if report.get("findings") != []:
            failures.append("audit_findings_invalid")
    else:
        failures.append("report_kind_invalid")
    return sorted(set(failures))


def identity_self_tests(
    scanner_hash: str,
    source_hashes: dict[str, str],
    runtime_hash: str,
    aggregate: str,
    source_bytes: int,
) -> list[dict[str, object]]:
    base: dict[str, object] = {
        "schema": 2,
        "kind": "audit",
        "status": "Ready",
        "classification": "passed",
        "scanner_sha256_pre": scanner_hash,
        "scanner_sha256_post": scanner_hash,
        "scanner_stable": True,
        "runtime": {"executable_sha256": runtime_hash},
        "rerun_command": "fixed",
        "source_sha256_pre": source_hashes,
        "source_sha256_post": source_hashes,
        "source_stable": True,
        "source_files": len(source_hashes),
        "source_bytes": source_bytes,
        "source_aggregate_sha256_pre": aggregate,
        "source_aggregate_sha256_post": aggregate,
        "findings": [],
    }
    cases = (
        ("scanner_pre_drift", {"scanner_sha256_pre": "0" * 64}, "audit_scanner_pre_identity_mismatch"),
        ("scanner_post_drift", {"scanner_sha256_post": "1" * 64}, "audit_scanner_post_identity_mismatch"),
        ("scanner_false_stability", {"scanner_stable": False}, "audit_scanner_stability_invalid"),
        ("source_pre_drift", {"source_sha256_pre": {}}, "audit_source_pre_identity_mismatch"),
        ("source_post_drift", {"source_sha256_post": {}}, "audit_source_post_identity_mismatch"),
        ("source_false_stability", {"source_stable": False}, "audit_source_stability_invalid"),
        ("runtime_drift", {"runtime": {"executable_sha256": "2" * 64}}, "audit_runtime_identity_mismatch"),
    )
    results: list[dict[str, object]] = []
    for name, mutation, expected in cases:
        candidate = dict(base)
        candidate.update(mutation)
        observed = validate_report(
            candidate,
            "audit",
            scanner_hash,
            source_hashes,
            runtime_hash,
            aggregate,
            source_bytes,
        )
        results.append(
            {
                "name": name,
                "expected": expected,
                "observed": observed,
                "passed": expected in observed,
            }
        )
    return results


def main() -> int:
    failures: list[str] = []
    observed_controls: list[str] = []
    identity_controls: list[dict[str, object]] = []
    try:
        checker_pre = safe_hash(Path(__file__).resolve())
        scanner_pre = safe_hash(SCANNER)
        runtime_path = Path(sys.executable).resolve(strict=True)
        runtime_pre = safe_hash(runtime_path, MAXIMUM_TOOL_BYTES)
        source_pre, source_bytes_pre, aggregate_pre = source_snapshot()
        module = load_scanner()
        if not hasattr(module, "erlang_execution"):
            failures.append("tokenized_execution_flow_missing")
        self_status, self_report = module.self_test_report()
        failures.extend(
            validate_report(
                self_report, "self_test", scanner_pre, None, runtime_pre
            )
        )
        controls = self_report.get("controls", []) if isinstance(self_report, dict) else []
        if isinstance(controls, list):
            observed_controls = sorted(
                control.get("name")
                for control in controls
                if isinstance(control, dict) and isinstance(control.get("name"), str)
            )
        if self_status != 0:
            failures.append("self_test_exit_invalid")
        audit_status, audit_report = module.audit()
        failures.extend(
            validate_report(
                audit_report,
                "audit",
                scanner_pre,
                source_pre,
                runtime_pre,
                aggregate_pre,
                source_bytes_pre,
            )
        )
        if audit_status != 0:
            failures.append("audit_exit_invalid")
        identity_controls = identity_self_tests(
            scanner_pre, source_pre, runtime_pre, aggregate_pre, source_bytes_pre
        )
        if any(control.get("passed") is not True for control in identity_controls):
            failures.append("identity_adversary_failed")
        source_post, source_bytes_post, aggregate_post = source_snapshot()
        scanner_post = safe_hash(SCANNER)
        checker_post = safe_hash(Path(__file__).resolve())
        runtime_post = safe_hash(runtime_path, MAXIMUM_TOOL_BYTES)
        if source_pre != source_post or source_bytes_pre != source_bytes_post or aggregate_pre != aggregate_post:
            failures.append("source_changed_during_check")
        if scanner_pre != scanner_post:
            failures.append("scanner_changed_during_check")
        if checker_pre != checker_post:
            failures.append("checker_changed_during_check")
        if runtime_pre != runtime_post:
            failures.append("runtime_changed_during_check")
    except (AttributeError, KeyError, OSError, TypeError, UnicodeError, ValueError):
        failures.append("checker_execution_rejected")
        checker_pre = checker_post = "unavailable"
        scanner_pre = scanner_post = "unavailable"
        runtime_pre = runtime_post = "unavailable"
        source_pre = source_post = {}
        aggregate_pre = aggregate_post = "unavailable"
        source_bytes_pre = source_bytes_post = 0
    failures = sorted(set(failures))
    report = {
        "schema": 2,
        "status": "Ready" if not failures else "Failed",
        "classification": "passed" if not failures else failures[0],
        "failures": failures,
        "expected_controls": sorted(EXPECTED_CONTROLS),
        "observed_controls": observed_controls,
        "identity_controls": identity_controls,
        "source_sha256_pre": source_pre,
        "source_sha256_post": source_post,
        "source_stable": source_pre == source_post,
        "source_aggregate_sha256_pre": aggregate_pre,
        "source_aggregate_sha256_post": aggregate_post,
        "source_bytes_pre": source_bytes_pre,
        "source_bytes_post": source_bytes_post,
        "scanner_sha256_pre": scanner_pre,
        "scanner_sha256_post": scanner_post,
        "scanner_stable": scanner_pre == scanner_post,
        "checker_sha256_pre": checker_pre,
        "checker_sha256_post": checker_post,
        "checker_stable": checker_pre == checker_post,
        "python_executable_sha256_pre": runtime_pre,
        "python_executable_sha256_post": runtime_post,
        "python_executable_stable": runtime_pre == runtime_post,
        "limits": {
            "source_file_bytes": MAXIMUM_SOURCE_BYTES,
            "tool_bytes": MAXIMUM_TOOL_BYTES,
            "report_bytes": MAXIMUM_REPORT_BYTES,
        },
        "rerun_command": (
            "python -I -B build/root-validation/"
            "spawn-monitor-dataflow-contract-check.py"
        ),
    }
    encoded = json.dumps(report, sort_keys=True, separators=(",", ":"))
    if len(encoded.encode("utf-8")) > MAXIMUM_REPORT_BYTES:
        print(json.dumps({"schema": 2, "status": "Failed", "classification": "report_limit_rejected"}))
        return 1
    print(encoded)
    return 0 if not failures else 1


if __name__ == "__main__":
    raise SystemExit(main())

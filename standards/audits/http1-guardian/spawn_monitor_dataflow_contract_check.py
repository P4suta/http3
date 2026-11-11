#!/usr/bin/env python3
"""Bounded identity and adversarial gate for the spawn-monitor scanner."""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import stat
import sys
import tempfile


ROOT = Path(__file__).resolve().parents[3]
SCANNER = ROOT / "scripts/spawn_monitor_contract_audit.py"
MAXIMUM_SOURCE_BYTES = 4 * 1024 * 1024
MAXIMUM_TOOL_BYTES = 64 * 1024 * 1024
MAXIMUM_REPORT_BYTES = 1024 * 1024
EXPECTED_PYTHON_VERSION = "3.12.13"
EXPECTED_CONTRACTS = 12
AUDIT_RERUN = (
    "mise exec python@3.12.13 -- python -I -B "
    "scripts/spawn_monitor_contract_audit.py"
)
SELF_TEST_RERUN = AUDIT_RERUN + " --self-test"
WRAPPER_RERUN = (
    "mise exec python@3.12.13 -- python -I -B "
    "standards/audits/http1-guardian/"
    "spawn_monitor_dataflow_contract_check.py"
)
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
    "guardian_return_after_valid_decoy",
    "owner_demonitor_before_handler",
    "owner_demonitor_before_publication",
    "nested_handler_state",
    "exit_before_handler_down",
    "throw_before_handler_down",
    "return_before_handler_down",
    "publication_in_unreachable_branch",
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
    expected_config_hash: str | None = None,
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
    config_hash = (
        expected_config_hash
        if expected_config_hash is not None
        else safe_hash(ROOT / ".mise.toml")
    )
    if (
        not isinstance(runtime, dict)
        or runtime.get("tool_request") != "python@3.12.13"
        or runtime.get("implementation") != "cpython"
        or runtime.get("version") != EXPECTED_PYTHON_VERSION
        or runtime.get("executable_sha256") != expected_runtime_hash
        or runtime.get("mise_config_sha256") != config_hash
    ):
        failures.append(f"{kind}_runtime_identity_mismatch")
    expected_rerun = SELF_TEST_RERUN if kind == "self_test" else AUDIT_RERUN
    if report.get("rerun_command") != expected_rerun:
        failures.append(f"{kind}_rerun_invalid")

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
        if report.get("completed_contracts") != EXPECTED_CONTRACTS:
            failures.append("audit_completed_contracts_mismatch")
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
    config_hash: str,
) -> list[dict[str, object]]:
    base: dict[str, object] = {
        "schema": 2,
        "kind": "audit",
        "status": "Ready",
        "classification": "passed",
        "scanner_sha256_pre": scanner_hash,
        "scanner_sha256_post": scanner_hash,
        "scanner_stable": True,
        "runtime": {
            "tool_request": "python@3.12.13",
            "implementation": "cpython",
            "version": EXPECTED_PYTHON_VERSION,
            "executable_sha256": runtime_hash,
            "mise_config_sha256": config_hash,
        },
        "rerun_command": AUDIT_RERUN,
        "completed_contracts": EXPECTED_CONTRACTS,
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
        (
            "runtime_drift",
            {"runtime": {
                "tool_request": "python@3.12.13",
                "implementation": "cpython",
                "version": EXPECTED_PYTHON_VERSION,
                "executable_sha256": "2" * 64,
                "mise_config_sha256": config_hash,
            }},
            "audit_runtime_identity_mismatch",
        ),
        ("completed_contracts_missing", {"completed_contracts": None}, "audit_completed_contracts_mismatch"),
        ("completed_contracts_zero", {"completed_contracts": 0}, "audit_completed_contracts_mismatch"),
        ("rerun_empty", {"rerun_command": ""}, "audit_rerun_invalid"),
        ("rerun_generic", {"rerun_command": "python -I -B scripts/spawn_monitor_contract_audit.py"}, "audit_rerun_invalid"),
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
            config_hash,
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


def atomic_publish(path: Path, payload: bytes) -> None:
    if len(payload) <= 0 or len(payload) > MAXIMUM_REPORT_BYTES:
        raise ValueError("report_limit_rejected")
    destination = Path(os.path.abspath(path))
    destination.parent.mkdir(parents=True, exist_ok=True)
    parent_metadata = os.lstat(destination.parent)
    reparse_flag = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0)
    parent_attributes = getattr(parent_metadata, "st_file_attributes", 0)
    if (
        stat.S_ISLNK(parent_metadata.st_mode)
        or (reparse_flag and parent_attributes & reparse_flag)
        or not stat.S_ISDIR(parent_metadata.st_mode)
    ):
        raise ValueError("report_parent_identity_rejected")
    if destination.exists():
        metadata = os.lstat(destination)
        reparse_flag = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0)
        attributes = getattr(metadata, "st_file_attributes", 0)
        if stat.S_ISLNK(metadata.st_mode) or (
            reparse_flag and attributes & reparse_flag
        ):
            raise ValueError("report_identity_rejected")
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=".spawn-wrapper-report-", dir=destination.parent
    )
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, destination)
        observed, _digest = safe_read_bytes(
            destination, MAXIMUM_REPORT_BYTES
        )
        if observed != payload:
            raise ValueError("report_readback_rejected")
    finally:
        try:
            temporary.unlink(missing_ok=True)
        except OSError:
            pass


def emit_report(report: dict[str, object], report_path: str | None) -> bool:
    payload = (json.dumps(report, sort_keys=True, separators=(",", ":")) + "\n").encode("utf-8")
    if report_path:
        try:
            atomic_publish(Path(report_path), payload)
        except (OSError, UnicodeError, ValueError):
            payload = (
                json.dumps(
                    {
                        "schema": 2,
                        "status": "Failed",
                        "classification": "report_publication_rejected",
                        "rerun_command": WRAPPER_RERUN,
                    },
                    sort_keys=True,
                    separators=(",", ":"),
                )
                + "\n"
            ).encode("utf-8")
            try:
                sys.stdout.buffer.write(payload)
                sys.stdout.buffer.flush()
            except OSError:
                pass
            return False
    try:
        sys.stdout.buffer.write(payload)
        sys.stdout.buffer.flush()
    except OSError:
        return False
    return True


def main(report_path: str | None = None) -> int:
    failures: list[str] = []
    observed_controls: list[str] = []
    identity_controls: list[dict[str, object]] = []
    try:
        checker_pre = safe_hash(Path(__file__).resolve())
        scanner_pre = safe_hash(SCANNER)
        runtime_path = Path(sys.executable).resolve(strict=True)
        runtime_pre = safe_hash(runtime_path, MAXIMUM_TOOL_BYTES)
        config_pre = safe_hash(ROOT / ".mise.toml")
        source_pre, source_bytes_pre, aggregate_pre = source_snapshot()
        module = load_scanner()
        if not hasattr(module, "erlang_execution"):
            failures.append("tokenized_execution_flow_missing")
        self_status, self_report = module.self_test_report()
        failures.extend(
            validate_report(
                self_report, "self_test", scanner_pre, None, runtime_pre,
                expected_config_hash=config_pre,
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
                config_pre,
            )
        )
        if audit_status != 0:
            failures.append("audit_exit_invalid")
        identity_controls = identity_self_tests(
            scanner_pre, source_pre, runtime_pre, aggregate_pre,
            source_bytes_pre, config_pre
        )
        if any(control.get("passed") is not True for control in identity_controls):
            failures.append("identity_adversary_failed")
        source_post, source_bytes_post, aggregate_post = source_snapshot()
        scanner_post = safe_hash(SCANNER)
        checker_post = safe_hash(Path(__file__).resolve())
        runtime_post = safe_hash(runtime_path, MAXIMUM_TOOL_BYTES)
        config_post = safe_hash(ROOT / ".mise.toml")
        if source_pre != source_post or source_bytes_pre != source_bytes_post or aggregate_pre != aggregate_post:
            failures.append("source_changed_during_check")
        if scanner_pre != scanner_post:
            failures.append("scanner_changed_during_check")
        if checker_pre != checker_post:
            failures.append("checker_changed_during_check")
        if runtime_pre != runtime_post:
            failures.append("runtime_changed_during_check")
        if config_pre != config_post:
            failures.append("config_changed_during_check")
        if ".".join(str(part) for part in sys.version_info[:3]) != EXPECTED_PYTHON_VERSION:
            failures.append("runtime_version_mismatch")
    except (AttributeError, KeyError, OSError, TypeError, UnicodeError, ValueError):
        failures.append("checker_execution_rejected")
        checker_pre = checker_post = "unavailable"
        scanner_pre = scanner_post = "unavailable"
        runtime_pre = runtime_post = "unavailable"
        config_pre = config_post = "unavailable"
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
        "python_version": ".".join(str(part) for part in sys.version_info[:3]),
        "python_tool_request": "python@3.12.13",
        "mise_config_sha256_pre": config_pre,
        "mise_config_sha256_post": config_post,
        "mise_config_stable": config_pre == config_post,
        "limits": {
            "source_file_bytes": MAXIMUM_SOURCE_BYTES,
            "tool_bytes": MAXIMUM_TOOL_BYTES,
            "report_bytes": MAXIMUM_REPORT_BYTES,
        },
        "rerun_command": WRAPPER_RERUN,
    }
    encoded = json.dumps(report, sort_keys=True, separators=(",", ":"))
    if len(encoded.encode("utf-8")) > MAXIMUM_REPORT_BYTES:
        emit_report(
            {"schema": 2, "status": "Failed", "classification": "report_limit_rejected"},
            report_path,
        )
        return 1
    published = emit_report(report, report_path)
    return 0 if not failures and published else 1


def cli_main() -> int:
    try:
        parser = argparse.ArgumentParser(add_help=True)
        parser.add_argument("--report")
        arguments = parser.parse_args()
        return main(arguments.report)
    except (KeyboardInterrupt, SystemExit, GeneratorExit):
        raise
    except BaseException:
        try:
            emit_report(
                {
                    "schema": 2,
                    "status": "Failed",
                    "classification": "internal_rejected",
                    "rerun_command": WRAPPER_RERUN,
                },
                None,
            )
        except BaseException:
            pass
        return 2


if __name__ == "__main__":
    raise SystemExit(cli_main())

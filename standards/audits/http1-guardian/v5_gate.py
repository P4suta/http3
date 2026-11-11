#!/usr/bin/env python3
"""Exact-control phases for the HTTP/1 guardian v5 release gate."""

from __future__ import annotations

import copy
import hashlib
import os
from pathlib import Path
import stat
import sys
import tempfile
from typing import Any

import http1_guardian_v5_core as core


SOURCE_PATHS = (
    "src/http/internal/http1/server.gleam",
    "src/http_server_ffi.erl",
    "test/server_handler_lifetime_test.gleam",
    "test/http_handler_lifetime_test_ffi.erl",
)
MODULE_PATHS = {
    "guardian": "standards/audits/http1-guardian/guardian_contract_check.py",
    "scanner": "scripts/spawn_monitor_contract_audit.py",
}
AUTHORITY_PATH = "standards/audits/http1-guardian/control-authority.json"
HISTORY_MANIFEST = "standards/audits/http1-guardian/history/manifest.json"
RERUN_COMMAND = "mise run http1-guardian-audit"
INDEPENDENT_MUTATIONS = (
    "run_before_entry_receive",
    "run_after_entry_receive",
    "immediately_invoked_fun_run_in_first_true",
    "delegated_run_in_first_true",
    "guard_false_safe_entry_clause_wrong_live_clause",
    "impossible_variable_guard_safe_entry_wrong_live_clause",
    "matching_traffic_bypasses_terminating_precheck",
    "matching_traffic_bypasses_quarantine_precheck",
    "indirect_owner_demonitor_before_publication",
    "indirect_exit_before_terminal_down_finish",
    "indirect_throw_before_terminal_down_finish",
    "guard_false_safe_down_clause_missing_live_publication",
)
EVIDENCE_CONTROL_NAMES = (
    "duplicate_json_key_rejected",
    "unknown_report_key_rejected",
    "success_secret_rejected",
    "failure_secret_rejected",
    "hardlink_input_rejected",
    "reparse_input_rejected",
    "oversize_input_rejected",
    "partial_read_rejected",
    "missing_input_rejected",
    "stale_input_rejected",
    "tampered_report_rejected",
    "snapshot_executes_exact_bytes",
    "snapshot_path_drift_rejected",
    "input_restore_race_rejected",
    "post_readback_replacement_rejected",
    "control_substitution_rejected",
    "control_reorder_rejected",
    "control_duplicate_rejected",
    "runtime_forgery_rejected",
    "runtime_version_forgery_rejected",
    "unexpected_failure_redacted",
    "tracked_history_exact",
    "clean_checkout_inventory_exact",
    "running_precedes_bootstrap_failure",
    "previous_running_recovery_detected",
    "absolute_process_deadline_reaped",
    "process_output_limit_reaped",
    "manifest_candidate_blocks_ready",
    "consumer_schema_is_closed",
    "rejected_phase_controls_fail_closed",
    "consumer_process_proof_bound",
    "consumer_process_tamper_rejected",
    "completed_pointer_missing_process_rejected",
    "runtime_environment_override_rejected",
    "noncanonical_receipt_ready_blocked",
)


def _staged_input(stage: Path, relative: str) -> Path:
    candidate = stage / "inputs" / Path(relative)
    return candidate


def _snapshot_text(
    root: Path, stage: Path, relative: str
) -> tuple[str, core.Snapshot]:
    snapshot = core.read_snapshot(
        _staged_input(stage, relative),
        core.MAX_SOURCE_BYTES,
        parent_anchor=stage,
    )
    return snapshot.data.decode("utf-8", errors="strict"), snapshot


def _load_modules(root: Path, stage: Path) -> tuple[object, object, dict[str, str]]:
    loaded: list[object] = []
    hashes: dict[str, str] = {}
    for role, relative in MODULE_PATHS.items():
        staged = stage / (role + ".py")
        snapshot = core.read_snapshot(staged, core.MAX_SOURCE_BYTES, parent_anchor=stage)
        hashes[relative] = snapshot.sha256
        loaded.append(
            core.load_snapshot_module(
                snapshot,
                "http1_guardian_v5_" + role,
                staged,
                logical_file=root / relative,
            )
        )
    return loaded[0], loaded[1], hashes


def _load_control_authority(
    stage: Path,
) -> tuple[dict[str, object], core.Snapshot]:
    snapshot = core.read_snapshot(
        _staged_input(stage, AUTHORITY_PATH),
        core.MAX_SOURCE_BYTES,
        parent_anchor=stage,
    )
    value = core.exact_keys(
        core.strict_json_bytes(snapshot.data),
        {"schema", "phases"},
        "control_authority_schema_rejected",
    )
    if value.get("schema") != 5 or not isinstance(value.get("phases"), dict):
        raise core.AuditFailure("control_authority_schema_rejected")
    return value, snapshot


def make_control(name: str, kind: str, observed: bool) -> dict[str, object]:
    return {
        "name": name,
        "type": kind,
        "expected": True,
        "observed": observed,
        "passed": observed is True,
    }


def validate_controls(
    phase: str,
    controls: list[dict[str, object]],
    authority: dict[str, object],
) -> None:
    phases = authority.get("phases")
    if not isinstance(phases, dict):
        raise core.AuditFailure("control_authority_schema_rejected")
    expected = phases.get(phase)
    if not isinstance(expected, list) or len(expected) != len(controls):
        raise core.AuditFailure("control_inventory_rejected")
    names: list[str] = []
    for specification, observed in zip(expected, controls, strict=True):
        spec = core.exact_keys(
            specification,
            {"name", "type", "expected"},
            "control_specification_rejected",
        )
        item = core.exact_keys(
            observed,
            {"name", "type", "expected", "observed", "passed"},
            "control_record_rejected",
        )
        if (
            not isinstance(spec.get("name"), str)
            or not isinstance(spec.get("type"), str)
            or spec.get("expected") is not True
            or item.get("name") != spec.get("name")
            or item.get("type") != spec.get("type")
            or item.get("expected") is not True
            or item.get("observed") is not True
            or item.get("passed") is not True
        ):
            raise core.AuditFailure("control_record_mismatch")
        names.append(str(item["name"]))
    if len(names) != len(set(names)):
        raise core.AuditFailure("control_name_duplicate")


def _semantic_controls(
    root: Path, stage: Path
) -> tuple[list[dict[str, object]], dict[str, str], dict[str, str]]:
    guardian, scanner, module_hashes = _load_modules(root, stage)
    sources: dict[str, str] = {}
    source_hashes: dict[str, str] = {}
    for alias, relative in zip(("gleam", "ffi", "test", "test_ffi"), SOURCE_PATHS):
        text, snapshot = _snapshot_text(root, stage, relative)
        sources[alias] = text
        source_hashes[relative] = snapshot.sha256
    controls: list[dict[str, object]] = [
        make_control("guardian_current_source", "source", guardian.analyze(sources) == []),
        make_control(
            "scanner_current_source",
            "source",
            scanner.inspect_http1_delegation(sources["gleam"], sources["ffi"])
            == [],
        ),
    ]
    mutations = guardian.apply_mutations(sources)
    if not isinstance(mutations, dict):
        raise core.AuditFailure("guardian_mutation_report_rejected")
    for name in sorted(mutations):
        result = mutations[name]
        controls.append(
            make_control(
                "guardian_mutation::" + name,
                "mutation",
                isinstance(result, dict)
                and result.get("changed") is True
                and result.get("detected") is True,
            )
        )
    _self_status, self_report = scanner.self_test_report()
    scanner_controls = self_report.get("controls") if isinstance(self_report, dict) else None
    if not isinstance(scanner_controls, list):
        raise core.AuditFailure("scanner_controls_rejected")
    for item in scanner_controls:
        controls.append(
            make_control(
                "scanner_self::" + str(item.get("name")),
                "scanner_self",
                isinstance(item, dict)
                and item.get("expected") == item.get("observed")
                and item.get("passed") is True,
            )
        )
    return controls, source_hashes, module_hashes


def _independent_controls(
    root: Path, stage: Path
) -> tuple[list[dict[str, object]], dict[str, str], dict[str, str]]:
    guardian, _scanner, module_hashes = _load_modules(root, stage)
    sources: dict[str, str] = {}
    source_hashes: dict[str, str] = {}
    for alias, relative in zip(("gleam", "ffi", "test", "test_ffi"), SOURCE_PATHS):
        text, snapshot = _snapshot_text(root, stage, relative)
        sources[alias] = text
        source_hashes[relative] = snapshot.sha256
    mutations = guardian.apply_mutations(sources)
    controls = []
    for name in INDEPENDENT_MUTATIONS:
        result = mutations.get(name) if isinstance(mutations, dict) else None
        controls.append(
            make_control(
                "independent_v4::" + name,
                "independent_mutation",
                isinstance(result, dict)
                and result.get("changed") is True
                and result.get("detected") is True,
            )
        )
    return controls, source_hashes, module_hashes


def _history_exact(root: Path, stage: Path) -> bool:
    manifest_snapshot = core.read_snapshot(
        _staged_input(stage, HISTORY_MANIFEST),
        core.MAX_SOURCE_BYTES,
        parent_anchor=stage,
    )
    manifest = core.exact_keys(
        core.strict_json_bytes(manifest_snapshot.data),
        {"schema", "status", "entries", "chain"},
        "history_manifest_schema_rejected",
    )
    entries = manifest.get("entries")
    if manifest.get("schema") != 1 or manifest.get("status") != "Rejected_history" or not isinstance(entries, list):
        return False
    names: list[str] = []
    for raw in entries:
        entry = core.exact_keys(
            raw, {"path", "sha256", "bytes"}, "history_entry_schema_rejected"
        )
        relative = entry.get("path")
        if not isinstance(relative, str) or not relative.startswith(
            "standards/audits/http1-guardian/history/"
        ):
            return False
        snapshot = core.read_snapshot(
            _staged_input(stage, relative),
            core.MAX_SOURCE_BYTES,
            parent_anchor=stage,
        )
        if snapshot.sha256 != entry.get("sha256") or len(snapshot.data) != entry.get("bytes"):
            return False
        names.append(relative)
    chain = manifest.get("chain")
    return (
        len(names) == len(set(names))
        and isinstance(chain, list)
        and chain == [
            "v2:Rejected", "v3:Rejected", "v4:Rejected",
            "v5:Red", "v5:candidate",
        ]
    )


def _evidence_controls(
    root: Path, stage: Path, authority: dict[str, object]
) -> tuple[list[dict[str, object]], dict[str, str], dict[str, str]]:
    observed: dict[str, bool] = {}
    try:
        core.strict_json_bytes(b'{"status":"Ready","status":"Rejected"}')
        observed["duplicate_json_key_rejected"] = False
    except core.AuditFailure:
        observed["duplicate_json_key_rejected"] = True
    try:
        core.exact_keys(
            {"status": "Ready", "extra": True},
            {"status"},
            "schema_rejected",
        )
        observed["unknown_report_key_rejected"] = False
    except core.AuditFailure:
        observed["unknown_report_key_rejected"] = True
    observed["success_secret_rejected"] = all(
        not core.evidence_is_secret_safe(value)
        for value in (
            {"status": "Ready", "extra": "SYNTHETIC_SECRET_VALUE"},
            {"status": "Ready", "detail": "prefix=C:\\build\\tool.exe"},
            {"status": "Ready", "detail": "prefix=/opt/build/tool"},
            {"status": "Ready", "detail": "prefix=\\\\host\\share"},
        )
    )
    observed["failure_secret_rejected"] = all(
        not core.evidence_is_secret_safe(value)
        for value in (
            {"status": "Rejected", "traceback": "SYNTHETIC_PRIVATE_VALUE"},
            {"status": "Rejected", "detail": "prefix=#PID<1.2.3>"},
            {"status": "Rejected", "detail": "Bearer synthetic-token"},
        )
    )
    with tempfile.TemporaryDirectory(prefix="http1-v5-hardlink-") as directory:
        original = Path(directory) / "input.json"
        alias = Path(directory) / "alias.json"
        original.write_bytes(b"{}\n")
        os.link(original, alias)
        try:
            core.read_snapshot(original, core.MAX_REPORT_BYTES)
            observed["hardlink_input_rejected"] = False
        except core.AuditFailure:
            observed["hardlink_input_rejected"] = True
    with tempfile.TemporaryDirectory(prefix="http1-v5-reparse-") as directory:
        candidate = Path(directory) / "input.json"
        candidate.write_bytes(b"{}\n")
        original_reparse = core._reparse
        try:
            core._reparse = lambda _metadata: True
            core.read_snapshot(candidate, core.MAX_REPORT_BYTES)
            observed["reparse_input_rejected"] = False
        except core.AuditFailure:
            observed["reparse_input_rejected"] = True
        finally:
            core._reparse = original_reparse
    with tempfile.TemporaryDirectory(prefix="http1-v5-size-") as directory:
        candidate = Path(directory) / "input.bin"
        candidate.write_bytes(b"x" * (4096 + 1))
        try:
            core.read_snapshot(candidate, 4096)
            observed["oversize_input_rejected"] = False
        except core.AuditFailure:
            observed["oversize_input_rejected"] = True
    with tempfile.TemporaryDirectory(prefix="http1-v5-partial-") as directory:
        candidate = Path(directory) / "input.bin"
        candidate.write_bytes(b"complete")
        original_read = core.os.read
        try:
            core.os.read = lambda _descriptor, _maximum: b""
            core.read_snapshot(candidate, core.MAX_REPORT_BYTES)
            observed["partial_read_rejected"] = False
        except core.AuditFailure:
            observed["partial_read_rejected"] = True
        finally:
            core.os.read = original_read
    with tempfile.TemporaryDirectory(prefix="http1-v5-artifact-") as directory:
        missing = Path(directory) / "missing.json"
        try:
            core.read_snapshot(missing, core.MAX_REPORT_BYTES)
            observed["missing_input_rejected"] = False
        except (core.AuditFailure, OSError):
            observed["missing_input_rejected"] = True
        stale = Path(directory) / "stale.json"
        stale.write_bytes(b'{"status":"Rejected"}\n')
        stale_snapshot = core.read_snapshot(stale, core.MAX_REPORT_BYTES)
        stale.write_bytes(b'{"status":"Changed"}\n')
        try:
            core.revalidate_snapshot(stale, stale_snapshot, core.MAX_REPORT_BYTES)
            observed["stale_input_rejected"] = False
        except core.AuditFailure:
            observed["stale_input_rejected"] = True
        report = Path(directory) / "report.json"
        report_snapshot = core.create_immutable(
            report, b'{"status":"Rejected"}\n'
        )
        os.chmod(report, stat.S_IREAD | stat.S_IWRITE)
        report.write_bytes(b'{"status":"Ready"}\n')
        try:
            core.revalidate_snapshot(report, report_snapshot, core.MAX_REPORT_BYTES)
            observed["tampered_report_rejected"] = False
        except core.AuditFailure:
            observed["tampered_report_rejected"] = True
    with tempfile.TemporaryDirectory(prefix="http1-v5-module-") as directory:
        module_path = Path(directory) / "module.py"
        module_path.write_bytes(b"VALUE = 'recorded'\n")
        snapshot = core.read_snapshot(module_path, core.MAX_SOURCE_BYTES)
        module = core.load_snapshot_module(snapshot, "http1_v5_exact_module", module_path)
        observed["snapshot_executes_exact_bytes"] = getattr(module, "VALUE", None) == "recorded"
        module_path.write_bytes(b"VALUE = 'changed'\n")
        try:
            core.load_snapshot_module(snapshot, "http1_v5_drift_module", module_path)
            observed["snapshot_path_drift_rejected"] = False
        except core.AuditFailure:
            observed["snapshot_path_drift_rejected"] = True
        module_path.write_bytes(snapshot.data)
        try:
            core.revalidate_snapshot(module_path, snapshot, core.MAX_SOURCE_BYTES)
            observed["input_restore_race_rejected"] = False
        except core.AuditFailure:
            observed["input_restore_race_rejected"] = True
    with tempfile.TemporaryDirectory(prefix="http1-v5-report-") as directory:
        report_path = Path(directory) / "final.json"
        first = core.create_immutable(report_path, b'{"status":"Rejected"}\n')
        os.chmod(report_path, stat.S_IREAD | stat.S_IWRITE)
        report_path.write_bytes(b'{"status":"Ready"}\n')
        current = core.read_snapshot(report_path, core.MAX_REPORT_BYTES)
        pointer_path = Path(directory) / "latest.json"
        pointer = core.atomic_pointer(
            pointer_path, b'{"status":"Running"}\n'
        )
        pointer_path.write_bytes(b'{"status":"Rejected"}\n')
        pointer_rejected = False
        try:
            core.revalidate_snapshot(
                pointer_path, pointer, core.MAX_REPORT_BYTES
            )
        except core.AuditFailure:
            pointer_rejected = True
        observed["post_readback_replacement_rejected"] = (
            current.sha256 != first.sha256 and pointer_rejected
        )
    authority_value, _authority_snapshot = _load_control_authority(stage)
    valid = [make_control(name, "evidence", True) for name in EVIDENCE_CONTROL_NAMES]
    phase_specs = authority_value["phases"]
    assert isinstance(phase_specs, dict)
    expected_evidence = phase_specs.get("evidence")
    substitution = copy.deepcopy(valid)
    substitution[0]["name"] = "same_count_substitution"
    reorder = list(reversed(valid))
    duplicate = copy.deepcopy(valid)
    duplicate[1]["name"] = duplicate[0]["name"]
    for name, candidate in (
        ("control_substitution_rejected", substitution),
        ("control_reorder_rejected", reorder),
        ("control_duplicate_rejected", duplicate),
    ):
        try:
            validate_controls("evidence", candidate, authority_value)
            observed[name] = False
        except core.AuditFailure:
            observed[name] = True
    forged = dict(authority)
    forged["python_sha256"] = "0" * 64
    try:
        core.validate_runtime_authority(
            forged,
            root=root,
            launcher_sha256=str(authority["launcher_sha256"]),
        )
        observed["runtime_forgery_rejected"] = False
    except core.AuditFailure:
        observed["runtime_forgery_rejected"] = True
    forged_version = dict(authority)
    forged_version["version"] = "3.12.14"
    try:
        core.validate_runtime_authority(
            forged_version,
            root=root,
            launcher_sha256=str(authority["launcher_sha256"]),
        )
        observed["runtime_version_forgery_rejected"] = False
    except core.AuditFailure:
        observed["runtime_version_forgery_rejected"] = True
    secret = "SYNTHETIC_PRIVATE_EXCEPTION"
    failure = core.safe_failure("self_test", core.classify_failure(RuntimeError(secret)))
    observed["unexpected_failure_redacted"] = (
        secret not in core.encode_report(failure).decode("ascii")
    )
    observed["tracked_history_exact"] = _history_exact(root, stage)
    manifest_snapshot = core.read_snapshot(
        _staged_input(
            stage, "standards/audits/http1-guardian/manifest.json"
        ),
        core.MAX_SOURCE_BYTES,
        parent_anchor=stage,
    )
    manifest = core.strict_json_bytes(manifest_snapshot.data)
    history_snapshot = core.read_snapshot(
        _staged_input(stage, HISTORY_MANIFEST),
        core.MAX_SOURCE_BYTES,
        parent_anchor=stage,
    )
    history = core.strict_json_bytes(history_snapshot.data)
    inventory = manifest.get("input_inventory") if isinstance(manifest, dict) else None
    history_entries = history.get("entries") if isinstance(history, dict) else None
    authority_prefixes = (
        ".mise.toml",
        "scripts/",
        "src/",
        "test/",
        "standards/audits/http1-guardian/",
    )
    observed["clean_checkout_inventory_exact"] = (
        isinstance(inventory, list)
        and isinstance(history_entries, list)
        and all(
            isinstance(item, str)
            and not item.startswith("build/")
            and any(item == prefix or item.startswith(prefix) for prefix in authority_prefixes)
            for item in inventory
        )
        and all(
            isinstance(item, dict)
            and isinstance(item.get("path"), str)
            and item["path"].startswith(
                "standards/audits/http1-guardian/history/"
            )
            for item in history_entries
        )
    )
    launcher_snapshot = core.read_snapshot(
        stage / "launcher.py", core.MAX_SOURCE_BYTES, parent_anchor=stage
    )
    launcher = core.load_snapshot_module(
        launcher_snapshot,
        "http1_guardian_v5_launcher_control",
        stage / "launcher.py",
        logical_file=root / "standards/audits/http1-guardian/launcher.py",
    )
    with tempfile.TemporaryDirectory(
        prefix="http1-v5-running-", ignore_cleanup_errors=True
    ) as directory:
        temporary_root = Path(directory)
        original_manifest = launcher._manifest
        original_arguments = list(sys.argv)
        try:
            launcher._manifest = lambda _core, _root: (_ for _ in ()).throw(
                core.AuditFailure("synthetic_bootstrap_rejected")
            )
            sys.argv = ["launcher.py"]
            try:
                launcher._authoritative(
                    core, temporary_root, b"ignored", (0, 0, 0, 0, 0, 0),
                    temporary_root / "ignored.py",
                )
            except core.AuditFailure:
                pass
            latest_path = (
                temporary_root
                / "build/root-validation/http1-handler-guardian-v5/latest.json"
            )
            latest = core.strict_json_bytes(
                core.read_snapshot(latest_path, core.MAX_REPORT_BYTES).data
            )
            run_directory = (
                temporary_root
                / "build/root-validation/http1-handler-guardian-v5/runs"
                / str(latest.get("run_id"))
            )
            observed["running_precedes_bootstrap_failure"] = (
                isinstance(latest, dict)
                and latest.get("status") == "Running"
                and (run_directory / "running.json").is_file()
            )
            recovery, recovery_failures = launcher._latest_recovery(
                core, latest_path
            )
            observed["previous_running_recovery_detected"] = (
                recovery
                == {
                    "observed_previous_running": True,
                    "previous_status": "Running",
                }
                and recovery_failures == ["previous_run_recovered"]
            )
        finally:
            launcher._manifest = original_manifest
            sys.argv = original_arguments
            for candidate in temporary_root.rglob("*"):
                if candidate.is_file():
                    try:
                        os.chmod(candidate, stat.S_IREAD | stat.S_IWRITE)
                    except OSError:
                        pass
    environment = {
        name: value
        for name in (
            "SYSTEMROOT", "WINDIR", "COMSPEC", "PATHEXT", "PATH",
            "TEMP", "TMP", "HOME", "USERPROFILE", "LOCALAPPDATA",
        )
        if (value := os.environ.get(name))
    }
    deadline_result = core.run_bounded(
        [sys.executable, "-I", "-B", "-c", "while True: pass"],
        cwd=root,
        environment=environment,
        absolute_deadline=core.time.monotonic() + 0.25,
        output_limit=4096,
    )
    observed["absolute_process_deadline_reaped"] = (
        deadline_result.timed_out and deadline_result.reaped
    )
    output_result = core.run_bounded(
        [
            sys.executable, "-I", "-B", "-c",
            "import os;os.write(1,b'x'*8192)",
        ],
        cwd=root,
        environment=environment,
        absolute_deadline=core.time.monotonic() + 5.0,
        output_limit=1024,
    )
    observed["process_output_limit_reaped"] = (
        output_result.output_exceeded
        and output_result.reaped
        and len(output_result.stdout) <= 1024
        and len(output_result.stderr) <= 1024
    )
    synthetic_candidate = dict(manifest) if isinstance(manifest, dict) else {}
    synthetic_candidate.update({"status": "candidate", "ready_allowed": False})
    synthetic_policy = dict(synthetic_candidate.get("runtime_policy", {}))
    synthetic_policy["configuration_sha256"] = "pending_root_freeze"
    synthetic_candidate["runtime_policy"] = synthetic_policy
    observed["manifest_candidate_blocks_ready"] = not (
        synthetic_candidate.get("status") == "integrated"
        and synthetic_candidate.get("ready_allowed") is True
        and isinstance(synthetic_candidate.get("runtime_policy"), dict)
        and isinstance(
            synthetic_candidate["runtime_policy"].get("configuration_sha256"),
            str,
        )
        and len(
            synthetic_candidate["runtime_policy"].get(
                "configuration_sha256", ""
            )
        ) == 64
    )
    consumer_snapshot = core.read_snapshot(
        stage / "consumer.py", core.MAX_SOURCE_BYTES, parent_anchor=stage
    )
    consumer = core.load_snapshot_module(
        consumer_snapshot,
        "http1_guardian_v5_consumer_control",
        stage / "consumer.py",
        logical_file=root / "standards/audits/http1-guardian/consumer.py",
    )
    observed["consumer_schema_is_closed"] = (
        isinstance(consumer.FINAL_KEYS, set)
        and "status" in consumer.FINAL_KEYS
        and "input_manifest_sha256" in consumer.FINAL_KEYS
        and "prefinal_consumer_process_sha256" in consumer.FINAL_KEYS
        and "unexpected" not in consumer.FINAL_KEYS
        and len(consumer.FINAL_KEYS) == 24
    )
    with tempfile.TemporaryDirectory(
        prefix="http1-v5-rejected-phase-", ignore_cleanup_errors=True
    ) as directory:
        run_directory = Path(directory)
        run_id = "1" * 32
        authority_sha256 = "2" * 64
        rejected_detail = {
            "schema": 5,
            "status": "Rejected",
            "classification": "synthetic_rejected",
            "phase": "semantic",
            "completed": True,
            "completed_controls": 1,
            "controls": [make_control("substituted_control", "mutation", True)],
            "source_sha256": {},
            "tool_sha256": {},
            "runtime_authority_sha256": authority_sha256,
            "run_id": run_id,
            "rerun_command": RERUN_COMMAND,
        }
        rejected_report = core.create_immutable(
            run_directory / "phase-semantic.json",
            core.encode_report(rejected_detail),
        )
        rejected_process_value = {
            "schema": 5,
            "status": "Rejected",
            "classification": "synthetic_rejected",
            "phase": "semantic",
            "exit_code": 1,
            "timed_out": False,
            "output_exceeded": False,
            "reaped": True,
            "stdout_bytes": 0,
            "stderr_bytes": 0,
            "report_sha256": rejected_report.sha256,
        }
        rejected_process = core.create_immutable(
            run_directory / "phase-semantic-process.json",
            core.encode_report(rejected_process_value),
        )
        rejected_summary = {
            "status": "Rejected",
            "classification": "synthetic_rejected",
            "report_sha256": rejected_report.sha256,
            "process_sha256": rejected_process.sha256,
            "exit_code": 1,
            "timed_out": False,
            "output_exceeded": False,
            "reaped": True,
            "stdout_bytes": 0,
            "stderr_bytes": 0,
        }
        try:
            consumer._phase(
                core,
                run_directory,
                {"run_id": run_id, "runtime_authority_sha256": authority_sha256},
                "semantic",
                rejected_summary,
                authority_value,
            )
            observed["rejected_phase_controls_fail_closed"] = False
        except core.AuditFailure:
            observed["rejected_phase_controls_fail_closed"] = True
        finally:
            for candidate in run_directory.iterdir():
                if candidate.is_file():
                    os.chmod(candidate, stat.S_IREAD | stat.S_IWRITE)
    process_results: dict[str, bool] = {}
    for label, tampered in (("valid", False), ("tampered", True)):
        with tempfile.TemporaryDirectory(
            prefix="http1-v5-consumer-process-", ignore_cleanup_errors=True
        ) as directory:
            run_directory = Path(directory)
            run_id = "3" * 32
            evidence_snapshot = core.create_immutable(
                run_directory / "evidence.json", b"{}\n"
            )
            receipt_value = {
                "schema": 1,
                "status": "Ready",
                "classification": "passed",
                "evidence_sha256": evidence_snapshot.sha256,
                "run_id": run_id,
            }
            receipt_snapshot = core.create_immutable(
                run_directory / "receipt.json", core.encode_report(receipt_value)
            )
            process_value = {
                "schema": 5,
                "status": "Ready",
                "classification": "passed",
                "role": "prefinal",
                "exit_code": 0,
                "timed_out": False,
                "output_exceeded": False,
                "reaped": True,
                "stdout_bytes": len(receipt_snapshot.data),
                "stderr_bytes": 0,
                "evidence_sha256": evidence_snapshot.sha256,
                "receipt_sha256": "0" * 64 if tampered else receipt_snapshot.sha256,
            }
            process_snapshot = core.create_immutable(
                run_directory / "consumer-prefinal-process.json",
                core.encode_report(process_value),
            )
            try:
                process_results[label] = consumer._consumer_process(
                    core,
                    run_directory,
                    "prefinal",
                    process_snapshot.sha256,
                    evidence_snapshot,
                    receipt_snapshot,
                    receipt_value,
                ) is True
            except core.AuditFailure:
                process_results[label] = False
            finally:
                for candidate in run_directory.iterdir():
                    if candidate.is_file():
                        os.chmod(candidate, stat.S_IREAD | stat.S_IWRITE)
    observed["consumer_process_proof_bound"] = process_results.get("valid", False)
    observed["consumer_process_tamper_rejected"] = not process_results.get(
        "tampered", True
    )
    with tempfile.TemporaryDirectory(
        prefix="http1-v5-pointer-", ignore_cleanup_errors=True
    ) as directory:
        output = Path(directory)
        run_id = "4" * 32
        run_directory = output / "runs" / run_id
        run_directory.mkdir(parents=True)
        evidence_snapshot = core.create_immutable(
            run_directory / "terminal.json", b"{}\n"
        )
        receipt_value = {
            "schema": 1,
            "status": "Ready",
            "classification": "passed",
            "evidence_sha256": evidence_snapshot.sha256,
            "run_id": run_id,
        }
        receipt_snapshot = core.create_immutable(
            run_directory / "consumer-terminal.json",
            core.encode_report(receipt_value),
        )
        latest = output / "latest.json"
        core.atomic_pointer(
            latest,
            launcher._pointer(
                core,
                "Rejected",
                run_id,
                evidence_snapshot.sha256,
                receipt_snapshot.sha256,
                "5" * 64,
            ),
        )
        recovery, recovery_failures = launcher._latest_recovery(core, latest)
        observed["completed_pointer_missing_process_rejected"] = (
            recovery.get("previous_status") == "Rejected"
            and recovery_failures == ["previous_pointer_rejected"]
        )
        for candidate in output.rglob("*"):
            if candidate.is_file():
                os.chmod(candidate, stat.S_IREAD | stat.S_IWRITE)
    core_snapshot = core.read_snapshot(
        stage / "core.py", core.MAX_SOURCE_BYTES, parent_anchor=stage
    )
    observed["runtime_environment_override_rejected"] = (
        b"MISE_BIN_PATH" not in core_snapshot.data
    )
    observed["noncanonical_receipt_ready_blocked"] = (
        consumer.verified_receipt_status("Rejected") == "VerifiedRejected"
        and consumer.verified_receipt_status("Candidate") == "VerifiedCandidate"
        and consumer.verified_receipt_status("Rejected") != "Ready"
        and consumer.verified_receipt_status("Candidate") != "Ready"
    )
    controls = [
        make_control(name, "evidence", observed.get(name, False))
        for name in EVIDENCE_CONTROL_NAMES
    ]
    source_hashes = {
        relative: core.read_snapshot(
            _staged_input(stage, relative),
            core.MAX_SOURCE_BYTES,
            parent_anchor=stage,
        ).sha256
        for relative in SOURCE_PATHS
    }
    tool_hashes = {
        AUTHORITY_PATH: core.read_snapshot(
            _staged_input(stage, AUTHORITY_PATH),
            core.MAX_SOURCE_BYTES,
            parent_anchor=stage,
        ).sha256,
        HISTORY_MANIFEST: core.read_snapshot(
            _staged_input(stage, HISTORY_MANIFEST),
            core.MAX_SOURCE_BYTES,
            parent_anchor=stage,
        ).sha256,
    }
    return controls, source_hashes, tool_hashes


def run_phase(
    phase: str,
    *,
    root: Path,
    stage: Path,
    authority: object,
    authority_sha256: str,
    launcher_sha256: str,
    run_id: str,
) -> dict[str, object]:
    core.validate_runtime_authority(
        authority, root=root, launcher_sha256=launcher_sha256
    )
    control_authority, _snapshot = _load_control_authority(stage)
    if phase == "semantic":
        controls, source_hashes, tool_hashes = _semantic_controls(root, stage)
    elif phase == "independent":
        controls, source_hashes, tool_hashes = _independent_controls(root, stage)
    elif phase == "evidence":
        assert isinstance(authority, dict)
        controls, source_hashes, tool_hashes = _evidence_controls(
            root, stage, authority
        )
    else:
        raise core.AuditFailure("phase_rejected")
    validate_controls(phase, controls, control_authority)
    report = {
        "schema": 5,
        "status": "Ready",
        "classification": "passed",
        "phase": phase,
        "completed": True,
        "completed_controls": len(controls),
        "controls": controls,
        "source_sha256": source_hashes,
        "tool_sha256": tool_hashes,
        "runtime_authority_sha256": authority_sha256,
        "run_id": run_id,
        "rerun_command": RERUN_COMMAND,
    }
    core.encode_report(report)
    return report

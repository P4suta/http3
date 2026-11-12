#!/usr/bin/env python3
"""Independent strict consumer for immutable HTTP/1 guardian evidence."""

from __future__ import annotations

import hashlib
import os
from pathlib import Path
import re
import stat
import sys
import time
import types


FINAL_KEYS = {
    "schema", "status", "classification", "run_id", "completed_phases",
    "expected_phases", "phases", "runtime_authority",
    "runtime_authority_sha256", "input_sha256", "input_stable",
    "input_manifest_sha256", "history_manifest_sha256",
    "control_authority_sha256", "manifest_sha256", "prefinal_sha256",
    "prefinal_consumer_sha256", "prefinal_consumer_process_sha256",
    "consumer_verified", "failure_classes",
    "rerun_command", "limits", "recovery", "native_execution",
}
PHASE_SUMMARY_KEYS = {
    "status", "classification", "report_sha256", "process_sha256",
    "exit_code", "timed_out", "output_exceeded", "reaped",
    "stdout_bytes", "stderr_bytes",
}
PHASE_REPORT_KEYS = {
    "schema", "status", "classification", "phase", "completed",
    "completed_controls", "controls", "source_sha256", "tool_sha256",
    "runtime_authority_sha256", "run_id", "rerun_command",
}
PROCESS_REPORT_KEYS = {
    "schema", "status", "classification", "phase", "exit_code",
    "timed_out", "output_exceeded", "reaped", "stdout_bytes",
    "stderr_bytes", "report_sha256",
}
INPUT_MANIFEST_KEYS = {"schema", "run_id", "manifest_sha256", "entries"}
INPUT_ENTRY_KEYS = {"path", "sha256", "bytes"}
CONTROL_KEYS = {"name", "type", "expected", "observed", "passed"}
CONTROL_SPEC_KEYS = {"name", "type", "expected"}
MANIFEST_KEYS = {
    "schema", "audit", "status", "ready_allowed", "canonical_command",
    "phase_order", "phase_control_counts", "input_inventory",
    "executable_roles", "control_authority", "history_manifest",
    "history_chain", "runtime_policy", "limits", "integration",
}
RECEIPT_KEYS = {
    "schema", "status", "classification", "evidence_sha256", "run_id",
}
CONSUMER_PROCESS_KEYS = {
    "schema", "status", "classification", "role", "exit_code",
    "timed_out", "output_exceeded", "reaped", "stdout_bytes",
    "stderr_bytes", "evidence_sha256", "receipt_sha256",
}
ZERO_SHA256 = "0" * 64


def _open_exact(path: Path, maximum: int) -> tuple[bytes, tuple[int, ...]]:
    before = os.lstat(path)
    reparse = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0)
    if (
        stat.S_ISLNK(before.st_mode)
        or (reparse and getattr(before, "st_file_attributes", 0) & reparse)
        or not stat.S_ISREG(before.st_mode)
        or before.st_nlink != 1
        or before.st_size <= 0
        or before.st_size > maximum
    ):
        raise RuntimeError("bootstrap_identity_rejected")
    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0)
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(path, flags)
    try:
        handle_before = os.fstat(descriptor)
        identity = (
            before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns,
            before.st_ctime_ns, before.st_nlink,
        )
        handle_identity = (
            handle_before.st_dev, handle_before.st_ino, handle_before.st_size,
            handle_before.st_mtime_ns, handle_before.st_nlink,
        )
        path_handle_identity = (
            before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns,
            before.st_nlink,
        )
        if handle_identity != path_handle_identity:
            raise RuntimeError("bootstrap_handle_rejected")
        chunks: list[bytes] = []
        consumed = 0
        while True:
            chunk = os.read(descriptor, min(1024 * 1024, maximum - consumed + 1))
            if not chunk:
                break
            consumed += len(chunk)
            if consumed > maximum:
                raise RuntimeError("bootstrap_size_rejected")
            chunks.append(chunk)
        handle_after = os.fstat(descriptor)
    finally:
        os.close(descriptor)
    after = os.lstat(path)
    if (
        after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns,
        after.st_ctime_ns, after.st_nlink,
    ) != identity or (
        handle_after.st_dev, handle_after.st_ino, handle_after.st_size,
        handle_after.st_mtime_ns, handle_after.st_nlink,
    ) != path_handle_identity:
        raise RuntimeError("bootstrap_changed")
    data = b"".join(chunks)
    if len(data) != before.st_size:
        raise RuntimeError("bootstrap_partial_read")
    return data, identity


def _bootstrap_core() -> object:
    stage_text = os.environ.get("HTTP1_GUARDIAN_STAGE")
    root_text = os.environ.get("HTTP1_GUARDIAN_ROOT")
    path = (
        Path(stage_text) / "core.py"
        if stage_text
        else Path(__file__).absolute().with_name("v5_core.py")
    )
    logical = (
        Path(root_text) / "standards/audits/http1-guardian/v5_core.py"
        if stage_text and root_text else path
    )
    data, identity = _open_exact(path, 4 * 1024 * 1024)
    module = types.ModuleType("http1_guardian_v5_core")
    module.__file__ = str(logical)
    sys.modules[module.__name__] = module
    code = compile(
        data,
        "<tracked:v5_core:" + hashlib.sha256(data).hexdigest()[:16] + ">",
        "exec",
        dont_inherit=True,
    )
    exec(code, module.__dict__, module.__dict__)
    module.revalidate_snapshot(
        path,
        module.Snapshot(data, hashlib.sha256(data).hexdigest(), identity),
        module.MAX_SOURCE_BYTES,
    )
    return module


def _sha256(value: object) -> bool:
    return (
        isinstance(value, str)
        and len(value) == 64
        and all(character in "0123456789abcdef" for character in value)
    )


def verified_receipt_status(evidence_status: object) -> str:
    result = {
        "Ready": "Ready",
        "Rejected": "VerifiedRejected",
        "Candidate": "VerifiedCandidate",
    }.get(evidence_status)
    if result is None:
        raise RuntimeError("evidence_status_rejected")
    return result


def _relative(value: object) -> bool:
    if not isinstance(value, str) or not value or "\\" in value:
        return False
    path = Path(value)
    return not path.is_absolute() and ".." not in path.parts and ":" not in value


def _manifest(core: object, run_directory: Path) -> tuple[dict[str, object], object]:
    path = run_directory / "stage/inputs/standards/audits/http1-guardian/manifest.json"
    snapshot = core.read_snapshot(path, core.MAX_SOURCE_BYTES, parent_anchor=run_directory)
    value = core.exact_keys(
        core.strict_json_bytes(snapshot.data), MANIFEST_KEYS,
        "manifest_schema_rejected",
    )
    counts = value.get("phase_control_counts")
    inventory = value.get("input_inventory")
    roles = value.get("executable_roles")
    runtime_policy = value.get("runtime_policy")
    limits = value.get("limits")
    integration = value.get("integration")
    if (
        value.get("schema") != 5
        or value.get("audit") != "http1_handler_guardian"
        or value.get("status") not in ("candidate", "integrated")
        or not isinstance(value.get("ready_allowed"), bool)
        or value.get("canonical_command") != "mise run http1-guardian-audit"
        or value.get("phase_order") != ["semantic", "independent", "evidence"]
        or counts != {"semantic": 71, "independent": 12, "evidence": 35}
        or not isinstance(inventory, list)
        or len(inventory) != len(set(inventory))
        or not all(_relative(item) for item in inventory)
        or not isinstance(roles, dict)
        or set(roles) != {"launcher", "core", "gate", "consumer", "guardian", "scanner"}
        or not all(_relative(item) and item in inventory for item in roles.values())
        or value.get("control_authority")
        != "standards/audits/http1-guardian/control-authority.json"
        or value.get("history_manifest")
        != "standards/audits/http1-guardian/history/manifest.json"
        or value.get("history_chain")
        != [
            "v2:Rejected", "v3:Rejected", "v4:Rejected",
            "v5:Red", "v5:candidate",
        ]
        or not isinstance(runtime_policy, dict)
        or set(runtime_policy) != {
            "implementation", "version", "mise_request", "configuration",
            "configuration_sha256",
        }
        or runtime_policy.get("implementation") != "cpython"
        or runtime_policy.get("version") != "3.12.13"
        or runtime_policy.get("mise_request") != "python@3.12.13"
        or runtime_policy.get("configuration") != ".mise.toml"
        or not isinstance(limits, dict)
        or set(limits) != {
            "overall_milliseconds", "phase_milliseconds",
            "cleanup_milliseconds", "input_bytes", "tool_bytes",
            "report_bytes", "process_output_bytes",
        }
        or any(not isinstance(item, int) or item <= 0 for item in limits.values())
        or not isinstance(integration, dict)
        or set(integration) != {"mise_task", "ci_job", "always_upload"}
        or any(item not in ("staged", "integrated") for item in integration.values())
    ):
        raise core.AuditFailure("manifest_contract_rejected")
    return value, snapshot


def _expanded_inventory(core: object, run_directory: Path, manifest: dict[str, object]) -> list[str]:
    base = manifest["input_inventory"]
    if not isinstance(base, list) or not all(_relative(item) for item in base):
        raise core.AuditFailure("input_inventory_rejected")
    history_name = manifest.get("history_manifest")
    if not _relative(history_name) or history_name not in base:
        raise core.AuditFailure("history_inventory_rejected")
    history_snapshot = core.read_snapshot(
        run_directory / "stage/inputs" / str(history_name),
        core.MAX_SOURCE_BYTES,
        parent_anchor=run_directory,
    )
    history = core.exact_keys(
        core.strict_json_bytes(history_snapshot.data),
        {"schema", "status", "entries", "chain"},
        "history_manifest_schema_rejected",
    )
    entries = history.get("entries")
    if (
        history.get("schema") != 1
        or history.get("status") != "Rejected_history"
        or history.get("chain") != manifest.get("history_chain")
        or not isinstance(entries, list)
    ):
        raise core.AuditFailure("history_manifest_rejected")
    expanded = list(base)
    for raw in entries:
        entry = core.exact_keys(
            raw, {"path", "sha256", "bytes"}, "history_entry_schema_rejected"
        )
        relative = entry.get("path")
        if not _relative(relative) or not _sha256(entry.get("sha256")):
            raise core.AuditFailure("history_entry_rejected")
        staged = core.read_snapshot(
            run_directory / "stage/inputs" / str(relative),
            core.MAX_SOURCE_BYTES,
            parent_anchor=run_directory,
        )
        if (
            staged.sha256 != entry.get("sha256")
            or len(staged.data) != entry.get("bytes")
        ):
            raise core.AuditFailure("history_entry_digest_rejected")
        expanded.append(str(relative))
    if len(expanded) != len(set(expanded)):
        raise core.AuditFailure("input_inventory_duplicate")
    return expanded


def _input_manifest(
    core: object,
    run_directory: Path,
    report: dict[str, object],
    manifest: dict[str, object],
) -> tuple[dict[str, object], object]:
    snapshot = core.read_snapshot(
        run_directory / "input-manifest.json",
        core.MAX_REPORT_BYTES,
        parent_anchor=run_directory,
    )
    if snapshot.sha256 != report.get("input_manifest_sha256"):
        raise core.AuditFailure("input_manifest_digest_rejected")
    value = core.exact_keys(
        core.strict_json_bytes(snapshot.data), INPUT_MANIFEST_KEYS,
        "input_manifest_schema_rejected",
    )
    entries = value.get("entries")
    expected = _expanded_inventory(core, run_directory, manifest)
    if (
        value.get("schema") != 5
        or value.get("run_id") != report.get("run_id")
        or value.get("manifest_sha256") != report.get("manifest_sha256")
        or not isinstance(entries, list)
        or len(entries) != len(expected)
    ):
        raise core.AuditFailure("input_manifest_contract_rejected")
    report_hashes = report.get("input_sha256")
    if not isinstance(report_hashes, dict) or set(report_hashes) != set(expected):
        raise core.AuditFailure("input_hash_inventory_rejected")
    for relative, raw in zip(expected, entries, strict=True):
        entry = core.exact_keys(
            raw, INPUT_ENTRY_KEYS, "input_entry_schema_rejected"
        )
        staged = core.read_snapshot(
            run_directory / "stage/inputs" / relative,
            core.MAX_SOURCE_BYTES,
            parent_anchor=run_directory,
        )
        if (
            entry.get("path") != relative
            or entry.get("sha256") != staged.sha256
            or entry.get("bytes") != len(staged.data)
            or report_hashes.get(relative) != staged.sha256
        ):
            raise core.AuditFailure("input_entry_mismatch")
    return value, snapshot


def _control_authority(
    core: object, run_directory: Path, manifest: dict[str, object]
) -> dict[str, object]:
    snapshot = core.read_snapshot(
        run_directory / "stage/inputs/standards/audits/http1-guardian/control-authority.json",
        core.MAX_SOURCE_BYTES,
        parent_anchor=run_directory,
    )
    value = core.exact_keys(
        core.strict_json_bytes(snapshot.data), {"schema", "phases"},
        "control_authority_schema_rejected",
    )
    phases = value.get("phases")
    counts = manifest.get("phase_control_counts")
    if (
        value.get("schema") != 5
        or not isinstance(phases, dict)
        or set(phases) != set(manifest.get("phase_order", []))
        or not isinstance(counts, dict)
    ):
        raise core.AuditFailure("control_authority_rejected")
    for phase in manifest["phase_order"]:
        specifications = phases.get(phase)
        if not isinstance(specifications, list) or len(specifications) != counts.get(phase):
            raise core.AuditFailure("control_authority_count_rejected")
        names: list[str] = []
        for raw in specifications:
            specification = core.exact_keys(
                raw, CONTROL_SPEC_KEYS, "control_specification_rejected"
            )
            if (
                not isinstance(specification.get("name"), str)
                or not isinstance(specification.get("type"), str)
                or specification.get("expected") is not True
            ):
                raise core.AuditFailure("control_specification_rejected")
            names.append(str(specification["name"]))
        if len(names) != len(set(names)):
            raise core.AuditFailure("control_authority_duplicate")
    return value


def _phase(
    core: object,
    run_directory: Path,
    run_report: dict[str, object],
    phase: str,
    summary: object,
    authority: dict[str, object],
) -> None:
    item = core.exact_keys(
        summary, PHASE_SUMMARY_KEYS, "phase_summary_schema_rejected"
    )
    report_snapshot = core.read_snapshot(
        run_directory / ("phase-" + phase + ".json"),
        core.MAX_REPORT_BYTES,
        parent_anchor=run_directory,
    )
    process_snapshot = core.read_snapshot(
        run_directory / ("phase-" + phase + "-process.json"),
        core.MAX_REPORT_BYTES,
        parent_anchor=run_directory,
    )
    if (
        item.get("report_sha256") != report_snapshot.sha256
        or item.get("process_sha256") != process_snapshot.sha256
    ):
        raise core.AuditFailure("phase_digest_rejected")
    detail = core.exact_keys(
        core.strict_json_bytes(report_snapshot.data), PHASE_REPORT_KEYS,
        "phase_report_schema_rejected",
    )
    process = core.exact_keys(
        core.strict_json_bytes(process_snapshot.data), PROCESS_REPORT_KEYS,
        "process_report_schema_rejected",
    )
    scalar_match = (
        detail.get("schema") == 5
        and detail.get("phase") == phase
        and detail.get("run_id") == run_report.get("run_id")
        and detail.get("rerun_command") == "mise run http1-guardian-audit"
        and detail.get("runtime_authority_sha256")
        == run_report.get("runtime_authority_sha256")
        and process.get("schema") == 5
        and process.get("phase") == phase
        and process.get("report_sha256") == report_snapshot.sha256
        and process.get("status") == item.get("status")
        and process.get("classification") == item.get("classification")
        and process.get("exit_code") == item.get("exit_code")
        and process.get("timed_out") == item.get("timed_out")
        and process.get("output_exceeded") == item.get("output_exceeded")
        and process.get("reaped") == item.get("reaped")
        and process.get("stdout_bytes") == item.get("stdout_bytes")
        and process.get("stderr_bytes") == item.get("stderr_bytes")
    )
    if not scalar_match or not core.evidence_is_secret_safe(detail) or not core.evidence_is_secret_safe(process):
        raise core.AuditFailure("phase_binding_rejected")
    controls = detail.get("controls")
    phases = authority.get("phases")
    specs = phases.get(phase) if isinstance(phases, dict) else None
    if not isinstance(controls, list) or not isinstance(specs, list):
        raise core.AuditFailure("phase_controls_rejected")
    if detail.get("status") == "Ready":
        if (
            item.get("status") != "Ready"
            or detail.get("classification") != "passed"
            or detail.get("completed") is not True
            or detail.get("completed_controls") != len(specs)
            or len(controls) != len(specs)
        ):
            raise core.AuditFailure("ready_phase_rejected")
        names: list[str] = []
        for specification, control in zip(specs, controls, strict=True):
            expected = core.exact_keys(
                specification, CONTROL_SPEC_KEYS, "control_specification_rejected"
            )
            observed = core.exact_keys(
                control, CONTROL_KEYS, "control_record_rejected"
            )
            if (
                observed.get("name") != expected.get("name")
                or observed.get("type") != expected.get("type")
                or expected.get("expected") is not True
                or observed.get("expected") is not True
                or observed.get("observed") is not True
                or observed.get("passed") is not True
            ):
                raise core.AuditFailure("control_record_mismatch")
            names.append(str(observed["name"]))
        if len(names) != len(set(names)):
            raise core.AuditFailure("control_duplicate_rejected")
    elif (
        detail.get("status") != "Rejected"
        or item.get("status") != "Rejected"
        or detail.get("completed") is not True
        or detail.get("completed_controls") != 0
        or controls != []
        or detail.get("source_sha256") != {}
        or detail.get("tool_sha256") != {}
        or not isinstance(detail.get("classification"), str)
        or not detail["classification"].replace("_", "a").isalnum()
        or not detail["classification"][0].islower()
        or len(detail["classification"]) > 80
    ):
        raise core.AuditFailure("rejected_phase_rejected")


def _runtime(
    core: object,
    report: dict[str, object],
    manifest: dict[str, object],
    root: Path,
) -> bool:
    authority = report.get("runtime_authority")
    try:
        value = core.exact_keys(
            authority, core.RUNTIME_AUTHORITY_KEYS,
            "runtime_authority_schema_rejected",
        )
    except core.AuditFailure:
        return False
    payload = core.encode_report(value)
    if hashlib.sha256(payload).hexdigest() != report.get("runtime_authority_sha256"):
        raise core.AuditFailure("runtime_authority_digest_rejected")
    launcher_hashes = report.get("input_sha256")
    launcher_sha = (
        launcher_hashes.get("standards/audits/http1-guardian/launcher.py")
        if isinstance(launcher_hashes, dict) else None
    )
    policy = manifest.get("runtime_policy")
    if not isinstance(policy, dict) or not _sha256(launcher_sha):
        return False
    if (
        value.get("implementation") != policy.get("implementation")
        or value.get("version") != policy.get("version")
        or value.get("tool_request") != policy.get("mise_request")
        or value.get("config_sha256") != report.get("input_sha256", {}).get(".mise.toml")
        or value.get("launcher_sha256") != launcher_sha
        or value.get("resolved") is not True
    ):
        return False
    try:
        core.validate_runtime_authority(value, root=root, launcher_sha256=launcher_sha)
        observed = core.resolve_runtime_authority(
            root, launcher_sha, time.monotonic() + 30.0
        )
        return observed.authority == value
    except core.CONTROL_EXCEPTIONS:
        raise
    except BaseException:
        return False


def _consumer_process(
    core: object,
    run_directory: Path,
    role: str,
    expected_sha256: str,
    evidence_snapshot: object,
    receipt_snapshot: object,
    receipt: dict[str, object],
) -> bool:
    snapshot = core.read_snapshot(
        run_directory / ("consumer-" + role + "-process.json"),
        core.MAX_REPORT_BYTES,
        parent_anchor=run_directory,
    )
    if snapshot.sha256 != expected_sha256:
        raise core.AuditFailure("consumer_process_digest_rejected")
    value = core.exact_keys(
        core.strict_json_bytes(snapshot.data), CONSUMER_PROCESS_KEYS,
        "consumer_process_schema_rejected",
    )
    if (
        value.get("schema") != 5
        or value.get("status") != receipt.get("status")
        or value.get("classification") != receipt.get("classification")
        or value.get("role") != role
        or value.get("evidence_sha256") != evidence_snapshot.sha256
        or value.get("receipt_sha256") != receipt_snapshot.sha256
        or not isinstance(value.get("exit_code"), int)
        or not isinstance(value.get("timed_out"), bool)
        or not isinstance(value.get("output_exceeded"), bool)
        or not isinstance(value.get("reaped"), bool)
        or not isinstance(value.get("stdout_bytes"), int)
        or not 0 <= value["stdout_bytes"] <= core.MAX_PROCESS_OUTPUT_BYTES
        or not isinstance(value.get("stderr_bytes"), int)
        or not 0 <= value["stderr_bytes"] <= core.MAX_PROCESS_OUTPUT_BYTES
        or not core.evidence_is_secret_safe(value)
    ):
        raise core.AuditFailure("consumer_process_binding_rejected")
    if receipt.get("status") in (
        "Ready", "VerifiedRejected", "VerifiedCandidate"
    ):
        return bool(
            receipt.get("classification") == "passed"
            and value.get("exit_code") == 0
            and value.get("timed_out") is False
            and value.get("output_exceeded") is False
            and value.get("reaped") is True
            and value.get("stdout_bytes") == len(receipt_snapshot.data)
            and value.get("stderr_bytes") == 0
        )
    expected_classification = (
        "consumer_deadline_expired" if value.get("timed_out") is True
        else "consumer_output_limit_exceeded"
        if value.get("output_exceeded") is True
        else "consumer_process_unreaped"
        if value.get("reaped") is False
        else "consumer_runtime_rejected"
        if value.get("exit_code") == -1
        else "consumer_report_rejected"
    )
    if receipt.get("classification") != expected_classification:
        raise core.AuditFailure("consumer_process_classification_rejected")
    return False


def validate_evidence(
    core: object,
    evidence_path: Path,
    expected_sha256: str,
    expected_status: str,
    root: Path,
) -> tuple[dict[str, object], object]:
    snapshot = core.read_snapshot(evidence_path, core.MAX_REPORT_BYTES)
    if snapshot.sha256 != expected_sha256:
        raise core.AuditFailure("evidence_digest_rejected")
    report = core.exact_keys(
        core.strict_json_bytes(snapshot.data), FINAL_KEYS,
        "evidence_schema_rejected",
    )
    run_id = report.get("run_id")
    run_directory = evidence_path.parent
    if (
        report.get("schema") != 5
        or report.get("status") != expected_status
        or expected_status not in ("Ready", "Rejected", "Candidate")
        or not isinstance(run_id, str)
        or len(run_id) != 32
        or any(character not in "0123456789abcdef" for character in run_id)
        or report.get("expected_phases") != 3
        or report.get("completed_phases") != 3
        or report.get("rerun_command") != "mise run http1-guardian-audit"
        or report.get("native_execution") != "not_invoked"
        or not isinstance(report.get("input_sha256"), dict)
        or not isinstance(report.get("input_stable"), bool)
        or not isinstance(report.get("failure_classes"), list)
        or not isinstance(report.get("recovery"), dict)
        or not isinstance(report.get("limits"), dict)
        or not _sha256(report.get("manifest_sha256"))
        or not _sha256(report.get("control_authority_sha256"))
        or not _sha256(report.get("history_manifest_sha256"))
        or not _sha256(report.get("input_manifest_sha256"))
    ):
        raise core.AuditFailure("evidence_contract_rejected")
    manifest, manifest_snapshot = _manifest(core, run_directory)
    if manifest_snapshot.sha256 != report.get("manifest_sha256"):
        raise core.AuditFailure("manifest_digest_rejected")
    _input_manifest(core, run_directory, report, manifest)
    hashes = report["input_sha256"]
    if (
        hashes.get(str(manifest.get("control_authority")))
        != report.get("control_authority_sha256")
        or hashes.get(str(manifest.get("history_manifest")))
        != report.get("history_manifest_sha256")
        or report.get("limits") != manifest.get("limits")
    ):
        raise core.AuditFailure("authority_binding_rejected")
    phases = report.get("phases")
    order = manifest.get("phase_order")
    if not isinstance(phases, dict) or not isinstance(order, list) or set(phases) != set(order):
        raise core.AuditFailure("phase_evidence_rejected")
    authority = _control_authority(core, run_directory, manifest)
    for phase in order:
        _phase(core, run_directory, report, str(phase), phases.get(str(phase)), authority)
    failures = report.get("failure_classes")
    if (
        not all(
            isinstance(item, str)
            and re.fullmatch(r"[a-z][a-z0-9_]{0,79}", item) is not None
            for item in failures
        )
        or failures != sorted(set(failures))
        or set(report.get("recovery", {}))
        != {"observed_previous_running", "previous_status"}
        or not isinstance(report["recovery"].get("observed_previous_running"), bool)
        or report["recovery"].get("previous_status")
        not in ("none", "Running", "Ready", "Rejected")
        or not core.evidence_is_secret_safe(report)
    ):
        raise core.AuditFailure("evidence_values_rejected")
    runtime_ready = _runtime(core, report, manifest, root)
    if expected_status == "Ready":
        policy = manifest.get("runtime_policy")
        config_hash = policy.get("configuration_sha256") if isinstance(policy, dict) else None
        integration = manifest.get("integration")
        if (
            manifest.get("status") != "integrated"
            or manifest.get("ready_allowed") is not True
            or not _sha256(config_hash)
            or config_hash != hashes.get(".mise.toml")
            or not isinstance(integration, dict)
            or set(integration.values()) != {"integrated"}
            or report.get("input_stable") is not True
            or report.get("consumer_verified") is not True
            or failures != []
            or any(phases[name].get("status") != "Ready" for name in order)
            or not runtime_ready
        ):
            raise core.AuditFailure("ready_predicate_rejected")
        for relative, expected in hashes.items():
            current = core.read_snapshot(root / relative, core.MAX_SOURCE_BYTES, parent_anchor=root)
            if current.sha256 != expected:
                raise core.AuditFailure("ready_input_drift_rejected")
    elif expected_status == "Candidate":
        if report.get("consumer_verified") is not False or not runtime_ready:
            raise core.AuditFailure("candidate_predicate_rejected")
    elif not failures:
        raise core.AuditFailure("rejected_failure_class_missing")
    prefinal = report.get("prefinal_sha256")
    receipt = report.get("prefinal_consumer_sha256")
    process = report.get("prefinal_consumer_process_sha256")
    if prefinal == ZERO_SHA256 and receipt == ZERO_SHA256 and process == ZERO_SHA256:
        if report.get("consumer_verified") is not False:
            raise core.AuditFailure("initial_chain_rejected")
    elif expected_status == "Candidate":
        raise core.AuditFailure("candidate_chain_rejected")
    else:
        if not _sha256(prefinal) or not _sha256(receipt) or not _sha256(process):
            raise core.AuditFailure("final_chain_rejected")
        prefinal_path = run_directory / "prefinal.json"
        prefinal_snapshot = core.read_snapshot(
            prefinal_path, core.MAX_REPORT_BYTES, parent_anchor=run_directory
        )
        receipt_snapshot = core.read_snapshot(
            run_directory / "consumer-prefinal.json",
            core.MAX_REPORT_BYTES,
            parent_anchor=run_directory,
        )
        if prefinal_snapshot.sha256 != prefinal or receipt_snapshot.sha256 != receipt:
            raise core.AuditFailure("final_chain_digest_rejected")
        prefinal_value = core.strict_json_bytes(prefinal_snapshot.data)
        if not isinstance(prefinal_value, dict) or prefinal_value.get("status") not in (
            "Candidate", "Rejected"
        ):
            raise core.AuditFailure("prefinal_status_rejected")
        validate_evidence(
            core, prefinal_path, prefinal_snapshot.sha256,
            str(prefinal_value["status"]), root,
        )
        receipt_value = core.exact_keys(
            core.strict_json_bytes(receipt_snapshot.data), RECEIPT_KEYS,
            "prefinal_receipt_schema_rejected",
        )
        expected_receipt_status = verified_receipt_status(
            prefinal_value.get("status")
        )
        receipt_ready = (
            receipt_value.get("schema") == 1
            and receipt_value.get("status") == expected_receipt_status
            and receipt_value.get("classification") == "passed"
            and receipt_value.get("evidence_sha256") == prefinal_snapshot.sha256
            and receipt_value.get("run_id") == run_id
        )
        process_ready = _consumer_process(
            core, run_directory, "prefinal", str(process),
            prefinal_snapshot, receipt_snapshot, receipt_value,
        )
        if report.get("consumer_verified") is not (
            receipt_ready and process_ready
        ):
            raise core.AuditFailure("prefinal_receipt_binding_rejected")
    core.revalidate_snapshot(evidence_path, snapshot, core.MAX_REPORT_BYTES)
    return report, snapshot


def _arguments() -> dict[str, str]:
    names = ("--evidence", "--sha256", "--status", "--root")
    if len(sys.argv) != 9:
        raise RuntimeError("arguments_rejected")
    result: dict[str, str] = {}
    for index in range(1, len(sys.argv), 2):
        key = sys.argv[index]
        if key not in names or key in result:
            raise RuntimeError("arguments_rejected")
        result[key] = sys.argv[index + 1]
    if set(result) != set(names):
        raise RuntimeError("arguments_rejected")
    return result


def main() -> int:
    core = _bootstrap_core()
    try:
        arguments = _arguments()
        report, snapshot = validate_evidence(
            core,
            Path(arguments["--evidence"]),
            arguments["--sha256"],
            arguments["--status"],
            Path(arguments["--root"]),
        )
        verified_status = verified_receipt_status(report.get("status"))
        result = {
            "schema": 1, "status": verified_status, "classification": "passed",
            "evidence_sha256": snapshot.sha256, "run_id": report["run_id"],
        }
        sys.stdout.buffer.write(core.encode_report(result))
        sys.stdout.buffer.flush()
        return 0
    except (KeyboardInterrupt, SystemExit, GeneratorExit):
        raise
    except BaseException as failure:
        result = core.safe_failure("consumer", core.classify_failure(failure))
        try:
            sys.stdout.buffer.write(core.encode_report(result))
            sys.stdout.buffer.flush()
        except BaseException:
            pass
        return 1


if __name__ == "__main__":
    raise SystemExit(main())

#!/usr/bin/env python3
"""Supervised, evidence-first launcher for the HTTP/1 guardian audit."""

from __future__ import annotations

import hashlib
import os
from pathlib import Path
import platform
import secrets
import stat
import sys
import time
import types


AUDIT_RELATIVE = Path("standards/audits/http1-guardian")
MANIFEST_RELATIVE = AUDIT_RELATIVE / "manifest.json"
HISTORY_RELATIVE = AUDIT_RELATIVE / "history/manifest.json"
OUTPUT_RELATIVE = Path("build/root-validation/http1-handler-guardian-v5")
PHASES = ("semantic", "independent", "evidence")
ZERO_SHA256 = "0" * 64
MANIFEST_KEYS = {
    "schema", "audit", "status", "ready_allowed", "canonical_command",
    "phase_order", "phase_control_counts", "input_inventory",
    "executable_roles", "control_authority", "history_manifest",
    "history_chain", "runtime_policy", "limits", "integration",
}
PHASE_REPORT_KEYS = {
    "schema", "status", "classification", "phase", "completed",
    "completed_controls", "controls", "source_sha256", "tool_sha256",
    "runtime_authority_sha256", "run_id", "rerun_command",
}
RECEIPT_KEYS = {
    "schema", "status", "classification", "evidence_sha256", "run_id",
}
CONSUMER_PROCESS_KEYS = {
    "schema", "status", "classification", "role", "exit_code",
    "timed_out", "output_exceeded", "reaped", "stdout_bytes",
    "stderr_bytes", "evidence_sha256", "receipt_sha256",
}
POINTER_KEYS = {
    "schema", "status", "run_id", "evidence_sha256", "consumer_sha256",
    "consumer_process_sha256",
}
RUNNING_KEYS = {
    "schema", "status", "classification", "run_id", "expected_phases",
    "completed_phases", "rerun_command", "native_execution",
}


def _sha256(value: object) -> bool:
    return (
        isinstance(value, str)
        and len(value) == 64
        and all(character in "0123456789abcdef" for character in value)
    )


def _verified_receipt_status(evidence_status: object) -> str:
    result = {
        "Ready": "Ready",
        "Rejected": "VerifiedRejected",
        "Candidate": "VerifiedCandidate",
    }.get(evidence_status)
    if result is None:
        raise RuntimeError("evidence_status_rejected")
    return result


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
        if (
            handle_before.st_dev, handle_before.st_ino, handle_before.st_size,
            handle_before.st_mtime_ns, handle_before.st_nlink,
        ) != (
            before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns,
            before.st_nlink,
        ):
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
    ) != (
        before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns,
        before.st_nlink,
    ):
        raise RuntimeError("bootstrap_changed")
    data = b"".join(chunks)
    if len(data) != before.st_size:
        raise RuntimeError("bootstrap_partial_read")
    return data, identity


def _root_for(source_path: Path) -> Path:
    configured = os.environ.get("HTTP1_GUARDIAN_ROOT")
    return Path(configured).absolute() if configured else source_path.absolute().parents[3]


def _bootstrap_core(root: Path) -> object:
    stage_text = os.environ.get("HTTP1_GUARDIAN_STAGE")
    path = (
        Path(stage_text) / "core.py"
        if stage_text
        else root / AUDIT_RELATIVE / "v5_core.py"
    )
    data, identity = _open_exact(path, 4 * 1024 * 1024)
    module = types.ModuleType("http1_guardian_v5_core")
    module.__file__ = str(root / AUDIT_RELATIVE / "v5_core.py")
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


def _safe_relative(value: object) -> bool:
    if not isinstance(value, str) or not value or "\\" in value or ":" in value:
        return False
    candidate = Path(value)
    return not candidate.is_absolute() and ".." not in candidate.parts


def _manifest(core: object, root: Path) -> tuple[dict[str, object], object]:
    snapshot = core.read_snapshot(
        root / MANIFEST_RELATIVE, core.MAX_SOURCE_BYTES, parent_anchor=root
    )
    manifest = core.exact_keys(
        core.strict_json_bytes(snapshot.data), MANIFEST_KEYS,
        "manifest_schema_rejected",
    )
    inventory = manifest.get("input_inventory")
    roles = manifest.get("executable_roles")
    counts = manifest.get("phase_control_counts")
    limits = manifest.get("limits")
    runtime_policy = manifest.get("runtime_policy")
    integration = manifest.get("integration")
    if (
        manifest.get("schema") != 5
        or manifest.get("audit") != "http1_handler_guardian"
        or manifest.get("status") not in ("candidate", "integrated")
        or not isinstance(manifest.get("ready_allowed"), bool)
        or manifest.get("canonical_command") != "mise run http1-guardian-audit"
        or manifest.get("phase_order") != list(PHASES)
        or not isinstance(inventory, list)
        or not inventory
        or not all(_safe_relative(item) for item in inventory)
        or len(inventory) != len(set(inventory))
        or str(MANIFEST_RELATIVE).replace("\\", "/") not in inventory
        or not isinstance(roles, dict)
        or set(roles) != {"launcher", "core", "gate", "consumer", "guardian", "scanner"}
        or not all(_safe_relative(item) and item in inventory for item in roles.values())
        or counts != {"semantic": 71, "independent": 12, "evidence": 35}
        or manifest.get("control_authority")
        != "standards/audits/http1-guardian/control-authority.json"
        or manifest.get("history_manifest")
        != "standards/audits/http1-guardian/history/manifest.json"
        or manifest.get("history_chain")
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
        or any(not isinstance(value, int) or value <= 0 for value in limits.values())
        or not isinstance(integration, dict)
        or set(integration) != {"mise_task", "ci_job", "always_upload"}
        or any(value not in ("staged", "integrated") for value in integration.values())
    ):
        raise core.AuditFailure("manifest_contract_rejected")
    return manifest, snapshot


def _history_entries(
    core: object, root: Path, manifest: dict[str, object]
) -> list[str]:
    history_name = manifest.get("history_manifest")
    inventory = manifest.get("input_inventory")
    if not _safe_relative(history_name) or history_name not in inventory:
        raise core.AuditFailure("history_inventory_rejected")
    snapshot = core.read_snapshot(
        root / str(history_name), core.MAX_SOURCE_BYTES, parent_anchor=root
    )
    history = core.exact_keys(
        core.strict_json_bytes(snapshot.data),
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
    result: list[str] = []
    for raw in entries:
        entry = core.exact_keys(
            raw, {"path", "sha256", "bytes"}, "history_entry_schema_rejected"
        )
        relative = entry.get("path")
        if not _safe_relative(relative):
            raise core.AuditFailure("history_entry_rejected")
        observed = core.read_snapshot(
            root / str(relative), core.MAX_SOURCE_BYTES, parent_anchor=root
        )
        if observed.sha256 != entry.get("sha256") or len(observed.data) != entry.get("bytes"):
            raise core.AuditFailure("history_entry_digest_rejected")
        result.append(str(relative))
    if len(result) != len(set(result)):
        raise core.AuditFailure("history_entry_duplicate")
    return result


def _snapshot_inputs(
    core: object,
    root: Path,
    manifest: dict[str, object],
    launcher_data: bytes,
    launcher_identity: tuple[int, ...],
    launcher_path: Path,
) -> tuple[list[str], dict[str, object]]:
    inventory = list(manifest["input_inventory"]) + _history_entries(core, root, manifest)
    if len(inventory) != len(set(inventory)):
        raise core.AuditFailure("expanded_inventory_duplicate")
    snapshots: dict[str, object] = {}
    for relative in inventory:
        snapshot = core.read_snapshot(
            root / relative, core.MAX_SOURCE_BYTES, parent_anchor=root
        )
        snapshots[relative] = snapshot
    launcher_relative = str(AUDIT_RELATIVE / "launcher.py").replace("\\", "/")
    executed = core.Snapshot(
        launcher_data, hashlib.sha256(launcher_data).hexdigest(), launcher_identity
    )
    recorded = snapshots.get(launcher_relative)
    if (
        launcher_path != root / launcher_relative
        or not isinstance(recorded, core.Snapshot)
        or recorded.sha256 != executed.sha256
        or recorded.identity != executed.identity
    ):
        raise core.AuditFailure("executed_launcher_identity_rejected")
    return inventory, snapshots


def _revalidate_inputs(
    core: object, root: Path, snapshots: dict[str, object]
) -> bool:
    try:
        for relative, snapshot in snapshots.items():
            core.revalidate_snapshot(
                root / relative, snapshot, core.MAX_SOURCE_BYTES, parent_anchor=root
            )
        return True
    except core.CONTROL_EXCEPTIONS:
        raise
    except BaseException:
        return False


def _stage_inputs(
    core: object,
    run_directory: Path,
    manifest: dict[str, object],
    manifest_snapshot: object,
    inventory: list[str],
    snapshots: dict[str, object],
) -> tuple[Path, object]:
    stage = run_directory / "stage"
    inputs = stage / "inputs"
    inputs.mkdir(parents=True, exist_ok=False)
    for relative in inventory:
        snapshot = snapshots[relative]
        core.create_immutable(
            inputs / relative, snapshot.data, core.MAX_SOURCE_BYTES
        )
    roles = manifest["executable_roles"]
    for role, relative in roles.items():
        snapshot = snapshots[relative]
        staged = core.create_immutable(
            stage / (role + ".py"), snapshot.data, core.MAX_SOURCE_BYTES
        )
        if staged.sha256 != snapshot.sha256:
            raise core.AuditFailure("stage_role_digest_rejected")
    entries = [
        {
            "path": relative,
            "sha256": snapshots[relative].sha256,
            "bytes": len(snapshots[relative].data),
        }
        for relative in inventory
    ]
    payload = core.encode_report({
        "schema": 5,
        "run_id": run_directory.name,
        "manifest_sha256": manifest_snapshot.sha256,
        "entries": entries,
    })
    return stage, core.create_immutable(run_directory / "input-manifest.json", payload)


def _minimal_environment(root: Path, stage: Path) -> dict[str, str]:
    result = {
        "HTTP1_GUARDIAN_ROOT": str(root),
        "HTTP1_GUARDIAN_STAGE": str(stage),
        "PYTHONDONTWRITEBYTECODE": "1",
        "PYTHONHASHSEED": "0",
        "PYTHONIOENCODING": "utf-8",
    }
    for name in (
        "SYSTEMROOT", "WINDIR", "COMSPEC", "PATHEXT", "PATH", "TEMP", "TMP",
        "HOME", "USERPROFILE", "LOCALAPPDATA",
    ):
        value = os.environ.get(name)
        if value:
            result[name] = value
    return result


def _unresolved_authority(launcher_sha256: str, config_sha256: str) -> dict[str, object]:
    return {
        "schema": 1,
        "tool_request": "python@3.12.13",
        "implementation": "unresolved",
        "version": "unresolved",
        "os": platform.system(),
        "arch": platform.machine(),
        "python_sha256": ZERO_SHA256,
        "python_path_identity_sha256": ZERO_SHA256,
        "mise_sha256": ZERO_SHA256,
        "mise_path_identity_sha256": ZERO_SHA256,
        "config_sha256": config_sha256,
        "launcher_sha256": launcher_sha256,
        "resolved": False,
    }


def _phase_failure(
    phase: str,
    classification: str,
    authority_sha256: str,
    run_id: str,
) -> dict[str, object]:
    return {
        "schema": 5,
        "status": "Rejected",
        "classification": classification,
        "phase": phase,
        "completed": True,
        "completed_controls": 0,
        "controls": [],
        "source_sha256": {},
        "tool_sha256": {},
        "runtime_authority_sha256": authority_sha256,
        "run_id": run_id,
        "rerun_command": "mise run http1-guardian-audit",
    }


def _valid_phase_report(
    core: object,
    value: object,
    phase: str,
    run_id: str,
    authority_sha256: str,
) -> bool:
    try:
        report = core.exact_keys(
            value, PHASE_REPORT_KEYS, "phase_report_schema_rejected"
        )
        return (
            report.get("schema") == 5
            and report.get("status") == "Ready"
            and report.get("classification") == "passed"
            and report.get("phase") == phase
            and report.get("completed") is True
            and isinstance(report.get("completed_controls"), int)
            and report.get("completed_controls") > 0
            and isinstance(report.get("controls"), list)
            and len(report["controls"]) == report["completed_controls"]
            and isinstance(report.get("source_sha256"), dict)
            and isinstance(report.get("tool_sha256"), dict)
            and report.get("runtime_authority_sha256") == authority_sha256
            and report.get("run_id") == run_id
            and report.get("rerun_command") == "mise run http1-guardian-audit"
            and core.evidence_is_secret_safe(report)
        )
    except core.CONTROL_EXCEPTIONS:
        raise
    except BaseException:
        return False


def _attempt_phase(
    core: object,
    phase: str,
    root: Path,
    stage: Path,
    run_directory: Path,
    runtime: object | None,
    authority_path: Path,
    authority_sha256: str,
    launcher_sha256: str,
    run_id: str,
    phase_deadline: float,
    output_limit: int,
) -> dict[str, object]:
    if runtime is None or time.monotonic() >= phase_deadline:
        result = core.ProcessResult(-1, b"", b"", runtime is not None, False, True)
        classification = (
            "phase_deadline_expired" if runtime is not None
            else "runtime_authority_rejected"
        )
        detail = _phase_failure(
            phase, classification, authority_sha256, run_id
        )
    else:
        environment = _minimal_environment(root, stage)
        result = core.run_bounded(
            [
                str(runtime.python_path), "-I", "-B", str(stage / "launcher.py"),
                "--phase", phase,
                "--authority", str(authority_path),
                "--authority-sha256", authority_sha256,
                "--launcher-sha256", launcher_sha256,
                "--run-id", run_id,
                "--root", str(root),
                "--stage", str(stage),
            ],
            cwd=root,
            environment=environment,
            absolute_deadline=phase_deadline,
            output_limit=output_limit,
        )
        classification = "passed"
        parsed: object | None = None
        if result.timed_out:
            classification = "phase_deadline_expired"
        elif result.output_exceeded:
            classification = "phase_output_limit_exceeded"
        elif not result.reaped:
            classification = "phase_process_unreaped"
        elif result.exit_code != 0:
            classification = "phase_process_rejected"
        elif result.stderr:
            classification = "phase_stderr_rejected"
        else:
            try:
                parsed = core.strict_json_bytes(result.stdout)
            except core.CONTROL_EXCEPTIONS:
                raise
            except BaseException:
                classification = "phase_report_rejected"
        if classification == "passed" and _valid_phase_report(
            core, parsed, phase, run_id, authority_sha256
        ):
            assert isinstance(parsed, dict)
            detail = parsed
        else:
            if classification == "passed":
                classification = "phase_report_rejected"
            detail = _phase_failure(
                phase, classification, authority_sha256, run_id
            )
    detail_snapshot = core.create_immutable(
        run_directory / ("phase-" + phase + ".json"),
        core.encode_report(detail),
    )
    status = "Ready" if classification == "passed" else "Rejected"
    process_report = {
        "schema": 5,
        "status": status,
        "classification": classification,
        "phase": phase,
        "exit_code": result.exit_code,
        "timed_out": result.timed_out,
        "output_exceeded": result.output_exceeded,
        "reaped": result.reaped,
        "stdout_bytes": len(result.stdout),
        "stderr_bytes": len(result.stderr),
        "report_sha256": detail_snapshot.sha256,
    }
    process_snapshot = core.create_immutable(
        run_directory / ("phase-" + phase + "-process.json"),
        core.encode_report(process_report),
    )
    return {
        "status": status,
        "classification": classification,
        "report_sha256": detail_snapshot.sha256,
        "process_sha256": process_snapshot.sha256,
        "exit_code": result.exit_code,
        "timed_out": result.timed_out,
        "output_exceeded": result.output_exceeded,
        "reaped": result.reaped,
        "stdout_bytes": len(result.stdout),
        "stderr_bytes": len(result.stderr),
    }


def _consumer_attempt(
    core: object,
    runtime: object | None,
    root: Path,
    stage: Path,
    evidence_path: Path,
    evidence_sha256: str,
    status: str,
    deadline: float,
    output_limit: int,
) -> tuple[bool, dict[str, object], object]:
    if runtime is None or time.monotonic() >= deadline:
        receipt = {
            "schema": 1, "status": "Rejected",
            "classification": "consumer_runtime_rejected",
            "evidence_sha256": evidence_sha256,
            "run_id": evidence_path.parent.name,
        }
        return False, receipt, core.ProcessResult(-1, b"", b"", False, False, True)
    result = core.run_bounded(
        [
            str(runtime.python_path), "-I", "-B", str(stage / "consumer.py"),
            "--evidence", str(evidence_path),
            "--sha256", evidence_sha256,
            "--status", status,
            "--root", str(root),
        ],
        cwd=root,
        environment=_minimal_environment(root, stage),
        absolute_deadline=deadline,
        output_limit=output_limit,
    )
    valid = False
    parsed: object | None = None
    if (
        result.exit_code == 0 and not result.timed_out
        and not result.output_exceeded and result.reaped and not result.stderr
    ):
        try:
            parsed = core.strict_json_bytes(result.stdout)
            item = core.exact_keys(
                parsed, RECEIPT_KEYS, "consumer_receipt_schema_rejected"
            )
            verified_status = _verified_receipt_status(status)
            valid = (
                item.get("schema") == 1
                and item.get("status") == verified_status
                and item.get("classification") == "passed"
                and item.get("evidence_sha256") == evidence_sha256
                and item.get("run_id") == evidence_path.parent.name
                and core.evidence_is_secret_safe(item)
            )
        except core.CONTROL_EXCEPTIONS:
            raise
        except BaseException:
            valid = False
    if valid:
        assert isinstance(parsed, dict)
        return True, parsed, result
    receipt = {
        "schema": 1, "status": "Rejected",
        "classification": (
            "consumer_deadline_expired" if result.timed_out
            else "consumer_output_limit_exceeded" if result.output_exceeded
            else "consumer_process_unreaped" if not result.reaped
            else "consumer_report_rejected"
        ),
        "evidence_sha256": evidence_sha256,
        "run_id": evidence_path.parent.name,
    }
    return False, receipt, result


def _consumer_process_report(
    role: str,
    evidence_sha256: str,
    receipt_sha256: str,
    receipt: dict[str, object],
    result: object,
) -> dict[str, object]:
    return {
        "schema": 5,
        "status": receipt["status"],
        "classification": receipt["classification"],
        "role": role,
        "exit_code": result.exit_code,
        "timed_out": result.timed_out,
        "output_exceeded": result.output_exceeded,
        "reaped": result.reaped,
        "stdout_bytes": len(result.stdout),
        "stderr_bytes": len(result.stderr),
        "evidence_sha256": evidence_sha256,
        "receipt_sha256": receipt_sha256,
    }


def _running_report(run_id: str) -> dict[str, object]:
    return {
        "schema": 5,
        "status": "Running",
        "classification": "running",
        "run_id": run_id,
        "expected_phases": 3,
        "completed_phases": 0,
        "rerun_command": "mise run http1-guardian-audit",
        "native_execution": "not_invoked",
    }


def _completed_pointer_proven(
    core: object, latest: Path, value: dict[str, object]
) -> bool:
    run_id = value.get("run_id")
    if (
        not isinstance(run_id, str)
        or len(run_id) != 32
        or any(character not in "0123456789abcdef" for character in run_id)
        or not _sha256(value.get("evidence_sha256"))
        or not _sha256(value.get("consumer_sha256"))
        or not _sha256(value.get("consumer_process_sha256"))
    ):
        return False
    output = latest.parent
    run_directory = output / "runs" / run_id
    evidence = core.read_snapshot(
        run_directory / "terminal.json", core.MAX_REPORT_BYTES,
        parent_anchor=output,
    )
    receipt = core.read_snapshot(
        run_directory / "consumer-terminal.json", core.MAX_REPORT_BYTES,
        parent_anchor=output,
    )
    process = core.read_snapshot(
        run_directory / "consumer-terminal-process.json", core.MAX_REPORT_BYTES,
        parent_anchor=output,
    )
    if (
        evidence.sha256 != value.get("evidence_sha256")
        or receipt.sha256 != value.get("consumer_sha256")
        or process.sha256 != value.get("consumer_process_sha256")
    ):
        return False
    receipt_value = core.exact_keys(
        core.strict_json_bytes(receipt.data), RECEIPT_KEYS,
        "consumer_receipt_schema_rejected",
    )
    process_value = core.exact_keys(
        core.strict_json_bytes(process.data), CONSUMER_PROCESS_KEYS,
        "consumer_process_schema_rejected",
    )
    if (
        receipt_value.get("schema") != 1
        or receipt_value.get("status") not in (
            "Ready", "VerifiedRejected", "Rejected"
        )
        or receipt_value.get("evidence_sha256") != evidence.sha256
        or receipt_value.get("run_id") != run_id
        or process_value.get("schema") != 5
        or process_value.get("status") != receipt_value.get("status")
        or process_value.get("classification")
        != receipt_value.get("classification")
        or process_value.get("role") != "terminal"
        or process_value.get("evidence_sha256") != evidence.sha256
        or process_value.get("receipt_sha256") != receipt.sha256
        or not isinstance(process_value.get("exit_code"), int)
        or not isinstance(process_value.get("timed_out"), bool)
        or not isinstance(process_value.get("output_exceeded"), bool)
        or not isinstance(process_value.get("reaped"), bool)
        or not isinstance(process_value.get("stdout_bytes"), int)
        or not 0 <= process_value["stdout_bytes"] <= core.MAX_PROCESS_OUTPUT_BYTES
        or not isinstance(process_value.get("stderr_bytes"), int)
        or not 0 <= process_value["stderr_bytes"] <= core.MAX_PROCESS_OUTPUT_BYTES
        or not core.evidence_is_secret_safe(receipt_value)
        or not core.evidence_is_secret_safe(process_value)
    ):
        return False
    if receipt_value.get("status") in ("Ready", "VerifiedRejected"):
        evidence_value = core.strict_json_bytes(evidence.data)
        expected_receipt_status = (
            "Ready"
            if isinstance(evidence_value, dict)
            and evidence_value.get("status") == "Ready"
            else "VerifiedRejected"
            if isinstance(evidence_value, dict)
            and evidence_value.get("status") == "Rejected"
            else "invalid"
        )
        return bool(
            receipt_value.get("status") == expected_receipt_status
            and value.get("status") == evidence_value.get("status")
            and receipt_value.get("classification") == "passed"
            and process_value.get("exit_code") == 0
            and process_value.get("timed_out") is False
            and process_value.get("output_exceeded") is False
            and process_value.get("reaped") is True
            and process_value.get("stdout_bytes") == len(receipt.data)
            and process_value.get("stderr_bytes") == 0
        )
    expected_classification = (
        "consumer_deadline_expired" if process_value.get("timed_out") is True
        else "consumer_output_limit_exceeded"
        if process_value.get("output_exceeded") is True
        else "consumer_process_unreaped"
        if process_value.get("reaped") is False
        else "consumer_runtime_rejected"
        if process_value.get("exit_code") == -1
        else "consumer_report_rejected"
    )
    return bool(
        value.get("status") == "Rejected"
        and receipt_value.get("classification") == expected_classification
    )


def _latest_recovery(core: object, latest: Path) -> tuple[dict[str, object], list[str]]:
    recovery = {"observed_previous_running": False, "previous_status": "none"}
    failures: list[str] = []
    if not latest.exists():
        return recovery, failures
    try:
        snapshot = core.read_snapshot(latest, core.MAX_REPORT_BYTES)
        value = core.exact_keys(
            core.strict_json_bytes(snapshot.data), POINTER_KEYS,
            "pointer_schema_rejected",
        )
        status = value.get("status")
        if status not in ("Running", "Ready", "Rejected"):
            raise core.AuditFailure("pointer_status_rejected")
        run_id = value.get("run_id")
        if (
            not isinstance(run_id, str)
            or len(run_id) != 32
            or any(character not in "0123456789abcdef" for character in run_id)
        ):
            raise core.AuditFailure("pointer_run_identity_rejected")
        if status == "Running":
            running = core.read_snapshot(
                latest.parent / "runs" / run_id / "running.json",
                core.MAX_REPORT_BYTES,
                parent_anchor=latest.parent,
            )
            running_value = core.exact_keys(
                core.strict_json_bytes(running.data), RUNNING_KEYS,
                "running_schema_rejected",
            )
            if (
                value.get("evidence_sha256") != running.sha256
                or value.get("consumer_sha256") != ZERO_SHA256
                or value.get("consumer_process_sha256") != ZERO_SHA256
                or running_value != _running_report(run_id)
            ):
                raise core.AuditFailure("running_pointer_binding_rejected")
        elif not _completed_pointer_proven(core, latest, value):
            raise core.AuditFailure("completed_pointer_binding_rejected")
        recovery = {
            "observed_previous_running": status == "Running",
            "previous_status": status,
        }
        if status == "Running":
            failures.append("previous_run_recovered")
    except core.CONTROL_EXCEPTIONS:
        raise
    except BaseException:
        recovery = {"observed_previous_running": False, "previous_status": "Rejected"}
        failures.append("previous_pointer_rejected")
    return recovery, failures


def _pointer(
    core: object,
    status: str,
    run_id: str,
    evidence: str,
    consumer: str,
    consumer_process: str,
) -> bytes:
    return core.encode_report({
        "schema": 5, "status": status, "run_id": run_id,
        "evidence_sha256": evidence, "consumer_sha256": consumer,
        "consumer_process_sha256": consumer_process,
    })


def _report(
    *,
    status: str,
    run_id: str,
    phases: dict[str, object],
    authority: dict[str, object],
    authority_sha256: str,
    input_hashes: dict[str, str],
    input_stable: bool,
    input_manifest_sha256: str,
    manifest: dict[str, object],
    manifest_sha256: str,
    prefinal_sha256: str,
    prefinal_consumer_sha256: str,
    prefinal_consumer_process_sha256: str,
    consumer_verified: bool,
    failures: list[str],
    recovery: dict[str, object],
) -> dict[str, object]:
    return {
        "schema": 5,
        "status": status,
        "classification": (
            "passed" if status == "Ready"
            else "candidate" if status == "Candidate"
            else "gate_rejected"
        ),
        "run_id": run_id,
        "completed_phases": 3,
        "expected_phases": 3,
        "phases": phases,
        "runtime_authority": authority,
        "runtime_authority_sha256": authority_sha256,
        "input_sha256": input_hashes,
        "input_stable": input_stable,
        "input_manifest_sha256": input_manifest_sha256,
        "history_manifest_sha256": input_hashes[str(manifest["history_manifest"])],
        "control_authority_sha256": input_hashes[str(manifest["control_authority"])],
        "manifest_sha256": manifest_sha256,
        "prefinal_sha256": prefinal_sha256,
        "prefinal_consumer_sha256": prefinal_consumer_sha256,
        "prefinal_consumer_process_sha256": prefinal_consumer_process_sha256,
        "consumer_verified": consumer_verified,
        "failure_classes": sorted(set(failures)),
        "rerun_command": "mise run http1-guardian-audit",
        "limits": manifest["limits"],
        "recovery": recovery,
        "native_execution": "not_invoked",
    }


def _internal_arguments(core: object) -> dict[str, str]:
    names = {
        "--phase", "--authority", "--authority-sha256",
        "--launcher-sha256", "--run-id", "--root", "--stage",
    }
    if len(sys.argv) != 15:
        raise core.AuditFailure("phase_arguments_rejected")
    result: dict[str, str] = {}
    for index in range(1, len(sys.argv), 2):
        key = sys.argv[index]
        if key not in names or key in result:
            raise core.AuditFailure("phase_arguments_rejected")
        result[key] = sys.argv[index + 1]
    if set(result) != names:
        raise core.AuditFailure("phase_arguments_rejected")
    return result


def _internal_phase(core: object) -> int:
    arguments = _internal_arguments(core)
    root = Path(arguments["--root"])
    stage = Path(arguments["--stage"])
    authority_snapshot = core.read_snapshot(
        Path(arguments["--authority"]), core.MAX_REPORT_BYTES
    )
    if authority_snapshot.sha256 != arguments["--authority-sha256"]:
        raise core.AuditFailure("runtime_authority_digest_rejected")
    authority = core.strict_json_bytes(authority_snapshot.data)
    gate_snapshot = core.read_snapshot(
        stage / "gate.py", core.MAX_SOURCE_BYTES, parent_anchor=stage
    )
    gate = core.load_snapshot_module(
        gate_snapshot,
        "http1_guardian_v5_gate",
        stage / "gate.py",
        logical_file=root / AUDIT_RELATIVE / "v5_gate.py",
    )
    report = gate.run_phase(
        arguments["--phase"],
        root=root,
        stage=stage,
        authority=authority,
        authority_sha256=authority_snapshot.sha256,
        launcher_sha256=arguments["--launcher-sha256"],
        run_id=arguments["--run-id"],
    )
    sys.stdout.buffer.write(core.encode_report(report))
    sys.stdout.buffer.flush()
    return 0


def _authoritative(
    core: object,
    root: Path,
    launcher_data: bytes,
    launcher_identity: tuple[int, ...],
    launcher_path: Path,
) -> int:
    if len(sys.argv) != 1:
        raise core.AuditFailure("launcher_arguments_rejected")
    core.validate_plain_directory(root)
    output = root / OUTPUT_RELATIVE
    runs = output / "runs"
    runs.mkdir(parents=True, exist_ok=True)
    core.validate_plain_directory(output)
    core.validate_plain_directory(runs)
    latest = output / "latest.json"
    recovery, early_failures = _latest_recovery(core, latest)
    run_directory: Path | None = None
    for _attempt in range(8):
        candidate = runs / secrets.token_hex(16)
        try:
            candidate.mkdir(exist_ok=False)
            run_directory = candidate
            break
        except FileExistsError:
            continue
    if run_directory is None:
        raise core.AuditFailure("run_identity_exhausted")
    run_id = run_directory.name
    running = core.create_immutable(
        run_directory / "running.json", core.encode_report(_running_report(run_id))
    )
    _running_pointer_snapshot = core.atomic_pointer(
        latest,
        _pointer(
            core, "Running", run_id, running.sha256, ZERO_SHA256, ZERO_SHA256
        ),
    )
    core.create_immutable(
        run_directory / "recovery.json",
        core.encode_report({"schema": 5, "status": "recovery", **recovery}),
    )
    manifest, manifest_snapshot = _manifest(core, root)
    inventory, snapshots = _snapshot_inputs(
        core, root, manifest, launcher_data, launcher_identity, launcher_path
    )
    stage, input_manifest = _stage_inputs(
        core, run_directory, manifest, manifest_snapshot, inventory, snapshots
    )
    launcher_relative = str(AUDIT_RELATIVE / "launcher.py").replace("\\", "/")
    launcher_sha256 = snapshots[launcher_relative].sha256
    overall_deadline = time.monotonic() + manifest["limits"]["overall_milliseconds"] / 1000.0
    runtime = None
    failures = list(early_failures)
    try:
        runtime = core.resolve_runtime_authority(root, launcher_sha256, overall_deadline)
        if runtime.config_snapshot.sha256 != snapshots[".mise.toml"].sha256:
            raise core.AuditFailure("runtime_config_snapshot_rejected")
        authority = runtime.authority
    except core.CONTROL_EXCEPTIONS:
        raise
    except BaseException:
        authority = _unresolved_authority(
            launcher_sha256, snapshots[".mise.toml"].sha256
        )
        failures.append("runtime_authority_rejected")
        runtime = None
    authority_payload = core.encode_report(authority)
    authority_snapshot = core.create_immutable(
        run_directory / "runtime-authority.json", authority_payload
    )
    phases: dict[str, object] = {}
    phase_seconds = manifest["limits"]["phase_milliseconds"] / 1000.0
    for phase in PHASES:
        deadline = min(overall_deadline, time.monotonic() + phase_seconds)
        try:
            phases[phase] = _attempt_phase(
                core, phase, root, stage, run_directory, runtime,
                run_directory / "runtime-authority.json",
                authority_snapshot.sha256, launcher_sha256, run_id, deadline,
                manifest["limits"]["process_output_bytes"],
            )
        except core.CONTROL_EXCEPTIONS:
            raise
        except BaseException as failure:
            classification = core.classify_failure(failure)
            detail = _phase_failure(
                phase, classification, authority_snapshot.sha256, run_id
            )
            detail_snapshot = core.create_immutable(
                run_directory / ("phase-" + phase + ".json"),
                core.encode_report(detail),
            )
            process = {
                "schema": 5, "status": "Rejected",
                "classification": classification, "phase": phase,
                "exit_code": -1, "timed_out": False,
                "output_exceeded": False, "reaped": True,
                "stdout_bytes": 0, "stderr_bytes": 0,
                "report_sha256": detail_snapshot.sha256,
            }
            process_snapshot = core.create_immutable(
                run_directory / ("phase-" + phase + "-process.json"),
                core.encode_report(process),
            )
            phases[phase] = {
                key: process[key] for key in (
                    "status", "classification", "exit_code", "timed_out",
                    "output_exceeded", "reaped", "stdout_bytes", "stderr_bytes",
                )
            }
            phases[phase]["report_sha256"] = detail_snapshot.sha256
            phases[phase]["process_sha256"] = process_snapshot.sha256
        if phases[phase]["status"] != "Ready":
            failures.append(str(phases[phase]["classification"]))
    stable = _revalidate_inputs(core, root, snapshots)
    if not stable:
        failures.append("input_identity_changed")
    input_hashes = {relative: snapshots[relative].sha256 for relative in inventory}
    prefinal_status = (
        "Candidate" if not failures and runtime is not None and stable else "Rejected"
    )
    prefinal = _report(
        status=prefinal_status,
        run_id=run_id,
        phases=phases,
        authority=authority,
        authority_sha256=authority_snapshot.sha256,
        input_hashes=input_hashes,
        input_stable=stable,
        input_manifest_sha256=input_manifest.sha256,
        manifest=manifest,
        manifest_sha256=manifest_snapshot.sha256,
        prefinal_sha256=ZERO_SHA256,
        prefinal_consumer_sha256=ZERO_SHA256,
        prefinal_consumer_process_sha256=ZERO_SHA256,
        consumer_verified=False,
        failures=failures,
        recovery=recovery,
    )
    prefinal_snapshot = core.create_immutable(
        run_directory / "prefinal.json", core.encode_report(prefinal)
    )
    consumer_deadline = min(overall_deadline, time.monotonic() + phase_seconds)
    consumer_ok, consumer_receipt, consumer_process = _consumer_attempt(
        core, runtime, root, stage, run_directory / "prefinal.json",
        prefinal_snapshot.sha256, prefinal_status, consumer_deadline,
        manifest["limits"]["process_output_bytes"],
    )
    prefinal_receipt = core.create_immutable(
        run_directory / "consumer-prefinal.json",
        core.encode_report(consumer_receipt),
    )
    prefinal_consumer_process = core.create_immutable(
        run_directory / "consumer-prefinal-process.json",
        core.encode_report(
            _consumer_process_report(
                "prefinal", prefinal_snapshot.sha256, prefinal_receipt.sha256,
                consumer_receipt, consumer_process,
            )
        ),
    )
    if not consumer_ok:
        failures.append("prefinal_consumer_rejected")
    stable = stable and _revalidate_inputs(core, root, snapshots)
    if not stable:
        failures.append("input_identity_changed")
    runtime_policy = manifest.get("runtime_policy")
    integration = manifest.get("integration")
    integrated = (
        manifest.get("status") == "integrated"
        and manifest.get("ready_allowed") is True
        and isinstance(runtime_policy, dict)
        and runtime_policy.get("configuration_sha256") == snapshots[".mise.toml"].sha256
        and isinstance(integration, dict)
        and set(integration.values()) == {"integrated"}
    )
    if not integrated:
        failures.append("integration_pending")
    final_status = (
        "Ready"
        if not failures and runtime is not None and consumer_ok and stable and integrated
        else "Rejected"
    )
    final_report = _report(
        status=final_status,
        run_id=run_id,
        phases=phases,
        authority=authority,
        authority_sha256=authority_snapshot.sha256,
        input_hashes=input_hashes,
        input_stable=stable,
        input_manifest_sha256=input_manifest.sha256,
        manifest=manifest,
        manifest_sha256=manifest_snapshot.sha256,
        prefinal_sha256=prefinal_snapshot.sha256,
        prefinal_consumer_sha256=prefinal_receipt.sha256,
        prefinal_consumer_process_sha256=prefinal_consumer_process.sha256,
        consumer_verified=consumer_ok,
        failures=failures,
        recovery=recovery,
    )
    final_payload = core.encode_report(final_report)
    proposal = core.create_immutable(
        run_directory / "terminal-proposal.json", final_payload
    )
    final_consumer_deadline = min(
        overall_deadline, time.monotonic() + phase_seconds
    )
    final_consumer_ok, final_receipt, _final_consumer_process = _consumer_attempt(
        core, runtime, root, stage, run_directory / "terminal-proposal.json",
        proposal.sha256, final_status, final_consumer_deadline,
        manifest["limits"]["process_output_bytes"],
    )
    stable_after = _revalidate_inputs(core, root, snapshots)
    if not final_consumer_ok or not stable_after:
        if not final_consumer_ok:
            failures.append("terminal_consumer_rejected")
        if not stable_after:
            failures.append("input_identity_changed")
        final_status = "Rejected"
        final_report = _report(
            status=final_status,
            run_id=run_id,
            phases=phases,
            authority=authority,
            authority_sha256=authority_snapshot.sha256,
            input_hashes=input_hashes,
            input_stable=False if not stable_after else stable,
            input_manifest_sha256=input_manifest.sha256,
            manifest=manifest,
            manifest_sha256=manifest_snapshot.sha256,
            prefinal_sha256=prefinal_snapshot.sha256,
            prefinal_consumer_sha256=prefinal_receipt.sha256,
            prefinal_consumer_process_sha256=prefinal_consumer_process.sha256,
            consumer_verified=consumer_ok,
            failures=failures,
            recovery=recovery,
        )
        final_payload = core.encode_report(final_report)
        proposal = core.create_immutable(
            run_directory / "terminal-rejected-proposal.json", final_payload
        )
        retry_deadline = min(
            overall_deadline, time.monotonic() + phase_seconds
        )
        final_consumer_ok, final_receipt, _final_consumer_process = _consumer_attempt(
            core, runtime, root, stage,
            run_directory / "terminal-rejected-proposal.json",
            proposal.sha256, final_status, retry_deadline,
            manifest["limits"]["process_output_bytes"],
        )
    final_receipt_snapshot = core.create_immutable(
        run_directory / "consumer-terminal.json",
        core.encode_report(final_receipt),
    )
    final_consumer_process_snapshot = core.create_immutable(
        run_directory / "consumer-terminal-process.json",
        core.encode_report(
            _consumer_process_report(
                "terminal", proposal.sha256, final_receipt_snapshot.sha256,
                final_receipt, _final_consumer_process,
            )
        ),
    )
    terminal = core.create_immutable(
        run_directory / "terminal.json", final_payload
    )
    core.revalidate_snapshot(
        run_directory / "terminal.json", terminal, core.MAX_REPORT_BYTES
    )
    if not _revalidate_inputs(core, root, snapshots):
        raise core.AuditFailure("pre_pointer_input_changed")
    pointer_status = final_status if final_consumer_ok else "Rejected"
    pointer_snapshot = core.atomic_pointer(
        latest,
        _pointer(
            core, pointer_status, run_id, terminal.sha256,
            final_receipt_snapshot.sha256,
            final_consumer_process_snapshot.sha256,
        ),
    )
    core.revalidate_snapshot(
        run_directory / "terminal.json", terminal, core.MAX_REPORT_BYTES
    )
    inputs_after_pointer = _revalidate_inputs(core, root, snapshots)
    pointer_after_publication = True
    try:
        core.revalidate_snapshot(latest, pointer_snapshot, core.MAX_REPORT_BYTES)
    except core.AuditFailure:
        pointer_after_publication = False
    if not inputs_after_pointer or not pointer_after_publication:
        recovery_pointer = core.atomic_pointer(
            latest,
            _pointer(
                core, "Running", run_id, running.sha256,
                ZERO_SHA256, ZERO_SHA256,
            ),
        )
        core.revalidate_snapshot(
            latest, recovery_pointer, core.MAX_REPORT_BYTES
        )
        raise core.AuditFailure(
            "post_pointer_input_changed"
            if not inputs_after_pointer
            else "post_pointer_identity_changed"
        )
    output_report = {
        "schema": 5,
        "status": pointer_status,
        "classification": (
            "passed" if pointer_status == "Ready" else "gate_rejected"
        ),
        "run_id": run_id,
        "evidence_sha256": terminal.sha256,
        "consumer_sha256": final_receipt_snapshot.sha256,
        "consumer_process_sha256": final_consumer_process_snapshot.sha256,
        "pointer_sha256": pointer_snapshot.sha256,
        "completed_phases": 3,
        "rerun_command": "mise run http1-guardian-audit",
    }
    sys.stdout.buffer.write(core.encode_report(output_report))
    sys.stdout.buffer.flush()
    return 0 if pointer_status == "Ready" else 1


def entrypoint(
    launcher_data: bytes,
    launcher_identity: tuple[int, ...],
    launcher_path: Path,
    root: Path,
) -> int:
    core = _bootstrap_core(root)
    if len(sys.argv) > 1 and "--phase" in sys.argv:
        return core.cli_boundary(lambda: _internal_phase(core), "phase")
    return core.cli_boundary(
        lambda: _authoritative(
            core, root, launcher_data, launcher_identity, launcher_path
        ),
        "launcher",
    )


def _exact_dispatch() -> int:
    source_path = Path(__file__).absolute()
    data, identity = _open_exact(source_path, 4 * 1024 * 1024)
    module = types.ModuleType("http1_guardian_v5_launcher_exact")
    module.__file__ = str(source_path)
    module.__package__ = ""
    sys.modules[module.__name__] = module
    code = compile(
        data,
        "<tracked:launcher:" + hashlib.sha256(data).hexdigest()[:16] + ">",
        "exec",
        dont_inherit=True,
    )
    exec(code, module.__dict__, module.__dict__)
    return module.entrypoint(data, identity, source_path, _root_for(source_path))


if __name__ == "__main__":
    try:
        raise SystemExit(_exact_dispatch())
    except (KeyboardInterrupt, SystemExit, GeneratorExit):
        raise
    except BaseException:
        try:
            sys.stdout.write(
                '{"classification":"bootstrap_rejected","completed":false,'
                '"phase":"launcher","schema":5,"status":"Rejected"}\n'
            )
            sys.stdout.flush()
        except BaseException:
            pass
        raise SystemExit(2)

#!/usr/bin/env python3
"""Adversarial, bounded release gate for the HTTP/1 handler guardian."""

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


ROOT = Path(".")
AUDIT_ROOT = ROOT / "standards/audits/http1-guardian"
GUARDIAN_CHECKER = AUDIT_ROOT / "guardian_contract_check.py"
SPAWN_SCANNER = ROOT / "scripts/spawn_monitor_contract_audit.py"
SPAWN_WRAPPER = AUDIT_ROOT / "spawn_monitor_dataflow_contract_check.py"
MANIFEST = AUDIT_ROOT / "manifest.json"
MAXIMUM_BYTES = 4 * 1024 * 1024
MAXIMUM_TOOL_BYTES = 64 * 1024 * 1024
MAXIMUM_REPORT_BYTES = 1024 * 1024
EXPECTED_PYTHON_VERSION = "3.12.13"
RERUN_COMMAND = (
    "mise exec python@3.12.13 -- python -I -B "
    "standards/audits/http1-guardian/adversarial_contract_check.py"
)
EVIDENCE_RERUN_COMMAND = "mise run http1-guardian-audit"
GUARDIAN_RERUN_COMMAND = (
    "mise exec python@3.12.13 -- python -I -B "
    "standards/audits/http1-guardian/guardian_contract_check.py"
)
SCANNER_RERUN_COMMAND = (
    "mise exec python@3.12.13 -- python -I -B "
    "scripts/spawn_monitor_contract_audit.py"
)
WRAPPER_RERUN_COMMAND = (
    "mise exec python@3.12.13 -- python -I -B "
    "standards/audits/http1-guardian/"
    "spawn_monitor_dataflow_contract_check.py"
)
SOURCE_PATHS = (
    "src/http/internal/http1/server.gleam",
    "src/http_server_ffi.erl",
    "test/server_handler_lifetime_test.gleam",
    "test/http_handler_lifetime_test_ffi.erl",
)
SCANNER_SOURCE_PATHS = (
    "packages/quic_core/src/quic_core/internal/tls/replay_guard.gleam",
    "packages/quic_core/src/quic_core_process_ffi.erl",
    "src/http/internal/http1/server.gleam",
    "src/http/internal/http3/server.gleam",
    "src/http_server_ffi.erl",
)
TOOL_PATHS = (
    "scripts/spawn_monitor_contract_audit.py",
    "standards/audits/http1-guardian/guardian_contract_check.py",
    "standards/audits/http1-guardian/spawn_monitor_dataflow_contract_check.py",
    "standards/audits/http1-guardian/adversarial_contract_check.py",
    "standards/audits/http1-guardian/review.md",
    "standards/audits/http1-guardian/manifest.json",
    ".mise.toml",
)
EVIDENCE_INVENTORY = (
    "guardian_report.json",
    "scanner_self_test_report.json",
    "scanner_audit_report.json",
    "wrapper_report.json",
    "adversarial_report.json",
    "v2_red.aggregate",
    "v3_red.aggregate",
    "v4_red.aggregate",
    "v2_invalidation.json",
    "v3_invalidation.json",
)


def safe_read(path: Path, maximum: int = MAXIMUM_BYTES) -> tuple[bytes, str]:
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
        value.st_dev, value.st_ino, value.st_size, value.st_mtime_ns
    )
    if not (
        identity(before_path) == identity(before_handle)
        == identity(after_handle) == identity(after_path)
    ):
        raise ValueError("changed_during_read")
    data = b"".join(chunks)
    if len(data) != before_path.st_size:
        raise ValueError("partial_read_rejected")
    return data, hashlib.sha256(data).hexdigest()


def safe_text(path: Path, maximum: int = MAXIMUM_BYTES) -> tuple[str, str]:
    data, digest = safe_read(path, maximum)
    return data.decode("utf-8", errors="strict"), digest


def safe_hash(path: Path, maximum: int = MAXIMUM_BYTES) -> str:
    return safe_read(path, maximum)[1]


def load(path: Path, name: str) -> object:
    specification = importlib.util.spec_from_file_location(name, path)
    if specification is None or specification.loader is None:
        raise ValueError("module_load_rejected")
    module = importlib.util.module_from_spec(specification)
    sys.modules[name] = module
    specification.loader.exec_module(module)
    return module


def snapshot(paths: tuple[str, ...]) -> dict[str, str]:
    return {relative: safe_hash(ROOT / relative) for relative in paths}


def replace_once(source: str, old: str, new: str) -> str:
    return source if source.count(old) != 1 else source.replace(old, new, 1)


def record(controls: list[dict[str, object]], name: str, observed: bool) -> None:
    controls.append({
        "name": name,
        "expected": True,
        "observed": observed,
        "passed": observed is True,
    })


def guardian_controls(
    guardian: object, sources: dict[str, str]
) -> list[dict[str, object]]:
    controls: list[dict[str, object]] = []
    ffi = sources["ffi"]
    mutations = (
        (
            "run_in_first_deadline_true_rejected",
            "true ->\n                    http1_handler_guardian_handler_timed_out(",
            "true ->\n                    _Forbidden = Run(),\n"
            "                    http1_handler_guardian_handler_timed_out(",
            "handler_run_outside_second_false",
        ),
        (
            "run_in_second_deadline_true_rejected",
            "true ->\n                            http1_handler_guardian_handler_timed_out(",
            "true ->\n                            _Forbidden = Run(),\n"
            "                            http1_handler_guardian_handler_timed_out(",
            "handler_run_outside_second_false",
        ),
        (
            "run_before_second_deadline_rejected",
            "http1_handler_guardian_safe_probe(Probe, 1, Guardian),\n"
            "                    case monotonic_millisecond() >= HandlerDeadline of",
            "http1_handler_guardian_safe_probe(Probe, 1, Guardian),\n"
            "                    _Forbidden = Run(),\n"
            "                    case monotonic_millisecond() >= HandlerDeadline of",
            "handler_run_before_second_deadline",
        ),
        (
            "dead_second_deadline_rejected",
            "http1_handler_guardian_safe_probe(Probe, 1, Guardian),\n"
            "                    case monotonic_millisecond() >= HandlerDeadline of",
            "http1_handler_guardian_safe_probe(Probe, 1, Guardian),\n"
            "                    _Dead = fun() ->\n"
            "                        case monotonic_millisecond() >= HandlerDeadline of\n"
            "                            true -> ok; false -> ok\n"
            "                        end\n"
            "                    end,\n"
            "                    case false of",
            "handler_entry_control_flow_unproven",
        ),
    )
    for name, old, new, expected in mutations:
        mutant_ffi = replace_once(ffi, old, new)
        mutant = dict(sources)
        mutant["ffi"] = mutant_ffi
        record(
            controls, name,
            mutant_ffi != ffi and expected in guardian.analyze(mutant)
        )
    record(controls, "guardian_current_source_green", guardian.analyze(sources) == [])
    return controls


def scanner_controls(
    scanner: object, sources: dict[str, str]
) -> list[dict[str, object]]:
    controls: list[dict[str, object]] = []
    ffi = sources["ffi"]
    gleam = sources["gleam"]
    cases = (
        (
            "guardian_return_after_valid_decoy_rejected",
            replace_once(
                ffi,
                "            {ok, {GuardianMonitor, Commands}};",
                "            _ValidDecoy = {ok, {GuardianMonitor, Commands}},\n"
                "            {ok, {DifferentMonitor, Commands}};",
            ),
            "guardian_monitor_return_unproven",
        ),
        (
            "owner_demonitor_before_handler_rejected",
            replace_once(
                ffi,
                "                            http1_handler_guardian_start_handler(",
                "                            erlang:demonitor(OwnerMonitor, [flush]),\n"
                "                            http1_handler_guardian_start_handler(",
            ),
            "guardian_owner_monitor_lifetime_unproven",
        ),
        (
            "owner_demonitor_before_publication_rejected",
            replace_once(
                ffi,
                "            http1_handler_guardian_publish_result(Events, Result),",
                "            erlang:demonitor("
                "maps:get(owner_monitor, State), [flush]),\n"
                "            http1_handler_guardian_publish_result(Events, Result),",
            ),
            "guardian_owner_monitor_lifetime_unproven",
        ),
        (
            "nested_handler_state_rejected",
            replace_once(
                ffi,
                "        handler => Handler,\n        handler_monitor => HandlerMonitor,",
                "        handler_pair => #{\n"
                "            handler => Handler,\n"
                "            handler_monitor => HandlerMonitor\n"
                "        },",
            ),
            "handler_state_top_level_unproven",
        ),
        (
            "exit_before_down_rejected",
            replace_once(
                ffi,
                "            http1_handler_guardian_down(State);",
                "            exit(handler_down_decoy),\n"
                "            http1_handler_guardian_down(State);",
            ),
            "handler_down_reachability_unproven",
        ),
        (
            "throw_before_down_rejected",
            replace_once(
                ffi,
                "            http1_handler_guardian_down(State);",
                "            throw(handler_down_decoy),\n"
                "            http1_handler_guardian_down(State);",
            ),
            "handler_down_reachability_unproven",
        ),
        (
            "return_before_down_rejected",
            replace_once(
                ffi,
                "            http1_handler_guardian_down(State);",
                "            return(handler_down_decoy),\n"
                "            http1_handler_guardian_down(State);",
            ),
            "handler_down_reachability_unproven",
        ),
        (
            "unreachable_publication_rejected",
            replace_once(
                ffi,
                "            http1_handler_guardian_publish_result(Events, Result),",
                "            case false of\n"
                "                true -> http1_handler_guardian_publish_result(Events, Result);\n"
                "                false -> ok\n"
                "            end,",
            ),
            "handler_publication_reachability_unproven",
        ),
    )
    for name, mutant, expected in cases:
        findings = scanner.inspect_http1_delegation(gleam, mutant)
        record(controls, name, mutant != ffi and expected in findings)
    record(
        controls, "scanner_current_source_green",
        scanner.inspect_http1_delegation(gleam, ffi) == []
    )
    self_status, self_report = scanner.self_test_report()
    names = {
        item.get("name")
        for item in self_report.get("controls", [])
        if isinstance(item, dict) and item.get("passed") is True
    } if isinstance(self_report, dict) else set()
    required = {
        "guardian_return_after_valid_decoy",
        "owner_demonitor_before_handler",
        "owner_demonitor_before_publication",
        "nested_handler_state",
        "exit_before_handler_down",
        "throw_before_handler_down",
        "return_before_handler_down",
        "publication_in_unreachable_branch",
    }
    record(
        controls, "scanner_internal_inventory_exact",
        self_status == 0
        and self_report.get("completed_controls") == 34
        and required.issubset(names)
    )
    return controls


def wrapper_controls(wrapper: object) -> list[dict[str, object]]:
    controls: list[dict[str, object]] = []
    scanner_hash = safe_hash(SPAWN_SCANNER)
    config_hash = safe_hash(ROOT / ".mise.toml")
    runtime_hash = safe_hash(Path(sys.executable).resolve(strict=True), MAXIMUM_TOOL_BYTES)
    sources = {relative: "a" * 64 for relative in wrapper.EXPECTED_SOURCE_PATHS}
    aggregate = "b" * 64
    base: dict[str, object] = {
        "schema": 2,
        "kind": "audit",
        "status": "Ready",
        "classification": "passed",
        "completed_contracts": wrapper.EXPECTED_CONTRACTS,
        "scanner_sha256_pre": scanner_hash,
        "scanner_sha256_post": scanner_hash,
        "scanner_stable": True,
        "runtime": {
            "tool_request": "python@3.12.13",
            "implementation": "cpython",
            "version": "3.12.13",
            "executable_sha256": runtime_hash,
            "mise_config_sha256": config_hash,
        },
        "rerun_command": wrapper.AUDIT_RERUN,
        "source_sha256_pre": sources,
        "source_sha256_post": sources,
        "source_stable": True,
        "source_files": len(sources),
        "source_bytes": 100,
        "source_aggregate_sha256_pre": aggregate,
        "source_aggregate_sha256_post": aggregate,
        "findings": [],
    }

    def rejected(change: dict[str, object], expected: str) -> bool:
        candidate = dict(base)
        candidate.update(change)
        return expected in wrapper.validate_report(
            candidate, "audit", scanner_hash, sources, runtime_hash,
            aggregate, 100, config_hash
        )

    for name, change, expected in (
        ("missing_completed_contracts_rejected", {"completed_contracts": None}, "audit_completed_contracts_mismatch"),
        ("zero_completed_contracts_rejected", {"completed_contracts": 0}, "audit_completed_contracts_mismatch"),
        ("empty_rerun_rejected", {"rerun_command": ""}, "audit_rerun_invalid"),
        ("false_scanner_stability_rejected", {"scanner_stable": False}, "audit_scanner_stability_invalid"),
        ("false_source_stability_rejected", {"source_stable": False}, "audit_source_stability_invalid"),
        ("scanner_post_drift_rejected", {"scanner_sha256_post": "c" * 64}, "audit_scanner_post_identity_mismatch"),
        ("source_post_drift_rejected", {"source_sha256_post": {}}, "audit_source_post_identity_mismatch"),
    ):
        record(controls, name, rejected(change, expected))
    record(
        controls, "wrapper_valid_report_green",
        wrapper.validate_report(
            base, "audit", scanner_hash, sources, runtime_hash,
            aggregate, 100, config_hash
        ) == []
    )
    return controls


def verify_evidence_bundle(
    bundle: object,
    payloads: dict[str, bytes],
    expected_sources: dict[str, str],
    expected_tools: dict[str, str],
) -> list[str]:
    """Fail closed on incomplete, stale, or byte-tampered generated evidence."""
    if not isinstance(bundle, dict):
        return ["bundle_not_map"]
    failures: list[str] = []
    if bundle.get("schema") != 4 or bundle.get("status") != "Ready":
        failures.append("bundle_schema_invalid")
    if bundle.get("rerun_command") != EVIDENCE_RERUN_COMMAND:
        failures.append("bundle_rerun_invalid")
    if bundle.get("completed_artifacts") != len(EVIDENCE_INVENTORY):
        failures.append("bundle_completed_artifacts_invalid")
    hashes = bundle.get("artifact_sha256")
    if (
        not isinstance(hashes, dict)
        or set(hashes) != set(EVIDENCE_INVENTORY)
        or set(payloads) != set(EVIDENCE_INVENTORY)
    ):
        failures.append("bundle_inventory_invalid")
    elif any(
        not isinstance(payload, bytes)
        or len(payload) <= 0
        or len(payload) > MAXIMUM_REPORT_BYTES
        or hashes.get(name) != hashlib.sha256(payload).hexdigest()
        for name, payload in payloads.items()
    ):
        failures.append("bundle_artifact_hash_mismatch")
    if (
        bundle.get("source_sha256_pre") != expected_sources
        or bundle.get("source_sha256_post") != expected_sources
        or bundle.get("source_stable") is not True
    ):
        failures.append("bundle_source_identity_invalid")
    if (
        bundle.get("tool_sha256_pre") != expected_tools
        or bundle.get("tool_sha256_post") != expected_tools
        or bundle.get("tool_stable") is not True
    ):
        failures.append("bundle_tool_identity_invalid")
    return sorted(set(failures))


def evidence_controls(
    source_hashes: dict[str, str], tool_hashes: dict[str, str]
) -> list[dict[str, object]]:
    controls: list[dict[str, object]] = []
    payloads = {name: (name + "\n").encode("ascii") for name in EVIDENCE_INVENTORY}
    bundle: dict[str, object] = {
        "schema": 4,
        "status": "Ready",
        "rerun_command": EVIDENCE_RERUN_COMMAND,
        "completed_artifacts": len(EVIDENCE_INVENTORY),
        "artifact_sha256": {
            name: hashlib.sha256(payload).hexdigest()
            for name, payload in payloads.items()
        },
        "source_sha256_pre": source_hashes,
        "source_sha256_post": source_hashes,
        "source_stable": True,
        "tool_sha256_pre": tool_hashes,
        "tool_sha256_post": tool_hashes,
        "tool_stable": True,
    }
    record(
        controls, "evidence_bundle_valid_green",
        verify_evidence_bundle(bundle, payloads, source_hashes, tool_hashes) == []
    )
    missing = dict(payloads)
    missing.pop(EVIDENCE_INVENTORY[0])
    record(
        controls, "missing_artifact_rejected",
        "bundle_inventory_invalid" in verify_evidence_bundle(
            bundle, missing, source_hashes, tool_hashes
        )
    )
    stale_bundle = dict(bundle)
    stale_bundle["source_sha256_post"] = {}
    record(
        controls, "stale_artifact_rejected",
        "bundle_source_identity_invalid" in verify_evidence_bundle(
            stale_bundle, payloads, source_hashes, tool_hashes
        )
    )
    tampered = dict(payloads)
    tampered[EVIDENCE_INVENTORY[0]] += b"tampered"
    record(
        controls, "tampered_artifact_rejected",
        "bundle_artifact_hash_mismatch" in verify_evidence_bundle(
            bundle, tampered, source_hashes, tool_hashes
        )
    )
    incomplete = dict(bundle)
    incomplete["completed_artifacts"] = 0
    record(
        controls, "zero_artifact_count_rejected",
        "bundle_completed_artifacts_invalid" in verify_evidence_bundle(
            incomplete, payloads, source_hashes, tool_hashes
        )
    )
    return controls


def safe_failure_report(classification: str) -> dict[str, object]:
    return {
        "schema": 4,
        "status": "Failed",
        "classification": classification,
        "completed_controls": 0,
        "rerun_command": RERUN_COMMAND,
    }


def failure_class(failure: BaseException) -> str:
    if isinstance(failure, UnicodeError):
        return "source_encoding_rejected"
    if isinstance(failure, OSError):
        return "io_rejected"
    if isinstance(failure, ValueError):
        return "validation_rejected"
    return "gate_execution_rejected"


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
        destination_metadata = os.lstat(destination)
        destination_attributes = getattr(
            destination_metadata, "st_file_attributes", 0
        )
        if stat.S_ISLNK(destination_metadata.st_mode) or (
            reparse_flag and destination_attributes & reparse_flag
        ):
            raise ValueError("report_identity_rejected")
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=".guardian-adversarial-report-", dir=destination.parent
    )
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, destination)
        observed, _digest = safe_read(destination, MAXIMUM_REPORT_BYTES)
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
        except (OSError, UnicodeError, ValueError) as failure:
            payload = (
                json.dumps(
                    safe_failure_report(failure_class(failure)),
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


def directory_aggregate(directory: Path) -> tuple[str, int]:
    directory_metadata = os.lstat(directory)
    reparse_flag = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0)
    directory_attributes = getattr(directory_metadata, "st_file_attributes", 0)
    if (
        stat.S_ISLNK(directory_metadata.st_mode)
        or (reparse_flag and directory_attributes & reparse_flag)
        or not stat.S_ISDIR(directory_metadata.st_mode)
    ):
        raise ValueError("red_directory_identity_rejected")
    entries = sorted(directory.iterdir(), key=lambda value: value.name)
    if not entries or len(entries) > 32:
        raise ValueError("red_directory_inventory_rejected")
    aggregate = hashlib.sha256()
    total = 0
    for entry in entries:
        before = os.lstat(entry)
        reparse_flag = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0)
        attributes = getattr(before, "st_file_attributes", 0)
        if stat.S_ISLNK(before.st_mode) or (reparse_flag and attributes & reparse_flag):
            raise ValueError("red_artifact_identity_rejected")
        if not stat.S_ISREG(before.st_mode) or before.st_size > MAXIMUM_REPORT_BYTES:
            raise ValueError("red_artifact_type_rejected")
        data = entry.read_bytes()
        after = os.lstat(entry)
        if (
            before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns
        ) != (
            after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns
        ) or len(data) != before.st_size:
            raise ValueError("red_artifact_changed_during_read")
        total += len(data)
        if total > MAXIMUM_BYTES:
            raise ValueError("red_directory_size_rejected")
        aggregate.update(entry.name.encode("utf-8") + b"\0" + data + b"\0")
    return aggregate.hexdigest(), total


def red_set_aggregate(directories: tuple[Path, ...]) -> tuple[str, int]:
    aggregate = hashlib.sha256()
    total = 0
    for directory in directories:
        digest, consumed = directory_aggregate(directory)
        total += consumed
        if total > 3 * MAXIMUM_BYTES:
            raise ValueError("red_set_size_rejected")
        relative = directory.relative_to(ROOT).as_posix()
        aggregate.update(
            relative.encode("utf-8") + b"\0" + digest.encode("ascii") + b"\0"
        )
    return aggregate.hexdigest(), total


def generated_reports_match_current_source(
    parsed: dict[str, dict[str, object]],
    source_hashes: dict[str, str],
    scanner_source_hashes: dict[str, str],
    tool_hashes: dict[str, str],
    runtime_hash: str,
    config_hash: str,
) -> bool:
    """Bind each generated result to this exact source/tool/runtime snapshot."""
    guardian = parsed["guardian_report.json"]
    scanner_self = parsed["scanner_self_test_report.json"]
    scanner_audit = parsed["scanner_audit_report.json"]
    wrapper = parsed["wrapper_report.json"]
    adversarial = parsed["adversarial_report.json"]
    guardian_sources = {
        "gleam": source_hashes[SOURCE_PATHS[0]],
        "ffi": source_hashes[SOURCE_PATHS[1]],
        "test": source_hashes[SOURCE_PATHS[2]],
        "test_ffi": source_hashes[SOURCE_PATHS[3]],
    }
    scanner_hash = tool_hashes["scripts/spawn_monitor_contract_audit.py"]
    guardian_hash = tool_hashes[
        "standards/audits/http1-guardian/guardian_contract_check.py"
    ]
    wrapper_hash = tool_hashes[
        "standards/audits/http1-guardian/"
        "spawn_monitor_dataflow_contract_check.py"
    ]
    adversarial_hash = tool_hashes[
        "standards/audits/http1-guardian/adversarial_contract_check.py"
    ]

    guardian_mutations = guardian.get("mutations")
    guardian_controls = guardian.get("adversarial_controls")
    guardian_exact = (
        guardian.get("schema") == 3
        and guardian.get("status") == "passed"
        and guardian.get("source_sha256_pre") == guardian_sources
        and guardian.get("source_sha256_post") == guardian_sources
        and guardian.get("source_stable") is True
        and guardian.get("scanner_sha256_pre") == guardian_hash
        and guardian.get("scanner_sha256_post") == guardian_hash
        and guardian.get("scanner_stable") is True
        and guardian.get("python_executable_sha256_pre") == runtime_hash
        and guardian.get("python_executable_sha256_post") == runtime_hash
        and guardian.get("python_executable_stable") is True
        and guardian.get("python_version") == EXPECTED_PYTHON_VERSION
        and guardian.get("python_tool_request") == "python@3.12.13"
        and guardian.get("mise_config_sha256_pre") == config_hash
        and guardian.get("mise_config_sha256_post") == config_hash
        and guardian.get("mise_config_stable") is True
        and guardian.get("rerun_command") == GUARDIAN_RERUN_COMMAND
        and isinstance(guardian_mutations, dict)
        and len(guardian_mutations) == 16
        and all(
            isinstance(result, dict)
            and result.get("changed") is True
            and result.get("detected") is True
            for result in guardian_mutations.values()
        )
        and isinstance(guardian_controls, list)
        and len(guardian_controls) == 2
        and all(
            isinstance(control, dict) and control.get("passed") is True
            for control in guardian_controls
        )
    )

    scanner_self_controls = scanner_self.get("controls")
    scanner_self_runtime = scanner_self.get("runtime")
    scanner_self_exact = (
        scanner_self.get("schema") == 2
        and scanner_self.get("kind") == "self_test"
        and scanner_self.get("status") == "Ready"
        and scanner_self.get("classification") == "passed"
        and scanner_self.get("completed_controls") == 34
        and isinstance(scanner_self_controls, list)
        and len(scanner_self_controls) == 34
        and all(
            isinstance(control, dict) and control.get("passed") is True
            for control in scanner_self_controls
        )
        and scanner_self.get("scanner_sha256_pre") == scanner_hash
        and scanner_self.get("scanner_sha256_post") == scanner_hash
        and scanner_self.get("scanner_stable") is True
        and isinstance(scanner_self_runtime, dict)
        and scanner_self_runtime.get("tool_request") == "python@3.12.13"
        and scanner_self_runtime.get("version") == EXPECTED_PYTHON_VERSION
        and scanner_self_runtime.get("executable_sha256") == runtime_hash
        and scanner_self_runtime.get("mise_config_sha256") == config_hash
        and scanner_self.get("rerun_command")
        == SCANNER_RERUN_COMMAND + " --self-test"
    )

    scanner_runtime = scanner_audit.get("runtime")
    scanner_audit_exact = (
        scanner_audit.get("schema") == 2
        and scanner_audit.get("kind") == "audit"
        and scanner_audit.get("status") == "Ready"
        and scanner_audit.get("classification") == "passed"
        and scanner_audit.get("completed_contracts") == 12
        and scanner_audit.get("findings") == []
        and scanner_audit.get("source_sha256_pre") == scanner_source_hashes
        and scanner_audit.get("source_sha256_post") == scanner_source_hashes
        and scanner_audit.get("source_stable") is True
        and scanner_audit.get("scanner_sha256_pre") == scanner_hash
        and scanner_audit.get("scanner_sha256_post") == scanner_hash
        and scanner_audit.get("scanner_stable") is True
        and isinstance(scanner_runtime, dict)
        and scanner_runtime.get("tool_request") == "python@3.12.13"
        and scanner_runtime.get("version") == EXPECTED_PYTHON_VERSION
        and scanner_runtime.get("executable_sha256") == runtime_hash
        and scanner_runtime.get("mise_config_sha256") == config_hash
        and scanner_audit.get("rerun_command") == SCANNER_RERUN_COMMAND
    )

    wrapper_controls = wrapper.get("identity_controls")
    wrapper_exact = (
        wrapper.get("schema") == 2
        and wrapper.get("status") == "Ready"
        and wrapper.get("classification") == "passed"
        and wrapper.get("source_sha256_pre") == scanner_source_hashes
        and wrapper.get("source_sha256_post") == scanner_source_hashes
        and wrapper.get("source_stable") is True
        and wrapper.get("scanner_sha256_pre") == scanner_hash
        and wrapper.get("scanner_sha256_post") == scanner_hash
        and wrapper.get("scanner_stable") is True
        and wrapper.get("checker_sha256_pre") == wrapper_hash
        and wrapper.get("checker_sha256_post") == wrapper_hash
        and wrapper.get("checker_stable") is True
        and wrapper.get("python_executable_sha256_pre") == runtime_hash
        and wrapper.get("python_executable_sha256_post") == runtime_hash
        and wrapper.get("python_executable_stable") is True
        and wrapper.get("python_version") == EXPECTED_PYTHON_VERSION
        and wrapper.get("python_tool_request") == "python@3.12.13"
        and wrapper.get("mise_config_sha256_pre") == config_hash
        and wrapper.get("mise_config_sha256_post") == config_hash
        and wrapper.get("mise_config_stable") is True
        and wrapper.get("rerun_command") == WRAPPER_RERUN_COMMAND
        and wrapper.get("expected_controls") == sorted(
            control["name"] for control in scanner_self_controls
            if isinstance(control, dict) and isinstance(control.get("name"), str)
        )
        and wrapper.get("observed_controls") == wrapper.get("expected_controls")
        and isinstance(wrapper_controls, list)
        and len(wrapper_controls) == 11
        and all(
            isinstance(control, dict) and control.get("passed") is True
            for control in wrapper_controls
        )
    )

    adversarial_runtime = adversarial.get("runtime")
    adversarial_controls = adversarial.get("controls")
    adversarial_exact = (
        adversarial.get("schema") == 4
        and adversarial.get("status") == "Ready"
        and adversarial.get("classification") == "passed"
        and adversarial.get("completed_controls") == 36
        and isinstance(adversarial_controls, list)
        and len(adversarial_controls) == 36
        and all(
            isinstance(control, dict) and control.get("passed") is True
            for control in adversarial_controls
        )
        and adversarial.get("source_sha256_pre") == source_hashes
        and adversarial.get("source_sha256_post") == source_hashes
        and adversarial.get("source_stable") is True
        and adversarial.get("tool_sha256_pre") == tool_hashes
        and adversarial.get("tool_sha256_post") == tool_hashes
        and adversarial.get("tool_stable") is True
        and adversarial.get("checker_sha256_pre") == adversarial_hash
        and adversarial.get("checker_sha256_post") == adversarial_hash
        and adversarial.get("checker_stable") is True
        and isinstance(adversarial_runtime, dict)
        and adversarial_runtime.get("tool_request") == "python@3.12.13"
        and adversarial_runtime.get("version") == EXPECTED_PYTHON_VERSION
        and adversarial_runtime.get("executable_sha256_pre") == runtime_hash
        and adversarial_runtime.get("executable_sha256_post") == runtime_hash
        and adversarial_runtime.get("executable_stable") is True
        and adversarial_runtime.get("mise_config_sha256_pre") == config_hash
        and adversarial_runtime.get("mise_config_sha256_post") == config_hash
        and adversarial_runtime.get("mise_config_stable") is True
        and adversarial.get("rerun_command") == RERUN_COMMAND
    )
    return all(
        (
            guardian_exact,
            scanner_self_exact,
            scanner_audit_exact,
            wrapper_exact,
            adversarial_exact,
        )
    )


def assemble_evidence(destination: Path) -> tuple[int, dict[str, object]]:
    """Assemble and verify current-source evidence from exact generated inputs."""
    try:
        evidence_root = destination.parent
        report_paths = {
            "guardian_report.json": evidence_root / "guardian_report.json",
            "scanner_self_test_report.json": evidence_root / "scanner_self_test_report.json",
            "scanner_audit_report.json": evidence_root / "scanner_audit_report.json",
            "wrapper_report.json": evidence_root / "wrapper_report.json",
            "adversarial_report.json": evidence_root / "adversarial_report.json",
        }
        payloads: dict[str, bytes] = {}
        parsed: dict[str, dict[str, object]] = {}
        for name, path in report_paths.items():
            data, _digest = safe_read(path, MAXIMUM_REPORT_BYTES)
            value = json.loads(data.decode("utf-8", errors="strict"))
            if not isinstance(value, dict):
                raise ValueError("generated_report_not_map")
            payloads[name] = data
            parsed[name] = value

        red_sets = {
            "v2_red.aggregate": (
                ROOT / "build/root-validation/http1-handler-guardian-deadline-v2-red",
                ROOT / "build/root-validation/spawn-monitor-dataflow-v2-red",
            ),
            "v3_red.aggregate": (
                ROOT / "build/root-validation/http1-handler-guardian-deadline-v3-starvation-red",
                ROOT / "build/root-validation/http1-handler-v3-adversarial-red",
            ),
            "v4_red.aggregate": (
                ROOT / "build/root-validation/http1-handler-guardian-v4-provisional-red",
            ),
        }
        red_aggregates: dict[str, dict[str, object]] = {}
        for name, directories in red_sets.items():
            digest, consumed = red_set_aggregate(directories)
            payload = (digest + "\n").encode("ascii")
            atomic_publish(evidence_root / name, payload)
            payloads[name] = payload
            red_aggregates[name] = {"sha256": digest, "bytes": consumed}
        red_directory = red_sets["v4_red.aggregate"][0]
        red_digest = str(red_aggregates["v4_red.aggregate"]["sha256"])
        red_bytes = int(red_aggregates["v4_red.aggregate"]["bytes"])
        for name, source in (
            ("v2_invalidation.json", ROOT / "build/root-validation/http1-handler-guardian-v2-invalidated.json"),
            ("v3_invalidation.json", ROOT / "build/root-validation/http1-handler-guardian-v3-invalidated.json"),
        ):
            data, _digest = safe_read(source, MAXIMUM_REPORT_BYTES)
            atomic_publish(evidence_root / name, data)
            payloads[name] = data

        red_report = json.loads(safe_text(red_directory / "stdout.jsonl")[0])
        red_controls = red_report.get("controls", []) if isinstance(red_report, dict) else []
        red_failed = sum(
            1 for control in red_controls
            if isinstance(control, dict) and control.get("passed") is not True
        )
        v3_red_report = json.loads(safe_text(
            ROOT / "build/root-validation/http1-handler-v3-adversarial-red/stdout.jsonl"
        )[0])
        v3_failed = sum(
            1 for control in v3_red_report.get("controls", [])
            if isinstance(control, dict) and control.get("passed") is not True
        ) if isinstance(v3_red_report, dict) else -1
        v3_record = json.loads(safe_text(
            ROOT / "build/root-validation/http1-handler-guardian-v3-static-green/evidence.json"
        )[0])
        v3_invalidation = json.loads(payloads["v3_invalidation.json"].decode("utf-8"))
        v2_invalidation = json.loads(payloads["v2_invalidation.json"].decode("utf-8"))
        replacement = "build/root-validation/http1-handler-guardian-v4-static-green/evidence.json"
        history_exact = (
            v3_failed == 10
            and v3_record.get("status") == "Rejected"
            and v3_record.get("red", {}).get("adversarial", {}).get("failed_controls") == v3_failed
            and v3_invalidation.get("actual_adversarial_red_failed_controls") == v3_failed
            and v3_invalidation.get("replacement") == replacement
            and v2_invalidation.get("replacement") == replacement
        )
        expected_statuses = {
            "guardian_report.json": "passed",
            "scanner_self_test_report.json": "Ready",
            "scanner_audit_report.json": "Ready",
            "wrapper_report.json": "Ready",
            "adversarial_report.json": "Ready",
        }
        generated_green = all(
            parsed[name].get("status") == status
            for name, status in expected_statuses.items()
        )
        runtime_versions = (
            parsed["guardian_report.json"].get("python_version"),
            parsed["scanner_self_test_report.json"].get("runtime", {}).get("version"),
            parsed["scanner_audit_report.json"].get("runtime", {}).get("version"),
            parsed["wrapper_report.json"].get("python_version"),
            parsed["adversarial_report.json"].get("runtime", {}).get("version"),
        )
        source_pre = snapshot(SOURCE_PATHS)
        scanner_source_pre = snapshot(SCANNER_SOURCE_PATHS)
        tool_pre = snapshot(TOOL_PATHS)
        runtime_path = Path(sys.executable).resolve(strict=True)
        runtime_hash_pre = safe_hash(runtime_path, MAXIMUM_TOOL_BYTES)
        config_pre = safe_hash(ROOT / ".mise.toml")
        source_post = snapshot(SOURCE_PATHS)
        scanner_source_post = snapshot(SCANNER_SOURCE_PATHS)
        tool_post = snapshot(TOOL_PATHS)
        runtime_hash_post = safe_hash(runtime_path, MAXIMUM_TOOL_BYTES)
        config_post = safe_hash(ROOT / ".mise.toml")
        reports_match_current_source = (
            source_pre == source_post
            and scanner_source_pre == scanner_source_post
            and tool_pre == tool_post
            and runtime_hash_pre == runtime_hash_post
            and config_pre == config_post
            and generated_reports_match_current_source(
                parsed,
                source_pre,
                scanner_source_pre,
                tool_pre,
                runtime_hash_pre,
                config_pre,
            )
        )
        bundle: dict[str, object] = {
            "schema": 4,
            "status": "Ready" if (
                generated_green
                and red_report.get("status") == "Red"
                and red_report.get("completed_controls") == 19
                and red_report.get("failed_controls") == red_failed == 19
                and history_exact
                and reports_match_current_source
                and all(version == EXPECTED_PYTHON_VERSION for version in runtime_versions)
                and source_pre == source_post
                and tool_pre == tool_post
                and runtime_hash_pre == runtime_hash_post
                and config_pre == config_post
            ) else "Failed",
            "classification": "passed",
            "revision": "v4",
            "completed_artifacts": len(EVIDENCE_INVENTORY),
            "artifact_sha256": {
                name: hashlib.sha256(payload).hexdigest()
                for name, payload in payloads.items()
            },
            "source_sha256_pre": source_pre,
            "source_sha256_post": source_post,
            "source_stable": source_pre == source_post,
            "scanner_audited_source_sha256_pre": scanner_source_pre,
            "scanner_audited_source_sha256_post": scanner_source_post,
            "scanner_audited_source_stable": (
                scanner_source_pre == scanner_source_post
            ),
            "tool_sha256_pre": tool_pre,
            "tool_sha256_post": tool_post,
            "tool_stable": tool_pre == tool_post,
            "runtime": {
                "tool_request": "python@3.12.13",
                "version": ".".join(str(part) for part in sys.version_info[:3]),
                "executable_sha256_pre": runtime_hash_pre,
                "executable_sha256_post": runtime_hash_post,
                "executable_stable": runtime_hash_pre == runtime_hash_post,
                "mise_config_sha256_pre": config_pre,
                "mise_config_sha256_post": config_post,
                "mise_config_stable": config_pre == config_post,
            },
            "red": {
                "status": red_report.get("status"),
                "completed_controls": red_report.get("completed_controls"),
                "failed_controls": red_failed,
                "directory_aggregate_sha256": red_digest,
                "directory_bytes": red_bytes,
                "runtime_version": red_report.get("runtime", {}).get("version"),
                "runtime_classification": "provisional_red_runtime",
                "aggregates": red_aggregates,
                "v3_actual_failed_controls": v3_failed,
            },
            "generated_reports_current": reports_match_current_source,
            "invalidation": {"v2": "Rejected", "v3": "Rejected"},
            "rerun_command": EVIDENCE_RERUN_COMMAND,
        }
        verification = verify_evidence_bundle(bundle, payloads, source_pre, tool_pre)
        if verification:
            bundle["status"] = "Failed"
            bundle["classification"] = verification[0]
        elif bundle["status"] != "Ready":
            bundle["classification"] = "generated_evidence_incomplete"
        encoded = (json.dumps(bundle, sort_keys=True, separators=(",", ":")) + "\n").encode("utf-8")
        atomic_publish(destination, encoded)
        return (0 if bundle["status"] == "Ready" else 1), bundle
    except (AttributeError, KeyError, OSError, TypeError, UnicodeError, ValueError) as failure:
        return 1, safe_failure_report(failure_class(failure))


def main(report_path: str | None = None) -> int:
    controls: list[dict[str, object]] = []
    try:
        checker_pre = safe_hash(Path(__file__).resolve())
        source_pre = snapshot(SOURCE_PATHS)
        tool_pre = snapshot(TOOL_PATHS)
        config_pre = safe_hash(ROOT / ".mise.toml")
        runtime_path = Path(sys.executable).resolve(strict=True)
        runtime_pre = safe_hash(runtime_path, MAXIMUM_TOOL_BYTES)
        source_text = {
            "gleam": safe_text(ROOT / SOURCE_PATHS[0])[0],
            "ffi": safe_text(ROOT / SOURCE_PATHS[1])[0],
            "test": safe_text(ROOT / SOURCE_PATHS[2])[0],
            "test_ffi": safe_text(ROOT / SOURCE_PATHS[3])[0],
        }
        manifest = json.loads(safe_text(MANIFEST)[0])
        guardian = load(GUARDIAN_CHECKER, "http1_guardian_v4_gate")
        scanner = load(SPAWN_SCANNER, "spawn_monitor_v4_gate")
        wrapper = load(SPAWN_WRAPPER, "spawn_monitor_wrapper_v4_gate")
        controls.extend(guardian_controls(guardian, source_text))
        controls.extend(scanner_controls(scanner, source_text))
        controls.extend(wrapper_controls(wrapper))
        controls.extend(evidence_controls(source_pre, tool_pre))
        secret = "PRIVATE_PATH_ENDPOINT_PID"
        classified = [
            safe_failure_report(failure_class(OSError(secret))),
            safe_failure_report(failure_class(UnicodeError(secret))),
        ]
        encoded_failures = json.dumps(classified, sort_keys=True)
        record(
            controls,
            "failure_classification_redacted",
            secret not in encoded_failures
            and classified[0].get("classification") == "io_rejected"
            and classified[1].get("classification") == "source_encoding_rejected",
        )
        record(
            controls,
            "tracked_manifest_inventory_exact",
            isinstance(manifest, dict)
            and manifest.get("schema") == 4
            and manifest.get("canonical_command") == EVIDENCE_RERUN_COMMAND
            and manifest.get("source_inventory") == list(SOURCE_PATHS)
            and manifest.get("tool_inventory") == list(TOOL_PATHS)
            and manifest.get("evidence_inventory") == list(EVIDENCE_INVENTORY)
            and manifest.get("expected_contracts") == 12
            and manifest.get("expected_scanner_controls") == 34
            and manifest.get("expected_adversarial_controls") == 36,
        )
        source_post = snapshot(SOURCE_PATHS)
        tool_post = snapshot(TOOL_PATHS)
        checker_post = safe_hash(Path(__file__).resolve())
        config_post = safe_hash(ROOT / ".mise.toml")
        runtime_post = safe_hash(runtime_path, MAXIMUM_TOOL_BYTES)
        record(controls, "source_identity_stable", source_pre == source_post)
        record(controls, "tool_identity_stable", tool_pre == tool_post)
        record(controls, "checker_identity_stable", checker_pre == checker_post)
        record(controls, "config_identity_stable", config_pre == config_post)
        record(controls, "runtime_identity_stable", runtime_pre == runtime_post)
        record(
            controls, "runtime_version_exact",
            ".".join(str(part) for part in sys.version_info[:3])
            == EXPECTED_PYTHON_VERSION
        )
    except (AttributeError, KeyError, OSError, TypeError, UnicodeError, ValueError) as failure:
        emit_report(safe_failure_report(failure_class(failure)), report_path)
        return 1

    failed = [control for control in controls if control.get("passed") is not True]
    report: dict[str, object] = {
        "schema": 4,
        "status": "Ready" if not failed else "Failed",
        "classification": "passed" if not failed else str(failed[0]["name"]),
        "completed_controls": len(controls),
        "controls": controls,
        "source_sha256_pre": source_pre,
        "source_sha256_post": source_post,
        "source_stable": source_pre == source_post,
        "tool_sha256_pre": tool_pre,
        "tool_sha256_post": tool_post,
        "tool_stable": tool_pre == tool_post,
        "checker_sha256_pre": checker_pre,
        "checker_sha256_post": checker_post,
        "checker_stable": checker_pre == checker_post,
        "runtime": {
            "tool_request": "python@3.12.13",
            "implementation": sys.implementation.name,
            "version": ".".join(str(part) for part in sys.version_info[:3]),
            "executable_sha256_pre": runtime_pre,
            "executable_sha256_post": runtime_post,
            "executable_stable": runtime_pre == runtime_post,
            "mise_config_sha256_pre": config_pre,
            "mise_config_sha256_post": config_post,
            "mise_config_stable": config_pre == config_post,
        },
        "limits": {
            "source_file_bytes": MAXIMUM_BYTES,
            "tool_bytes": MAXIMUM_TOOL_BYTES,
            "report_bytes": MAXIMUM_REPORT_BYTES,
        },
        "rerun_command": RERUN_COMMAND,
    }
    encoded = json.dumps(report, sort_keys=True, separators=(",", ":"))
    if len(encoded.encode("utf-8")) > MAXIMUM_REPORT_BYTES:
        emit_report(safe_failure_report("report_limit_rejected"), report_path)
        return 1
    published = emit_report(report, report_path)
    return 0 if not failed and published else 1


def cli_main() -> int:
    try:
        parser = argparse.ArgumentParser(add_help=True)
        parser.add_argument("--report")
        parser.add_argument("--assemble")
        arguments = parser.parse_args()
        if arguments.assemble:
            status, report = assemble_evidence(Path(arguments.assemble))
            published = emit_report(report, None)
            return status if published else 1
        return main(arguments.report)
    except (KeyboardInterrupt, SystemExit, GeneratorExit):
        raise
    except BaseException:
        try:
            emit_report(safe_failure_report("internal_rejected"), None)
        except BaseException:
            pass
        return 2


if __name__ == "__main__":
    raise SystemExit(cli_main())

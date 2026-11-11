#!/usr/bin/env python3

# SPDX-FileCopyrightText: 2026 the http contributors
# SPDX-License-Identifier: MIT OR Apache-2.0

"""Closed schemas for every RFC 9114 v4 terminal evidence object."""

from __future__ import annotations

import json
import re
from typing import Any


HASH = re.compile(r"^[0-9a-f]{64}$")
RUN_ID = re.compile(r"^[0-9a-f]{32}$")
CATEGORY = re.compile(r"^[a-z0-9_]{1,120}$")
TERMINAL_STATUSES = {
    "ObservedRed",
    "StaticReady",
    "AuditPending",
    "Ready",
    "UnexpectedGreen",
    "Rejected",
}


class SchemaRejected(ValueError):
    pass


def closed_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise SchemaRejected("json_duplicate_key")
        value[key] = item
    return value


def object_from(data: bytes, category: str) -> dict[str, Any]:
    try:
        value = json.loads(data, object_pairs_hook=closed_pairs)
    except SchemaRejected:
        raise
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise SchemaRejected(f"{category}_invalid_json") from error
    if not isinstance(value, dict):
        raise SchemaRejected(f"{category}_not_object")
    return value


def exact_keys(value: Any, keys: set[str]) -> bool:
    return isinstance(value, dict) and set(value) == keys


def counts_valid(value: Any) -> bool:
    return exact_keys(value, {"Implemented", "NotApplicable", "Open"}) and all(
        item is None or (isinstance(item, int) and not isinstance(item, bool) and item >= 0)
        for item in value.values()
    )


def counts_complete_or_absent(value: Any) -> bool:
    if not counts_valid(value):
        return False
    items = list(value.values())
    return all(item is None for item in items) or (
        all(isinstance(item, int) and not isinstance(item, bool) for item in items)
        and sum(items) == 215
    )


def reviewed_controls(manifest: dict[str, Any], source_state: str) -> list[dict[str, str]]:
    if (
        not exact_keys(
            manifest,
            {"schema", "manifest_kind", "generation", "count", "result_shape", "controls"},
        )
        or manifest.get("schema") != 1
        or manifest.get("manifest_kind") != "rfc9114_v4_reviewed_application_controls"
        or manifest.get("generation") != 4
        or manifest.get("count") != 45
        or manifest.get("result_shape") != ["name", "observed"]
        or not isinstance(manifest.get("controls"), list)
        or len(manifest["controls"]) != 45
    ):
        raise SchemaRejected("control_manifest_invalid")
    expected: list[dict[str, str]] = []
    names: set[str] = set()
    for item in manifest["controls"]:
        if not exact_keys(item, {"name", "observed"}) or not isinstance(item["name"], str):
            raise SchemaRejected("control_manifest_invalid")
        observed = item["observed"]
        if isinstance(observed, dict):
            if not exact_keys(observed, {"pre_review", "reviewed"}):
                raise SchemaRejected("control_manifest_invalid")
            result = observed.get(source_state)
        else:
            result = observed
        if not isinstance(result, str) or item["name"] in names:
            raise SchemaRejected("control_manifest_invalid")
        names.add(item["name"])
        expected.append({"name": item["name"], "observed": result})
    return expected


def gate_controls(manifest: dict[str, Any]) -> list[dict[str, str]]:
    if (
        not exact_keys(
            manifest,
            {"schema", "manifest_kind", "generation", "count", "result_shape", "controls"},
        )
        or manifest.get("schema") != 1
        or manifest.get("manifest_kind") != "rfc9114_v4_reviewed_gate_controls"
        or manifest.get("generation") != 4
        or manifest.get("count") != 22
        or manifest.get("result_shape") != ["name", "observed"]
        or not isinstance(manifest.get("controls"), list)
        or len(manifest["controls"]) != 22
    ):
        raise SchemaRejected("gate_control_manifest_invalid")
    expected: list[dict[str, str]] = []
    for item in manifest["controls"]:
        if (
            not exact_keys(item, {"name", "observed"})
            or not isinstance(item["name"], str)
            or not isinstance(item["observed"], str)
        ):
            raise SchemaRejected("gate_control_manifest_invalid")
        expected.append({"name": item["name"], "observed": item["observed"]})
    if len({item["name"] for item in expected}) != len(expected):
        raise SchemaRejected("gate_control_manifest_invalid")
    return expected


def validate_control_prefix(
    controls: Any, completed: Any, expected: list[dict[str, str]], *, gate: bool = False
) -> None:
    prefix = "gate_" if gate else ""
    if (
        not isinstance(completed, int)
        or isinstance(completed, bool)
        or completed < 0
        or completed > len(expected)
        or not isinstance(controls, list)
        or len(controls) != completed
    ):
        raise SchemaRejected(f"{prefix}control_inventory_count_mismatch")
    for index, item in enumerate(controls):
        if not exact_keys(item, {"name", "observed"}) or item != expected[index]:
            raise SchemaRejected(f"{prefix}control_inventory_entry_mismatch")


REPORT_KEYS = {
    "schema",
    "report_kind",
    "status",
    "shareable",
    "mode",
    "run_id",
    "failure_category",
    "identity",
    "source_state_before",
    "source_state_after",
    "applied_now",
    "before_counts",
    "after_counts",
    "reviewed_counts",
    "scope",
    "completion",
    "self_test_controls",
    "expected_output_sha256",
    "result_requirements_sha256",
    "target_transaction",
    "diagnostic_evidence",
    "rerun",
}


def validate_python_identity(value: Any, allowed: list[dict[str, Any]], mise_hash: str) -> None:
    keys = {
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
    if not isinstance(allowed, list) or not 0 < len(allowed) <= 16:
        raise SchemaRejected("python_identity_not_allowed")
    normalized: list[tuple[tuple[str, Any], ...]] = []
    for item in allowed:
        if (
            not exact_keys(item, keys)
            or item.get("implementation") != "cpython"
            or not isinstance(item.get("version"), str)
            or not re.fullmatch(r"3\.12\.\d+", item["version"])
            or not isinstance(item.get("executable_sha256"), str)
            or not HASH.fullmatch(item["executable_sha256"])
            or not isinstance(item.get("executable_path_sha256"), str)
            or not HASH.fullmatch(item["executable_path_sha256"])
            or not isinstance(item.get("executable_link_count"), int)
            or isinstance(item["executable_link_count"], bool)
            or not 1 <= item["executable_link_count"] <= 64
            or item.get("os") not in {"windows", "linux", "darwin"}
            or not isinstance(item.get("architecture"), str)
            or not re.fullmatch(r"[a-z0-9_.-]{1,64}", item["architecture"])
            or item.get("mise_config_sha256") != mise_hash
            or item.get("identity_kind") != "mise_resolved_cpython"
        ):
            raise SchemaRejected("python_identity_not_allowed")
        normalized.append(tuple(sorted(item.items())))
    if len(set(normalized)) != len(normalized):
        raise SchemaRejected("python_identity_not_allowed")
    if (
        not exact_keys(value, keys)
        or value not in allowed
        or value.get("mise_config_sha256") != mise_hash
        or not isinstance(value.get("executable_path_sha256"), str)
        or not HASH.fullmatch(value["executable_path_sha256"])
        or not isinstance(value.get("executable_link_count"), int)
        or isinstance(value["executable_link_count"], bool)
        or not 1 <= value["executable_link_count"] <= 64
    ):
        raise SchemaRejected("python_identity_not_allowed")


def validate_transaction(value: Any, expected_run_id: str) -> None:
    if not exact_keys(
        value,
        {"required", "run_id", "journal_sha256", "reconciled"},
    ) or not isinstance(value.get("required"), bool):
        raise SchemaRejected("report_schema_mismatch")
    if value["required"]:
        if (
            not isinstance(value.get("run_id"), str)
            or not RUN_ID.fullmatch(value["run_id"])
            or value["run_id"] != expected_run_id
        ):
            raise SchemaRejected("report_schema_mismatch")
        if not isinstance(value.get("journal_sha256"), str) or not HASH.fullmatch(value["journal_sha256"]):
            raise SchemaRejected("report_schema_mismatch")
    elif value.get("run_id") is not None or value.get("journal_sha256") is not None:
        raise SchemaRejected("report_schema_mismatch")
    reconciled = value.get("reconciled")
    if not isinstance(reconciled, list) or len(reconciled) > 4096:
        raise SchemaRejected("report_schema_mismatch")
    reconciled_run_ids: list[str] = []
    for item in reconciled:
        if (
            not exact_keys(item, {"run_id", "state", "journal_sha256"})
            or not isinstance(item["run_id"], str)
            or not RUN_ID.fullmatch(item["run_id"])
            or item["state"] not in {"RecoveredCommitted", "RecoveredOriginal", "Rejected"}
            or not isinstance(item["journal_sha256"], str)
            or not HASH.fullmatch(item["journal_sha256"])
        ):
            raise SchemaRejected("report_schema_mismatch")
        reconciled_run_ids.append(item["run_id"])
    if (
        reconciled_run_ids != sorted(reconciled_run_ids)
        or len(set(reconciled_run_ids)) != len(reconciled_run_ids)
        or expected_run_id in reconciled_run_ids
    ):
        raise SchemaRejected("report_schema_mismatch")


def validate_report(
    data: bytes,
    mode: str,
    expected_run_id: str,
    *,
    anchor: dict[str, Any],
    controls_manifest: dict[str, Any],
) -> dict[str, Any]:
    report = object_from(data, "report")
    if not exact_keys(report, REPORT_KEYS):
        raise SchemaRejected("report_schema_mismatch")
    status = report.get("status")
    source_before = report.get("source_state_before")
    source_after = report.get("source_state_after")
    if (
        report.get("schema") != 4
        or report.get("report_kind") != "rfc9114_v4_review_application"
        or status not in TERMINAL_STATUSES
        or report.get("shareable") is not True
        or report.get("mode") != mode
        or report.get("run_id") != expected_run_id
        or not RUN_ID.fullmatch(expected_run_id)
        or source_before not in {"pre_review", "reviewed", "unknown"}
        or source_after not in {"pre_review", "reviewed", "unknown"}
        or not isinstance(report.get("applied_now"), bool)
        or not counts_valid(report.get("before_counts"))
        or not counts_valid(report.get("after_counts"))
        or report.get("reviewed_counts") != {"Implemented": 31, "NotApplicable": 36, "Open": 148}
    ):
        raise SchemaRejected("report_schema_mismatch")
    category = report.get("failure_category")
    if category is not None and (not isinstance(category, str) or not CATEGORY.fullmatch(category)):
        raise SchemaRejected("report_schema_mismatch")
    if status == "Rejected" and category is None:
        raise SchemaRejected("report_schema_mismatch")
    semantic_states = {
        "ObservedRed": ("red", "pre_review", "pre_review", False, "expected_red_observed"),
        "StaticReady": (
            "self-test",
            "pre_review",
            "pre_review",
            False,
            "application_pending",
        ),
        "UnexpectedGreen": (
            "red",
            "reviewed",
            "reviewed",
            False,
            "red_control_unexpected_green",
        ),
    }
    if status in semantic_states and (
        mode,
        source_before,
        source_after,
        report["applied_now"],
        category,
    ) != semantic_states[status]:
        raise SchemaRejected("report_status_semantics_mismatch")
    if status in {"AuditPending", "Ready"}:
        allowed_transition = (
            mode == "apply"
            and source_before == "pre_review"
            and source_after == "reviewed"
            and report["applied_now"] is True
        ) or (
            mode in {"apply", "self-test"}
            and source_before == "reviewed"
            and source_after == "reviewed"
            and report["applied_now"] is False
        )
        expected_category = None if status == "Ready" else "independent_audit_pending"
        if not allowed_transition or category != expected_category:
            raise SchemaRejected("report_status_semantics_mismatch")
    identity = report.get("identity")
    if not exact_keys(identity, {"anchor_sha256", "member_sha256", "python"}):
        raise SchemaRejected("report_schema_mismatch")
    if identity.get("anchor_sha256") != anchor.get("anchor_sha256") or identity.get("member_sha256") != anchor.get("members"):
        raise SchemaRejected("report_identity_mismatch")
    python_policy = anchor.get("python_policy")
    if (
        not exact_keys(
            python_policy,
            {"allowed", "configured_version", "resolution", "mise_config_sha256"},
        )
        or python_policy.get("resolution") != "mise"
        or python_policy.get("mise_config_sha256") != anchor["members"].get(".mise.toml")
        or not isinstance(python_policy.get("configured_version"), str)
        or not re.fullmatch(r"3\.12\.\d+", python_policy["configured_version"])
        or not isinstance(python_policy["allowed"], list)
        or any(
            not isinstance(item, dict)
            or item.get("version") != python_policy["configured_version"]
            for item in python_policy["allowed"]
        )
    ):
        raise SchemaRejected("anchor_python_policy_invalid")
    validate_python_identity(
        identity.get("python"),
        python_policy["allowed"],
        anchor["members"].get(".mise.toml", ""),
    )
    if identity["python"].get("version") != python_policy["configured_version"]:
        raise SchemaRejected("python_version_config_mismatch")
    if (
        report.get("scope")
        != {"standard": "RFC9114", "canonical_rows": 215, "independently_assessed_rows": 161}
        or not exact_keys(report.get("completion"), {"phase", "controls_expected", "controls_completed"})
        or report["completion"].get("controls_expected") != 45
        or not isinstance(report["completion"].get("phase"), str)
        or not CATEGORY.fullmatch(report["completion"]["phase"])
        or not isinstance(report.get("expected_output_sha256"), str)
        or not HASH.fullmatch(report["expected_output_sha256"])
        or not isinstance(report.get("result_requirements_sha256"), str)
        or not HASH.fullmatch(report["result_requirements_sha256"])
        or report.get("rerun")
        != {
            "command": f"python -I -B standards/audits/rfc9114_v4_bootstrap.py cycle {mode}",
            "expected_run_id_required": True,
        }
    ):
        raise SchemaRejected("report_schema_mismatch")
    expected = reviewed_controls(controls_manifest, source_before if source_before != "unknown" else "pre_review")
    completed = report["completion"]["controls_completed"]
    validate_control_prefix(report.get("self_test_controls"), completed, expected)
    if status != "Rejected" and completed != 45:
        raise SchemaRejected("control_inventory_count_mismatch")
    validate_transaction(report.get("target_transaction"), expected_run_id)
    if report["applied_now"] != report["target_transaction"]["required"]:
        raise SchemaRejected("report_transaction_semantics_mismatch")
    diagnostic = report.get("diagnostic_evidence")
    if not exact_keys(
        diagnostic,
        {"safe_fixture_run_id", "manifest_sha256", "artifact_count"},
    ):
        raise SchemaRejected("report_schema_mismatch")
    diagnostic_values = (
        diagnostic.get("safe_fixture_run_id"),
        diagnostic.get("manifest_sha256"),
        diagnostic.get("artifact_count"),
    )
    diagnostic_absent = diagnostic_values == (None, None, None)
    diagnostic_complete = (
        diagnostic.get("safe_fixture_run_id") == expected_run_id
        and isinstance(diagnostic.get("manifest_sha256"), str)
        and bool(HASH.fullmatch(diagnostic["manifest_sha256"]))
        and isinstance(diagnostic.get("artifact_count"), int)
        and not isinstance(diagnostic["artifact_count"], bool)
        and 0 < diagnostic["artifact_count"] <= 4096
    )
    if (
        (not diagnostic_absent and not diagnostic_complete)
        or (status != "Rejected" and not diagnostic_complete)
    ):
        raise SchemaRejected("report_diagnostic_evidence_mismatch")
    requirements_policy = anchor.get("requirements_policy")
    if not exact_keys(requirements_policy, {"before_sha256", "after_sha256"}):
        raise SchemaRejected("anchor_requirements_policy_invalid")
    expected_result = {
        "pre_review": requirements_policy["before_sha256"],
        "reviewed": requirements_policy["after_sha256"],
    }.get(source_after)
    if (
        not counts_complete_or_absent(report["before_counts"])
        or not counts_complete_or_absent(report["after_counts"])
        or report["expected_output_sha256"] != requirements_policy["after_sha256"]
        or report["result_requirements_sha256"]
        not in {
            requirements_policy["before_sha256"],
            requirements_policy["after_sha256"],
        }
        or (
            expected_result is not None
            and report["result_requirements_sha256"] != expected_result
        )
        or (
            source_before == "unknown"
            and any(value is not None for value in report["before_counts"].values())
        )
        or (
            source_before != "unknown"
            and any(value is None for value in report["before_counts"].values())
        )
        or (
            source_after == "unknown"
            and any(value is not None for value in report["after_counts"].values())
        )
        or (
            source_after != "unknown"
            and any(value is None for value in report["after_counts"].values())
        )
    ):
        raise SchemaRejected("report_completeness_mismatch")
    if status != "Rejected" and (
        report["result_requirements_sha256"] != expected_result
    ):
        raise SchemaRejected("report_status_semantics_mismatch")
    audit = anchor.get("independent_audit")
    if status == "Ready" and (
        not exact_keys(audit, {"status", "report_sha256"})
        or audit.get("status") != "Approved"
        or not isinstance(audit.get("report_sha256"), str)
        or not HASH.fullmatch(audit["report_sha256"])
    ):
        raise SchemaRejected("ready_without_independent_audit")
    return report


def validate_gate_report(
    data: bytes,
    *,
    anchor: dict[str, Any],
    controls_manifest: dict[str, Any],
) -> dict[str, Any]:
    report = object_from(data, "gate_report")
    keys = {
        "schema",
        "report_kind",
        "status",
        "shareable",
        "anchor_sha256",
        "controls_expected",
        "controls_completed",
        "controls",
        "rerun_command",
    }
    if (
        not exact_keys(report, keys)
        or report.get("schema") != 4
        or report.get("report_kind") != "rfc9114_v4_gate_self_test"
        or report.get("status") != "StaticReady"
        or report.get("shareable") is not True
        or report.get("anchor_sha256") != anchor.get("anchor_sha256")
        or report.get("controls_expected") != 22
        or report.get("rerun_command")
        != "python -I -B standards/audits/rfc9114_v4_bootstrap.py gate-self-test"
    ):
        raise SchemaRejected("gate_report_schema_mismatch")
    expected = gate_controls(controls_manifest)
    validate_control_prefix(report.get("controls"), report.get("controls_completed"), expected, gate=True)
    if report.get("controls_completed") != 22:
        raise SchemaRejected("gate_control_inventory_count_mismatch")
    return report

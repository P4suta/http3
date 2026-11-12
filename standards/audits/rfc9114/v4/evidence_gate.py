#!/usr/bin/env python3

# SPDX-FileCopyrightText: 2026 the http contributors
# SPDX-License-Identifier: MIT OR Apache-2.0

"""Strict consumer and adversarial gate for RFC 9114 v4 evidence."""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import platform
import re
import stat
import sys
import tempfile
from typing import Any, Callable


GATE_PATH = "standards/audits/rfc9114/v4/evidence_gate.py"
TOOL_PATH = "standards/audits/rfc9114/v4/apply_review.py"
LAUNCHER_PATH = "standards/audits/rfc9114/v4/launcher.py"
IO_PATH = "standards/audits/rfc9114/v4/io_state.py"
SCHEMA_PATH = "standards/audits/rfc9114/v4/report_schema.py"
APP_CONTROL_PATH = "standards/audits/rfc9114/v4/reviewed-controls.json"
GATE_CONTROL_PATH = "standards/audits/rfc9114/v4/reviewed-gate-controls.json"
ARTIFACT_MANIFEST_PATH = "standards/audits/rfc9114/v4/artifact-manifest.json"
REQUIREMENTS_PATH = "standards/requirements.json"
MISE_PATH = ".mise.toml"
CI_PATH = ".github/workflows/ci.yml"


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def checked_binding() -> dict[str, Any]:
    value = globals().get("__rfc9114_v4_binding__")
    if not isinstance(value, dict) or set(value) != {
        "schema",
        "root",
        "anchor",
        "anchor_relative",
        "anchor_snapshot",
        "anchor_sha256",
        "snapshots",
        "python_identity",
        "launcher_snapshot",
        "launcher_sha256",
    }:
        raise RuntimeError("gate_binding_invalid")
    anchor = value.get("anchor")
    snapshots = value.get("snapshots")
    if (
        value.get("schema") != 4
        or not isinstance(anchor, dict)
        or not isinstance(anchor.get("members"), dict)
        or not isinstance(value.get("anchor_relative"), str)
        or not isinstance(value.get("anchor_snapshot"), bytes)
        or digest(value["anchor_snapshot"]) != value.get("anchor_sha256")
        or value.get("anchor_sha256") != anchor.get("anchor_sha256")
        or not isinstance(snapshots, dict)
        or set(snapshots) != set(anchor["members"])
        or not 0 < len(snapshots) <= 1024
        or not all(isinstance(relative, str) for relative in snapshots)
        or len(
            {
                os.path.normcase(
                    os.path.normpath(relative.replace("/", os.sep))
                )
                for relative in snapshots
            }
        )
        != len(snapshots)
    ):
        raise RuntimeError("gate_binding_invalid")
    for relative, expected in anchor["members"].items():
        snapshot = snapshots.get(relative)
        if not isinstance(snapshot, bytes) or digest(snapshot) != expected:
            raise RuntimeError("anchor_member_identity_mismatch")
    return value


BINDING = checked_binding()
ROOT = Path(BINDING["root"])
ANCHOR = BINDING["anchor"]
SNAPSHOTS = BINDING["snapshots"]
EVIDENCE = ROOT / "build/root-validation/rfc9114-v4"


def load_snapshot(relative: str, name: str) -> dict[str, Any]:
    namespace = {
        "__name__": name,
        "__file__": f"<{name}-snapshot>",
        "__package__": None,
        "__builtins__": __builtins__,
    }
    exec(compile(SNAPSHOTS[relative], f"<{name}-snapshot>", "exec"), namespace, namespace)
    return namespace


IO = load_snapshot(IO_PATH, "rfc9114_v4_gate_io")
SCHEMA = load_snapshot(SCHEMA_PATH, "rfc9114_v4_gate_schema")
Rejected = IO["Rejected"]
APP_CONTROLS = SCHEMA["object_from"](
    SNAPSHOTS[APP_CONTROL_PATH], "application_control_manifest"
)
GATE_CONTROLS = SCHEMA["object_from"](
    SNAPSHOTS[GATE_CONTROL_PATH], "gate_control_manifest"
)


def load_tool() -> dict[str, Any]:
    namespace = {
        "__name__": "rfc9114_v4_gate_tool",
        "__file__": "<rfc9114-v4-gate-tool-snapshot>",
        "__package__": None,
        "__builtins__": __builtins__,
        "__rfc9114_v4_binding__": BINDING,
    }
    exec(
        compile(SNAPSHOTS[TOOL_PATH], "<rfc9114-v4-gate-tool-snapshot>", "exec"),
        namespace,
        namespace,
    )
    return namespace


TOOL = load_tool()
ToolRejected = TOOL["Rejected"]


def expect_rejected(expected: str, operation: Callable[[], Any]) -> None:
    try:
        operation()
    except (Rejected, ToolRejected, SCHEMA["SchemaRejected"]) as error:
        if str(error) != expected:
            raise Rejected("gate_self_test_wrong_rejection") from error
    else:
        raise Rejected("gate_self_test_mutant_accepted")


def validate_snapshot(relative: str, snapshot: bytes) -> None:
    if relative not in ANCHOR["members"] or digest(snapshot) != ANCHOR["members"][relative]:
        raise Rejected("anchor_member_identity_mismatch")


def validate_runtime_python() -> None:
    identity = BINDING["python_identity"]
    try:
        SCHEMA["validate_python_identity"](
            identity,
            ANCHOR["python_policy"]["allowed"],
            ANCHOR["members"][MISE_PATH],
        )
    except (KeyError, TypeError, SCHEMA["SchemaRejected"]) as error:
        raise Rejected("python_identity_not_allowed") from error
    executable = Path(os.path.realpath(os.path.abspath(sys.executable)))
    executable_before = os.stat(executable, follow_symlinks=False)
    executable_bytes = IO["strict_read_path"](
        executable, require_single_link=False
    )
    executable_after = os.stat(executable, follow_symlinks=False)
    if (
        executable_before.st_dev,
        executable_before.st_ino,
        executable_before.st_nlink,
    ) != (
        executable_after.st_dev,
        executable_after.st_ino,
        executable_after.st_nlink,
    ):
        raise Rejected("execution_identity_drift")
    actual = {
        "implementation": sys.implementation.name,
        "version": ".".join(str(value) for value in sys.version_info[:3]),
        "executable_sha256": digest(executable_bytes),
        "executable_path_sha256": digest(
            os.fsencode(os.path.normcase(os.path.normpath(os.fspath(executable))))
        ),
        "executable_link_count": executable_after.st_nlink,
        "os": platform.system().lower(),
        "architecture": platform.machine().lower(),
        "mise_config_sha256": ANCHOR["members"][MISE_PATH],
        "identity_kind": identity["identity_kind"],
    }
    if actual != identity:
        raise Rejected("execution_identity_drift")


def tracked_gate() -> None:
    expected_anchor_keys = {
        "schema",
        "anchor_kind",
        "generation",
        "anchor_sha256",
        "members",
        "requirements_policy",
        "python_policy",
        "independent_audit",
    }
    independent_audit = ANCHOR.get("independent_audit")
    audit_pending = independent_audit == {
        "status": "Pending",
        "report_sha256": None,
    }
    audit_approved = (
        isinstance(independent_audit, dict)
        and set(independent_audit) == {"status", "report_sha256"}
        and independent_audit.get("status") == "Approved"
        and isinstance(independent_audit.get("report_sha256"), str)
        and bool(re.fullmatch(r"[0-9a-f]{64}", independent_audit["report_sha256"]))
    )
    if (
        set(ANCHOR) != expected_anchor_keys
        or ANCHOR.get("schema") != 4
        or ANCHOR.get("anchor_kind") != "rfc9114_v4_external_source_tree"
        or ANCHOR.get("generation") != 4
        or ANCHOR.get("requirements_policy")
        != {
            "before_sha256": "6d9c34e9311c73cc9540b5b51a133c755d6225d88015068169a44369842bf533",
            "after_sha256": "76bdca016340f90dc8a75157b5fc4b04951e151eae3ed1cd000000ba0cd7115a",
        }
        or not (audit_pending or audit_approved)
    ):
        raise Rejected("anchor_schema_mismatch")
    anchor_current = IO["strict_read"](ROOT, BINDING["anchor_relative"])
    if (
        anchor_current != BINDING["anchor_snapshot"]
        or digest(anchor_current) != BINDING["anchor_sha256"]
    ):
        raise Rejected("external_anchor_disk_drift")
    for relative, snapshot in SNAPSHOTS.items():
        observed = IO["strict_read"](ROOT, relative)
        if observed != snapshot:
            raise Rejected("anchor_member_disk_drift")
    requirements_hash = digest(IO["strict_read"](ROOT, REQUIREMENTS_PATH))
    if requirements_hash not in set(ANCHOR["requirements_policy"].values()):
        raise Rejected("requirements_identity_mismatch")
    artifact_manifest = SCHEMA["object_from"](
        SNAPSHOTS[ARTIFACT_MANIFEST_PATH], "artifact_manifest"
    )
    anchored_artifacts = {
        relative: sha256
        for relative, sha256 in ANCHOR["members"].items()
        if relative != ARTIFACT_MANIFEST_PATH
    }
    if (
        not isinstance(artifact_manifest, dict)
        or set(artifact_manifest) != {"schema", "manifest_kind", "generation", "members"}
        or artifact_manifest.get("schema") != 4
        or artifact_manifest.get("manifest_kind") != "rfc9114_v4_anchored_artifacts"
        or artifact_manifest.get("generation") != 4
        or artifact_manifest.get("members") != anchored_artifacts
    ):
        raise Rejected("artifact_manifest_mismatch")
    validate_runtime_python()


def validate_complete_application_controls(value: Any, source_state: str = "pre_review") -> None:
    expected = SCHEMA["reviewed_controls"](APP_CONTROLS, source_state)
    if not isinstance(value, list) or len(value) != len(expected):
        raise SCHEMA["SchemaRejected"]("control_inventory_count_mismatch")
    SCHEMA["validate_control_prefix"](value, len(value), expected)
    if value != expected:
        raise SCHEMA["SchemaRejected"]("control_inventory_entry_mismatch")


def validate_complete_gate_controls(value: Any) -> None:
    expected = SCHEMA["gate_controls"](GATE_CONTROLS)
    if not isinstance(value, list) or len(value) != len(expected):
        raise SCHEMA["SchemaRejected"]("gate_control_inventory_count_mismatch")
    SCHEMA["validate_control_prefix"](value, len(value), expected, gate=True)
    if value != expected:
        raise SCHEMA["SchemaRejected"]("gate_control_inventory_entry_mismatch")


def independent_recovery_files(directory: Path) -> None:
    paths = [
        directory / name
        for name in (
            "original.bin",
            "intended.bin",
            "claimed.bin",
            "published.bin",
            "concurrent.bin",
        )
        if os.path.lexists(directory / name)
    ]
    identities: set[tuple[int, int]] = set()
    for path in paths:
        observed = IO["strict_read_path"](path, with_metadata=True)
        if not isinstance(observed, tuple) or len(observed) != 2:
            raise Rejected("report_transaction_evidence_mismatch")
        _data, metadata = observed
        if (
            not stat.S_ISREG(metadata.st_mode)
            or stat.S_ISLNK(metadata.st_mode)
            or IO["is_reparse"](metadata)
            or metadata.st_nlink != 1
            or (metadata.st_dev, metadata.st_ino) in identities
        ):
            raise Rejected("report_transaction_evidence_mismatch")
        identities.add((metadata.st_dev, metadata.st_ino))


def validate_preparation_recovery(
    directory: Path, run_id: str, journal_sha256: str
) -> None:
    IO["assert_plain_directory"](
        directory, "report_transaction_evidence_mismatch"
    )
    marker_path = directory / "preparation-rejected.json"
    marker_data = IO["strict_read_path"](marker_path)
    if digest(marker_data) != journal_sha256:
        raise Rejected("report_transaction_evidence_mismatch")
    marker = IO["json_object"](marker_data, "transaction_preparation")
    artifact_sha256 = marker.get("artifact_sha256")
    stage_hashes: list[str] = []
    observed_artifacts: dict[str, str | None] = {
        "original": None,
        "intended": None,
    }
    for child in IO["bounded_directory_entries"](
        directory, "report_transaction_evidence_mismatch"
    ):
        if child == marker_path:
            continue
        if child.name == "original.bin":
            role = "original"
        elif child.name == "intended.bin":
            role = "intended"
        elif re.fullmatch(
            r"\.transaction\.json\.[A-Za-z0-9_-]+\.tmp", child.name
        ):
            role = "journal_stage"
        else:
            raise Rejected("report_transaction_evidence_mismatch")
        data = IO["strict_read_path"](child)
        if role == "journal_stage":
            stage_hashes.append(digest(data))
        else:
            observed_artifacts[role] = digest(data)
    if (
        marker
        != {
            "schema": 4,
            "journal_kind": "rfc9114_v4_transaction_preparation",
            "run_id": run_id,
            "state": "Rejected",
            "failure_category": "transaction_preparation_incomplete",
            "artifact_sha256": artifact_sha256,
            "journal_stage_count": len(stage_hashes),
            "journal_stage_aggregate_sha256": digest(
                "".join(sorted(stage_hashes)).encode("ascii")
            ),
        }
        or artifact_sha256 != observed_artifacts
        or (
            observed_artifacts["original"] is not None
            and observed_artifacts["original"]
            != ANCHOR["requirements_policy"]["before_sha256"]
        )
        or (
            observed_artifacts["intended"] is not None
            and observed_artifacts["intended"]
            != ANCHOR["requirements_policy"]["after_sha256"]
        )
    ):
        raise Rejected("report_transaction_evidence_mismatch")
    independent_recovery_files(directory)


def validate_reconciled_transaction(item: dict[str, Any]) -> None:
    run_id = item["run_id"]
    directory = EVIDENCE / "transactions" / f"run-{run_id}"
    preparation = (
        EVIDENCE
        / "transactions"
        / f"abandoned-preparation-{run_id}"
    )
    directory_exists = os.path.lexists(directory)
    preparation_exists = os.path.lexists(preparation)
    if directory_exists == preparation_exists:
        raise Rejected("report_transaction_evidence_mismatch")
    if not directory_exists:
        if item["state"] != "Rejected":
            raise Rejected("report_transaction_evidence_mismatch")
        validate_preparation_recovery(
            preparation, run_id, item["journal_sha256"]
        )
        return
    IO["assert_plain_directory"](
        directory, "report_transaction_evidence_mismatch"
    )
    journal_data = IO["strict_read_path"](directory / "transaction.json")
    if digest(journal_data) != item["journal_sha256"]:
        raise Rejected("report_transaction_evidence_mismatch")
    transaction = IO["TargetTransaction"]._load_transaction(
        ROOT / REQUIREMENTS_PATH,
        EVIDENCE / "transactions",
        directory,
    )
    journal = IO["json_object"](journal_data, "transaction_journal")
    artifacts = journal.get("artifacts")
    terminal_artifacts_valid = True
    if transaction.state == "RecoveredCommitted":
        terminal_artifacts_valid = artifacts == {
            "original": ANCHOR["requirements_policy"]["before_sha256"],
            "intended": ANCHOR["requirements_policy"]["after_sha256"],
            "claimed": ANCHOR["requirements_policy"]["before_sha256"],
            "published": ANCHOR["requirements_policy"]["after_sha256"],
            "concurrent": None,
        }
    elif transaction.state == "RecoveredOriginal":
        terminal_artifacts_valid = artifacts == {
            "original": ANCHOR["requirements_policy"]["before_sha256"],
            "intended": ANCHOR["requirements_policy"]["after_sha256"],
            "claimed": ANCHOR["requirements_policy"]["before_sha256"],
            "published": None,
            "concurrent": None,
        }
    if (
        transaction.state != item["state"]
        or transaction.journal_sha256 != digest(journal_data)
        or not terminal_artifacts_valid
        or journal.get("expected_sha256")
        != ANCHOR["requirements_policy"]["before_sha256"]
        or journal.get("intended_sha256")
        != ANCHOR["requirements_policy"]["after_sha256"]
    ):
        raise Rejected("report_transaction_evidence_mismatch")
    independent_recovery_files(directory)


def validate_transaction_evidence(report: dict[str, Any]) -> None:
    transaction = report["target_transaction"]
    for reconciled in transaction["reconciled"]:
        validate_reconciled_transaction(reconciled)
    if not transaction["required"]:
        return
    run_id = transaction["run_id"]
    directory = EVIDENCE / "transactions" / f"run-{run_id}"
    IO["assert_plain_directory"](
        directory, "report_transaction_evidence_mismatch"
    )
    journal_data = IO["strict_read_path"](directory / "transaction.json")
    if digest(journal_data) != transaction["journal_sha256"]:
        raise Rejected("report_transaction_evidence_mismatch")
    persisted = IO["TargetTransaction"]._load_transaction(
        ROOT / REQUIREMENTS_PATH,
        EVIDENCE / "transactions",
        directory,
    )
    journal = IO["json_object"](journal_data, "transaction_journal")
    expected_before = ANCHOR["requirements_policy"]["before_sha256"]
    expected_after = ANCHOR["requirements_policy"]["after_sha256"]
    if (
        persisted.state != "Committed"
        or persisted.journal_sha256 != digest(journal_data)
        or journal.get("expected_sha256") != expected_before
        or journal.get("intended_sha256") != expected_after
        or journal.get("artifacts")
        != {
            "original": expected_before,
            "intended": expected_after,
            "claimed": expected_before,
            "published": expected_after,
            "concurrent": None,
        }
    ):
        raise Rejected("report_transaction_evidence_mismatch")
    independent_recovery_files(directory)


def validate_report(data: bytes, mode: str, run_id: str) -> None:
    try:
        report = SCHEMA["validate_report"](
            data,
            mode,
            run_id,
            anchor=ANCHOR,
            controls_manifest=APP_CONTROLS,
        )
    except SCHEMA["SchemaRejected"] as error:
        raise Rejected(str(error)) from error
    try:
        validate_transaction_evidence(report)
    except Rejected:
        raise
    except (KeyError, OSError, TypeError, ValueError) as error:
        raise Rejected("report_transaction_evidence_mismatch") from error


def consume(mode: str, expected_run_id: str | None) -> dict[str, Any]:
    tracked_gate()
    report_bytes = IO["consume_pointer_pair"](
        EVIDENCE, mode, expected_run_id, validate_report
    )
    report = SCHEMA["object_from"](report_bytes, "report")
    if digest(IO["strict_read"](ROOT, REQUIREMENTS_PATH)) != report[
        "result_requirements_sha256"
    ]:
        raise Rejected("report_result_source_mismatch")
    diagnostic = report["diagnostic_evidence"]
    if diagnostic["safe_fixture_run_id"] is not None:
        observed = TOOL["checked_safe_fixture_summary"](report["run_id"])
        if observed != diagnostic:
            raise Rejected("report_diagnostic_evidence_mismatch")
    tracked_gate()
    return report


def self_test() -> list[dict[str, str]]:
    controls: list[dict[str, str]] = []

    TOOL["ensure_evidence_directory"]()

    def add(name: str, observed: str) -> None:
        controls.append({"name": name, "observed": observed})

    tracked_gate()
    add("tracked_anchor", "accepted")

    substitutions = (
        (TOOL_PATH, "coordinated_tool_substitution"),
        (LAUNCHER_PATH, "coordinated_launcher_substitution"),
        (GATE_PATH, "coordinated_gate_substitution"),
        (ARTIFACT_MANIFEST_PATH, "coordinated_manifest_substitution"),
        (MISE_PATH, "coordinated_mise_substitution"),
        (CI_PATH, "coordinated_ci_substitution"),
    )
    for relative, name in substitutions:
        expect_rejected(
            "anchor_member_identity_mismatch",
            lambda relative=relative: validate_snapshot(relative, SNAPSHOTS[relative] + b"\n"),
        )
        add(name, "anchor_member_identity_mismatch")

    tool_mutant = SNAPSHOTS[TOOL_PATH].replace(
        b"def run(mode: str, run_id: str) -> int:\n",
        b"def run(mode: str, run_id: str) -> int:\n    return 0\n",
        1,
    )
    if tool_mutant == SNAPSHOTS[TOOL_PATH]:
        raise Rejected("tool_mutant_fixture_drift")
    expect_rejected("anchor_member_identity_mismatch", lambda: validate_snapshot(TOOL_PATH, tool_mutant))
    add("tool_early_return", "anchor_member_identity_mismatch")

    launcher_mutant = SNAPSHOTS[LAUNCHER_PATH].replace(
        b"def launch(mode: str, run_id: str) -> int:\n",
        b"def launch(mode: str, run_id: str) -> int:\n    return 0\n",
        1,
    )
    if launcher_mutant == SNAPSHOTS[LAUNCHER_PATH]:
        raise Rejected("launcher_mutant_fixture_drift")
    expect_rejected("anchor_member_identity_mismatch", lambda: validate_snapshot(LAUNCHER_PATH, launcher_mutant))
    add("launcher_early_return", "anchor_member_identity_mismatch")

    gate_mutant = SNAPSHOTS[GATE_PATH].replace(
        b"def self_test() -> list[dict[str, str]]:\n",
        b"def self_test() -> list[dict[str, str]]:\n    return []\n",
        1,
    )
    if gate_mutant == SNAPSHOTS[GATE_PATH]:
        raise Rejected("gate_mutant_fixture_drift")
    expect_rejected(
        "anchor_member_identity_mismatch",
        lambda: validate_snapshot(GATE_PATH, gate_mutant),
    )

    expected_app = SCHEMA["reviewed_controls"](APP_CONTROLS, "pre_review")
    expect_rejected("control_inventory_count_mismatch", lambda: validate_complete_application_controls([]))
    add("application_inventory_empty", "control_inventory_count_mismatch")
    expect_rejected("control_inventory_count_mismatch", lambda: validate_complete_application_controls(expected_app[:-1]))
    add("application_inventory_missing", "control_inventory_count_mismatch")
    substituted = copy_controls(expected_app)
    substituted[-1] = {"name": "invented_control", "observed": "accepted"}
    expect_rejected("control_inventory_entry_mismatch", lambda: validate_complete_application_controls(substituted))
    add("application_inventory_substitution", "control_inventory_entry_mismatch")
    reordered = copy_controls(expected_app)
    reordered[0], reordered[1] = reordered[1], reordered[0]
    expect_rejected("control_inventory_entry_mismatch", lambda: validate_complete_application_controls(reordered))
    add("application_inventory_reorder", "control_inventory_entry_mismatch")

    expected_gate = SCHEMA["gate_controls"](GATE_CONTROLS)
    original_self_test = globals()["self_test"]
    globals()["self_test"] = lambda: []
    try:
        expect_rejected(
            "gate_control_inventory_count_mismatch", publish_gate_self_test
        )
    finally:
        globals()["self_test"] = original_self_test
    add("gate_inventory_empty", "gate_control_inventory_count_mismatch")
    expect_rejected("gate_control_inventory_count_mismatch", lambda: validate_complete_gate_controls(expected_gate[:-1]))
    add("gate_inventory_missing", "gate_control_inventory_count_mismatch")
    substituted_gate = copy_controls(expected_gate)
    substituted_gate[-1] = {"name": "invented_gate_control", "observed": "accepted"}
    expect_rejected("gate_control_inventory_entry_mismatch", lambda: validate_complete_gate_controls(substituted_gate))
    add("gate_inventory_substitution", "gate_control_inventory_entry_mismatch")
    reordered_gate = copy_controls(expected_gate)
    reordered_gate[0], reordered_gate[1] = reordered_gate[1], reordered_gate[0]
    expect_rejected(
        "gate_control_inventory_entry_mismatch",
        lambda: validate_complete_gate_controls(reordered_gate),
    )

    strict_run = "1" * 32
    valid = TOOL["valid_rejected_report"]("self-test", strict_run)
    extra = json.loads(valid)
    extra["secret"] = "sensitive"
    expect_rejected("report_schema_mismatch", lambda: validate_report(json.dumps(extra).encode(), "self-test", strict_run))
    add("strict_report_extra_top_level", "report_schema_mismatch")
    nested = json.loads(valid)
    nested["identity"]["pid"] = 123
    expect_rejected("report_schema_mismatch", lambda: validate_report(json.dumps(nested).encode(), "self-test", strict_run))
    add("strict_report_extra_nested", "report_schema_mismatch")
    incomplete = json.loads(valid)
    del incomplete["completion"]
    expect_rejected("report_schema_mismatch", lambda: validate_report(json.dumps(incomplete).encode(), "self-test", strict_run))
    add("rejected_report_incomplete", "report_schema_mismatch")

    static_ready = TOOL["make_report"](
        mode="self-test",
        run_id=strict_run,
        status="StaticReady",
        failure="application_pending",
        phase="complete",
        controls=expected_app,
        source_before="pre_review",
        source_after="pre_review",
        applied_now=False,
        before_counts={"Implemented": 8, "NotApplicable": 0, "Open": 207},
        after_counts={"Implemented": 8, "NotApplicable": 0, "Open": 207},
        result_hash=ANCHOR["requirements_policy"]["before_sha256"],
        transaction=TOOL["no_transaction"](),
        diagnostic_evidence_override={
            "safe_fixture_run_id": strict_run,
            "manifest_sha256": "0" * 64,
            "artifact_count": 1,
        },
    )
    validate_report(static_ready, "self-test", strict_run)
    control_extra = json.loads(static_ready)
    control_extra["self_test_controls"][0]["secret"] = "sensitive"
    expect_rejected(
        "control_inventory_entry_mismatch",
        lambda: validate_report(
            json.dumps(control_extra).encode(), "self-test", strict_run
        ),
    )
    control_non_object = json.loads(static_ready)
    control_non_object["self_test_controls"][0] = "sensitive"
    expect_rejected(
        "control_inventory_entry_mismatch",
        lambda: validate_report(
            json.dumps(control_non_object).encode(), "self-test", strict_run
        ),
    )
    duplicate = static_ready.replace(
        b'{\n  "after_counts"', b'{\n  "status": "StaticReady",\n  "after_counts"', 1
    )
    expect_rejected(
        "json_duplicate_key",
        lambda: validate_report(duplicate, "self-test", strict_run),
    )

    safe_parent = EVIDENCE / "safe-fixtures"
    if not os.path.lexists(safe_parent):
        try:
            os.mkdir(safe_parent)
        except FileExistsError:
            pass
    IO["assert_plain_directory"](safe_parent, "report_directory_alias_rejected")
    diagnostic_run = digest(os.urandom(32))[:32]
    diagnostic_root = safe_parent / f"run-{diagnostic_run}"
    os.mkdir(diagnostic_root)
    diagnostic_artifact = diagnostic_root / "original.bin"
    diagnostic_manifest = diagnostic_root / "fixture-summary.json"
    IO["durable_new_file"](diagnostic_artifact, b"safe-diagnostic-fixture\n")
    diagnostic_data = IO["strict_read_path"](diagnostic_artifact)
    IO["atomic_write"](
        diagnostic_manifest,
        IO["json_bytes"](
            {
                "schema": 4,
                "manifest_kind": "rfc9114_v4_safe_fixture_manifest",
                "run_id": diagnostic_run,
                "application_controls": 45,
                "infrastructure_controls": 31,
                "artifact_count": 1,
                "artifacts": [
                    {
                        "relative": "original.bin",
                        "bytes": len(diagnostic_data),
                        "sha256": digest(diagnostic_data),
                    }
                ],
            }
        ),
        prefix="diagnostic_fixture_manifest",
    )
    TOOL["checked_safe_fixture_summary"](diagnostic_run)
    unlisted_root = diagnostic_root / "unlisted"
    os.mkdir(unlisted_root)
    unlisted_artifact = unlisted_root / "original.bin"
    IO["durable_new_file"](unlisted_artifact, b"unlisted-safe-fixture\n")
    expect_rejected(
        "fixture_summary_completeness_mismatch",
        lambda: TOOL["checked_safe_fixture_summary"](diagnostic_run),
    )
    unlisted_artifact.unlink()
    unlisted_root.rmdir()
    IO["atomic_write"](
        diagnostic_artifact,
        b"tampered-diagnostic-fixture\n",
        prefix="diagnostic_fixture_mutant",
    )
    expect_rejected(
        "fixture_summary_identity_mismatch",
        lambda: TOOL["checked_safe_fixture_summary"](diagnostic_run),
    )
    diagnostic_artifact.unlink()
    diagnostic_manifest.unlink()
    diagnostic_root.rmdir()
    ready_mutant = json.loads(static_ready)
    ready_mutant["status"] = "Ready"
    ready_mutant["failure_category"] = None
    expect_rejected(
        "report_status_semantics_mismatch",
        lambda: validate_report(
            json.dumps(ready_mutant).encode(), "self-test", strict_run
        ),
    )

    with tempfile.TemporaryDirectory(prefix="rfc9114-v4-gate-", dir=EVIDENCE) as name:
        base = Path(name)
        expect_rejected(
            "expected_run_id_required",
            lambda: IO["consume_pointer_pair"](base, "self-test", None, validate_report),
        )
        expect_rejected(
            "report_mode_invalid",
            lambda: IO["consume_pointer_pair"](
                base, "../../../outside", strict_run, validate_report
            ),
        )
        add("mandatory_expected_run_missing", "expected_run_id_required")
        store = IO["ReportStore"](
            base, "self-test", strict_run, validate_report
        )
        store.begin()
        try:
            store.publish(valid, validate_report)
        finally:
            store.close()
        expect_rejected(
            "report_run_id_mismatch",
            lambda: IO["consume_pointer_pair"](base, "self-test", "2" * 32, validate_report),
        )
        add("stale_expected_run", "report_run_id_mismatch")

        alias = base / "alias-report.json"
        source = base / "source-report.json"
        IO["durable_new_file"](source, b"{}\n")
        os.link(source, alias)
        expect_rejected("input_alias_rejected", lambda: IO["strict_read_path"](alias))
        add("gate_input_alias", "input_alias_rejected")

    validate_complete_gate_controls(controls)
    return controls


def copy_controls(value: list[dict[str, str]]) -> list[dict[str, str]]:
    return [{"name": item["name"], "observed": item["observed"]} for item in value]


def gate_report(controls: list[dict[str, str]]) -> bytes:
    report = {
        "schema": 4,
        "report_kind": "rfc9114_v4_gate_self_test",
        "status": "StaticReady",
        "shareable": True,
        "anchor_sha256": ANCHOR["anchor_sha256"],
        "controls_expected": 22,
        "controls_completed": len(controls),
        "controls": controls,
        "rerun_command": "python -I -B standards/audits/rfc9114_v4_bootstrap.py gate-self-test",
    }
    data = (json.dumps(report, indent=2, sort_keys=True) + "\n").encode("utf-8")
    try:
        SCHEMA["validate_gate_report"](
            data, anchor=ANCHOR, controls_manifest=GATE_CONTROLS
        )
    except SCHEMA["SchemaRejected"] as error:
        raise Rejected(str(error)) from error
    return data


def publish_gate_self_test() -> bytes:
    TOOL["ensure_evidence_directory"]()
    controls = self_test()
    data = gate_report(controls)
    IO["atomic_write"](
        EVIDENCE / "gate-self-test.json", data, prefix="gate_self_test"
    )
    if IO["strict_read_path"](EVIDENCE / "gate-self-test.json") != data:
        raise Rejected("gate_report_readback_mismatch")
    tracked_gate()
    return data

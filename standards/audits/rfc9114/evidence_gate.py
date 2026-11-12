#!/usr/bin/env python3

# SPDX-FileCopyrightText: 2026 the http contributors
# SPDX-License-Identifier: MIT OR Apache-2.0

"""Consume the tracked RFC 9114 audit bundle and generated report pairs."""

from __future__ import annotations

import ast
import hashlib
import json
from pathlib import Path
import re
import os
import shutil
import sys
import tempfile
from typing import Any


ROOT = Path(__file__).resolve().parents[3]
AUDIT = Path(__file__).resolve().parent
EVIDENCE = ROOT / "build" / "root-validation" / "rfc9114-strict-inventory"
MAX_BYTES = 32 * 1024 * 1024
EXPECTED_FIXED = {
    "standards/audits/rfc9114/candidate-inventory.json": "ee42fef95798249cecf1b333cbf613a7ffa7f7a302cd0d3a7e438bd9efbf1243",
    "standards/audits/rfc9114/independent-review.json": "74cc3dc2db970c4eb3a36e9fd73f11886fbc80dfdc3ab3aa510a5b0b0170fbb9",
    "standards/audits/rfc9114/reviewed-source-manifest.json": "8d047bee7cd06e314449c525a6a32d6d090e53c886ddd42bb4472b99712f699a",
    "standards/audits/rfc9114/invalidation-chain.json": "52d00f658761d717ca02f27f46b83bdeffdeef41571da6ee6deae2f88716a342",
    "standards/audits/rfc9114/review-v1-invalidated.json": "97385909eb2f695b751889a0a3e5d212fb53b6193b183de8e3fdbafd22903009",
}
EXPECTED_REQUIREMENTS_BEFORE = "6d9c34e9311c73cc9540b5b51a133c755d6225d88015068169a44369842bf533"
EXPECTED_REQUIREMENTS_AFTER = "76bdca016340f90dc8a75157b5fc4b04951e151eae3ed1cd000000ba0cd7115a"
RUN_ID = re.compile(r"^[0-9a-f]{32}$")
EXPECTED_CONTROL_COUNT = 45


class Rejected(ValueError):
    pass


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def read_bounded(path: Path) -> bytes:
    try:
        with path.open("rb") as handle:
            data = handle.read(MAX_BYTES + 1)
            if len(data) > MAX_BYTES or handle.read(1):
                raise Rejected("input_too_large")
            return data
    except FileNotFoundError as error:
        raise Rejected("input_missing") from error
    except Rejected:
        raise
    except OSError as error:
        raise Rejected("input_read_failed") from error


def object_from(data: bytes, category: str) -> dict[str, Any]:
    try:
        value = json.loads(data)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise Rejected(f"{category}_invalid_json") from error
    if not isinstance(value, dict):
        raise Rejected(f"{category}_not_object")
    return value


def artifact_index(manifest: dict[str, Any]) -> dict[str, str]:
    artifacts = manifest.get("artifacts")
    if not isinstance(artifacts, list):
        raise Rejected("artifact_manifest_entries_invalid")
    indexed: dict[str, str] = {}
    for item in artifacts:
        if (
            not isinstance(item, dict)
            or set(item) != {"path", "sha256"}
            or not isinstance(item.get("path"), str)
            or not re.fullmatch(r"[0-9a-f]{64}", item.get("sha256", ""))
            or item["path"] in indexed
        ):
            raise Rejected("artifact_manifest_entry_invalid")
        indexed[item["path"]] = item["sha256"]
    return indexed


def launcher_tool_pin(launcher: bytes) -> str:
    try:
        module = ast.parse(launcher)
    except (SyntaxError, ValueError) as error:
        raise Rejected("launcher_syntax_invalid") from error
    values: list[str] = []
    for node in module.body:
        if (
            isinstance(node, ast.Assign)
            and len(node.targets) == 1
            and isinstance(node.targets[0], ast.Name)
            and node.targets[0].id == "EXPECTED_TOOL_SHA256"
            and isinstance(node.value, ast.Constant)
            and isinstance(node.value.value, str)
        ):
            values.append(node.value.value)
    if len(values) != 1 or not re.fullmatch(r"[0-9a-f]{64}", values[0]):
        raise Rejected("launcher_tool_pin_invalid")
    return values[0]


def named_definition(
    module: ast.Module, class_name: str | None, function_name: str
) -> ast.FunctionDef:
    body: list[ast.stmt] = module.body
    if class_name is not None:
        classes = [
            node
            for node in body
            if isinstance(node, ast.ClassDef) and node.name == class_name
        ]
        if len(classes) != 1:
            raise Rejected("tool_contract_definition_missing")
        body = classes[0].body
    functions = [
        node
        for node in body
        if isinstance(node, ast.FunctionDef) and node.name == function_name
    ]
    if len(functions) != 1:
        raise Rejected("tool_contract_definition_missing")
    return functions[0]


def call_name(call: ast.Call) -> str:
    current: ast.expr = call.func
    parts: list[str] = []
    while isinstance(current, ast.Attribute):
        parts.append(current.attr)
        current = current.value
    if isinstance(current, ast.Name):
        parts.append(current.id)
    return ".".join(reversed(parts))


def is_self_attribute(node: ast.AST, name: str) -> bool:
    return (
        isinstance(node, ast.Attribute)
        and isinstance(node.value, ast.Name)
        and node.value.id == "self"
        and node.attr == name
    )


def tool_contract(tool: bytes) -> None:
    try:
        module = ast.parse(tool)
    except (SyntaxError, ValueError) as error:
        raise Rejected("tool_syntax_invalid") from error
    replace = named_definition(module, "LosslessTargetTransaction", "replace")
    calls = sorted(
        (node for node in ast.walk(replace) if isinstance(node, ast.Call)),
        key=lambda node: (node.lineno, node.col_offset),
    )
    claim_positions = [
        index
        for index, call in enumerate(calls)
        if call_name(call) == "os.replace"
        and len(call.args) == 2
        and is_self_attribute(call.args[0], "target")
        and is_self_attribute(call.args[1], "claimed_path")
    ]
    publish_positions = [
        index
        for index, call in enumerate(calls)
        if call_name(call) == "os.link"
        and len(call.args) == 2
        and is_self_attribute(call.args[0], "intended_path")
        and is_self_attribute(call.args[1], "target")
    ]
    overwrite_calls = [
        call
        for call in calls
        if call_name(call) == "os.replace"
        and len(call.args) == 2
        and is_self_attribute(call.args[1], "target")
    ]
    hook_names = {
        call.args[1].value
        for call in calls
        if call_name(call) == "invoke_hook"
        and len(call.args) >= 2
        and isinstance(call.args[1], ast.Constant)
        and isinstance(call.args[1].value, str)
    }
    if (
        len(claim_positions) != 1
        or len(publish_positions) != 1
        or claim_positions[0] >= publish_positions[0]
        or overwrite_calls
        or hook_names
        != {
            "after_recovery",
            "after_expected_validation",
            "after_claim",
            "before_publish",
            "after_publish",
            "before_commit",
        }
    ):
        raise Rejected("lossless_transaction_contract_mismatch")

    semantic = named_definition(module, None, "semantic_self_test")
    if sum(
        1
        for node in ast.walk(semantic)
        if isinstance(node, ast.Call) and call_name(node) == "validate_control_inventory"
    ) != 1:
        raise Rejected("mandatory_inventory_contract_mismatch")

    post = named_definition(module, None, "post_publication_validate")
    post_names = [
        call_name(node)
        for node in ast.walk(post)
        if isinstance(node, ast.Call)
    ]
    for required in (
        "exact_file_bytes",
        "checked_source_manifest",
        "checked_launch_binding",
        "audited_python_identity",
        "platform_identity",
    ):
        if required not in post_names:
            raise Rejected("post_publication_revalidation_contract_mismatch")

    execute = named_definition(module, None, "execute")
    execute_calls = sorted(
        (node for node in ast.walk(execute) if isinstance(node, ast.Call)),
        key=lambda node: (node.lineno, node.col_offset),
    )
    names = [call_name(call) for call in execute_calls]
    try:
        stage = names.index("publisher.stage_final")
        first_post = names.index("post_publication_validate", stage + 1)
        commit = names.index("commit", first_post + 1)
        complete = names.index("publisher.complete_final", commit + 1)
        second_post = names.index("post_publication_validate", complete + 1)
        consume = names.index("consume_report_pair", second_post + 1)
    except ValueError as error:
        raise Rejected("publication_sequence_contract_mismatch") from error
    if not stage < first_post < commit < complete < second_post < consume:
        raise Rejected("publication_sequence_contract_mismatch")


def launcher_contract(launcher: bytes) -> None:
    try:
        module = ast.parse(launcher)
    except (SyntaxError, ValueError) as error:
        raise Rejected("launcher_syntax_invalid") from error
    execute = named_definition(module, None, "execute_snapshot")
    calls = [node for node in ast.walk(execute) if isinstance(node, ast.Call)]
    compile_calls = [call for call in calls if call_name(call) == "compile"]
    exec_calls = [call for call in calls if call_name(call) == "exec"]
    if (
        len(compile_calls) != 1
        or not compile_calls[0].args
        or not isinstance(compile_calls[0].args[0], ast.Name)
        or compile_calls[0].args[0].id != "tool_snapshot"
        or len(exec_calls) != 1
        or not exec_calls[0].args
        or not isinstance(exec_calls[0].args[0], ast.Name)
        or exec_calls[0].args[0].id != "code"
    ):
        raise Rejected("launcher_snapshot_execution_contract_mismatch")


def tracked_gate() -> dict[str, str]:
    manifest_bytes = read_bounded(AUDIT / "artifact-manifest.json")
    manifest = object_from(manifest_bytes, "artifact_manifest")
    if (
        manifest.get("schema") != 1
        or manifest.get("manifest_kind")
        != "rfc9114_strict_inventory_canonical_inputs"
        or manifest.get("standard") != "RFC9114"
        or manifest.get("generation") != 3
        or manifest.get("expected_requirements_before_sha256")
        != EXPECTED_REQUIREMENTS_BEFORE
        or manifest.get("expected_requirements_after_sha256")
        != EXPECTED_REQUIREMENTS_AFTER
        or manifest.get("release_policy")
        != {
            "pre_review_self_test_status": "StaticReady",
            "release_eligible_statuses": ["Ready"],
            "independent_review_required": True,
        }
    ):
        raise Rejected("artifact_manifest_contract_mismatch")
    indexed = artifact_index(manifest)
    expected_paths = set(EXPECTED_FIXED) | {
        "standards/audits/rfc9114/apply_review.py",
        "standards/audits/rfc9114/launcher.py",
        "standards/audits/rfc9114/evidence_gate.py",
        ".mise.toml",
    }
    if set(indexed) != expected_paths:
        raise Rejected("artifact_manifest_path_set_mismatch")
    for relative, expected in EXPECTED_FIXED.items():
        if indexed.get(relative) != expected:
            raise Rejected("fixed_artifact_manifest_mismatch")
    observed: dict[str, str] = {}
    contents: dict[str, bytes] = {}
    for relative in sorted(indexed):
        content = read_bounded(ROOT / Path(relative))
        contents[relative] = content
        observed[relative] = digest(content)
        if observed[relative] != indexed[relative]:
            raise Rejected("tracked_artifact_identity_mismatch")
    launcher = read_bounded(AUDIT / "launcher.py")
    if launcher_tool_pin(launcher) != indexed[
        "standards/audits/rfc9114/apply_review.py"
    ]:
        raise Rejected("launcher_tool_pin_mismatch")
    tool_contract(contents["standards/audits/rfc9114/apply_review.py"])
    launcher_contract(launcher)
    chain = object_from(
        read_bounded(AUDIT / "invalidation-chain.json"), "invalidation_chain"
    )
    entries = chain.get("entries")
    if (
        chain.get("current_generation") != 3
        or not isinstance(entries, list)
        or [item.get("generation") for item in entries if isinstance(item, dict)]
        != [1, 2]
        or any(item.get("status") != "Rejected" for item in entries)
    ):
        raise Rejected("invalidation_chain_contract_mismatch")
    return observed


def tool_control_inventory(tool: bytes, exact_pre_state: bool) -> tuple[tuple[str, str], ...]:
    try:
        module = ast.parse(tool)
    except (SyntaxError, ValueError) as error:
        raise Rejected("tool_syntax_invalid") from error
    assignments: dict[str, Any] = {}
    for node in module.body:
        if (
            isinstance(node, ast.Assign)
            and len(node.targets) == 1
            and isinstance(node.targets[0], ast.Name)
            and node.targets[0].id
            in {"BASE_CONTROL_NAMES", "INFRASTRUCTURE_CONTROL_NAMES"}
        ):
            try:
                assignments[node.targets[0].id] = ast.literal_eval(node.value)
            except (ValueError, TypeError) as error:
                raise Rejected("tool_control_inventory_invalid") from error
    if set(assignments) != {"BASE_CONTROL_NAMES", "INFRASTRUCTURE_CONTROL_NAMES"}:
        raise Rejected("tool_control_inventory_missing")
    source_identity = (
        "input_identity_mismatch"
        if exact_pre_state
        else "post_requirements_identity_mismatch"
    )
    base = tuple(
        (name, source_identity if observed == "__SOURCE_IDENTITY__" else observed)
        for name, observed in assignments["BASE_CONTROL_NAMES"]
    )
    result = base + tuple(assignments["INFRASTRUCTURE_CONTROL_NAMES"])
    if (
        not result
        or len(result) != EXPECTED_CONTROL_COUNT
        or len({name for name, _observed in result}) != len(result)
        or any(not isinstance(name, str) or not isinstance(value, str) for name, value in result)
    ):
        raise Rejected("tool_control_inventory_invalid")
    return result


def consume_pair(
    directory: Path, mode: str, *, expected_run_id: str | None = None
) -> dict[str, Any]:
    canonical = read_bounded(directory / "report.json")
    per_mode = read_bounded(directory / f"report-{mode}.json")
    if canonical != per_mode:
        raise Rejected("report_pair_bytes_mismatch")
    report = object_from(canonical, "report")
    if (
        report.get("schema") != 2
        or report.get("report_kind")
        != "rfc9114_strict_inventory_review_application"
        or report.get("mode") != mode
        or report.get("status") == "Running"
        or report.get("shareable") is not True
        or not isinstance(report.get("run_id"), str)
        or not RUN_ID.fullmatch(report["run_id"])
    ):
        raise Rejected("report_pair_contract_mismatch")
    if expected_run_id is not None and report["run_id"] != expected_run_id:
        raise Rejected("report_pair_run_mismatch")
    if report.get("status") == "Rejected":
        return report

    checked_status_policy(mode, report.get("source_state_before"), report.get("status"))

    tracked = tracked_gate()
    inputs = report.get("input_sha256")
    if not isinstance(inputs, dict):
        raise Rejected("report_input_identity_missing")
    expected_inputs = {
        "candidate": EXPECTED_FIXED[
            "standards/audits/rfc9114/candidate-inventory.json"
        ],
        "review": EXPECTED_FIXED[
            "standards/audits/rfc9114/independent-review.json"
        ],
        "reviewed_source_manifest": EXPECTED_FIXED[
            "standards/audits/rfc9114/reviewed-source-manifest.json"
        ],
        "invalidation_chain": EXPECTED_FIXED[
            "standards/audits/rfc9114/invalidation-chain.json"
        ],
        "artifact_manifest": digest(read_bounded(AUDIT / "artifact-manifest.json")),
        "mise_config": tracked[".mise.toml"],
        "tool_snapshot": tracked[
            "standards/audits/rfc9114/apply_review.py"
        ],
        "launcher_snapshot": tracked[
            "standards/audits/rfc9114/launcher.py"
        ],
        "gate_snapshot": tracked[
            "standards/audits/rfc9114/evidence_gate.py"
        ],
    }
    for key, expected in expected_inputs.items():
        if inputs.get(key) != expected:
            raise Rejected("report_input_identity_mismatch")
    requirements_sha256 = digest(read_bounded(ROOT / "standards/requirements.json"))
    if (
        inputs.get("requirements")
        not in {EXPECTED_REQUIREMENTS_BEFORE, EXPECTED_REQUIREMENTS_AFTER}
        or report.get("result_requirements_sha256") != requirements_sha256
        or report.get("expected_output_sha256") != EXPECTED_REQUIREMENTS_AFTER
    ):
        raise Rejected("report_requirements_identity_mismatch")
    exact_pre = report.get("source_state_before") == "pre_review"
    expected_controls = tool_control_inventory(
        read_bounded(AUDIT / "apply_review.py"), exact_pre
    )
    controls = report.get("self_test_controls")
    if not isinstance(controls, list) or [
        (item.get("name"), item.get("observed"))
        for item in controls
        if isinstance(item, dict)
    ] != list(expected_controls):
        raise Rejected("report_control_inventory_mismatch")
    completion = report.get("completion")
    if (
        not isinstance(completion, dict)
        or completion.get("self_test_controls_completed") != len(expected_controls)
    ):
        raise Rejected("report_control_count_mismatch")
    transaction = report.get("target_transaction")
    if report.get("applied_now") is True:
        expected_journal = (
            "build/root-validation/rfc9114-strict-inventory/transactions/"
            f"run-{report['run_id']}/transaction.json"
        )
        if (
            not isinstance(transaction, dict)
            or transaction.get("required") is not True
            or transaction.get("run_id") != report["run_id"]
            or transaction.get("journal") != expected_journal
            or not re.fullmatch(
                r"[0-9a-f]{64}", transaction.get("committed_journal_sha256", "")
            )
        ):
            raise Rejected("report_transaction_contract_mismatch")
        journal = read_bounded(ROOT / expected_journal)
        if digest(journal) != transaction["committed_journal_sha256"]:
            raise Rejected("report_transaction_identity_mismatch")
        journal_object = object_from(journal, "transaction_journal")
        if (
            journal_object.get("status") != "Committed"
            or journal_object.get("run_id") != report["run_id"]
        ):
            raise Rejected("report_transaction_not_committed")
    elif transaction != {"required": False}:
        raise Rejected("report_transaction_unexpected")
    return report


def checked_status_policy(mode: str, source_state: Any, status: Any) -> None:
    status_policy = {
        ("red", "pre_review"): "ObservedRed",
        ("red", "reviewed"): "UnexpectedGreen",
        ("self-test", "pre_review"): "StaticReady",
        ("self-test", "reviewed"): "Ready",
        ("apply", "pre_review"): "Ready",
        ("apply", "reviewed"): "Ready",
    }
    if status_policy.get((mode, source_state)) != status:
        raise Rejected("report_status_policy_mismatch")


def expect_rejected(expected: str, operation: Any) -> None:
    try:
        operation()
    except Rejected as error:
        if str(error) != expected:
            raise Rejected("self_test_wrong_rejection") from error
    else:
        raise Rejected("self_test_mutant_accepted")


def write(path: Path, data: bytes) -> None:
    path.write_bytes(data)


def publication_drift_fixture() -> list[dict[str, str]]:
    source_manifest = object_from(
        read_bounded(AUDIT / "reviewed-source-manifest.json"), "source_manifest"
    )
    source_files = source_manifest.get("files")
    if not isinstance(source_files, list):
        raise Rejected("publication_fixture_manifest_invalid")
    canonical_files = [
        ".mise.toml",
        "standards/requirements.json",
        "standards/audits/rfc9114/apply_review.py",
        "standards/audits/rfc9114/launcher.py",
        "standards/audits/rfc9114/evidence_gate.py",
        "standards/audits/rfc9114/artifact-manifest.json",
        "standards/audits/rfc9114/candidate-inventory.json",
        "standards/audits/rfc9114/independent-review.json",
        "standards/audits/rfc9114/reviewed-source-manifest.json",
        "standards/audits/rfc9114/invalidation-chain.json",
        "standards/audits/rfc9114/review-v1-invalidated.json",
    ]
    for item in source_files:
        if not isinstance(item, dict) or not isinstance(item.get("path"), str):
            raise Rejected("publication_fixture_manifest_invalid")
        canonical_files.append(item["path"])

    prior_python = os.environ.get("HTTP_AUDIT_PYTHON")
    try:
        with tempfile.TemporaryDirectory(prefix="rfc9114-publication-drift-") as name:
            fixture_root = Path(name)
            for relative in sorted(set(canonical_files)):
                source = ROOT / relative
                destination = fixture_root / relative
                destination.parent.mkdir(parents=True, exist_ok=True)
                shutil.copyfile(source, destination)

            fixture_audit = fixture_root / "standards/audits/rfc9114"
            tool_path = fixture_audit / "apply_review.py"
            launcher_path = fixture_audit / "launcher.py"
            gate_path = fixture_audit / "evidence_gate.py"
            manifest_path = fixture_audit / "artifact-manifest.json"
            mise_path = fixture_root / ".mise.toml"
            tool_snapshot = read_bounded(tool_path)
            launcher_snapshot = read_bounded(launcher_path)
            gate_snapshot = read_bounded(gate_path)
            manifest_snapshot = read_bounded(manifest_path)
            mise_snapshot = read_bounded(mise_path)
            executable = Path(sys.executable).resolve(strict=True)
            python_sha256 = digest(read_bounded(executable))
            os.environ["HTTP_AUDIT_PYTHON"] = str(executable)
            binding = {
                "schema": 1,
                "tool_relative_path": "standards/audits/rfc9114/apply_review.py",
                "tool_snapshot": tool_snapshot,
                "tool_sha256": digest(tool_snapshot),
                "launcher_relative_path": "standards/audits/rfc9114/launcher.py",
                "launcher_snapshot": launcher_snapshot,
                "launcher_sha256": digest(launcher_snapshot),
                "gate_snapshot": gate_snapshot,
                "gate_sha256": digest(gate_snapshot),
                "artifact_manifest_snapshot": manifest_snapshot,
                "mise_config_snapshot": mise_snapshot,
                "python_implementation": sys.implementation.name,
                "python_version": ".".join(
                    str(value) for value in sys.version_info[:3]
                ),
                "python_executable_sha256": python_sha256,
            }
            namespace: dict[str, Any] = {
                "__name__": "rfc9114_publication_fixture",
                "__file__": str(tool_path),
                "__package__": None,
                "__builtins__": __builtins__,
                "__audit_launch__": binding,
            }
            exec(
                compile(tool_snapshot, "<rfc9114-publication-fixture>", "exec"),
                namespace,
                namespace,
            )
            run_id = "c" * 32
            holder: list[Any] = []
            result = namespace["prepare_result"]("self-test", run_id, holder)
            publisher = namespace["ReportPublisher"](
                fixture_root
                / "build/root-validation/rfc9114-strict-inventory",
                "self-test",
                run_id,
            )
            publisher.begin()
            report = namespace["result_report"](result)
            publisher.publish_final(report)

            def fixture_expect(category: str, operation: Any) -> None:
                try:
                    operation()
                except Exception as error:
                    if (
                        error.__class__.__name__ != "Rejected"
                        or str(error) != category
                    ):
                        raise Rejected("publication_fixture_wrong_rejection") from error
                else:
                    raise Rejected("publication_fixture_drift_accepted")

            candidate_path = fixture_audit / "candidate-inventory.json"
            candidate_bytes = read_bounded(candidate_path)
            write(candidate_path, candidate_bytes + b" ")
            fixture_expect(
                "input_drift_after_publication",
                lambda: namespace["post_publication_validate"](result),
            )
            write(candidate_path, candidate_bytes)

            first_source = fixture_root / source_files[0]["path"]
            first_source_bytes = read_bounded(first_source)
            write(first_source, first_source_bytes + b"\n")
            fixture_expect(
                "current_evidence_source_mismatch",
                lambda: namespace["post_publication_validate"](result),
            )
            write(first_source, first_source_bytes)

            write(tool_path, tool_snapshot + b"\n")
            fixture_expect(
                "audit_tool_disk_drift",
                lambda: namespace["post_publication_validate"](result),
            )
            write(tool_path, tool_snapshot)

            binding["python_executable_sha256"] = "0" * 64
            fixture_expect(
                "audit_launch_binding_invalid",
                lambda: namespace["post_publication_validate"](result),
            )
            binding["python_executable_sha256"] = python_sha256
            namespace["post_publication_validate"](result)
            publisher.publish_rejected("publication_drift_fixture_complete")
            namespace["consume_report_pair"](
                fixture_root
                / "build/root-validation/rfc9114-strict-inventory",
                "self-test",
                expected_run_id=run_id,
            )
            publisher.close()
    finally:
        if prior_python is None:
            os.environ.pop("HTTP_AUDIT_PYTHON", None)
        else:
            os.environ["HTTP_AUDIT_PYTHON"] = prior_python
    return [
        {"name": "publication_input_drift", "observed": "rejected"},
        {"name": "publication_cited_source_drift", "observed": "rejected"},
        {"name": "publication_tool_drift", "observed": "rejected"},
        {"name": "publication_execution_drift", "observed": "rejected"},
    ]


def self_test() -> list[dict[str, str]]:
    tracked_gate()
    tool = read_bounded(AUDIT / "apply_review.py")
    launcher = read_bounded(AUDIT / "launcher.py")
    link_needle = b"os.link(self.intended_path, self.target)"
    if tool.count(link_needle) != 1:
        raise Rejected("self_test_fixture_drift")
    target_overwrite_mutant = tool.replace(
        link_needle, b"os.replace(self.intended_path, self.target)"
    )
    expect_rejected(
        "lossless_transaction_contract_mismatch",
        lambda: tool_contract(target_overwrite_mutant),
    )

    sequence_needle = b"publisher.stage_final(report)"
    if tool.count(sequence_needle) != 1:
        raise Rejected("self_test_fixture_drift")
    publication_order_mutant = tool.replace(
        sequence_needle, b"publisher.complete_final(report)"
    )
    expect_rejected(
        "publication_sequence_contract_mismatch",
        lambda: tool_contract(publication_order_mutant),
    )

    inventory_needle = b'    ("exact_inventory", "accepted"),\n'
    if tool.count(inventory_needle) != 1:
        raise Rejected("self_test_fixture_drift")
    inventory_mutant = tool.replace(inventory_needle, b"")
    expect_rejected(
        "tool_control_inventory_invalid",
        lambda: tool_control_inventory(inventory_mutant, True),
    )

    validation_needle = b"    validate_control_inventory(controls, exact_pre_state)\n"
    if tool.count(validation_needle) != 1:
        raise Rejected("self_test_fixture_drift")
    validation_mutant = tool.replace(validation_needle, b"")
    expect_rejected(
        "mandatory_inventory_contract_mismatch",
        lambda: tool_contract(validation_mutant),
    )

    source_recheck_needle = b"    current_source = checked_source_manifest(\n"
    if tool.count(source_recheck_needle) != 1:
        raise Rejected("self_test_fixture_drift")
    source_recheck_mutant = tool.replace(
        source_recheck_needle,
        b"    current_source = source_manifest_object(\n",
    )
    expect_rejected(
        "post_publication_revalidation_contract_mismatch",
        lambda: tool_contract(source_recheck_mutant),
    )

    compile_needle = b'compile(tool_snapshot, "<rfc9114-reviewed-applicator>", "exec")'
    if launcher.count(compile_needle) != 1:
        raise Rejected("self_test_fixture_drift")
    launcher_mutant = launcher.replace(
        compile_needle,
        b'compile(read_bounded(TOOL), "<rfc9114-reviewed-applicator>", "exec")',
    )
    expect_rejected(
        "launcher_snapshot_execution_contract_mismatch",
        lambda: launcher_contract(launcher_mutant),
    )
    expect_rejected(
        "report_status_policy_mismatch",
        lambda: checked_status_policy("self-test", "pre_review", "Ready"),
    )

    run_id = "a" * 32
    valid = {
        "schema": 2,
        "report_kind": "rfc9114_strict_inventory_review_application",
        "status": "Rejected",
        "shareable": True,
        "mode": "self-test",
        "run_id": run_id,
        "failure_classification": "fixture_rejection",
    }
    valid_bytes = (json.dumps(valid, indent=2) + "\n").encode("utf-8")
    with tempfile.TemporaryDirectory(prefix="rfc9114-gate-") as name:
        base = Path(name)

        missing = base / "missing"
        missing.mkdir()
        write(missing / "report.json", valid_bytes)
        expect_rejected("input_missing", lambda: consume_pair(missing, "self-test"))

        tampered = base / "tampered"
        tampered.mkdir()
        write(tampered / "report.json", valid_bytes)
        write(tampered / "report-self-test.json", valid_bytes + b" ")
        expect_rejected(
            "report_pair_bytes_mismatch",
            lambda: consume_pair(tampered, "self-test"),
        )

        stale = base / "stale"
        stale.mkdir()
        write(stale / "report.json", valid_bytes)
        write(stale / "report-self-test.json", valid_bytes)
        expect_rejected(
            "report_pair_run_mismatch",
            lambda: consume_pair(
                stale, "self-test", expected_run_id="b" * 32
            ),
        )

        substituted = dict(valid)
        substituted["mode"] = "red"
        substituted_bytes = (json.dumps(substituted, indent=2) + "\n").encode(
            "utf-8"
        )
        substitute = base / "substituted"
        substitute.mkdir()
        write(substitute / "report.json", substituted_bytes)
        write(substitute / "report-self-test.json", substituted_bytes)
        expect_rejected(
            "report_pair_contract_mismatch",
            lambda: consume_pair(substitute, "self-test"),
        )

        valid_pair = base / "valid"
        valid_pair.mkdir()
        write(valid_pair / "report.json", valid_bytes)
        write(valid_pair / "report-self-test.json", valid_bytes)
        consume_pair(valid_pair, "self-test", expected_run_id=run_id)
    controls = [
        {"name": "target_overwrite_mutant", "observed": "rejected"},
        {"name": "publication_order_mutant", "observed": "rejected"},
        {"name": "mandatory_control_missing_mutant", "observed": "rejected"},
        {"name": "inventory_validator_removed_mutant", "observed": "rejected"},
        {"name": "source_recheck_removed_mutant", "observed": "rejected"},
        {"name": "launcher_reread_mutant", "observed": "rejected"},
        {"name": "pre_review_ready_mutant", "observed": "rejected"},
        {"name": "split_report_missing", "observed": "rejected"},
        {"name": "split_report_tampered", "observed": "rejected"},
        {"name": "split_report_stale", "observed": "rejected"},
        {"name": "split_report_substituted", "observed": "rejected"},
        {"name": "exact_split_pair", "observed": "accepted"},
    ]
    controls.extend(publication_drift_fixture())
    return controls


def publish_self_test_report(controls: list[dict[str, str]]) -> None:
    EVIDENCE.mkdir(parents=True, exist_ok=True)
    report = {
        "schema": 1,
        "report_kind": "rfc9114_evidence_gate_self_test",
        "status": "StaticReady",
        "shareable": True,
        "controls_completed": len(controls),
        "controls": controls,
        "identity": {
            "gate": digest(read_bounded(AUDIT / "evidence_gate.py")),
            "tool": digest(read_bounded(AUDIT / "apply_review.py")),
            "launcher": digest(read_bounded(AUDIT / "launcher.py")),
            "artifact_manifest": digest(
                read_bounded(AUDIT / "artifact-manifest.json")
            ),
            "requirements": digest(read_bounded(ROOT / "standards/requirements.json")),
            "mise_config": digest(read_bounded(ROOT / ".mise.toml")),
            "python_executable": digest(
                read_bounded(Path(sys.executable).resolve(strict=True))
            ),
        },
        "python": {
            "implementation": sys.implementation.name,
            "version": ".".join(str(value) for value in sys.version_info[:3]),
        },
        "rerun_command": (
            "python -I -B standards/audits/rfc9114/evidence_gate.py --self-test"
        ),
    }
    data = (json.dumps(report, indent=2) + "\n").encode("utf-8")
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=".gate-self-test.", suffix=".tmp", dir=EVIDENCE
    )
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, EVIDENCE / "gate-self-test.json")
        if read_bounded(EVIDENCE / "gate-self-test.json") != data:
            raise Rejected("self_test_report_readback_mismatch")
    finally:
        try:
            temporary.unlink(missing_ok=True)
        except OSError:
            pass


def main(arguments: list[str]) -> int:
    if arguments == ["tracked"]:
        tracked_gate()
        print("rfc9114_evidence_gate status=TrackedReady")
        return 0
    if arguments == ["--self-test"]:
        controls = self_test()
        publish_self_test_report(controls)
        print(
            f"rfc9114_evidence_gate status=SelfTestReady controls={len(controls)}"
        )
        return 0
    if len(arguments) == 2 and arguments[0] == "report" and arguments[1] in {
        "red",
        "self-test",
        "apply",
    }:
        report = consume_pair(EVIDENCE, arguments[1])
        print(f"rfc9114_evidence_gate status={report['status']} mode={arguments[1]}")
        return 0
    raise Rejected("invalid_arguments")


if __name__ == "__main__":
    try:
        raise SystemExit(main(sys.argv[1:]))
    except Rejected as error:
        category = str(error)
        if not re.fullmatch(r"[a-z0-9_]{1,120}", category):
            category = "typed_rejection"
        print(
            f"rfc9114_evidence_gate status=Rejected category={category}",
            file=sys.stderr,
        )
        raise SystemExit(1)
    except SystemExit:
        raise
    except Exception:
        print(
            "rfc9114_evidence_gate status=Rejected "
            "category=unexpected_internal_failure",
            file=sys.stderr,
        )
        raise SystemExit(1)

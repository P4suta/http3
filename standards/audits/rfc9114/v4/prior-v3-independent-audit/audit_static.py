from __future__ import annotations

import contextlib
import hashlib
import io
import json
import os
from pathlib import Path
import re
import runpy
import shutil
import sys
import tempfile


ROOT = Path(__file__).resolve().parents[3]
OUT = Path(__file__).resolve().parent
AUDIT = ROOT / "standards/audits/rfc9114"
PYTHON = Path(__file__).resolve()

FROZEN = {
    "standards/audits/rfc9114/apply_review.py": "6ce19c30a5cb42bd786e06d9110532cadcf83976900dd4f37fc93b0826124c74",
    "standards/audits/rfc9114/launcher.py": "49e90fcce126756bdee94f2b2180e326d26729440c19090743e99e46c9c01a97",
    "standards/audits/rfc9114/evidence_gate.py": "9e41a4071b35f665198135f193b78b83b0f540688c79cf5fbc22c7fdf77c075d",
    "standards/audits/rfc9114/artifact-manifest.json": "1553b35577aa89bc8d5a375447df46fc62dda98f6ede1041ca6cf72b56b2f189",
    ".mise.toml": "a715189cf527ca30e3a47f6b93b1b8f9c89021a4e020004f7e43705578746c35",
    ".github/workflows/ci.yml": "de49d2c660c451bd564ba36c6f19b56cd9e91b892c2288cc72d6ca494596b7a6",
    "standards/requirements.json": "6d9c34e9311c73cc9540b5b51a133c755d6225d88015068169a44369842bf533",
}


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def read(relative: str) -> bytes:
    return (ROOT / relative).read_bytes()


def rel_hash(relative: str) -> str:
    return sha(read(relative))


def add_control(controls: list[dict[str, object]], name: str, observed: str, **detail: object) -> None:
    item: dict[str, object] = {"name": name, "observed": observed}
    item.update(detail)
    controls.append(item)


def main() -> int:
    canonical_before = rel_hash("standards/requirements.json")
    frozen_observed = {name: rel_hash(name) for name in FROZEN}
    if frozen_observed != FROZEN:
        raise RuntimeError("frozen_identity_mismatch")

    apply_ns = runpy.run_path(
        str(AUDIT / "apply_review.py"), run_name="independent_apply_static"
    )
    gate_ns = runpy.run_path(
        str(AUDIT / "evidence_gate.py"), run_name="independent_gate_static"
    )
    controls: list[dict[str, object]] = []

    requirements = read("standards/requirements.json")
    candidate = read("standards/audits/rfc9114/candidate-inventory.json")
    review = read("standards/audits/rfc9114/independent-review.json")
    rendered = apply_ns["build_output"](requirements, candidate, review)
    rendered_hash = sha(rendered)
    requirements_text = requirements.decode("utf-8")
    rendered_text = rendered.decode("utf-8")
    start, end = apply_ns["rfc9114_text_span"](requirements_text)
    out_start, out_end = apply_ns["rfc9114_text_span"](rendered_text)
    outside_preserved = (
        requirements_text[:start] == rendered_text[:out_start]
        and requirements_text[end:] == rendered_text[out_end:]
    )
    add_control(
        controls,
        "rendered_output_identity_and_scope",
        "accepted",
        rendered_sha256=rendered_hash,
        expected_sha256=apply_ns["EXPECTED_OUTPUT_SHA256"],
        outside_rfc9114_preserved=outside_preserved,
    )
    source_contract = apply_ns["checked_source_manifest"](
        rendered,
        candidate,
        review,
        read("standards/audits/rfc9114/reviewed-source-manifest.json"),
    )
    add_control(
        controls,
        "reviewed_source_contract",
        "accepted",
        source_files=source_contract["source_files"],
        citation_references=source_contract["citation_references"],
        unique_citations=source_contract["unique_citations"],
        source_aggregate_sha256=source_contract["source_aggregate_sha256"],
    )

    with tempfile.TemporaryDirectory(prefix=".independent-rfc9114-", dir=OUT) as tmp_name:
        tmp = Path(tmp_name)

        # The intended recovery file remains aliased to the canonical target after commit.
        hardlink_case = tmp / "hardlink-recovery"
        hardlink_case.mkdir()
        target = hardlink_case / "target.json"
        original = b'{"state":"original"}\n'
        intended = b'{"state":"intended"}\n'
        target.write_bytes(original)
        transaction = apply_ns["LosslessTargetTransaction"](
            target, original, intended, hardlink_case / "recovery", "1" * 32
        )
        transaction.replace()
        transaction.commit()
        links_before = target.stat().st_nlink
        mutated = b'{"state":"mutated-in-place"}\n'
        with target.open("wb") as handle:
            handle.write(mutated)
            handle.flush()
            os.fsync(handle.fileno())
        recovery_after = transaction.intended_path.read_bytes()
        add_control(
            controls,
            "committed_target_in_place_write",
            "recovery_intended_destroyed" if recovery_after == mutated else "recovery_preserved",
            links_before=links_before,
            intended_before_sha256=sha(intended),
            intended_after_sha256=sha(recovery_after),
            target_after_sha256=sha(target.read_bytes()),
        )

        # A crash after lock acquisition but before Running leaves old Ready authoritative.
        stale_case = tmp / "stale-ready-lock"
        stale_case.mkdir()
        old_ready = apply_ns["lifecycle_report"]("self-test", "a" * 32, "Ready", None)
        (stale_case / "report.json").write_bytes(old_ready)
        abandoned = apply_ns["ReportPublisher"](stale_case, "self-test", "b" * 32)
        abandoned.lock.acquire()
        successor = apply_ns["ReportPublisher"](stale_case, "self-test", "c" * 32)
        category = None
        try:
            successor.begin()
        except apply_ns["Rejected"] as error:
            category = str(error)
        stale_report = json.loads((stale_case / "report.json").read_bytes())
        abandoned.lock.release()
        add_control(
            controls,
            "crash_after_report_lock_before_running",
            "stale_ready_survives",
            successor_category=category,
            surviving_status=stale_report.get("status"),
            surviving_run_id=stale_report.get("run_id"),
        )

        # If rejection publication fails after Ready, the previous Ready remains.
        reject_case = tmp / "reject-after-ready"
        reject_case.mkdir()
        publisher = apply_ns["ReportPublisher"](reject_case, "self-test", "d" * 32)
        publisher.begin()
        current_ready = apply_ns["lifecycle_report"]("self-test", "d" * 32, "Ready", None)
        (reject_case / "report.json").write_bytes(current_ready)
        mode_path = reject_case / "report-self-test.json"
        mode_path.mkdir()
        reject_category = None
        try:
            publisher.publish_rejected("fixture_rejection")
        except apply_ns["Rejected"] as error:
            reject_category = str(error)
        ready_after_failed_reject = json.loads((reject_case / "report.json").read_bytes())
        publisher.close()
        add_control(
            controls,
            "rejected_publication_failure_after_ready",
            "ready_survives",
            publication_category=reject_category,
            surviving_status=ready_after_failed_reject.get("status"),
        )

        arbitrary_identity = {
            "implementation": "cpython",
            "version": "3.12.13",
            "sha256": "0" * 64,
            "identity_kind": "mise_configured",
        }
        accepted_identity = apply_ns["checked_python_identity"](arbitrary_identity)
        add_control(
            controls,
            "mise_python_arbitrary_executable_hash",
            "accepted",
            accepted_sha256=accepted_identity["sha256"],
        )

        # A coordinated manifest/tool/launcher/gate/mise substitution is accepted.
        substitute_root = tmp / "coordinated-substitution"
        manifest = json.loads(read("standards/audits/rfc9114/artifact-manifest.json"))
        for item in manifest["artifacts"]:
            relative = item["path"]
            destination = substitute_root / relative
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(ROOT / relative, destination)
        tool_path = substitute_root / "standards/audits/rfc9114/apply_review.py"
        launcher_path = substitute_root / "standards/audits/rfc9114/launcher.py"
        gate_path = substitute_root / "standards/audits/rfc9114/evidence_gate.py"
        mise_path = substitute_root / ".mise.toml"
        tool_mutant = tool_path.read_bytes().replace(
            b"def execute() -> int:\n", b"def execute() -> int:\n    return 0\n", 1
        )
        tool_path.write_bytes(tool_mutant)
        mutant_tool_hash = sha(tool_mutant)
        launcher_mutant = launcher_path.read_bytes().replace(
            b"def execute_snapshot() -> int:\n",
            b"def execute_snapshot() -> int:\n    return 0\n",
            1,
        )
        launcher_mutant = re.sub(
            rb'EXPECTED_TOOL_SHA256 = "[0-9a-f]{64}"',
            b'EXPECTED_TOOL_SHA256 = "' + mutant_tool_hash.encode("ascii") + b'"',
            launcher_mutant,
            count=1,
        )
        launcher_path.write_bytes(launcher_mutant)
        gate_mutant = b"raise SystemExit(0)\n"
        gate_path.write_bytes(gate_mutant)
        mise_mutant = mise_path.read_bytes() + b"\n# coordinated substitution\n"
        mise_path.write_bytes(mise_mutant)
        replacement_hashes = {
            "standards/audits/rfc9114/apply_review.py": sha(tool_mutant),
            "standards/audits/rfc9114/launcher.py": sha(launcher_mutant),
            "standards/audits/rfc9114/evidence_gate.py": sha(gate_mutant),
            ".mise.toml": sha(mise_mutant),
        }
        for item in manifest["artifacts"]:
            if item["path"] in replacement_hashes:
                item["sha256"] = replacement_hashes[item["path"]]
        manifest_path = substitute_root / "standards/audits/rfc9114/artifact-manifest.json"
        manifest_path.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
        old_root, old_audit = gate_ns["ROOT"], gate_ns["AUDIT"]
        gate_ns["tracked_gate"].__globals__["ROOT"] = substitute_root
        gate_ns["tracked_gate"].__globals__["AUDIT"] = substitute_root / "standards/audits/rfc9114"
        coordinated_result = gate_ns["tracked_gate"]()
        gate_ns["tracked_gate"].__globals__["ROOT"] = old_root
        gate_ns["tracked_gate"].__globals__["AUDIT"] = old_audit
        add_control(
            controls,
            "coordinated_artifact_substitution",
            "accepted",
            substituted_artifacts=sorted(replacement_hashes),
            observed_artifacts=len(coordinated_result),
            substituted_manifest_sha256=sha(manifest_path.read_bytes()),
        )

        # Same-count name substitution and reordering are not independently anchored.
        tool = read("standards/audits/rfc9114/apply_review.py")
        substitution = tool.replace(b'("exact_inventory", "accepted")', b'("invented_inventory", "accepted")')
        substituted_inventory = gate_ns["tool_control_inventory"](substitution, True)
        base_a = b'    ("baseline_render", "accepted"),\n'
        base_b = b'    ("reviewed_counts", "accepted"),\n'
        reordered = tool.replace(base_a + base_b, base_b + base_a, 1)
        reordered_inventory = gate_ns["tool_control_inventory"](reordered, True)
        dead_tool = tool.replace(
            b"def execute() -> int:\n", b"def execute() -> int:\n    return 0\n", 1
        )
        gate_ns["tool_contract"](dead_tool)
        launcher = read("standards/audits/rfc9114/launcher.py")
        dead_launcher = launcher.replace(
            b"def execute_snapshot() -> int:\n",
            b"def execute_snapshot() -> int:\n    return 0\n",
            1,
        )
        gate_ns["launcher_contract"](dead_launcher)
        add_control(
            controls,
            "inventory_and_dead_branch_mutants",
            "accepted",
            substituted_name=substituted_inventory[-1][0],
            reordered_prefix=[name for name, _ in reordered_inventory[:2]],
            dead_tool_contract="accepted",
            dead_launcher_contract="accepted",
        )

        # Gate self-test can be monkeypatched to empty and still publish StaticReady.
        gate_report_dir = tmp / "empty-gate-self-test"
        gate_ns["main"].__globals__["EVIDENCE"] = gate_report_dir
        original_self_test = gate_ns["main"].__globals__["self_test"]
        gate_ns["main"].__globals__["self_test"] = lambda: []
        captured = io.StringIO()
        with contextlib.redirect_stdout(captured):
            empty_exit = gate_ns["main"](["--self-test"])
        gate_ns["main"].__globals__["self_test"] = original_self_test
        empty_report = json.loads((gate_report_dir / "gate-self-test.json").read_bytes())
        add_control(
            controls,
            "gate_empty_self_test_monkeypatch",
            "static_ready",
            exit_code=empty_exit,
            controls_completed=empty_report.get("controls_completed"),
            status=empty_report.get("status"),
        )

        # The report consumer ignores unknown fields and non-object controls.
        report = json.loads(
            read("build/root-validation/rfc9114-strict-inventory/report-self-test.json")
        )
        report["untrusted_private_value"] = "SENSITIVE_SENTINEL_DO_NOT_SHARE"
        report["self_test_controls"][0]["raw_detail"] = "SENSITIVE_SENTINEL_DO_NOT_SHARE"
        report["self_test_controls"].append("SENSITIVE_SENTINEL_DO_NOT_SHARE")
        permissive = tmp / "permissive-report"
        permissive.mkdir()
        report_bytes = (json.dumps(report, indent=2) + "\n").encode("utf-8")
        (permissive / "report.json").write_bytes(report_bytes)
        (permissive / "report-self-test.json").write_bytes(report_bytes)
        gate_ns["consume_pair"](permissive, "self-test")
        add_control(
            controls,
            "report_unknown_secret_fields",
            "accepted",
            extra_top_level=True,
            extra_control_field=True,
            extra_non_object_control=True,
        )

        rejected = {
            "schema": 2,
            "report_kind": "rfc9114_strict_inventory_review_application",
            "status": "Rejected",
            "shareable": True,
            "mode": "self-test",
            "run_id": "e" * 32,
            "failure_classification": "fixture_rejection",
            "untrusted_private_value": "SENSITIVE_SENTINEL_DO_NOT_SHARE",
        }
        rejected_bytes = (json.dumps(rejected, indent=2) + "\n").encode("utf-8")
        rejected_dir = tmp / "rejected-short-circuit"
        rejected_dir.mkdir()
        (rejected_dir / "report.json").write_bytes(rejected_bytes)
        (rejected_dir / "report-self-test.json").write_bytes(rejected_bytes)
        gate_ns["consume_pair"](rejected_dir, "self-test")
        add_control(
            controls,
            "rejected_report_identity_short_circuit",
            "accepted",
            input_identity_present=False,
            completion_present=False,
            unknown_field_present=True,
        )

        # Hard-link and (where available) symlink aliases are accepted by bounded readers.
        aliases = tmp / "aliases"
        aliases.mkdir()
        alias_source = aliases / "source.bin"
        alias_source.write_bytes(b"alias-fixture\n")
        hard_alias = aliases / "hard.bin"
        os.link(alias_source, hard_alias)
        gate_ns["read_bounded"](hard_alias)
        hard_accepted = hard_alias.stat().st_nlink >= 2
        symlink_available = False
        symlink_accepted = False
        symlink_error = None
        soft_alias = aliases / "soft.bin"
        try:
            os.symlink(alias_source, soft_alias)
            symlink_available = True
            gate_ns["read_bounded"](soft_alias)
            symlink_accepted = True
        except OSError as error:
            symlink_error = error.__class__.__name__
        add_control(
            controls,
            "alias_inputs",
            "accepted",
            hardlink_accepted=hard_accepted,
            hardlink_count=hard_alias.stat().st_nlink,
            symlink_available=symlink_available,
            symlink_accepted=symlink_accepted,
            symlink_unavailable_category=symlink_error,
        )

    ci = read(".github/workflows/ci.yml").decode("utf-8")
    recovery_names = [
        "original.bin",
        "intended.bin",
        "claimed.bin",
        "published.bin",
        "concurrent-target.bin",
    ]
    add_control(
        controls,
        "ci_recovery_artifact_scope",
        "journal_only",
        transaction_journal_included="transactions/**/transaction.json" in ci,
        missing_recovery_patterns=[name for name in recovery_names if name not in ci],
    )
    artifact_manifest = json.loads(read("standards/audits/rfc9114/artifact-manifest.json"))
    artifact_paths = [item["path"] for item in artifact_manifest["artifacts"]]
    add_control(
        controls,
        "ci_identity_binding",
        "missing",
        ci_in_artifact_manifest=".github/workflows/ci.yml" in artifact_paths,
        ci_in_report_inputs=False,
    )
    add_control(
        controls,
        "production_report_freshness_binding",
        "missing",
        production_expected_run_id_supplied=False,
        consumer_call_site="evidence_gate.py:892",
    )

    canonical_after = rel_hash("standards/requirements.json")
    if canonical_before != canonical_after or canonical_after != FROZEN["standards/requirements.json"]:
        raise RuntimeError("canonical_requirements_modified")

    blockers = [
        {
            "id": "hardlinked_recovery_copy_is_mutable_through_target",
            "source": ["standards/audits/rfc9114/apply_review.py:1242", "standards/audits/rfc9114/apply_review.py:1261"],
            "control": "committed_target_in_place_write",
        },
        {
            "id": "stale_report_lock_can_preserve_old_ready",
            "source": ["standards/audits/rfc9114/apply_review.py:1132", "standards/audits/rfc9114/apply_review.py:1674"],
            "control": "crash_after_report_lock_before_running",
        },
        {
            "id": "failed_rejection_publication_can_preserve_ready",
            "source": ["standards/audits/rfc9114/apply_review.py:1732", "standards/audits/rfc9114/apply_review.py:2671", "standards/audits/rfc9114/apply_review.py:2696"],
            "control": "rejected_publication_failure_after_ready",
        },
        {
            "id": "mise_python_executable_hash_is_not_pinned",
            "source": ["standards/audits/rfc9114/launcher.py:62", "standards/audits/rfc9114/apply_review.py:1361"],
            "control": "mise_python_arbitrary_executable_hash",
        },
        {
            "id": "coordinated_mutable_artifact_substitution_is_accepted",
            "source": ["standards/audits/rfc9114/apply_review.py:1438", "standards/audits/rfc9114/evidence_gate.py:277"],
            "control": "coordinated_artifact_substitution",
        },
        {
            "id": "mandatory_inventory_and_ast_contracts_are_self_defined_and_dead_code_blind",
            "source": ["standards/audits/rfc9114/evidence_gate.py:154", "standards/audits/rfc9114/evidence_gate.py:340"],
            "control": "inventory_and_dead_branch_mutants",
        },
        {
            "id": "gate_self_test_inventory_can_be_empty",
            "source": ["standards/audits/rfc9114/evidence_gate.py:677", "standards/audits/rfc9114/evidence_gate.py:825", "standards/audits/rfc9114/evidence_gate.py:880"],
            "control": "gate_empty_self_test_monkeypatch",
        },
        {
            "id": "report_schema_and_secret_fields_are_not_closed",
            "source": ["standards/audits/rfc9114/evidence_gate.py:387", "standards/audits/rfc9114/evidence_gate.py:450"],
            "control": "report_unknown_secret_fields",
        },
        {
            "id": "rejected_reports_skip_identity_and_completion_validation",
            "source": ["standards/audits/rfc9114/evidence_gate.py:401"],
            "control": "rejected_report_identity_short_circuit",
        },
        {
            "id": "audit_inputs_accept_aliases",
            "source": ["standards/audits/rfc9114/apply_review.py:99", "standards/audits/rfc9114/evidence_gate.py:47"],
            "control": "alias_inputs",
        },
        {
            "id": "ci_omits_recovery_bytes",
            "source": [".github/workflows/ci.yml:87", ".github/workflows/ci.yml:96"],
            "control": "ci_recovery_artifact_scope",
        },
        {
            "id": "ci_workflow_identity_is_not_bound",
            "source": ["standards/audits/rfc9114/evidence_gate.py:299", "standards/audits/rfc9114/apply_review.py:2587"],
            "control": "ci_identity_binding",
        },
        {
            "id": "report_consumer_has_no_fresh_run_binding",
            "source": ["standards/audits/rfc9114/evidence_gate.py:380", "standards/audits/rfc9114/evidence_gate.py:892"],
            "control": "production_report_freshness_binding",
        },
        {
            "id": "no_crash_recovery_or_stale_lock_reconciliation_exists",
            "source": ["standards/audits/rfc9114/apply_review.py:1123", "standards/audits/rfc9114/apply_review.py:1163"],
            "control": "crash_after_report_lock_before_running",
        },
    ]
    report_object = {
        "schema": 1,
        "report_kind": "independent_rfc9114_v3_application_audit",
        "status": "Rejected",
        "shareable": True,
        "native_processes_started": 0,
        "audit_python": {
            "implementation": sys.implementation.name,
            "version": ".".join(str(value) for value in sys.version_info[:3]),
            "executable_sha256": sha(Path(sys.executable).resolve(strict=True).read_bytes()),
            "isolated": sys.flags.isolated == 1,
            "bytecode_disabled": sys.flags.dont_write_bytecode == 1,
        },
        "canonical_requirements_before_sha256": canonical_before,
        "canonical_requirements_after_sha256": canonical_after,
        "frozen_identities": FROZEN,
        "observed_identities": frozen_observed,
        "rendered_output_sha256": rendered_hash,
        "controls_completed": len(controls),
        "controls": controls,
        "blockers": blockers,
        "rerun_command": (
            "python -I -B build/root-validation/rfc9114-v3-independent-audit/audit_static.py"
        ),
    }
    OUT.mkdir(parents=True, exist_ok=True)
    report_path = OUT / "report.json"
    report_path.write_text(json.dumps(report_object, indent=2) + "\n", encoding="utf-8")
    manifest = {
        "schema": 1,
        "manifest_kind": "independent_rfc9114_v3_application_audit_evidence",
        "status": "Rejected",
        "artifacts": {
            "audit_static.py": sha(PYTHON.read_bytes()),
            "report.json": sha(report_path.read_bytes()),
        },
        "canonical_requirements_before_sha256": canonical_before,
        "canonical_requirements_after_sha256": canonical_after,
        "production_frozen_identities": frozen_observed,
    }
    (OUT / "evidence-manifest.json").write_text(
        json.dumps(manifest, indent=2) + "\n", encoding="utf-8"
    )
    print(
        "independent_rfc9114_audit status=Rejected "
        f"blockers={len(blockers)} controls={len(controls)}"
    )
    return 1


if __name__ == "__main__":
    raise SystemExit(main())

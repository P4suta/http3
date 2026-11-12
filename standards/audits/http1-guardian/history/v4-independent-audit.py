from __future__ import annotations

import copy
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import sys
import tempfile
import traceback


ROOT = Path(__file__).resolve().parents[3]
AUDIT = ROOT / "standards/audits/http1-guardian"
SYNTHETIC_SECRET = "SYNTHETIC_PRIVATE_PATH_ENDPOINT_PID_EXCEPTION"


def load(path: Path, name: str):
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError("load_failed")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


def replace_once(source: str, old: str, new: str) -> str:
    if source.count(old) != 1:
        raise RuntimeError("fixture_anchor_missing")
    return source.replace(old, new, 1)


def mutate_region(source: str, start_name: str, next_name: str, transform) -> str:
    start = source.index("\n" + start_name + "(") + 1
    end = source.index("\n" + next_name + "(", start + len(start_name) + 1) + 1
    region = source[start:end]
    changed = transform(region)
    if changed == region:
        raise RuntimeError("region_mutation_unchanged")
    return source[:start] + changed + source[end:]


def sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main() -> int:
    guardian = load(AUDIT / "guardian_contract_check.py", "ind_guardian")
    scanner = load(ROOT / "scripts/spawn_monitor_contract_audit.py", "ind_scanner")
    gate = load(AUDIT / "adversarial_contract_check.py", "ind_gate")
    source_text = {
        "gleam": (ROOT / "src/http/internal/http1/server.gleam").read_text(encoding="utf-8"),
        "ffi": (ROOT / "src/http_server_ffi.erl").read_text(encoding="utf-8"),
        "test": (ROOT / "test/server_handler_lifetime_test.gleam").read_text(encoding="utf-8"),
        "test_ffi": (ROOT / "test/http_handler_lifetime_test_ffi.erl").read_text(encoding="utf-8"),
    }
    ffi = source_text["ffi"]
    gleam = source_text["gleam"]
    results: list[dict[str, object]] = []

    def check(name: str, mutant: str, check_guardian: bool = True, check_scanner: bool = True):
        candidate = dict(source_text)
        candidate["ffi"] = mutant
        guardian_findings = guardian.analyze(candidate) if check_guardian else []
        scanner_findings = scanner.inspect_http1_delegation(gleam, mutant) if check_scanner else []
        results.append({
            "name": name,
            "guardian_findings": guardian_findings,
            "scanner_findings": scanner_findings,
            "false_green": not guardian_findings and not scanner_findings,
        })

    check(
        "run_before_entry_receive",
        replace_once(
            ffi,
            '    ok = proc_lib:set_label(<<"http.http1_handler">>),\n    receive',
            '    ok = proc_lib:set_label(<<"http.http1_handler">>),\n'
            '    _Forbidden = Run(),\n    receive',
        ),
    )

    def post_receive(region: str) -> str:
        marker = "    end.\n\n"
        if not region.endswith(marker):
            raise RuntimeError("post_receive_anchor_missing")
        return region[:-len(marker)] + "    end,\n    Run().\n\n"

    check(
        "run_after_entry_receive",
        mutate_region(
            ffi,
            "http1_handler_guardian_handler_entry",
            "http1_handler_guardian_handler_timed_out",
            post_receive,
        ),
    )

    check(
        "immediately_invoked_fun_run_in_first_true",
        replace_once(
            ffi,
            "                true ->\n                    http1_handler_guardian_handler_timed_out(",
            "                true ->\n                    _Forbidden = (fun() -> Run() end)(),\n"
            "                    http1_handler_guardian_handler_timed_out(",
        ),
    )

    delegated = replace_once(
        ffi,
        "                true ->\n                    http1_handler_guardian_handler_timed_out(",
        "                true ->\n"
        "                    _Forbidden = http1_handler_guardian_forbidden_run(Run),\n"
        "                    http1_handler_guardian_handler_timed_out(",
    ) + "\nhttp1_handler_guardian_forbidden_run(Run) -> Run().\n"
    check("delegated_run_in_first_true", delegated)

    def dead_safe_handler_clause(region: str) -> str:
        header = (
            "http1_handler_guardian_handler_entry(\n"
            "    Guardian, HandlerReference, Run, Probe, AfterResult, HandlerDeadline\n"
            ") ->\n"
        )
        region = replace_once(region, header, header[:-4] + " when false ->\n")
        marker = "    end.\n\n"
        if not region.endswith(marker):
            raise RuntimeError("handler_clause_anchor_missing")
        unsafe = (
            "    end;\n"
            "http1_handler_guardian_handler_entry(\n"
            "    Guardian, HandlerReference, Run, Probe, AfterResult, HandlerDeadline\n"
            ") ->\n"
            "    Run().\n\n"
        )
        return region[:-len(marker)] + unsafe

    check(
        "guard_false_safe_entry_clause_wrong_live_clause",
        mutate_region(
            ffi,
            "http1_handler_guardian_handler_entry",
            "http1_handler_guardian_handler_timed_out",
            dead_safe_handler_clause,
        ),
    )

    def impossible_guard_safe_handler_clause(region: str) -> str:
        header = (
            "http1_handler_guardian_handler_entry(\n"
            "    Guardian, HandlerReference, Run, Probe, AfterResult, HandlerDeadline\n"
            ") ->\n"
        )
        region = replace_once(
            region,
            header,
            header[:-4] + " when HandlerDeadline =:= impossible_deadline ->\n",
        )
        marker = "    end.\n\n"
        if not region.endswith(marker):
            raise RuntimeError("variable_guard_clause_anchor_missing")
        return region[:-len(marker)] + (
            "    end;\n"
            "http1_handler_guardian_handler_entry(\n"
            "    Guardian, HandlerReference, Run, Probe, AfterResult, HandlerDeadline\n"
            ") ->\n"
            "    Run().\n\n"
        )

    check(
        "impossible_variable_guard_safe_entry_wrong_live_clause",
        mutate_region(
            ffi,
            "http1_handler_guardian_handler_entry",
            "http1_handler_guardian_handler_timed_out",
            impossible_guard_safe_handler_clause,
        ),
    )

    direct_terminating = mutate_region(
        ffi,
        "http1_handler_guardian_terminating_receive",
        "http1_handler_guardian_termination_expired",
        lambda region: replace_once(
            region,
            "            http1_handler_guardian_terminating(\n"
            "                State#{result => {some, Result}}, Termination, Notify,\n"
            "                CleanupDeadline\n"
            "            );",
            "            http1_handler_guardian_terminating_receive(\n"
            "                State#{result => {some, Result}}, Termination, Notify,\n"
            "                CleanupDeadline\n"
            "            );",
        ),
    )
    check("matching_traffic_bypasses_terminating_precheck", direct_terminating)

    direct_quarantine = mutate_region(
        ffi,
        "http1_handler_guardian_quarantine_receive",
        "http1_handler_guardian_quarantine_retry",
        lambda region: replace_once(
            region,
            "            http1_handler_guardian_quarantine(\n"
            "                State#{result => {some, Result}}, Termination, RetryDeadline\n"
            "            );",
            "            http1_handler_guardian_quarantine_receive(\n"
            "                State#{result => {some, Result}}, Termination, RetryDeadline\n"
            "            );",
        ),
    )
    check("matching_traffic_bypasses_quarantine_precheck", direct_quarantine)

    indirect_demonitor = replace_once(
        ffi,
        "    HandlerDeadline = maps:get(handler_deadline, State),\n    receive",
        "    HandlerDeadline = maps:get(handler_deadline, State),\n"
        "    http1_handler_guardian_drop_owner_monitor(State),\n    receive",
    ) + (
        "\nhttp1_handler_guardian_drop_owner_monitor(State) ->\n"
        "    erlang:demonitor(maps:get(owner_monitor, State), [flush]).\n"
    )
    check("indirect_owner_demonitor_before_publication", indirect_demonitor)

    def indirect_exit(region: str) -> str:
        return replace_once(
            region,
            "            http1_handler_guardian_finish(State);",
            "            http1_handler_guardian_abort_indirectly(),\n"
            "            http1_handler_guardian_finish(State);",
        )

    indirect_terminal = mutate_region(
        ffi,
        "http1_handler_guardian_terminating_receive",
        "http1_handler_guardian_termination_expired",
        indirect_exit,
    ) + (
        "\nhttp1_handler_guardian_abort_indirectly() ->\n"
        "    exit(indirect_terminal_abort).\n"
    )
    check("indirect_exit_before_terminal_down_finish", indirect_terminal)

    def indirect_throw(region: str) -> str:
        return replace_once(
            region,
            "            http1_handler_guardian_finish(State);",
            "            http1_handler_guardian_throw_indirectly(),\n"
            "            http1_handler_guardian_finish(State);",
        )

    indirect_throw_terminal = mutate_region(
        ffi,
        "http1_handler_guardian_quarantine_receive",
        "http1_handler_guardian_quarantine_retry",
        indirect_throw,
    ) + (
        "\nhttp1_handler_guardian_throw_indirectly() ->\n"
        "    throw(indirect_terminal_throw).\n"
    )
    check("indirect_throw_before_terminal_down_finish", indirect_throw_terminal)

    def dead_safe_down(region: str) -> str:
        region = replace_once(region, "http1_handler_guardian_down(State) ->", "http1_handler_guardian_down(State) when false ->")
        marker = "    end.\n\n"
        if not region.endswith(marker):
            raise RuntimeError("down_clause_anchor_missing")
        return region[:-len(marker)] + (
            "    end;\n"
            "http1_handler_guardian_down(State) ->\n"
            "    http1_handler_guardian_finish(State).\n\n"
        )

    check(
        "guard_false_safe_down_clause_missing_live_publication",
        mutate_region(
            ffi,
            "http1_handler_guardian_down",
            "http1_handler_guardian_begin_termination",
            dead_safe_down,
        ),
    )

    source_hashes = gate.snapshot(gate.SOURCE_PATHS)
    scanner_source_hashes = gate.snapshot(gate.SCANNER_SOURCE_PATHS)
    tool_hashes = gate.snapshot(gate.TOOL_PATHS)
    runtime_hash = gate.safe_hash(Path(os.sys.executable).resolve(strict=True), gate.MAXIMUM_TOOL_BYTES)
    config_hash = gate.safe_hash(ROOT / ".mise.toml")
    dev = ROOT / "build/root-validation/http1-handler-guardian-v4-dev-final"
    parsed = {
        "guardian_report.json": json.loads((dev / "guardian.report.json").read_text(encoding="utf-8")),
        "scanner_self_test_report.json": json.loads((dev / "scanner_self.report.json").read_text(encoding="utf-8")),
        "scanner_audit_report.json": json.loads((dev / "scanner_audit.report.json").read_text(encoding="utf-8")),
        "wrapper_report.json": json.loads((dev / "wrapper.report.json").read_text(encoding="utf-8")),
        "adversarial_report.json": json.loads((dev / "adversarial.report.json").read_text(encoding="utf-8")),
    }
    guardian_report = parsed["guardian_report.json"]
    guardian_report["status"] = "passed"
    guardian_report["class"] = "ok"
    guardian_report["failures"] = []
    guardian_report["python_version"] = "3.12.13"
    guardian_report["python_executable_sha256_pre"] = runtime_hash
    guardian_report["python_executable_sha256_post"] = runtime_hash
    guardian_report["mise_config_sha256_pre"] = config_hash
    guardian_report["mise_config_sha256_post"] = config_hash
    guardian_report["source_sha256_pre"] = guardian_report["source_sha256_post"] = {
        "gleam": source_hashes[gate.SOURCE_PATHS[0]],
        "ffi": source_hashes[gate.SOURCE_PATHS[1]],
        "test": source_hashes[gate.SOURCE_PATHS[2]],
        "test_ffi": source_hashes[gate.SOURCE_PATHS[3]],
    }
    guardian_report["scanner_sha256_pre"] = guardian_report["scanner_sha256_post"] = tool_hashes[str(gate.GUARDIAN_CHECKER).replace("\\", "/")]
    guardian_report["mutations"] = {
        f"substituted_mutation_{index:02d}": {"changed": True, "detected": True}
        for index in range(16)
    }
    guardian_report["adversarial_controls"] = [
        {"name": "substituted_guardian_control", "passed": True},
        {"name": "substituted_guardian_control", "passed": True},
    ]
    guardian_report["secret_path_pid_exception"] = SYNTHETIC_SECRET

    scanner_self = parsed["scanner_self_test_report.json"]
    scanner_self["scanner_sha256_pre"] = scanner_self["scanner_sha256_post"] = tool_hashes["scripts/spawn_monitor_contract_audit.py"]
    scanner_self["runtime"]["version"] = "3.12.13"
    scanner_self["runtime"]["executable_sha256"] = runtime_hash
    scanner_self["runtime"]["mise_config_sha256"] = config_hash
    scanner_self["controls"] = [
        {"name": f"substituted_scanner_{index:02d}", "passed": True}
        for index in range(34)
    ]

    scanner_audit = parsed["scanner_audit_report.json"]
    scanner_audit["scanner_sha256_pre"] = scanner_audit["scanner_sha256_post"] = tool_hashes["scripts/spawn_monitor_contract_audit.py"]
    scanner_audit["source_sha256_pre"] = scanner_audit["source_sha256_post"] = scanner_source_hashes
    scanner_audit["runtime"]["version"] = "3.12.13"
    scanner_audit["runtime"]["executable_sha256"] = runtime_hash
    scanner_audit["runtime"]["mise_config_sha256"] = config_hash

    wrapper = parsed["wrapper_report.json"]
    wrapper.update({"status": "Ready", "classification": "passed", "failures": []})
    wrapper["source_sha256_pre"] = wrapper["source_sha256_post"] = scanner_source_hashes
    wrapper["scanner_sha256_pre"] = wrapper["scanner_sha256_post"] = tool_hashes["scripts/spawn_monitor_contract_audit.py"]
    wrapper_path = "standards/audits/http1-guardian/spawn_monitor_dataflow_contract_check.py"
    wrapper["checker_sha256_pre"] = wrapper["checker_sha256_post"] = tool_hashes[wrapper_path]
    wrapper["python_executable_sha256_pre"] = wrapper["python_executable_sha256_post"] = runtime_hash
    wrapper["python_version"] = "3.12.13"
    wrapper["mise_config_sha256_pre"] = wrapper["mise_config_sha256_post"] = config_hash
    substituted_scanner_names = sorted(control["name"] for control in scanner_self["controls"])
    wrapper["expected_controls"] = wrapper["observed_controls"] = substituted_scanner_names
    wrapper["identity_controls"] = [
        {"name": "substituted_wrapper_control", "passed": True}
        for _ in range(11)
    ]

    adversarial = parsed["adversarial_report.json"]
    adversarial.update({"status": "Ready", "classification": "passed"})
    adversarial["source_sha256_pre"] = adversarial["source_sha256_post"] = source_hashes
    adversarial["tool_sha256_pre"] = adversarial["tool_sha256_post"] = tool_hashes
    adversarial["checker_sha256_pre"] = adversarial["checker_sha256_post"] = tool_hashes["standards/audits/http1-guardian/adversarial_contract_check.py"]
    adversarial["runtime"]["version"] = "3.12.13"
    adversarial["runtime"]["executable_sha256_pre"] = adversarial["runtime"]["executable_sha256_post"] = runtime_hash
    adversarial["runtime"]["mise_config_sha256_pre"] = adversarial["runtime"]["mise_config_sha256_post"] = config_hash
    adversarial["controls"] = [
        {"name": "substituted_adversarial_control", "passed": True}
        for _ in range(36)
    ]

    in_memory_forgery_accepted = gate.generated_reports_match_current_source(
        parsed, source_hashes, scanner_source_hashes, tool_hashes, runtime_hash, config_hash
    )

    forged_root = ROOT / "build/root-validation/http1-handler-guardian-v4-independent-audit/forged"
    forged_root.mkdir(parents=True, exist_ok=True)
    for name, value in parsed.items():
        encoded = json.dumps(value, sort_keys=True, separators=(",", ":"))
        if name == "guardian_report.json":
            encoded = '{"status":"Failed",' + encoded[1:]
        (forged_root / name).write_text(encoded + "\n", encoding="utf-8")
    assemble_status, assembled = gate.assemble_evidence(forged_root / "evidence.json")

    original_atomic_publish = gate.atomic_publish
    replaced_root = ROOT / "build/root-validation/http1-handler-guardian-v4-independent-audit/replaced"
    replaced_root.mkdir(parents=True, exist_ok=True)
    for name in (
        "guardian_report.json",
        "scanner_self_test_report.json",
        "scanner_audit_report.json",
        "wrapper_report.json",
        "adversarial_report.json",
    ):
        (replaced_root / name).write_bytes((forged_root / name).read_bytes())

    def replace_after_internal_readback(path: Path, payload: bytes) -> None:
        original_atomic_publish(path, payload)
        if Path(path).name == "evidence.json":
            Path(path).write_text(
                '{"status":"Ready","secret_path_pid_exception":"'
                + SYNTHETIC_SECRET
                + '"}\n',
                encoding="utf-8",
            )

    gate.atomic_publish = replace_after_internal_readback
    replacement_status, replacement_memory_report = gate.assemble_evidence(
        replaced_root / "evidence.json"
    )
    replacement_disk = (replaced_root / "evidence.json").read_text(encoding="utf-8")
    gate.atomic_publish = original_atomic_publish

    payloads = {name: (name + "\n").encode("ascii") for name in gate.EVIDENCE_INVENTORY}
    payloads[gate.EVIDENCE_INVENTORY[0]] = (SYNTHETIC_SECRET + "\n").encode("ascii")
    bundle = {
        "schema": 4,
        "status": "Ready",
        "rerun_command": gate.EVIDENCE_RERUN_COMMAND,
        "completed_artifacts": len(gate.EVIDENCE_INVENTORY),
        "artifact_sha256": {name: hashlib.sha256(data).hexdigest() for name, data in payloads.items()},
        "source_sha256_pre": source_hashes,
        "source_sha256_post": source_hashes,
        "source_stable": True,
        "tool_sha256_pre": tool_hashes,
        "tool_sha256_post": tool_hashes,
        "tool_stable": True,
        "secret_path_pid_exception": SYNTHETIC_SECRET,
    }
    secret_bundle_findings = gate.verify_evidence_bundle(bundle, payloads, source_hashes, tool_hashes)

    with tempfile.TemporaryDirectory(prefix="http1-audit-hardlink-") as directory:
        original = Path(directory) / "report.json"
        alias = Path(directory) / "report-alias.json"
        original.write_bytes(b"{}\n")
        os.link(original, alias)
        hardlink_accepted = gate.safe_read(original)[0] == b"{}\n"

    with tempfile.TemporaryDirectory(prefix="http1-audit-import-") as directory:
        module_path = Path(directory) / "mutable_module.py"
        original_module = b"VALUE = 'recorded'\n"
        substituted_module = b"VALUE = 'executed'\n"
        module_path.write_bytes(original_module)
        module_pre = gate.safe_hash(module_path)
        module_path.write_bytes(substituted_module)
        executed_module = gate.load(module_path, "independent_toctou_module")
        module_path.write_bytes(original_module)
        module_post = gate.safe_hash(module_path)
        path_import_toctou_accepted = (
            module_pre == module_post
            and executed_module.VALUE == "executed"
            and module_pre != hashlib.sha256(substituted_module).hexdigest()
        )

    escaped_failures: dict[str, bool] = {}
    original_gate_load = gate.load
    gate.load = lambda *_args, **_kwargs: (_ for _ in ()).throw(
        RuntimeError(SYNTHETIC_SECRET)
    )
    try:
        gate.main(None)
        escaped_failures["adversarial_runtime_error"] = False
    except RuntimeError:
        escaped_failures["adversarial_runtime_error"] = SYNTHETIC_SECRET in traceback.format_exc()
    finally:
        gate.load = original_gate_load

    original_guardian_analyze = guardian.analyze
    guardian.analyze = lambda *_args, **_kwargs: (_ for _ in ()).throw(
        RuntimeError(SYNTHETIC_SECRET)
    )
    try:
        guardian.main(None)
        escaped_failures["guardian_runtime_error"] = False
    except RuntimeError:
        escaped_failures["guardian_runtime_error"] = SYNTHETIC_SECRET in traceback.format_exc()
    finally:
        guardian.analyze = original_guardian_analyze

    original_scanner_audit = scanner.audit
    scanner.audit = lambda: (_ for _ in ()).throw(RuntimeError(SYNTHETIC_SECRET))
    saved_argv = sys.argv
    sys.argv = ["spawn_monitor_contract_audit.py"]
    try:
        scanner.main()
        escaped_failures["scanner_runtime_error"] = False
    except RuntimeError:
        escaped_failures["scanner_runtime_error"] = SYNTHETIC_SECRET in traceback.format_exc()
    finally:
        sys.argv = saved_argv
        scanner.audit = original_scanner_audit

    provisional = json.loads((ROOT / "build/root-validation/http1-handler-guardian-v4-provisional-red/stdout.jsonl").read_text(encoding="utf-8"))
    provisional_exact = (
        provisional.get("status") == "Red"
        and provisional.get("completed_controls") == 19
        and provisional.get("failed_controls") == 19
        and isinstance(provisional.get("controls"), list)
        and len(provisional["controls"]) == 19
        and all(control.get("passed") is False for control in provisional["controls"])
    )

    report = {
        "schema": 1,
        "status": "Rejected",
        "candidate_hashes": {
            "scripts/spawn_monitor_contract_audit.py": sha(ROOT / "scripts/spawn_monitor_contract_audit.py"),
            "guardian_contract_check.py": sha(AUDIT / "guardian_contract_check.py"),
            "spawn_monitor_dataflow_contract_check.py": sha(AUDIT / "spawn_monitor_dataflow_contract_check.py"),
            "adversarial_contract_check.py": sha(AUDIT / "adversarial_contract_check.py"),
            "manifest.json": sha(AUDIT / "manifest.json"),
            "review.md": sha(AUDIT / "review.md"),
            ".mise.toml": sha(ROOT / ".mise.toml"),
        },
        "current_source_green": {
            "guardian": guardian.analyze(source_text) == [],
            "scanner": scanner.inspect_http1_delegation(gleam, ffi) == [],
        },
        "independent_mutants": results,
        "false_green_count": sum(1 for result in results if result["false_green"]),
        "provisional_red_19_of_19": provisional_exact,
        "evidence_forgery": {
            "same_count_substituted_controls_accepted": in_memory_forgery_accepted,
            "full_assembler_exit": assemble_status,
            "full_assembler_status": assembled.get("status"),
            "full_assembler_recorded_actual_runtime": assembled.get("runtime", {}).get("version"),
            "duplicate_json_key_present": (forged_root / "guardian_report.json").read_text(encoding="utf-8").count('"status"') >= 2,
            "synthetic_secret_report_accepted": assembled.get("status") == "Ready",
            "secret_payload_bundle_findings": secret_bundle_findings,
            "hardlink_input_accepted": hardlink_accepted,
            "path_import_toctou_accepted": path_import_toctou_accepted,
            "post_readback_replacement_exit": replacement_status,
            "post_readback_replacement_memory_status": replacement_memory_report.get("status"),
            "post_readback_replacement_disk_contains_secret": SYNTHETIC_SECRET in replacement_disk,
            "unexpected_failure_traceback_contains_secret": escaped_failures,
        },
        "runtime": {
            "actual_version": ".".join(str(value) for value in os.sys.version_info[:3]),
            "actual_executable_sha256": runtime_hash,
        },
    }
    print(json.dumps(report, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

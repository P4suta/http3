#!/usr/bin/env python3
"""Deterministic Red controls for the rejected v3 guardian evidence."""

from __future__ import annotations

import contextlib
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import sys


ROOT = Path(__file__).resolve().parents[2]
MAXIMUM_BYTES = 4 * 1024 * 1024


def safe_read(path: Path) -> str:
    if path.is_symlink() or not path.is_file():
        raise ValueError("identity_rejected")
    size = path.stat().st_size
    if size <= 0 or size > MAXIMUM_BYTES:
        raise ValueError("size_rejected")
    data = path.read_bytes()
    if len(data) != size:
        raise ValueError("partial_read_rejected")
    return data.decode("utf-8")


def load(path: Path, name: str) -> object:
    specification = importlib.util.spec_from_file_location(name, path)
    if specification is None or specification.loader is None:
        raise ValueError("module_load_rejected")
    module = importlib.util.module_from_spec(specification)
    sys.modules[name] = module
    specification.loader.exec_module(module)
    return module


def replace_nth(source: str, old: str, new: str, occurrence: int) -> str:
    cursor = 0
    for _ in range(occurrence):
        found = source.find(old, cursor)
        if found < 0:
            return source
        cursor = found + len(old)
    return source[:found] + new + source[found + len(old) :]


def record(controls: list[dict[str, object]], name: str, observed: bool) -> None:
    controls.append(
        {"name": name, "expected": True, "observed": observed, "passed": observed is True}
    )


def main() -> int:
    controls: list[dict[str, object]] = []
    try:
        guardian_path = ROOT / "build/root-validation/http1-handler-guardian-contract-check.py"
        scanner_path = ROOT / "scripts/spawn_monitor_contract_audit.py"
        wrapper_path = ROOT / "build/root-validation/spawn-monitor-dataflow-contract-check.py"
        adversarial_path = ROOT / "build/root-validation/http1-handler-v3-adversarial-contract-check.py"
        guardian = load(guardian_path, "guardian_v4_red")
        scanner = load(scanner_path, "scanner_v4_red")
        wrapper = load(wrapper_path, "wrapper_v4_red")
        adversarial = load(adversarial_path, "adversarial_v4_red")
        ffi = safe_read(ROOT / "src/http_server_ffi.erl")
        gleam = safe_read(ROOT / "src/http/internal/http1/server.gleam")
        test = safe_read(ROOT / "test/server_handler_lifetime_test.gleam")
        test_ffi = safe_read(ROOT / "test/http_handler_lifetime_test_ffi.erl")
        sources = {"ffi": ffi, "gleam": gleam, "test": test, "test_ffi": test_ffi}

        true_branch = (
            "true ->\n"
            "                    http1_handler_guardian_handler_timed_out("
        )
        first_true = dict(sources)
        first_true["ffi"] = replace_nth(
            ffi,
            true_branch,
            "true ->\n                    _Forbidden = Run(),\n"
            "                    http1_handler_guardian_handler_timed_out(",
            1,
        )
        second_true = dict(sources)
        second_true["ffi"] = replace_nth(
            ffi,
            "true ->\n"
            "                            http1_handler_guardian_handler_timed_out(",
            "true ->\n                            _Forbidden = Run(),\n"
            "                            http1_handler_guardian_handler_timed_out(",
            1,
        )
        record(
            controls,
            "run_in_first_deadline_true_rejected",
            first_true != sources
            and "handler_run_outside_second_false" in guardian.analyze(first_true),
        )
        record(
            controls,
            "run_in_second_deadline_true_rejected",
            second_true != sources
            and "handler_run_outside_second_false" in guardian.analyze(second_true),
        )

        wrong_return = ffi.replace(
            "            {ok, {GuardianMonitor, Commands}};",
            "            _ValidDecoy = {ok, {GuardianMonitor, Commands}},\n"
            "            {ok, {DifferentMonitor, Commands}};",
            1,
        )
        record(
            controls,
            "wrong_monitor_after_valid_tuple_decoy_rejected",
            wrong_return != ffi
            and "guardian_monitor_return_unproven"
            in scanner.inspect_http1_delegation(gleam, wrong_return),
        )

        owner_demonitor = ffi.replace(
            "                            http1_handler_guardian_start_handler(",
            "                            erlang:demonitor(OwnerMonitor, [flush]),\n"
            "                            http1_handler_guardian_start_handler(",
            1,
        )
        record(
            controls,
            "owner_demonitor_before_handler_rejected",
            owner_demonitor != ffi
            and "guardian_owner_monitor_lifetime_unproven"
            in scanner.inspect_http1_delegation(gleam, owner_demonitor),
        )

        nested_state = ffi.replace(
            "        handler => Handler,\n        handler_monitor => HandlerMonitor,",
            "        handler_pair => #{\n"
            "            handler => Handler,\n"
            "            handler_monitor => HandlerMonitor\n"
            "        },",
            1,
        )
        record(
            controls,
            "nested_handler_state_rejected",
            nested_state != ffi
            and "handler_state_top_level_unproven"
            in scanner.inspect_http1_delegation(gleam, nested_state),
        )

        down_call = "            http1_handler_guardian_down(State);"
        exit_before_down = ffi.replace(
            down_call,
            "            exit(handler_down_decoy),\n" + down_call,
            1,
        )
        throw_before_down = ffi.replace(
            down_call,
            "            throw(handler_down_decoy),\n" + down_call,
            1,
        )
        for name, mutant in (
            ("exit_before_down_rejected", exit_before_down),
            ("throw_before_down_rejected", throw_before_down),
        ):
            record(
                controls,
                name,
                mutant != ffi
                and "handler_down_reachability_unproven"
                in scanner.inspect_http1_delegation(gleam, mutant),
            )

        publication = "            http1_handler_guardian_publish_result(Events, Result),"
        publication_decoy = ffi.replace(
            publication,
            "            case false of\n"
            "                true -> http1_handler_guardian_publish_result(Events, Result);\n"
            "                false -> ok\n"
            "            end,",
            1,
        )
        record(
            controls,
            "unreachable_success_publication_rejected",
            publication_decoy != ffi
            and "handler_publication_reachability_unproven"
            in scanner.inspect_http1_delegation(gleam, publication_decoy),
        )

        scanner_hash = wrapper.safe_hash(scanner_path)
        runtime_hash = wrapper.safe_hash(
            Path(sys.executable).resolve(strict=True), wrapper.MAXIMUM_TOOL_BYTES
        )
        source_hashes, source_bytes, aggregate = wrapper.source_snapshot()
        base_report = {
            "schema": 2,
            "kind": "audit",
            "status": "Ready",
            "classification": "passed",
            "scanner_sha256_pre": scanner_hash,
            "scanner_sha256_post": scanner_hash,
            "scanner_stable": True,
            "runtime": {"executable_sha256": runtime_hash},
            "rerun_command": "fixed",
            "source_sha256_pre": source_hashes,
            "source_sha256_post": source_hashes,
            "source_stable": True,
            "source_files": len(source_hashes),
            "source_bytes": source_bytes,
            "source_aggregate_sha256_pre": aggregate,
            "source_aggregate_sha256_post": aggregate,
            "findings": [],
        }
        record(
            controls,
            "missing_completed_contracts_rejected",
            "audit_completed_contracts_mismatch" in wrapper.validate_report(
                base_report, "audit", scanner_hash, source_hashes,
                runtime_hash, aggregate, source_bytes
            ),
        )
        zero_contracts = dict(base_report)
        zero_contracts["completed_contracts"] = 0
        record(
            controls,
            "zero_completed_contracts_rejected",
            "audit_completed_contracts_mismatch" in wrapper.validate_report(
                zero_contracts, "audit", scanner_hash, source_hashes,
                runtime_hash, aggregate, source_bytes
            ),
        )
        empty_rerun = dict(base_report)
        empty_rerun["completed_contracts"] = 12
        empty_rerun["rerun_command"] = ""
        record(
            controls,
            "empty_rerun_rejected",
            "audit_rerun_invalid" in wrapper.validate_report(
                empty_rerun, "audit", scanner_hash, source_hashes,
                runtime_hash, aggregate, source_bytes
            ),
        )

        red_report = json.loads(safe_read(
            ROOT / "build/root-validation/http1-handler-v3-adversarial-red/stdout.jsonl"
        ))
        actual_failed = sum(
            1 for control in red_report.get("controls", [])
            if isinstance(control, dict) and control.get("passed") is not True
        )
        v3_manifest = json.loads(safe_read(
            ROOT / "build/root-validation/http1-handler-guardian-v3-static-green/evidence.json"
        ))
        record(
            controls,
            "red_failure_count_exact",
            v3_manifest.get("red", {}).get("adversarial", {}).get("failed_controls")
            == actual_failed,
        )
        v2 = json.loads(safe_read(
            ROOT / "build/root-validation/http1-handler-guardian-v2-invalidated.json"
        ))
        expected_replacement = (
            "build/root-validation/http1-handler-guardian-v3-static-green/evidence.json"
        )
        record(
            controls,
            "v2_replacement_resolves",
            v2.get("replacement") == expected_replacement
            and (ROOT / expected_replacement).is_file(),
        )
        artifact_hashes = v3_manifest.get("artifact_sha256", {})
        record(
            controls,
            "red_and_invalidation_hashed",
            isinstance(artifact_hashes, dict)
            and "v2-invalidation.json" in artifact_hashes
            and "v3-adversarial-red.aggregate" in artifact_hashes,
        )

        tracked_root = ROOT / "standards/audits/http1-guardian"
        tracked_names = (
            "guardian_contract_check.py",
            "spawn_monitor_dataflow_contract_check.py",
            "adversarial_contract_check.py",
            "review.md",
            "manifest.json",
        )
        record(
            controls,
            "canonical_tracked_layout_present",
            all((tracked_root / name).is_file() for name in tracked_names),
        )
        mise_source = safe_read(ROOT / ".mise.toml")
        record(
            controls,
            "canonical_mise_gate_present",
            "[tasks.http1-guardian-audit]" in mise_source
            and "mise exec python@3.12.13" in mise_source,
        )
        record(
            controls,
            "runtime_config_identity_reported",
            "mise_config_sha256" in safe_read(scanner_path)
            and "python@3.12.13" in safe_read(scanner_path),
        )
        record(
            controls,
            "artifact_tamper_verifier_present",
            hasattr(adversarial, "verify_evidence_bundle"),
        )

        captured = io.StringIO()
        original_safe_read = adversarial.safe_read
        adversarial.safe_read = lambda _path: (_ for _ in ()).throw(
            OSError("PRIVATE_PATH_ENDPOINT_PID")
        )
        try:
            with contextlib.redirect_stdout(captured):
                status = adversarial.main()
            encoded = captured.getvalue()
            safe_failure = status != 0 and "PRIVATE_PATH_ENDPOINT_PID" not in encoded
        except (OSError, UnicodeError, ValueError):
            safe_failure = False
        finally:
            adversarial.safe_read = original_safe_read
        record(controls, "adversarial_read_failure_safe", safe_failure)
    except (AttributeError, KeyError, OSError, TypeError, UnicodeError, ValueError):
        record(controls, "red_gate_execution", False)

    failed = [control for control in controls if control["passed"] is not True]
    report = {
        "schema": 1,
        "status": "Red" if failed else "UnexpectedGreen",
        "classification": failed[0]["name"] if failed else "unexpected_green",
        "completed_controls": len(controls),
        "failed_controls": len(failed),
        "controls": controls,
        "runtime": {
            "tool_request": "python@3.12.13",
            "version": ".".join(str(part) for part in sys.version_info[:3]),
            "executable_sha256": hashlib.sha256(
                Path(sys.executable).read_bytes()
            ).hexdigest(),
            "mise_config_sha256": hashlib.sha256(
                (ROOT / ".mise.toml").read_bytes()
            ).hexdigest(),
        },
        "rerun_command": (
            "mise exec python@3.12.13 -- python -I -B "
            "build/root-validation/http1-handler-v4-red-check.py"
        ),
    }
    print(json.dumps(report, sort_keys=True, separators=(",", ":")))
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())

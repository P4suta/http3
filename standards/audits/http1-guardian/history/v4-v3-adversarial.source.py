#!/usr/bin/env python3
"""Adversarial static gate for the third HTTP/1 guardian proof revision."""

from __future__ import annotations

import hashlib
import importlib.util
import json
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
GUARDIAN_CHECKER = ROOT / "build/root-validation/http1-handler-guardian-contract-check.py"
SPAWN_SCANNER = ROOT / "scripts/spawn_monitor_contract_audit.py"
SPAWN_WRAPPER = ROOT / "build/root-validation/spawn-monitor-dataflow-contract-check.py"
MAXIMUM_BYTES = 4 * 1024 * 1024


def safe_read(path: Path) -> tuple[str, str]:
    if path.is_symlink() or not path.is_file():
        raise ValueError("identity_rejected")
    size = path.stat().st_size
    if size <= 0 or size > MAXIMUM_BYTES:
        raise ValueError("size_rejected")
    data = path.read_bytes()
    if len(data) != size:
        raise ValueError("partial_read_rejected")
    return data.decode("utf-8"), hashlib.sha256(data).hexdigest()


def load(path: Path, name: str) -> object:
    specification = importlib.util.spec_from_file_location(name, path)
    if specification is None or specification.loader is None:
        raise ValueError("module_load_rejected")
    module = importlib.util.module_from_spec(specification)
    sys.modules[name] = module
    specification.loader.exec_module(module)
    return module


def guardian_mutants(guardian: object) -> dict[str, bool]:
    ffi = safe_read(ROOT / "src/http_server_ffi.erl")[0]
    gleam = safe_read(ROOT / "src/http/internal/http1/server.gleam")[0]
    test = safe_read(ROOT / "test/server_handler_lifetime_test.gleam")[0]
    test_ffi = safe_read(ROOT / "test/http_handler_lifetime_test_ffi.erl")[0]
    sources = {"ffi": ffi, "gleam": gleam, "test": test, "test_ffi": test_ffi}
    needle = (
        "http1_handler_guardian_safe_probe(Probe, 1, Guardian),\n"
        "                    case monotonic_millisecond() >= HandlerDeadline of"
    )
    dead_decoy = (
        "http1_handler_guardian_safe_probe(Probe, 1, Guardian),\n"
        "                    _DeadCheck = fun() ->\n"
        "                        case monotonic_millisecond() >= HandlerDeadline of\n"
        "                            true -> ok; false -> ok\n"
        "                        end\n"
        "                    end,\n"
        "                    case false of"
    )
    premature = (
        "http1_handler_guardian_safe_probe(Probe, 1, Guardian),\n"
        "                    _Premature = Run(),\n"
        "                    case monotonic_millisecond() >= HandlerDeadline of"
    )
    comment_decoy = (
        "http1_handler_guardian_safe_probe(Probe, 1, Guardian),\n"
        "                    % case monotonic_millisecond() >= HandlerDeadline of\n"
        "                    case false of"
    )
    dead_sources = dict(sources)
    dead_sources["ffi"] = ffi.replace(needle, dead_decoy, 1)
    premature_sources = dict(sources)
    premature_sources["ffi"] = ffi.replace(needle, premature, 1)
    comment_sources = dict(sources)
    comment_sources["ffi"] = ffi.replace(needle, comment_decoy, 1)
    dead_findings = guardian.analyze(dead_sources)
    premature_findings = guardian.analyze(premature_sources)
    comment_findings = guardian.analyze(comment_sources)
    return {
        "guardian_dead_second_check_rejected": (
            dead_sources != sources
            and "handler_entry_control_flow_unproven" in dead_findings
        ),
        "guardian_run_before_second_check_rejected": (
            premature_sources != sources
            and "handler_run_before_second_deadline" in premature_findings
        ),
        "guardian_comment_second_check_rejected": (
            comment_sources != sources
            and "handler_entry_control_flow_unproven" in comment_findings
        ),
        "guardian_token_proof_present": hasattr(
            guardian, "handler_entry_flow_findings"
        ),
    }


def composite_erlang_fixture() -> str:
    return r'''
-export([start_http1_handler_guardian/10]).
start_http1_handler_guardian(A, B, C, D, E, F, G, H, I, J) ->
    ReadyReference = make_ref(),
    Owner = A,
    _DeadOwner = fun() -> Owner = self() end,
    {Guardian, GuardianMonitor} = erlang:spawn_monitor(fun() ->
        http1_handler_guardian_boot(Owner, B, C, D, E, F, G, H, I, J)
    end),
    http1_handler_guardian_await_ready(
        Guardian, GuardianMonitor, ReadyReference
    ).
http1_handler_guardian_await_ready(Guardian, GuardianMonitor, ReadyReference) ->
    receive
        {ReadyReference, Guardian, Commands, _ReadyAt} ->
            {ok, {GuardianMonitor, Commands}}
    end.
http1_handler_guardian_boot(Owner, B, C, D, E, F, G, H, I, J) ->
    _DeadChain = fun() ->
        OwnerMonitor = erlang:monitor(process, Owner),
        http1_handler_guardian_start_handler(
            Owner, OwnerMonitor, B, C, D, E, F, G, H, I, J
        )
    end,
    WrongReceiver = self(),
    WrongMonitor = erlang:monitor(process, WrongReceiver),
    http1_handler_guardian_start_handler(
        Owner, WrongMonitor, B, C, D, E, F, G, H, I, J
    ).
http1_handler_guardian_start_handler(
    Owner, OwnerMonitor, B, C, D, E, F, G, H, I, J
) ->
    {Handler, HandlerMonitor} = erlang:spawn_opt(fun() ->
        http1_handler_guardian_handler_entry(B, C, D)
    end, [link, monitor]),
    _DeadMap = fun() ->
        State = #{handler => Handler, handler_monitor => HandlerMonitor},
        http1_handler_guardian_active(State)
    end,
    WrongState = #{owner => Owner, owner_monitor => OwnerMonitor},
    http1_handler_guardian_active(WrongState).
http1_handler_guardian_handler_entry(B, C, D) -> {B, C, D}.
http1_handler_guardian_active(State) ->
    _DeadDown = fun() ->
        Handler = maps:get(handler, State),
        HandlerMonitor = maps:get(handler_monitor, State),
        receive
            {'DOWN', HandlerMonitor, process, Handler, _} ->
                http1_handler_guardian_down(State)
        end
    end,
    WrongReceiver = maps:get(owner, State),
    WrongMonitor = maps:get(owner_monitor, State),
    receive
        {'DOWN', WrongMonitor, process, WrongReceiver, _} ->
            http1_handler_guardian_down(State)
    end.
http1_handler_guardian_down(State) ->
    http1_handler_guardian_publish_result(State, result).
http1_handler_guardian_publish_result(State, Result) -> {State, Result}.
'''


def scanner_controls(scanner: object) -> dict[str, bool]:
    gleam = r'''
@external(erlang, "http_server_ffi", "start_http1_handler_guardian")
fn start_http1_handler_guardian(
  a: Int, b: Int, c: Int, d: Int, e: Int,
  f: Int, g: Int, h: Int, i: Int, j: Int,
) -> Result(#(Monitor, Commands), Failure)
fn run_handler() {
  let started = start_http1_handler_guardian(1, 2, 3, 4, 5, 6, 7, 8, 9, 10)
  case started {
    Ok(#(guardian_monitor, guardian_commands)) ->
      await_handler(a, b, c, guardian_commands, e, guardian_monitor, g, h, i)
    Error(_) -> Nil
  }
}
'''
    findings = scanner.inspect_http1_delegation(
        gleam, composite_erlang_fixture()
    )
    required = {
        "guardian_monitor_provenance_missing",
        "guardian_owner_chain_unproven",
        "handler_spawn_not_atomic",
        "handler_down_to_terminal_flow_unproven",
    }
    return {
        "scanner_dead_scope_composite_rejected": required.issubset(
            set(findings)
        )
    }


def wrapper_controls(wrapper: object, scanner_hash: str) -> dict[str, bool]:
    runtime_hash = wrapper.safe_hash(
        Path(sys.executable).resolve(strict=True), wrapper.MAXIMUM_TOOL_BYTES
    )
    expected_sources = {"fixture": "a" * 64}
    base = {
        "schema": 2,
        "kind": "audit",
        "status": "Ready",
        "classification": "passed",
        "scanner_sha256_pre": scanner_hash,
        "scanner_sha256_post": scanner_hash,
        "scanner_stable": True,
        "runtime": {"executable_sha256": runtime_hash},
        "rerun_command": "fixed",
        "source_sha256_pre": expected_sources,
        "source_sha256_post": expected_sources,
        "source_stable": True,
        "source_files": 1,
        "findings": [],
    }

    def rejected(change: dict[str, object], expected: str) -> bool:
        candidate = dict(base)
        candidate.update(change)
        try:
            findings = wrapper.validate_report(
                candidate,
                "audit",
                scanner_hash,
                expected_sources,
                runtime_hash,
            )
        except TypeError:
            findings = wrapper.validate_report(candidate, "audit")
        return expected in findings

    return {
        "wrapper_scanner_identity_drift_rejected": rejected(
            {"scanner_sha256_post": "b" * 64},
            "audit_scanner_post_identity_mismatch",
        ),
        "wrapper_scanner_stability_false_rejected": rejected(
            {"scanner_stable": False},
            "audit_scanner_stability_invalid",
        ),
        "wrapper_source_identity_drift_rejected": rejected(
            {"source_sha256_post": {"fixture": "c" * 64}},
            "audit_source_post_identity_mismatch",
        ),
        "wrapper_source_stability_false_rejected": rejected(
            {"source_stable": False},
            "audit_source_stability_invalid",
        ),
    }


def safe_failure_controls(guardian: object) -> dict[str, bool]:
    secret = "PRIVATE_PATH_AND_ENDPOINT_203_0_113_9"
    if not hasattr(guardian, "safe_failure_report"):
        return {
            "oserror_payload_redacted": False,
            "unicode_payload_redacted": False,
        }
    os_report = guardian.safe_failure_report(OSError(secret), "pre_read")
    unicode_report = guardian.safe_failure_report(
        UnicodeError(secret), "pre_read"
    )
    encoded = json.dumps([os_report, unicode_report], sort_keys=True)
    return {
        "oserror_payload_redacted": (
            secret not in encoded
            and os_report.get("class") == "io_rejected"
        ),
        "unicode_payload_redacted": (
            secret not in encoded
            and unicode_report.get("class") == "source_encoding_rejected"
        ),
    }


def main() -> int:
    checker_pre = safe_read(Path(__file__).resolve())[1]
    identities_pre = {
        "guardian": safe_read(GUARDIAN_CHECKER)[1],
        "scanner": safe_read(SPAWN_SCANNER)[1],
        "wrapper": safe_read(SPAWN_WRAPPER)[1],
    }
    controls: dict[str, bool] = {}
    try:
        guardian = load(GUARDIAN_CHECKER, "http1_guardian_v3_gate")
        scanner = load(SPAWN_SCANNER, "spawn_monitor_v3_gate")
        wrapper = load(SPAWN_WRAPPER, "spawn_monitor_wrapper_v3_gate")
        controls.update(guardian_mutants(guardian))
        controls.update(scanner_controls(scanner))
        controls.update(wrapper_controls(wrapper, identities_pre["scanner"]))
        controls.update(safe_failure_controls(guardian))
    except (AttributeError, KeyError, OSError, TypeError, UnicodeError, ValueError):
        controls["gate_execution"] = False
    identities_post = {
        "guardian": safe_read(GUARDIAN_CHECKER)[1],
        "scanner": safe_read(SPAWN_SCANNER)[1],
        "wrapper": safe_read(SPAWN_WRAPPER)[1],
    }
    checker_post = safe_read(Path(__file__).resolve())[1]
    controls["source_identity_stable"] = identities_pre == identities_post
    controls["checker_identity_stable"] = checker_pre == checker_post
    passed = all(value is True for value in controls.values())
    report = {
        "schema": 1,
        "status": "Ready" if passed else "Failed",
        "classification": "passed" if passed else next(
            name for name, value in sorted(controls.items()) if value is not True
        ),
        "controls": [
            {"name": name, "expected": True, "observed": value, "passed": value is True}
            for name, value in sorted(controls.items())
        ],
        "completed_controls": len(controls),
        "identities_pre": identities_pre,
        "identities_post": identities_post,
        "identities_stable": identities_pre == identities_post,
        "checker_sha256_pre": checker_pre,
        "checker_sha256_post": checker_post,
        "checker_stable": checker_pre == checker_post,
        "rerun_command": (
            "python -I -B build/root-validation/"
            "http1-handler-v3-adversarial-contract-check.py"
        ),
    }
    print(json.dumps(report, sort_keys=True, separators=(",", ":")))
    return 0 if passed else 1


if __name__ == "__main__":
    raise SystemExit(main())

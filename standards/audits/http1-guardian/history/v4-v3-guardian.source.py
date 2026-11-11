#!/usr/bin/env python3
"""Finite static contract and mutation gate for the HTTP/1 handler guardian."""

from __future__ import annotations

import hashlib
import json
import platform
import re
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
MAXIMUM_BYTES = 2 * 1024 * 1024
MAXIMUM_TOKENS = 300_000
FILES = {
    "gleam": ROOT / "src/http/internal/http1/server.gleam",
    "ffi": ROOT / "src/http_server_ffi.erl",
    "test": ROOT / "test/server_handler_lifetime_test.gleam",
    "test_ffi": ROOT / "test/http_handler_lifetime_test_ffi.erl",
}


def safe_read(path: Path) -> tuple[str, str]:
    if path.is_symlink() or not path.is_file():
        raise ValueError("source_identity_rejected")
    size = path.stat().st_size
    if size <= 0 or size > MAXIMUM_BYTES:
        raise ValueError("source_size_rejected")
    data = path.read_bytes()
    if len(data) != size:
        raise ValueError("partial_read_rejected")
    return data.decode("utf-8"), hashlib.sha256(data).hexdigest()


def safe_hash(path: Path) -> str:
    if path.is_symlink() or not path.is_file():
        raise ValueError("source_identity_rejected")
    size = path.stat().st_size
    if size <= 0 or size > MAXIMUM_BYTES:
        raise ValueError("source_size_rejected")
    data = path.read_bytes()
    if len(data) != size:
        raise ValueError("partial_read_rejected")
    return hashlib.sha256(data).hexdigest()


def function_region(source: str, name: str, next_name: str) -> str:
    start_match = re.search(r"(?m)^" + re.escape(name) + r"\(", source)
    if start_match is None:
        return ""
    end_match = re.search(
        r"(?m)^" + re.escape(next_name) + r"\(", source[start_match.end() :]
    )
    if end_match is None:
        return ""
    end = start_match.end() + end_match.start()
    return source[start_match.start() : end]


def mask_erlang_noncode(source: str) -> str:
    """Mask comments and quoted data while preserving offsets and newlines."""
    output = list(source)
    index = 0
    state = "code"
    quote = ""
    while index < len(source):
        current = source[index]
        following = source[index + 1] if index + 1 < len(source) else ""
        if state == "code":
            if current == "%":
                output[index] = " "
                state = "comment"
            elif current in ("'", '"'):
                quote = current
                output[index] = " "
                state = "quoted"
        elif state == "comment":
            if current == "\n":
                state = "code"
            else:
                output[index] = " "
        elif current == "\\" and following:
            output[index] = " "
            if following != "\n":
                output[index + 1] = " "
            index += 1
        elif current == quote:
            output[index] = " "
            state = "code"
        elif current != "\n":
            output[index] = " "
        index += 1
    return "".join(output)


def erlang_function_region(source: str, name: str) -> str:
    clean = mask_erlang_noncode(source)
    declaration = re.search(rf"(?m)^{re.escape(name)}\s*\(", clean)
    if declaration is None:
        return ""
    following = re.search(
        r"(?m)^[a-z][A-Za-z0-9_]*\s*\(", clean[declaration.end() :]
    )
    end = len(source) if following is None else declaration.end() + following.start()
    return source[declaration.start() : end]


def erlang_token_values(source: str) -> list[str]:
    """Bounded Erlang lexer; comments and quoted payloads cannot be code."""
    values: list[str] = []
    index = 0
    multi = ("=:=" , "=/=", "->", "=>", ":=", "=<", ">=", "<<", ">>")
    while index < len(source):
        current = source[index]
        if current.isspace():
            index += 1
            continue
        if current == "%":
            newline = source.find("\n", index + 1)
            index = len(source) if newline < 0 else newline + 1
            continue
        if current in ("'", '"'):
            quote = current
            index += 1
            quoted: list[str] = []
            while index < len(source):
                current = source[index]
                if current == quote:
                    index += 1
                    break
                if current == "\\":
                    index += 1
                    if index >= len(source):
                        raise ValueError("unterminated_quoted_token")
                    quoted.append(source[index])
                    index += 1
                    continue
                quoted.append(current)
                index += 1
            else:
                raise ValueError("unterminated_quoted_token")
            values.append("".join(quoted) if quote == "'" else "<string>")
        elif current.isalpha() or current == "_":
            end = index + 1
            while end < len(source) and (
                source[end].isalnum() or source[end] in ("_", "@")
            ):
                end += 1
            values.append(source[index:end])
            index = end
        elif current.isdigit():
            end = index + 1
            while end < len(source) and source[end].isdigit():
                end += 1
            values.append(source[index:end])
            index = end
        else:
            symbol = next(
                (candidate for candidate in multi if source.startswith(candidate, index)),
                current,
            )
            values.append(symbol)
            index += len(symbol)
        if len(values) > MAXIMUM_TOKENS:
            raise ValueError("token_limit_rejected")
    return values


def matching_delimiter(
    values: list[str], opening_index: int, opening: str, closing: str
) -> int:
    if opening_index < 0 or opening_index >= len(values):
        return -1
    depth = 0
    for index in range(opening_index, len(values)):
        if values[index] == opening:
            depth += 1
        elif values[index] == closing:
            depth -= 1
            if depth == 0:
                return index
    return -1


def block_opens(values: list[str], index: int) -> bool:
    value = values[index]
    if value in {"case", "receive", "try", "if", "begin", "maybe"}:
        return True
    return value == "fun" and index + 1 < len(values) and values[index + 1] == "("


def matching_block_end(values: list[str], opening_index: int) -> int:
    if opening_index < 0 or not block_opens(values, opening_index):
        return -1
    depth = 0
    for index in range(opening_index, len(values)):
        if block_opens(values, index):
            depth += 1
        elif values[index] == "end":
            depth -= 1
            if depth == 0:
                return index
    return -1


def function_body_values(source: str, name: str) -> list[str] | None:
    region = erlang_function_region(source, name)
    if not region:
        return None
    values = erlang_token_values(region)
    try:
        opening = values.index("(", 1)
    except ValueError:
        return None
    closing = matching_delimiter(values, opening, "(", ")")
    if closing < 0:
        return None
    arrow = -1
    delimiter_depth = 0
    for index in range(closing + 1, len(values)):
        value = values[index]
        if value in ("(", "[", "{"):
            delimiter_depth += 1
        elif value in (")", "]", "}"):
            delimiter_depth = max(0, delimiter_depth - 1)
        elif value == "->" and delimiter_depth == 0:
            arrow = index
            break
        elif value == "." and delimiter_depth == 0:
            break
    return None if arrow < 0 else values[arrow + 1 :]


def find_live_block(values: list[str], name: str, start: int = 0) -> int:
    """Find a block in the current lexical entry, skipping nested fun bodies."""
    index = start
    while index < len(values):
        if values[index] == "fun" and block_opens(values, index):
            end = matching_block_end(values, index)
            if end < 0:
                return -1
            index = end + 1
            continue
        if values[index] == name:
            return index
        index += 1
    return -1


def top_level_segments(values: list[str], separator: str = ",") -> list[list[str]]:
    segments: list[list[str]] = []
    start = 0
    index = 0
    delimiters = {"(": ")", "[": "]", "{": "}"}
    while index < len(values):
        value = values[index]
        if value in delimiters:
            end = matching_delimiter(values, index, value, delimiters[value])
            if end < 0:
                return []
            index = end + 1
            continue
        if block_opens(values, index):
            end = matching_block_end(values, index)
            if end < 0:
                return []
            index = end + 1
            continue
        if value == separator:
            segments.append(values[start:index])
            start = index + 1
        index += 1
    segments.append(values[start:])
    return [segment for segment in segments if segment]


def case_condition_and_branch(
    values: list[str], case_index: int, label: str
) -> tuple[list[str], list[str]] | None:
    end = matching_block_end(values, case_index)
    if end < 0:
        return None
    of_index = -1
    index = case_index + 1
    while index < end:
        if block_opens(values, index):
            nested_end = matching_block_end(values, index)
            if nested_end < 0:
                return None
            index = nested_end + 1
            continue
        if values[index] == "of":
            of_index = index
            break
        index += 1
    if of_index < 0:
        return None
    index = of_index + 1
    while index < end:
        if block_opens(values, index):
            nested_end = matching_block_end(values, index)
            if nested_end < 0:
                return None
            index = nested_end + 1
            continue
        if values[index : index + 2] == [label, "->"]:
            body_start = index + 2
            cursor = body_start
            while cursor < end:
                if block_opens(values, cursor):
                    nested_end = matching_block_end(values, cursor)
                    if nested_end < 0:
                        return None
                    cursor = nested_end + 1
                    continue
                if values[cursor] == ";":
                    return values[case_index + 1 : of_index], values[body_start:cursor]
                cursor += 1
            return values[case_index + 1 : of_index], values[body_start:end]
        index += 1
    return None


def receive_clause(
    values: list[str], receive_index: int, expected_pattern: list[str]
) -> list[str] | None:
    end = matching_block_end(values, receive_index)
    if end < 0:
        return None
    start = receive_index + 1
    index = start
    while index < end:
        if block_opens(values, index):
            nested_end = matching_block_end(values, index)
            if nested_end < 0:
                return None
            index = nested_end + 1
            continue
        if values[index] == "after":
            return None
        if values[index] == "->":
            pattern = values[start:index]
            body_start = index + 1
            cursor = body_start
            while cursor < end:
                if block_opens(values, cursor):
                    nested_end = matching_block_end(values, cursor)
                    if nested_end < 0:
                        return None
                    cursor = nested_end + 1
                    continue
                if values[cursor] in (";", "after"):
                    body = values[body_start:cursor]
                    if pattern == expected_pattern:
                        return body
                    start = cursor + 1
                    index = start
                    break
                cursor += 1
            else:
                return values[body_start:end] if pattern == expected_pattern else None
            continue
        index += 1
    return None


def direct_call(values: list[str], name: str, arguments: list[str]) -> bool:
    expected = [name, "("] + arguments + [")"]
    return values[: len(expected)] == expected


def live_call_present(values: list[str], name: str) -> bool:
    index = 0
    while index < len(values):
        if values[index] == "fun" and block_opens(values, index):
            end = matching_block_end(values, index)
            if end < 0:
                return True
            index = end + 1
            continue
        if values[index : index + 2] == [name, "("]:
            return True
        index += 1
    return False


def handler_entry_flow_findings(ffi: str) -> list[str]:
    """Prove the live handler-start clause's deadline/probe/Run ordering."""
    failures: list[str] = []
    body = function_body_values(ffi, "http1_handler_guardian_handler_entry")
    if body is None:
        return ["handler_entry_control_flow_unproven", "handler_entry_deadline_missing"]
    receive_index = find_live_block(body, "receive")
    clause = receive_clause(
        body,
        receive_index,
        ["{", "HandlerReference", ",", "handler_start", ",", "Guardian", "}"],
    ) if receive_index >= 0 else None
    deadline = ["monotonic_millisecond", "(", ")", ">=", "HandlerDeadline"]
    if clause is None or not clause or clause[0] != "case":
        return ["handler_entry_control_flow_unproven", "handler_entry_deadline_missing"]
    first_false = case_condition_and_branch(clause, 0, "false")
    if first_false is None or first_false[0] != deadline:
        failures.extend(("handler_entry_control_flow_unproven", "handler_entry_deadline_missing"))
        return sorted(set(failures))
    receive_values = body[receive_index : matching_block_end(body, receive_index) + 1]
    if ["after", "http1_handler_guardian_remaining", "(", "HandlerDeadline", ")", "->"] not in [
        receive_values[index : index + 6]
        for index in range(max(0, len(receive_values) - 5))
    ]:
        failures.append("handler_entry_deadline_missing")
    false_body = first_false[1]
    segments = top_level_segments(false_body)
    second_case_index = find_live_block(false_body, "case")
    prefix = false_body[:second_case_index] if second_case_index >= 0 else false_body
    if live_call_present(prefix, "Run"):
        failures.append("handler_run_before_second_deadline")
    probe = [
        "http1_handler_guardian_safe_probe", "(", "Probe", ",", "1", ",", "Guardian", ")"
    ]
    structural = (
        len(segments) >= 2
        and segments[0] == probe
        and segments[1]
        and segments[1][0] == "case"
        and second_case_index == len(segments[0]) + 1
    )
    second_false = (
        case_condition_and_branch(false_body, second_case_index, "false")
        if structural
        else None
    )
    if (
        not structural
        or second_false is None
        or second_false[0] != deadline
        or second_false[1][:5] != ["try", "Run", "(", ")", "of"]
    ):
        failures.extend(
            ("handler_entry_control_flow_unproven", "handler_entry_second_deadline_missing")
        )
    return sorted(set(failures))


def pre_receive_deadline_proven(
    ffi: str,
    function: str,
    deadline: str,
    true_target: str,
    true_arguments: list[str],
    false_target: str,
    false_arguments: list[str],
) -> bool:
    body = function_body_values(ffi, function)
    if body is None or not body or body[0] != "case":
        return False
    expected = ["monotonic_millisecond", "(", ")", ">=", deadline]
    true_branch = case_condition_and_branch(body, 0, "true")
    false_branch = case_condition_and_branch(body, 0, "false")
    return bool(
        true_branch
        and false_branch
        and true_branch[0] == expected
        and false_branch[0] == expected
        and direct_call(true_branch[1], true_target, true_arguments)
        and direct_call(false_branch[1], false_target, false_arguments)
    )


def safe_failure_report(failure: BaseException, phase: str) -> dict[str, object]:
    """Map failures to finite classes without serialising exception payloads."""
    if isinstance(failure, UnicodeError):
        classification = "source_encoding_rejected"
    elif isinstance(failure, OSError):
        classification = "io_rejected"
    elif isinstance(failure, ValueError):
        classification = "source_validation_rejected"
    else:
        classification = "checker_internal_rejected"
    return {"status": "failed", "class": classification, "phase": phase}


def failure_mapping_controls() -> list[dict[str, object]]:
    secret = "PRIVATE_PATH_ENDPOINT_AND_PID"
    cases: tuple[tuple[str, BaseException, str], ...] = (
        ("oserror_payload_redacted", OSError(secret), "io_rejected"),
        (
            "unicode_payload_redacted",
            UnicodeError(secret),
            "source_encoding_rejected",
        ),
    )
    controls: list[dict[str, object]] = []
    for name, failure, expected in cases:
        report = safe_failure_report(failure, "self_test")
        encoded = json.dumps(report, sort_keys=True)
        observed = report.get("class")
        controls.append(
            {
                "name": name,
                "expected": expected,
                "observed": observed,
                "passed": observed == expected and secret not in encoded,
            }
        )
    return controls


def analyze(sources: dict[str, str]) -> list[str]:
    gleam = sources["gleam"]
    ffi = sources["ffi"]
    test = sources["test"]
    test_ffi = sources["test_ffi"]
    failures: list[str] = []

    required_tests = (
        "http1_handler_normal_contract",
        "http1_handler_stop_contract",
        "http1_handler_timeout_contract",
        "http1_handler_crash_contract",
        "http1_handler_owner_down_contract",
        "http1_handler_unconfirmed_cleanup_contract",
        "http1_handler_startup_deadline_contract",
        "http1_handler_entry_deadline_contract",
        "http1_handler_owner_startup_contract",
        "http1_handler_cleanup_deadline_contract",
        "http1_handler_quarantine_retry_deadline_contract",
    )
    for control in required_tests:
        if control not in test or control not in test_ffi:
            failures.append("deterministic_control_missing")
            break

    if '"start_http1_handler_guardian"' not in gleam:
        failures.append("guardian_external_missing")
    if "start_http1_handler_guardian/10" not in ffi:
        failures.append("guardian_export_missing")
    if "erlang:spawn_monitor(fun() ->" not in ffi:
        failures.append("guardian_spawn_not_atomic")

    start_region = function_region(
        ffi,
        "http1_handler_guardian_start_handler",
        "http1_handler_guardian_handler_entry",
    )
    if "erlang:spawn_opt(fun() ->" not in start_region or (
        "end, [link, monitor])," not in start_region
    ):
        failures.append("handler_spawn_not_atomic")

    boot_region = function_region(
        ffi, "http1_handler_guardian_boot", "http1_handler_guardian_start_handler"
    )
    owner_monitor = boot_region.find("erlang:monitor(process, Owner)")
    start_call = boot_region.find("http1_handler_guardian_start_handler(")
    if owner_monitor < 0 or start_call < 0 or owner_monitor > start_call:
        failures.append("owner_monitor_not_dominant")
    probe_call = boot_region.find("http1_handler_guardian_safe_probe(")
    deadline_guard = boot_region.find("monotonic_millisecond() >= HandlerDeadline")
    if (
        probe_call < 0
        or deadline_guard < 0
        or start_call < 0
        or not (probe_call < deadline_guard < start_call)
    ):
        failures.append("handler_start_deadline_not_dominant")
    if not re.search(
        r"erlang:min\(\s*StartupDeadline\s*,\s*HandlerDeadline\s*\)", ffi
    ):
        failures.append("request_deadline_not_bound_to_startup")
    failures.extend(handler_entry_flow_findings(ffi))

    active_region = function_region(
        ffi, "http1_handler_guardian_active", "http1_handler_guardian_down"
    )
    down_region = function_region(
        ffi, "http1_handler_guardian_down", "http1_handler_guardian_begin_termination"
    )
    terminating_region = function_region(
        ffi, "http1_handler_guardian_terminating", "http1_handler_guardian_quarantine"
    )
    quarantine_region = function_region(
        ffi, "http1_handler_guardian_quarantine", "http1_handler_guardian_finish"
    )
    if not pre_receive_deadline_proven(
        ffi,
        "http1_handler_guardian_terminating",
        "CleanupDeadline",
        "http1_handler_guardian_termination_expired",
        ["State", ",", "Termination", ",", "Notify", ",", "CleanupDeadline"],
        "http1_handler_guardian_terminating_receive",
        ["State", ",", "Termination", ",", "Notify", ",", "CleanupDeadline"],
    ):
        failures.append("terminating_pre_receive_deadline_missing")
    if not pre_receive_deadline_proven(
        ffi,
        "http1_handler_guardian_quarantine",
        "RetryDeadline",
        "http1_handler_guardian_quarantine_retry",
        ["State", ",", "Termination", ",", "RetryDeadline"],
        "http1_handler_guardian_quarantine_receive",
        ["State", ",", "Termination", ",", "RetryDeadline"],
    ):
        failures.append("quarantine_pre_receive_deadline_missing")
    joined_regions = down_region + terminating_region + quarantine_region
    if "{'DOWN', HandlerMonitor, process, Handler," not in (
        active_region + joined_regions
    ):
        failures.append("original_handler_down_not_consumed")
    if "erlang:demonitor(HandlerMonitor" in ffi or re.search(
        r"erlang:monitor\s*\(\s*process\s*,\s*Handler\s*\)", ffi
    ):
        failures.append("handler_monitor_replaced")

    publish_calls = len(re.findall(r"http1_handler_guardian_publish_result\s*\(", ffi))
    if publish_calls != 2 or "http1_handler_guardian_publish_result(" not in down_region:
        failures.append("result_not_bound_to_handler_down")
    if "http1_handler_guardian_publish_result(" in active_region:
        failures.append("result_published_before_handler_down")

    if "handler_cleanup_unconfirmed" not in terminating_region:
        failures.append("cleanup_unconfirmed_missing")
    if "http1_handler_guardian_quarantine(" not in terminating_region:
        failures.append("cleanup_owner_not_retained")
    begin_region = function_region(
        ffi,
        "http1_handler_guardian_begin_termination",
        "http1_handler_guardian_terminating",
    )
    if not re.search(
        r"CleanupDeadline\s*=\s*RequestedAt\s*"
        r"\+\s*maps:get\(cleanup_milliseconds,\s*State\)",
        active_region,
    ):
        failures.append("cleanup_deadline_not_derived_from_request")
    if not re.search(
        r"State\s*,\s*EffectiveTermination\s*,\s*true\s*,\s*CleanupDeadline",
        active_region,
    ):
        failures.append("cleanup_deadline_not_forwarded")
    if re.search(
        r"CleanupDeadline\s*=\s*monotonic_millisecond\(\)\s*"
        r"\+\s*maps:get\(cleanup_milliseconds,\s*State\)",
        begin_region,
    ):
        failures.append("cleanup_deadline_reset")
    compact_quarantine = re.sub(r"\s+", "", quarantine_region)
    if not quarantine_region.startswith(
        "http1_handler_guardian_quarantine(State, Termination, RetryDeadline) ->"
    ):
        failures.append("quarantine_retry_deadline_missing")
    if (
        "monotonic_millisecond()+maps:get(cleanup_milliseconds,State)"
        in compact_quarantine
        or "http1_handler_guardian_remaining(RetryDeadline)"
        not in compact_quarantine
    ):
        failures.append("quarantine_retry_deadline_reset")
    if compact_quarantine.count(",Termination,RetryDeadline)") < 6:
        failures.append("quarantine_retry_deadline_not_threaded")
    if not re.search(
        r"http1_handler_guardian_quarantine_retry\(\s*"
        r"State\s*,\s*Termination\s*,\s*RetryDeadline\s*\)\s*->\s*"
        r"http1_handler_guardian_safe_terminate\(State\)\s*,\s*"
        r"NextRetryDeadline\s*=\s*RetryDeadline\s*\+\s*"
        r"maps:get\(cleanup_milliseconds\s*,\s*State\)\s*,\s*"
        r"http1_handler_guardian_quarantine\(\s*State\s*,\s*Termination\s*,\s*"
        r"NextRetryDeadline\s*\)",
        quarantine_region,
        re.DOTALL,
    ):
        failures.append("quarantine_retry_advance_missing")
    if not re.search(
        r"http1_handler_guardian_quarantine\(\s*State\s*,\s*Termination\s*,\s*"
        r"CleanupDeadline\s*\+\s*maps:get\(cleanup_milliseconds\s*,\s*State\)\s*\)",
        terminating_region,
        re.DOTALL,
    ):
        failures.append("quarantine_retry_origin_missing")
    if not re.search(
        r"State\s*,\s*handler_timed_out\s*,\s*true\s*,\s*"
        r"HandlerDeadline\s*\+\s*maps:get\(cleanup_milliseconds,\s*State\)",
        active_region,
    ):
        failures.append("internal_timeout_cleanup_origin_missing")
    if not re.search(
        r"OwnerDownAt\s*\+\s*maps:get\(cleanup_milliseconds,\s*State\)",
        active_region,
    ):
        failures.append("owner_down_cleanup_origin_missing")
    if "handler_deadline" not in gleam or not re.search(
        r"handler_deadline\s*=\s*transport\.monotonic_millisecond\(\)\s*\+\s*context\.remaining_milliseconds",
        gleam,
        re.DOTALL,
    ):
        failures.append("absolute_handler_deadline_missing")
    absolute_receive_region = function_region(
        gleam,
        "fn receive_http1_handler_message",
        "pub fn handler_deadline_traffic_control",
    )
    if (
        "within: config.operation_timeout_milliseconds" in function_region(
            gleam, "fn await_handler", "fn fulfill_incoming"
        )
        or "within: relative_timeout_milliseconds" in absolute_receive_region
    ):
        failures.append("handler_deadline_reset")
    if gleam.count("handler_deadline,") < 5:
        failures.append("handler_deadline_not_threaded")
    if "TerminateHandler(termination, requested_at)" not in gleam:
        failures.append("typed_termination_command_missing")
    if "HandlerCleanupUnconfirmed" not in gleam:
        failures.append("typed_cleanup_outcome_missing")
    await_region = function_region(
        gleam, "fn await_handler", "fn terminate_handler_and_await"
    )
    if "receive_http1_handler_message(" not in await_region:
        failures.append("production_await_not_bound_to_absolute_receiver")
    if not re.search(
        r"HandlerTimedOut\s*,\s*handler_deadline\s*,", await_region
    ):
        failures.append("internal_timeout_connection_origin_missing")
    if "pub fn handler_deadline_traffic_control(" not in gleam:
        failures.append("await_traffic_behavior_control_missing")
    if "within: handler_remaining(handler_deadline)" not in gleam:
        failures.append("absolute_receive_primitive_missing")
    behavior_markers = (
        "handler_entry_topology",
        "handler_entry_barrier",
        "entry_deadline_probe",
        "startup_probe",
        "owner_startup_probe",
        "suspend_process",
        "RequestedAt + 1500",
        "entry_phase_one",
        "release_entry_phase_one",
        "record_termination",
        "quarantine_duplicate_dispatched",
        "release_quarantine_dispatch",
        "RetryWhileTrafficActive",
        "termination_called",
        "RequestedAt + 2000",
    )
    if not all(marker in test_ffi for marker in behavior_markers):
        failures.append("production_behavior_control_missing")
    entry_control_region = function_region(
        test_ffi,
        "http1_handler_entry_deadline_contract_run",
        "http1_handler_owner_startup_contract_run",
    )
    entry_order = [
        entry_control_region.find("PhaseTwoBeforeDeadline"),
        entry_control_region.find("Guardian ! {Reference, release_entry_deadline}"),
        entry_control_region.find("PhaseOneOutcome"),
        entry_control_region.find("contract_wait_until(HandlerDeadline)"),
        entry_control_region.find("Handler ! {Reference, release_entry_phase_one}"),
        entry_control_region.find("TimedOut ="),
        entry_control_region.find("RunNeverExecuted"),
        entry_control_region.find("CancelOnce"),
        entry_control_region.find("NoDuplicate"),
    ]
    if any(position < 0 for position in entry_order) or entry_order != sorted(
        entry_order
    ):
        failures.append("handler_entry_behavior_order_missing")
    if not all(
        marker in entry_control_region
        for marker in (
            "handler_terminated, handler_timed_out",
            "contract_await_down",
            "PhaseOneOnce",
            "HandlerObserver = erlang:monitor(process, Handler)",
            "HandlerDown",
            "GuardianDown",
            "Reference, entry_phase_one, self(),",
            "{Reference, release_entry_phase_one} -> nil",
        )
    ):
        failures.append("handler_entry_behavior_outcome_missing")
    quarantine_control_region = function_region(
        test_ffi,
        "http1_handler_quarantine_retry_deadline_contract_run",
        "start_contract_guardian",
    )
    if not all(
        marker in quarantine_control_region
        for marker in (
            "record_termination",
            "RequestedAt + 1500",
            "RequestedAt + 2000",
            "quarantine_duplicate_dispatched",
            "release_quarantine_dispatch",
            "RetryWhileTrafficActive",
            "termination_called",
            "CancelOnce",
            "GuardianDown",
            "NoDuplicate",
        )
    ):
        failures.append("quarantine_retry_behavior_control_missing")
    if "handler_deadline_traffic_control(" not in test:
        failures.append("await_traffic_test_missing")
    return sorted(set(failures))


def replace_in_region(
    source: str, name: str, next_name: str, old: str, new: str
) -> str:
    region = function_region(source, name, next_name)
    if not region or region.count(old) != 1:
        return source
    return source.replace(region, region.replace(old, new, 1), 1)


def apply_mutations(sources: dict[str, str]) -> dict[str, dict[str, object]]:
    mutants: dict[str, tuple[dict[str, str], str]] = {}

    spawn_gap = dict(sources)
    spawn_gap["ffi"] = replace_in_region(
        sources["ffi"],
        "http1_handler_guardian_start_handler",
        "http1_handler_guardian_handler_entry",
        "{Handler, HandlerMonitor} = erlang:spawn_opt(fun() ->\n"
        "        http1_handler_guardian_handler_entry(\n"
        "            Guardian, HandlerReference, Run, Probe, AfterResult,\n"
        "            HandlerDeadline\n"
        "        )\n"
        "    end, [link, monitor]),",
        "Handler = erlang:spawn_link(fun() ->\n"
        "        http1_handler_guardian_handler_entry(\n"
        "            Guardian, HandlerReference, Run, Probe, AfterResult,\n"
        "            HandlerDeadline\n"
        "        )\n"
        "    end),\n"
        "    Handler ! {HandlerReference, handler_start, Guardian},\n"
        "    receive\n"
        "        {_ContractReference, handler_entry_barrier} -> ok\n"
        "    after 1000 -> ok\n"
        "    end,\n"
        "    HandlerMonitor = erlang:monitor(process, Handler),",
    )
    mutants["spawn_then_monitor_gap"] = (spawn_gap, "handler_spawn_not_atomic")

    monitor_gap = dict(sources)
    monitor_gap["ffi"] = sources["ffi"].replace(
        "    end, [link, monitor]),\n"
        "    State = #{",
        "    end, [link, monitor]),\n"
        "    erlang:demonitor(HandlerMonitor, [flush]),\n"
        "    ReplacementHandlerMonitor = erlang:monitor(process, Handler),\n"
        "    State = #{",
        1,
    ).replace(
        "        handler_monitor => HandlerMonitor,",
        "        handler_monitor => ReplacementHandlerMonitor,",
        1,
    )
    mutants["monitor_replacement_gap"] = (
        monitor_gap,
        "handler_monitor_replaced",
    )

    reset = dict(sources)
    reset["gleam"] = sources["gleam"].replace(
        "within: handler_remaining(handler_deadline)",
        "within: relative_timeout_milliseconds",
        1,
    )
    mutants["relative_deadline_reset"] = (reset, "handler_deadline_reset")

    owner_gap = dict(sources)
    owner_gap["ffi"] = sources["ffi"].replace(
        "OwnerMonitor = erlang:monitor(process, Owner),",
        "OwnerMonitor = make_ref(),",
        1,
    )
    mutants["owner_monitor_gap"] = (owner_gap, "owner_monitor_not_dominant")

    startup = dict(sources)
    startup["ffi"] = replace_in_region(
        sources["ffi"],
        "http1_handler_guardian_boot",
        "http1_handler_guardian_start_handler",
        "monotonic_millisecond() >= HandlerDeadline",
        "false",
    )
    mutants["startup_deadline_removed"] = (
        startup,
        "handler_start_deadline_not_dominant",
    )

    entry_deadline = dict(sources)
    entry_deadline["ffi"] = replace_in_region(
        sources["ffi"],
        "http1_handler_guardian_handler_entry",
        "http1_handler_guardian_handler_timed_out",
        "http1_handler_guardian_safe_probe(Probe, 1, Guardian),\n"
        "                    case monotonic_millisecond() >= HandlerDeadline of",
        "http1_handler_guardian_safe_probe(Probe, 1, Guardian),\n"
        "                    case false of",
    )
    mutants["handler_entry_second_deadline_removed"] = (
        entry_deadline,
        "handler_entry_second_deadline_missing",
    )

    dead_second_check = dict(sources)
    dead_second_check["ffi"] = replace_in_region(
        sources["ffi"],
        "http1_handler_guardian_handler_entry",
        "http1_handler_guardian_handler_timed_out",
        "http1_handler_guardian_safe_probe(Probe, 1, Guardian),\n"
        "                    case monotonic_millisecond() >= HandlerDeadline of",
        "http1_handler_guardian_safe_probe(Probe, 1, Guardian),\n"
        "                    _DeadCheck = fun() ->\n"
        "                        case monotonic_millisecond() >= HandlerDeadline of\n"
        "                            true -> ok; false -> ok\n"
        "                        end\n"
        "                    end,\n"
        "                    case false of",
    )
    mutants["dead_second_deadline_decoy"] = (
        dead_second_check,
        "handler_entry_control_flow_unproven",
    )

    comment_second_check = dict(sources)
    comment_second_check["ffi"] = replace_in_region(
        sources["ffi"],
        "http1_handler_guardian_handler_entry",
        "http1_handler_guardian_handler_timed_out",
        "http1_handler_guardian_safe_probe(Probe, 1, Guardian),\n"
        "                    case monotonic_millisecond() >= HandlerDeadline of",
        "http1_handler_guardian_safe_probe(Probe, 1, Guardian),\n"
        "                    % case monotonic_millisecond() >= HandlerDeadline of\n"
        "                    case false of",
    )
    mutants["comment_second_deadline_decoy"] = (
        comment_second_check,
        "handler_entry_control_flow_unproven",
    )

    premature_run = dict(sources)
    premature_run["ffi"] = replace_in_region(
        sources["ffi"],
        "http1_handler_guardian_handler_entry",
        "http1_handler_guardian_handler_timed_out",
        "http1_handler_guardian_safe_probe(Probe, 1, Guardian),\n"
        "                    case monotonic_millisecond() >= HandlerDeadline of",
        "http1_handler_guardian_safe_probe(Probe, 1, Guardian),\n"
        "                    _Premature = Run(),\n"
        "                    case monotonic_millisecond() >= HandlerDeadline of",
    )
    mutants["run_before_second_deadline"] = (
        premature_run,
        "handler_run_before_second_deadline",
    )

    terminating_precheck = dict(sources)
    terminating_precheck["ffi"] = replace_in_region(
        sources["ffi"],
        "http1_handler_guardian_terminating",
        "http1_handler_guardian_terminating_receive",
        "case monotonic_millisecond() >= CleanupDeadline of",
        "case false of",
    )
    mutants["terminating_pre_receive_deadline_removed"] = (
        terminating_precheck,
        "terminating_pre_receive_deadline_missing",
    )

    quarantine_precheck = dict(sources)
    quarantine_precheck["ffi"] = replace_in_region(
        sources["ffi"],
        "http1_handler_guardian_quarantine",
        "http1_handler_guardian_quarantine_receive",
        "case monotonic_millisecond() >= RetryDeadline of",
        "case false of",
    )
    mutants["quarantine_pre_receive_deadline_removed"] = (
        quarantine_precheck,
        "quarantine_pre_receive_deadline_missing",
    )

    cleanup_reset = dict(sources)
    cleanup_reset["ffi"] = replace_in_region(
        sources["ffi"],
        "http1_handler_guardian_active",
        "http1_handler_guardian_down",
        "CleanupDeadline = RequestedAt\n"
        "                + maps:get(cleanup_milliseconds, State)",
        "CleanupDeadline = monotonic_millisecond()\n"
        "                + maps:get(cleanup_milliseconds, State)",
    )
    mutants["cleanup_deadline_reset"] = (
        cleanup_reset,
        "cleanup_deadline_not_derived_from_request",
    )

    quarantine_reset = dict(sources)
    quarantine_reset["ffi"] = replace_in_region(
        sources["ffi"],
        "http1_handler_guardian_quarantine",
        "http1_handler_guardian_finish",
        "http1_handler_guardian_quarantine(\n"
        "                State, Termination, RetryDeadline\n"
        "            );",
        "http1_handler_guardian_quarantine(\n"
        "                State, Termination,\n"
        "                monotonic_millisecond()\n"
        "                    + maps:get(cleanup_milliseconds, State)\n"
        "            );",
    )
    mutants["quarantine_retry_deadline_reset"] = (
        quarantine_reset,
        "quarantine_retry_deadline_reset",
    )

    early = dict(sources)
    early["ffi"] = sources["ffi"].replace(
        "{HandlerReference, handler_result, Handler, Result} ->",
        "{HandlerReference, handler_result, Handler, Result} ->\n"
        "            http1_handler_guardian_publish_result(Events, Result),",
        1,
    )
    mutants["publish_before_down"] = (
        early,
        "result_published_before_handler_down",
    )

    results: dict[str, dict[str, object]] = {}
    for name, (mutant, expected_failure) in mutants.items():
        changed = mutant != sources
        failures = analyze(mutant) if changed else ["mutation_not_applied"]
        results[name] = {
            "changed": changed,
            "detected": expected_failure in failures,
            "expected_failure": expected_failure,
            "failures": failures,
        }
    return results


def main() -> int:
    try:
        loaded = {name: safe_read(path) for name, path in FILES.items()}
        _scanner_source, scanner_hash = safe_read(Path(__file__).resolve())
        runtime_hash = safe_hash(Path(sys.executable).resolve(strict=True))
    except (OSError, UnicodeError, ValueError) as failure:
        print(json.dumps(safe_failure_report(failure, "pre_read"), sort_keys=True))
        return 1
    sources = {name: value[0] for name, value in loaded.items()}
    hashes = {name: value[1] for name, value in loaded.items()}
    failures = analyze(sources)
    mutations = apply_mutations(sources) if not failures else {}
    mutations_green = bool(mutations) and all(
        result["changed"] and result["detected"] for result in mutations.values()
    )
    safe_controls = failure_mapping_controls()
    safe_controls_green = all(
        control.get("passed") is True for control in safe_controls
    )
    try:
        post_loaded = {name: safe_read(path) for name, path in FILES.items()}
        post_hashes = {name: value[1] for name, value in post_loaded.items()}
        _scanner_post_source, scanner_post_hash = safe_read(Path(__file__).resolve())
        runtime_post_hash = safe_hash(Path(sys.executable).resolve(strict=True))
    except (OSError, UnicodeError, ValueError) as failure:
        print(json.dumps(safe_failure_report(failure, "post_read"), sort_keys=True))
        return 1
    source_stable = hashes == post_hashes
    scanner_stable = scanner_hash == scanner_post_hash
    runtime_stable = runtime_hash == runtime_post_hash
    identity_stable = source_stable and scanner_stable and runtime_stable
    if not identity_stable:
        failures.append("source_changed_during_scan")
    status = "passed" if (
        not failures
        and mutations_green
        and safe_controls_green
        and identity_stable
    ) else "failed"
    report = {
        "schema": 3,
        "status": status,
        "class": "ok" if status == "passed" else (
            failures[0]
            if failures
            else (
                "mutation_detection_failed"
                if not mutations_green
                else "safe_output_control_failed"
            )
        ),
        "source_sha256_pre": hashes,
        "source_sha256_post": post_hashes,
        "source_stable": source_stable,
        "scanner_sha256_pre": scanner_hash,
        "scanner_sha256_post": scanner_post_hash,
        "scanner_stable": scanner_stable,
        "python_executable_sha256_pre": runtime_hash,
        "python_executable_sha256_post": runtime_post_hash,
        "python_executable_stable": runtime_stable,
        "python_version": platform.python_version(),
        "limits": {
            "source_bytes": MAXIMUM_BYTES,
            "tokens": MAXIMUM_TOKENS,
            "report_bytes": 1024 * 1024,
        },
        "failures": failures,
        "mutations": mutations,
        "adversarial_controls": safe_controls,
        "completed_adversarial_controls": len(safe_controls),
        "rerun_command": (
            "python -I -B build/root-validation/"
            "http1-handler-guardian-contract-check.py"
        ),
    }
    encoded = json.dumps(report, sort_keys=True, separators=(",", ":"))
    if len(encoded.encode("utf-8")) > 1024 * 1024:
        print(json.dumps({"status": "failed", "class": "report_limit_rejected"}, sort_keys=True))
        return 1
    print(encoded)
    return 0 if status == "passed" else 1


if __name__ == "__main__":
    sys.exit(main())

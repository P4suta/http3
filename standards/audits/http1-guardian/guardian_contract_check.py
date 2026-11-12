#!/usr/bin/env python3
"""Finite static contract and mutation gate for the HTTP/1 handler guardian."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import re
import stat
import sys
import tempfile
from pathlib import Path


ROOT = Path(__file__).resolve().parents[3]
MAXIMUM_BYTES = 2 * 1024 * 1024
MAXIMUM_TOOL_BYTES = 64 * 1024 * 1024
MAXIMUM_TOKENS = 300_000
EXPECTED_PYTHON_VERSION = "3.12.13"
FILES = {
    "gleam": ROOT / "src/http/internal/http1/server.gleam",
    "ffi": ROOT / "src/http_server_ffi.erl",
    "test": ROOT / "test/server_handler_lifetime_test.gleam",
    "test_ffi": ROOT / "test/http_handler_lifetime_test_ffi.erl",
}


def safe_read_bytes(path: Path, maximum: int) -> tuple[bytes, str]:
    absolute = Path(os.path.abspath(path))
    before_path = os.lstat(absolute)
    reparse_flag = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0)
    attributes = getattr(before_path, "st_file_attributes", 0)
    if stat.S_ISLNK(before_path.st_mode) or (
        reparse_flag and attributes & reparse_flag
    ):
        raise ValueError("source_identity_rejected")
    if not stat.S_ISREG(before_path.st_mode):
        raise ValueError("source_identity_rejected")
    if before_path.st_size <= 0 or before_path.st_size > maximum:
        raise ValueError("source_size_rejected")
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
                raise ValueError("source_size_rejected")
            chunks.append(chunk)
        after_handle = os.fstat(handle.fileno())
    after_path = os.lstat(absolute)
    identity = lambda item: (
        item.st_dev, item.st_ino, item.st_size, item.st_mtime_ns
    )
    if not (
        identity(before_path) == identity(before_handle)
        == identity(after_handle) == identity(after_path)
    ):
        raise ValueError("source_changed_during_read")
    data = b"".join(chunks)
    if len(data) != before_path.st_size:
        raise ValueError("partial_read_rejected")
    return data, hashlib.sha256(data).hexdigest()


def safe_read(path: Path) -> tuple[str, str]:
    data, digest = safe_read_bytes(path, MAXIMUM_BYTES)
    return data.decode("utf-8", errors="strict"), digest


def safe_hash(path: Path, maximum: int = MAXIMUM_BYTES) -> str:
    return safe_read_bytes(path, maximum)[1]


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
    declarations = list(
        re.finditer(r"(?m)^([a-z][A-Za-z0-9_]*)\s*\(", clean)
    )
    target = next(
        (index for index, match in enumerate(declarations) if match.group(1) == name),
        None,
    )
    if target is None:
        return ""
    declaration = declarations[target]
    following = next(
        (
            match
            for match in declarations[target + 1 :]
            if match.group(1) != name
        ),
        None,
    )
    following_attribute = re.search(r"(?m)^-", clean[declaration.end() :])
    candidate_ends = [
        position
        for position in (
            following.start() if following is not None else None,
            (
                declaration.end() + following_attribute.start()
                if following_attribute is not None
                else None
            ),
        )
        if position is not None
    ]
    end = min(candidate_ends) if candidate_ends else len(source)
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


def single_clause_body_values(source: str, name: str) -> list[str] | None:
    """Return one unguarded Erlang function clause or fail closed.

    Multiple clauses with the same name are kept in one source region.  A
    top-level semicolon therefore proves that the function has another live
    clause and cannot be validated from a convenient dead first clause.
    """
    region = erlang_function_region(source, name)
    if not region:
        return None
    values = erlang_token_values(region)
    if len(values) < 6 or values[0:2] != [name, "("]:
        return None
    closing = matching_delimiter(values, 1, "(", ")")
    if closing < 0 or values[closing + 1 : closing + 2] != ["->"]:
        return None
    if values[-1:] != ["."]:
        return None
    body = values[closing + 2 : -1]
    if not body or top_level_token_present(body, ";"):
        return None
    return body


def strict_receive_parts(
    values: list[str],
) -> tuple[list[str], list[str], list[str], list[str]] | None:
    """Parse exactly one receive clause and one after clause."""
    if not values or values[0] != "receive":
        return None
    block_end = matching_block_end(values, 0)
    if block_end != len(values) - 1:
        return None
    live: list[tuple[int, str]] = []
    index = 1
    delimiters = {"(": ")", "[": "]", "{": "}"}
    while index < block_end:
        value = values[index]
        if value in delimiters:
            end = matching_delimiter(values, index, value, delimiters[value])
            if end < 0:
                return None
            index = end + 1
            continue
        if block_opens(values, index):
            end = matching_block_end(values, index)
            if end < 0:
                return None
            index = end + 1
            continue
        live.append((index, value))
        index += 1
    arrows = [position for position, value in live if value == "->"]
    afters = [position for position, value in live if value == "after"]
    semicolons = [position for position, value in live if value == ";"]
    if len(arrows) != 2 or len(afters) != 1 or semicolons:
        return None
    first_arrow, after_arrow = arrows
    after = afters[0]
    if not (1 < first_arrow < after < after_arrow < block_end):
        return None
    return (
        values[1:first_arrow],
        values[first_arrow + 1 : after],
        values[after + 1 : after_arrow],
        values[after_arrow + 1 : block_end],
    )


def receive_clauses_and_after(
    values: list[str],
) -> tuple[list[tuple[list[str], list[str]]], list[str], list[str]] | None:
    """Parse every live top-level receive clause and the after arm."""
    if not values or values[0] != "receive":
        return None
    block_end = matching_block_end(values, 0)
    if block_end != len(values) - 1:
        return None
    live: list[tuple[int, str]] = []
    index = 1
    delimiters = {"(": ")", "[": "]", "{": "}"}
    while index < block_end:
        value = values[index]
        if value in delimiters:
            end = matching_delimiter(values, index, value, delimiters[value])
            if end < 0:
                return None
            index = end + 1
            continue
        if block_opens(values, index):
            end = matching_block_end(values, index)
            if end < 0:
                return None
            index = end + 1
            continue
        live.append((index, value))
        index += 1
    after_positions = [position for position, value in live if value == "after"]
    if len(after_positions) != 1:
        return None
    after = after_positions[0]
    before_after = values[1:after]
    after_values = values[after + 1 : block_end]
    after_arrows = [
        index
        for index in range(len(after_values))
        if after_values[index] == "->"
        and not top_level_token_present(after_values[:index], "->")
    ]
    if len(after_arrows) != 1:
        return None
    after_arrow = after_arrows[0]
    timeout = after_values[:after_arrow]
    timeout_body = after_values[after_arrow + 1 :]
    raw_clauses = top_level_segments(before_after, ";")
    clauses: list[tuple[list[str], list[str]]] = []
    for clause in raw_clauses:
        arrows: list[int] = []
        cursor = 0
        while cursor < len(clause):
            if clause[cursor] in ("(", "[", "{"):
                closing = {"(": ")", "[": "]", "{": "}"}[clause[cursor]]
                cursor = matching_delimiter(clause, cursor, clause[cursor], closing) + 1
                if cursor <= 0:
                    return None
                continue
            if block_opens(clause, cursor):
                cursor = matching_block_end(clause, cursor) + 1
                if cursor <= 0:
                    return None
                continue
            if clause[cursor] == "->":
                arrows.append(cursor)
            cursor += 1
        if len(arrows) != 1:
            return None
        arrow = arrows[0]
        clauses.append((clause[:arrow], clause[arrow + 1 :]))
    return clauses, timeout, timeout_body


def case_subject_and_clauses(
    values: list[str],
) -> tuple[list[str], list[tuple[list[str], list[str]]]] | None:
    """Parse one complete case expression without accepting nested decoys."""
    if not values or values[0] != "case":
        return None
    block_end = matching_block_end(values, 0)
    if block_end != len(values) - 1:
        return None
    of_index = -1
    index = 1
    delimiters = {"(": ")", "[": "]", "{": "}"}
    while index < block_end:
        value = values[index]
        if value in delimiters:
            end = matching_delimiter(values, index, value, delimiters[value])
            if end < 0:
                return None
            index = end + 1
            continue
        if block_opens(values, index):
            end = matching_block_end(values, index)
            if end < 0:
                return None
            index = end + 1
            continue
        if value == "of":
            of_index = index
            break
        index += 1
    if of_index <= 1:
        return None
    raw_clauses = top_level_segments(values[of_index + 1 : block_end], ";")
    if not raw_clauses:
        return None
    clauses: list[tuple[list[str], list[str]]] = []
    for clause in raw_clauses:
        arrows: list[int] = []
        cursor = 0
        while cursor < len(clause):
            value = clause[cursor]
            if value in delimiters:
                end = matching_delimiter(clause, cursor, value, delimiters[value])
                if end < 0:
                    return None
                cursor = end + 1
                continue
            if block_opens(clause, cursor):
                end = matching_block_end(clause, cursor)
                if end < 0:
                    return None
                cursor = end + 1
                continue
            if value == "->":
                arrows.append(cursor)
            cursor += 1
        if len(arrows) != 1:
            return None
        arrow = arrows[0]
        clauses.append((clause[:arrow], clause[arrow + 1 :]))
    return values[1:of_index], clauses


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


def top_level_token_present(values: list[str], token: str) -> bool:
    index = 0
    delimiters = {"(": ")", "[": "]", "{": "}"}
    while index < len(values):
        value = values[index]
        if value in delimiters:
            end = matching_delimiter(values, index, value, delimiters[value])
            if end < 0:
                return True
            index = end + 1
            continue
        if block_opens(values, index):
            end = matching_block_end(values, index)
            if end < 0:
                return True
            index = end + 1
            continue
        if value == token:
            return True
        index += 1
    return False


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


def live_call_count(values: list[str], name: str) -> int:
    """Count reachable calls in this lexical scope, excluding nested funs."""
    count = 0
    index = 0
    while index < len(values):
        if values[index] == "fun" and block_opens(values, index):
            end = matching_block_end(values, index)
            if end < 0:
                return MAXIMUM_TOKENS
            index = end + 1
            continue
        if values[index : index + 2] == [name, "("]:
            count += 1
        index += 1
    return count


def token_call_count(values: list[str], name: str) -> int:
    """Count every syntactic call, including calls hidden in nested funs."""
    return sum(
        values[index : index + 2] == [name, "("]
        for index in range(max(0, len(values) - 1))
    )


def split_token_arguments(values: list[str], opening: int) -> list[list[str]] | None:
    closing = matching_delimiter(values, opening, "(", ")")
    if closing < 0:
        return None
    arguments = top_level_segments(values[opening + 1 : closing])
    return arguments


def live_call_arguments(values: list[str], name: str) -> list[list[list[str]]]:
    calls: list[list[list[str]]] = []
    index = 0
    while index < len(values) - 1:
        if values[index] == "fun" and block_opens(values, index):
            end = matching_block_end(values, index)
            if end < 0:
                return []
            index = end + 1
            continue
        if values[index : index + 2] == [name, "("]:
            arguments = split_token_arguments(values, index + 1)
            closing = matching_delimiter(values, index + 1, "(", ")")
            if arguments is None or closing < 0:
                return []
            calls.append(arguments)
            index = closing + 1
            continue
        index += 1
    return calls


def exact_call_arguments(
    values: list[str], name: str
) -> list[list[str]] | None:
    if values[:2] != [name, "("]:
        return None
    closing = matching_delimiter(values, 1, "(", ")")
    if closing != len(values) - 1:
        return None
    return split_token_arguments(values, 1)


def handler_down_flow_proven(ffi: str) -> bool:
    """Bind every reachable handler-DOWN outcome to one terminal finish."""
    body = single_clause_body_values(ffi, "http1_handler_guardian_down")
    if body is None:
        return False
    segments = top_level_segments(body)
    if len(segments) != 3:
        return False
    if segments[0] != [
        "Deadline", "=", "maps", ":", "get", "(",
        "handler_deadline", ",", "State", ")",
    ] or segments[1] != [
        "Events", "=", "maps", ":", "get", "(",
        "events", ",", "State", ")",
    ]:
        return False
    parsed = case_subject_and_clauses(segments[2])
    expected_subject = [
        "{",
        "maps", ":", "get", "(", "timed_out", ",", "State", ")", ",",
        "maps", ":", "get", "(", "result", ",", "State", ")", ",",
        "maps", ":", "get", "(", "exit_at", ",", "State", ")", ",",
        "maps", ":", "get", "(", "failure_at", ",", "State", ")",
        "}",
    ]
    if parsed is None or parsed[0] != expected_subject:
        return False
    clauses = parsed[1]
    expected_heads = [
        ["{", "true", ",", "Result", ",", "_ExitAt", ",", "_FailureAt", "}"],
        [
            "{", "false", ",", "{", "some", ",", "Result", "}", ",",
            "{", "some", ",", "ExitAt", "}", ",", "none", "}",
            "when", "ExitAt", "=<", "Deadline",
        ],
        [
            "{", "false", ",", "{", "some", ",", "Result", "}", ",",
            "{", "some", ",", "_LateExitAt", "}", ",", "none", "}",
        ],
        [
            "{", "false", ",", "Result", ",", "_ExitAt", ",",
            "{", "some", ",", "FailureAt", "}", "}",
            "when", "FailureAt", ">=", "Deadline",
        ],
        [
            "{", "false", ",", "Result", ",", "_ExitAt", ",",
            "{", "some", ",", "_FailureAt", "}", "}",
        ],
        ["{", "false", ",", "Result", ",", "_ExitAt", ",", "none", "}"],
    ]
    if len(clauses) != len(expected_heads):
        return False
    cancel = ["http1_handler_guardian_safe_cancel", "(", "State", ")"]
    discard_optional = [
        "http1_handler_guardian_discard_optional", "(",
        "State", ",", "Result", ")",
    ]
    discard = [
        "http1_handler_guardian_safe_discard", "(",
        "State", ",", "Result", ")",
    ]
    timeout = [
        "send_subject", "(", "Events", ",", "{",
        "handler_terminated", ",", "handler_timed_out", "}", ")",
    ]
    failed = ["send_subject", "(", "Events", ",", "handler_failed", ")"]
    publish = [
        "http1_handler_guardian_publish_result", "(",
        "Events", ",", "Result", ")",
    ]
    finish = ["http1_handler_guardian_finish", "(", "State", ")"]
    expected_branches = [
        [cancel, discard_optional, timeout, finish],
        [publish, finish],
        [cancel, discard, timeout, finish],
        [cancel, discard_optional, timeout, finish],
        [cancel, discard_optional, failed, finish],
        [cancel, discard_optional, failed, finish],
    ]
    for (head, branch), expected_head, expected_segments in zip(
        clauses, expected_heads, expected_branches, strict=True
    ):
        if head != expected_head or top_level_segments(branch) != expected_segments:
            return False
    return True


def receive_dispatcher_proven(
    ffi: str,
    receive_function: str,
    dispatcher: str,
    deadline: str,
    arity: int,
    expected_calls: int,
) -> bool:
    body = single_clause_body_values(ffi, receive_function)
    if body is None or live_call_count(body, receive_function) != 0:
        return False
    segments = top_level_segments(body)
    if not segments or not segments[-1] or segments[-1][0] != "receive":
        return False
    parsed = receive_clauses_and_after(segments[-1])
    if parsed is None:
        return False
    clauses, timeout, timeout_body = parsed
    if len(clauses) != expected_calls + 1:
        return False
    terminal_pattern = ["{", "DOWN", ",", "HandlerMonitor", ",", "process", ",", "Handler", ",", "_", "}"]
    terminal_count = 0
    dispatcher_count = 0
    for pattern, branch in clauses:
        if "<unproved_fun>" in live_local_call_names(branch):
            return False
        if live_call_count(branch, receive_function) != 0:
            return False
        branch_segments = top_level_segments(branch)
        if not branch_segments:
            return False
        if pattern == terminal_pattern:
            terminal_count += 1
            if (
                exact_call_arguments(
                    branch_segments[-1], "http1_handler_guardian_finish"
                ) != [["State"]]
                or live_call_count(branch, dispatcher) != 0
            ):
                return False
            continue
        arguments = exact_call_arguments(branch_segments[-1], dispatcher)
        if arguments is None or len(arguments) != arity or arguments[-1] != [deadline]:
            return False
        state = arguments[0]
        if state != ["State"] and state[:3] != ["State", "#", "{"]:
            return False
        if live_call_count(branch, dispatcher) != 1:
            return False
        dispatcher_count += 1
    timeout_target = (
        "http1_handler_guardian_termination_expired"
        if dispatcher == "http1_handler_guardian_terminating"
        else "http1_handler_guardian_quarantine_retry"
    )
    timeout_arguments = exact_call_arguments(timeout_body, timeout_target)
    return bool(
        terminal_count == 1
        and dispatcher_count == expected_calls
        and timeout == [
            "http1_handler_guardian_remaining", "(", deadline, ")"
        ]
        and timeout_arguments is not None
        and len(timeout_arguments) == arity
        and timeout_arguments[-1] == [deadline]
    )


def live_local_call_names(values: list[str]) -> list[str]:
    names: list[str] = []
    index = 0
    while index < len(values) - 1:
        if values[index] == "fun" and block_opens(values, index):
            return ["<unproved_fun>"]
        value = values[index]
        if (
            re.fullmatch(r"[a-z][A-Za-z0-9_]*", value)
            and values[index + 1] == "("
            and (index == 0 or values[index - 1] != ":")
        ):
            names.append(value)
        index += 1
    return names


def region_local_call_names(ffi: str, function: str) -> list[str]:
    region = erlang_function_region(ffi, function)
    if not region:
        return ["<missing>"]
    values = erlang_token_values(region)
    names: list[str] = []
    index = 0
    while index < len(values) - 1:
        if values[index] == "fun" and block_opens(values, index):
            return ["<unproved_fun>"]
        value = values[index]
        if (
            re.fullmatch(r"[a-z][A-Za-z0-9_]*", value)
            and values[index + 1] == "("
            and (index == 0 or values[index - 1] != ":")
        ):
            is_clause_header = value == function and (
                index == 0 or values[index - 1] == ";"
            )
            if not is_clause_header:
                names.append(value)
        index += 1
    return names


def closed_critical_helpers_proven(ffi: str) -> bool:
    """Permit only reviewed local semantics before publication/finish."""
    if not handler_down_flow_proven(ffi):
        return False
    allowlists = {
        "http1_handler_guardian_active": {
            "is_integer",
            "monotonic_millisecond",
            "http1_handler_guardian_active",
            "http1_handler_guardian_begin_termination",
            "http1_handler_guardian_down",
            "http1_handler_guardian_remaining",
        },
        "http1_handler_guardian_down": {
            "send_subject",
            "http1_handler_guardian_safe_cancel",
            "http1_handler_guardian_discard_optional",
            "http1_handler_guardian_safe_discard",
            "http1_handler_guardian_publish_result",
            "http1_handler_guardian_finish",
        },
        "http1_handler_guardian_terminating_receive": {
            "is_integer",
            "send_subject",
            "http1_handler_guardian_terminating",
            "http1_handler_guardian_discard_optional",
            "http1_handler_guardian_finish",
            "http1_handler_guardian_remaining",
            "http1_handler_guardian_termination_expired",
        },
        "http1_handler_guardian_quarantine_receive": {
            "is_integer",
            "http1_handler_guardian_quarantine",
            "http1_handler_guardian_discard_optional",
            "http1_handler_guardian_finish",
            "http1_handler_guardian_safe_probe",
            "http1_handler_guardian_remaining",
            "http1_handler_guardian_quarantine_retry",
        },
        "http1_handler_guardian_begin_termination": {
            "http1_handler_guardian_safe_terminate",
            "http1_handler_guardian_safe_cancel",
            "http1_handler_guardian_terminating",
        },
        "http1_handler_guardian_terminating": {
            "monotonic_millisecond",
            "http1_handler_guardian_termination_expired",
            "http1_handler_guardian_terminating_receive",
        },
        "http1_handler_guardian_termination_expired": {
            "send_subject",
            "http1_handler_guardian_quarantine",
        },
        "http1_handler_guardian_quarantine": {
            "monotonic_millisecond",
            "http1_handler_guardian_quarantine_retry",
            "http1_handler_guardian_quarantine_receive",
        },
        "http1_handler_guardian_quarantine_retry": {
            "http1_handler_guardian_safe_terminate",
            "http1_handler_guardian_quarantine",
        },
        "http1_handler_guardian_safe_cancel": {
            "http1_handler_guardian_safe_call",
        },
        "http1_handler_guardian_safe_terminate": {
            "http1_handler_guardian_safe_call",
        },
        "http1_handler_guardian_discard_optional": {
            "http1_handler_guardian_safe_discard",
        },
        "http1_handler_guardian_safe_discard": {
            "http1_handler_guardian_safe_call",
        },
        "http1_handler_guardian_safe_probe": {
            "http1_handler_guardian_safe_call",
        },
        "http1_handler_guardian_safe_call": set(),
        "http1_handler_guardian_remaining": {
            "monotonic_millisecond",
        },
        "http1_handler_guardian_publish_result": {"send_subject"},
        "http1_handler_guardian_finish": set(),
    }
    for function, allowed in allowlists.items():
        region = erlang_function_region(ffi, function)
        if not region:
            return False
        names = region_local_call_names(ffi, function)
        if any(name not in allowed for name in names):
            return False
        values = erlang_token_values(region)
        dangerous = (
            ["erlang", ":", "demonitor", "("],
            ["erlang", ":", "monitor", "("],
            ["erlang", ":", "error", "("],
            ["exit", "("],
            ["throw", "("],
            ["return", "("],
        )
        for sequence in dangerous:
            present = any(
                values[index : index + len(sequence)] == sequence
                for index in range(len(values) - len(sequence) + 1)
            )
            if present and not (
                function == "http1_handler_guardian_finish"
                and sequence == ["erlang", ":", "demonitor", "("]
            ):
                return False
    finish = erlang_token_values(
        erlang_function_region(ffi, "http1_handler_guardian_finish")
    )
    if (
        sum(
            finish[index : index + 4] == ["erlang", ":", "demonitor", "("]
            for index in range(max(0, len(finish) - 3))
        )
        != 1
        or not any(
            finish[index : index + 6]
            == ["maps", ":", "get", "(", "owner_monitor", ","]
            for index in range(max(0, len(finish) - 5))
        )
    ):
        return False
    return True


def handler_entry_flow_findings(ffi: str) -> list[str]:
    """Prove every live handler-entry expression and deadline branch."""
    failures: list[str] = []
    body = single_clause_body_values(
        ffi, "http1_handler_guardian_handler_entry"
    )
    if body is None:
        return [
            "handler_entry_control_flow_unproven",
            "handler_entry_deadline_missing",
            "handler_run_outside_second_false",
        ]
    outer = top_level_segments(body)
    label = [
        "ok", "=", "proc_lib", ":", "set_label", "(",
        "<<", "<string>", ">>", ")",
    ]
    if len(outer) != 2 or outer[0] != label:
        return [
            "handler_entry_control_flow_unproven",
            "handler_run_outside_second_false",
        ]
    receive_parts = strict_receive_parts(outer[1])
    expected_pattern = [
        "{", "HandlerReference", ",", "handler_start", ",", "Guardian", "}",
    ]
    expected_after = [
        "http1_handler_guardian_remaining", "(", "HandlerDeadline", ")",
    ]
    expected_timeout = [
        "http1_handler_guardian_handler_timed_out", "(",
        "Guardian", ",", "HandlerReference", ")",
    ]
    if (
        receive_parts is None
        or receive_parts[0] != expected_pattern
        or receive_parts[2] != expected_after
        or receive_parts[3] != expected_timeout
    ):
        return [
            "handler_entry_control_flow_unproven",
            "handler_entry_deadline_missing",
            "handler_run_outside_second_false",
        ]
    clause = receive_parts[1]
    deadline = ["monotonic_millisecond", "(", ")", ">=", "HandlerDeadline"]
    clause_segments = top_level_segments(clause)
    if (
        len(clause_segments) != 1
        or not clause_segments[0]
        or clause_segments[0][0] != "case"
        or matching_block_end(clause_segments[0], 0)
        != len(clause_segments[0]) - 1
    ):
        return ["handler_entry_control_flow_unproven", "handler_entry_deadline_missing"]
    first_case = clause_segments[0]
    first_true = case_condition_and_branch(first_case, 0, "true")
    first_false = case_condition_and_branch(first_case, 0, "false")
    if (
        first_true is None
        or first_false is None
        or first_true[0] != deadline
        or first_false[0] != deadline
        or first_true[1] != expected_timeout
    ):
        failures.extend(("handler_entry_control_flow_unproven", "handler_entry_deadline_missing"))
        if live_call_count(body, "Run") != 1:
            failures.append("handler_run_outside_second_false")
        return sorted(set(failures))
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
    second_true = (
        case_condition_and_branch(false_body, second_case_index, "true")
        if structural
        else None
    )
    if (
        not structural
        or second_true is None
        or second_false is None
        or second_true[0] != deadline
        or second_false[0] != deadline
        or second_true[1] != expected_timeout
        or second_false[1][:5] != ["try", "Run", "(", ")", "of"]
        or matching_block_end(second_false[1], 0)
        != len(second_false[1]) - 1
    ):
        failures.extend(
            ("handler_entry_control_flow_unproven", "handler_entry_second_deadline_missing")
        )
    elif (
        live_call_count(second_true[1], "Run") != 0
        or live_call_count(second_false[1], "Run") != 1
        or token_call_count(body, "Run") != 1
        or any(
            name not in {"Run", "AfterResult", "self", "monotonic_millisecond"}
            for name in live_local_call_names(second_false[1])
        )
    ):
        failures.append("handler_run_outside_second_false")
    if live_call_count(prefix, "Run") != 0 or live_call_count(body, "Run") != 1:
        failures.append("handler_run_outside_second_false")
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
    if not receive_dispatcher_proven(
        ffi,
        "http1_handler_guardian_terminating_receive",
        "http1_handler_guardian_terminating",
        "CleanupDeadline",
        4,
        6,
    ):
        failures.append("terminating_dispatcher_bypassed")
    if not receive_dispatcher_proven(
        ffi,
        "http1_handler_guardian_quarantine_receive",
        "http1_handler_guardian_quarantine",
        "RetryDeadline",
        3,
        6,
    ):
        failures.append("quarantine_dispatcher_bypassed")
    joined_regions = down_region + terminating_region + quarantine_region
    if not closed_critical_helpers_proven(ffi):
        failures.append("critical_helper_semantics_unproven")
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


def transform_region(
    source: str, name: str, next_name: str, transform: object
) -> str:
    region = function_region(source, name, next_name)
    if not region or not callable(transform):
        return source
    changed = transform(region)
    return source if changed == region else source.replace(region, changed, 1)


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

    first_true_run = dict(sources)
    first_true_run["ffi"] = replace_in_region(
        sources["ffi"],
        "http1_handler_guardian_handler_entry",
        "http1_handler_guardian_handler_timed_out",
        "true ->\n                    http1_handler_guardian_handler_timed_out(",
        "true ->\n                    _Forbidden = Run(),\n"
        "                    http1_handler_guardian_handler_timed_out(",
    )
    mutants["run_in_first_deadline_true"] = (
        first_true_run,
        "handler_run_outside_second_false",
    )

    second_true_run = dict(sources)
    second_true_run["ffi"] = replace_in_region(
        sources["ffi"],
        "http1_handler_guardian_handler_entry",
        "http1_handler_guardian_handler_timed_out",
        "true ->\n                            http1_handler_guardian_handler_timed_out(",
        "true ->\n                            _Forbidden = Run(),\n"
        "                            http1_handler_guardian_handler_timed_out(",
    )
    mutants["run_in_second_deadline_true"] = (
        second_true_run,
        "handler_run_outside_second_false",
    )

    nested_second_run = dict(sources)
    nested_second_run["ffi"] = replace_in_region(
        sources["ffi"],
        "http1_handler_guardian_handler_entry",
        "http1_handler_guardian_handler_timed_out",
        "                                Result ->\n"
        "                                    Guardian ! {",
        "                                Result ->\n"
        "                                    _Forbidden = (fun() -> Run() end)(),\n"
        "                                    Guardian ! {",
    )
    mutants["nested_iife_second_run"] = (
        nested_second_run, "handler_run_outside_second_false"
    )

    delegated_second_run = dict(sources)
    delegated_second_run["ffi"] = replace_in_region(
        sources["ffi"],
        "http1_handler_guardian_handler_entry",
        "http1_handler_guardian_handler_timed_out",
        "                                Result ->\n"
        "                                    Guardian ! {",
        "                                Result ->\n"
        "                                    _Forbidden = "
        "http1_handler_guardian_forbidden_second_run(Run),\n"
        "                                    Guardian ! {",
    ) + (
        "\nhttp1_handler_guardian_forbidden_second_run(Run) -> Run().\n"
    )
    mutants["delegated_second_run"] = (
        delegated_second_run, "handler_run_outside_second_false"
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

    before_receive = dict(sources)
    before_receive["ffi"] = sources["ffi"].replace(
        '    ok = proc_lib:set_label(<<"http.http1_handler">>),\n    receive',
        '    ok = proc_lib:set_label(<<"http.http1_handler">>),\n'
        '    _Forbidden = Run(),\n    receive',
        1,
    )
    mutants["run_before_entry_receive"] = (
        before_receive, "handler_entry_control_flow_unproven"
    )

    after_receive = dict(sources)
    after_receive["ffi"] = transform_region(
        sources["ffi"],
        "http1_handler_guardian_handler_entry",
        "http1_handler_guardian_handler_timed_out",
        lambda region: (
            region[:-10] + "    end,\n    Run().\n\n"
            if region.endswith("    end.\n\n") else region
        ),
    )
    mutants["run_after_entry_receive"] = (
        after_receive, "handler_entry_control_flow_unproven"
    )

    invoked_fun = dict(sources)
    invoked_fun["ffi"] = replace_in_region(
        sources["ffi"],
        "http1_handler_guardian_handler_entry",
        "http1_handler_guardian_handler_timed_out",
        "                true ->\n"
        "                    http1_handler_guardian_handler_timed_out(",
        "                true ->\n"
        "                    _Forbidden = (fun() -> Run() end)(),\n"
        "                    http1_handler_guardian_handler_timed_out(",
    )
    mutants["immediately_invoked_fun_run_in_first_true"] = (
        invoked_fun, "handler_entry_control_flow_unproven"
    )

    delegated_run = dict(sources)
    delegated_run["ffi"] = replace_in_region(
        sources["ffi"],
        "http1_handler_guardian_handler_entry",
        "http1_handler_guardian_handler_timed_out",
        "                true ->\n"
        "                    http1_handler_guardian_handler_timed_out(",
        "                true ->\n"
        "                    _Forbidden = "
        "http1_handler_guardian_forbidden_run(Run),\n"
        "                    http1_handler_guardian_handler_timed_out(",
    ) + "\nhttp1_handler_guardian_forbidden_run(Run) -> Run().\n"
    mutants["delegated_run_in_first_true"] = (
        delegated_run, "handler_entry_control_flow_unproven"
    )

    def add_unsafe_handler_clause(region: str) -> str:
        header = (
            "http1_handler_guardian_handler_entry(\n"
            "    Guardian, HandlerReference, Run, Probe, AfterResult, "
            "HandlerDeadline\n) ->\n"
        )
        if region.count(header) != 1 or not region.endswith("    end.\n\n"):
            return region
        safe = region.replace(header, header[:-4] + " when false ->\n", 1)
        return safe[:-10] + (
            "    end;\n"
            "http1_handler_guardian_handler_entry(\n"
            "    Guardian, HandlerReference, Run, Probe, AfterResult, "
            "HandlerDeadline\n) ->\n"
            "    Run().\n\n"
        )

    dead_safe_entry = dict(sources)
    dead_safe_entry["ffi"] = transform_region(
        sources["ffi"],
        "http1_handler_guardian_handler_entry",
        "http1_handler_guardian_handler_timed_out",
        add_unsafe_handler_clause,
    )
    mutants["guard_false_safe_entry_clause_wrong_live_clause"] = (
        dead_safe_entry, "handler_entry_control_flow_unproven"
    )

    impossible_safe_entry = dict(sources)
    impossible_safe_entry["ffi"] = dead_safe_entry["ffi"].replace(
        ") when false ->\n", ") when HandlerDeadline =:= impossible_deadline ->\n", 1
    )
    mutants["impossible_variable_guard_safe_entry_wrong_live_clause"] = (
        impossible_safe_entry, "handler_entry_control_flow_unproven"
    )

    terminating_bypass = dict(sources)
    terminating_bypass["ffi"] = replace_in_region(
        sources["ffi"],
        "http1_handler_guardian_terminating_receive",
        "http1_handler_guardian_termination_expired",
        "            http1_handler_guardian_terminating(\n"
        "                State#{result => {some, Result}}, Termination, Notify,\n"
        "                CleanupDeadline\n            );",
        "            http1_handler_guardian_terminating_receive(\n"
        "                State#{result => {some, Result}}, Termination, Notify,\n"
        "                CleanupDeadline\n            );",
    )
    mutants["matching_traffic_bypasses_terminating_precheck"] = (
        terminating_bypass, "terminating_dispatcher_bypassed"
    )

    quarantine_bypass = dict(sources)
    quarantine_bypass["ffi"] = replace_in_region(
        sources["ffi"],
        "http1_handler_guardian_quarantine_receive",
        "http1_handler_guardian_quarantine_retry",
        "            http1_handler_guardian_quarantine(\n"
        "                State#{result => {some, Result}}, Termination, RetryDeadline\n"
        "            );",
        "            http1_handler_guardian_quarantine_receive(\n"
        "                State#{result => {some, Result}}, Termination, RetryDeadline\n"
        "            );",
    )
    mutants["matching_traffic_bypasses_quarantine_precheck"] = (
        quarantine_bypass, "quarantine_dispatcher_bypassed"
    )

    balanced_terminating_bypass = dict(sources)
    balanced_terminating_bypass["ffi"] = replace_in_region(
        sources["ffi"],
        "http1_handler_guardian_terminating_receive",
        "http1_handler_guardian_termination_expired",
        "            http1_handler_guardian_terminating(\n"
        "                State#{result => {some, Result}}, Termination, Notify,\n"
        "                CleanupDeadline\n            );",
        "            _UnreachableBalance = fun() ->\n"
        "                http1_handler_guardian_terminating(\n"
        "                    State, Termination, Notify, CleanupDeadline\n"
        "                )\n"
        "            end,\n"
        "            http1_handler_guardian_terminating_receive(\n"
        "                State#{result => {some, Result}}, Termination, Notify,\n"
        "                CleanupDeadline\n            );",
    )
    mutants["balanced_decoy_terminating_dispatcher_bypass"] = (
        balanced_terminating_bypass, "terminating_dispatcher_bypassed"
    )

    balanced_quarantine_bypass = dict(sources)
    balanced_quarantine_bypass["ffi"] = replace_in_region(
        sources["ffi"],
        "http1_handler_guardian_quarantine_receive",
        "http1_handler_guardian_quarantine_retry",
        "            http1_handler_guardian_quarantine(\n"
        "                State#{result => {some, Result}}, Termination, RetryDeadline\n"
        "            );",
        "            _UnreachableBalance = fun() ->\n"
        "                http1_handler_guardian_quarantine(\n"
        "                    State, Termination, RetryDeadline\n"
        "                )\n"
        "            end,\n"
        "            http1_handler_guardian_quarantine_receive(\n"
        "                State#{result => {some, Result}}, Termination, RetryDeadline\n"
        "            );",
    )
    mutants["balanced_decoy_quarantine_dispatcher_bypass"] = (
        balanced_quarantine_bypass, "quarantine_dispatcher_bypassed"
    )

    helper_demonitor = dict(sources)
    helper_demonitor["ffi"] = replace_in_region(
        sources["ffi"],
        "http1_handler_guardian_safe_cancel",
        "http1_handler_guardian_safe_terminate",
        "http1_handler_guardian_safe_call(maps:get(cancel, State), []).",
        "erlang:demonitor(maps:get(owner_monitor, State), [flush]),\n"
        "    http1_handler_guardian_safe_call(maps:get(cancel, State), []).",
    )
    mutants["allowed_helper_owner_demonitor"] = (
        helper_demonitor, "critical_helper_semantics_unproven"
    )

    helper_exit = dict(sources)
    helper_exit["ffi"] = replace_in_region(
        sources["ffi"],
        "http1_handler_guardian_safe_discard",
        "http1_handler_guardian_safe_probe",
        "http1_handler_guardian_safe_call(maps:get(discard, State), [Result]).",
        "exit(helper_aborted_before_finish),\n"
        "    http1_handler_guardian_safe_call(maps:get(discard, State), [Result]).",
    )
    mutants["allowed_helper_exit_before_finish"] = (
        helper_exit, "critical_helper_semantics_unproven"
    )

    reordered_success = dict(sources)
    reordered_success["ffi"] = replace_in_region(
        sources["ffi"],
        "http1_handler_guardian_down",
        "http1_handler_guardian_begin_termination",
        "            http1_handler_guardian_publish_result(Events, Result),\n"
        "            http1_handler_guardian_finish(State);",
        "            http1_handler_guardian_finish(State),\n"
        "            http1_handler_guardian_publish_result(Events, Result);",
    )
    mutants["success_publication_after_finish"] = (
        reordered_success, "critical_helper_semantics_unproven"
    )

    indirect_demonitor = dict(sources)
    indirect_demonitor["ffi"] = replace_in_region(
        sources["ffi"],
        "http1_handler_guardian_active",
        "http1_handler_guardian_down",
        "    HandlerDeadline = maps:get(handler_deadline, State),\n    receive",
        "    HandlerDeadline = maps:get(handler_deadline, State),\n"
        "    http1_handler_guardian_drop_owner_monitor(State),\n    receive",
    ) + (
        "\nhttp1_handler_guardian_drop_owner_monitor(State) ->\n"
        "    erlang:demonitor(maps:get(owner_monitor, State), [flush]).\n"
    )
    mutants["indirect_owner_demonitor_before_publication"] = (
        indirect_demonitor, "critical_helper_semantics_unproven"
    )

    indirect_exit = dict(sources)
    indirect_exit["ffi"] = replace_in_region(
        sources["ffi"],
        "http1_handler_guardian_terminating_receive",
        "http1_handler_guardian_termination_expired",
        "            http1_handler_guardian_finish(State);",
        "            http1_handler_guardian_abort_indirectly(),\n"
        "            http1_handler_guardian_finish(State);",
    ) + (
        "\nhttp1_handler_guardian_abort_indirectly() ->\n"
        "    exit(indirect_terminal_abort).\n"
    )
    mutants["indirect_exit_before_terminal_down_finish"] = (
        indirect_exit, "critical_helper_semantics_unproven"
    )

    indirect_throw = dict(sources)
    indirect_throw["ffi"] = replace_in_region(
        sources["ffi"],
        "http1_handler_guardian_quarantine_receive",
        "http1_handler_guardian_quarantine_retry",
        "            http1_handler_guardian_finish(State);",
        "            http1_handler_guardian_throw_indirectly(),\n"
        "            http1_handler_guardian_finish(State);",
    ) + (
        "\nhttp1_handler_guardian_throw_indirectly() ->\n"
        "    throw(indirect_terminal_throw).\n"
    )
    mutants["indirect_throw_before_terminal_down_finish"] = (
        indirect_throw, "critical_helper_semantics_unproven"
    )

    def dead_safe_down(region: str) -> str:
        if not region.endswith("    end.\n\n"):
            return region
        safe = region.replace(
            "http1_handler_guardian_down(State) ->",
            "http1_handler_guardian_down(State) when false ->",
            1,
        )
        return safe[:-10] + (
            "    end;\n"
            "http1_handler_guardian_down(State) ->\n"
            "    http1_handler_guardian_finish(State).\n\n"
        )

    dead_down_clause = dict(sources)
    dead_down_clause["ffi"] = transform_region(
        sources["ffi"],
        "http1_handler_guardian_down",
        "http1_handler_guardian_begin_termination",
        dead_safe_down,
    )
    mutants["guard_false_safe_down_clause_missing_live_publication"] = (
        dead_down_clause, "critical_helper_semantics_unproven"
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


def atomic_publish(path: Path, payload: bytes) -> None:
    if len(payload) <= 0 or len(payload) > 1024 * 1024:
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
        metadata = os.lstat(destination)
        reparse_flag = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0)
        attributes = getattr(metadata, "st_file_attributes", 0)
        if stat.S_ISLNK(metadata.st_mode) or (
            reparse_flag and attributes & reparse_flag
        ):
            raise ValueError("report_identity_rejected")
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=".guardian-report-", dir=destination.parent
    )
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, destination)
        observed, _digest = safe_read_bytes(destination, 1024 * 1024)
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
                    safe_failure_report(failure, "report_publication"),
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


def main(report_path: str | None = None) -> int:
    try:
        loaded = {name: safe_read(path) for name, path in FILES.items()}
        _scanner_source, scanner_hash = safe_read(Path(__file__).resolve())
        runtime_hash = safe_hash(
            Path(sys.executable).resolve(strict=True), MAXIMUM_TOOL_BYTES
        )
        config_hash = safe_hash(ROOT / ".mise.toml")
    except (OSError, UnicodeError, ValueError) as failure:
        emit_report(safe_failure_report(failure, "pre_read"), report_path)
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
        runtime_post_hash = safe_hash(
            Path(sys.executable).resolve(strict=True), MAXIMUM_TOOL_BYTES
        )
        config_post_hash = safe_hash(ROOT / ".mise.toml")
    except (OSError, UnicodeError, ValueError) as failure:
        emit_report(safe_failure_report(failure, "post_read"), report_path)
        return 1
    source_stable = hashes == post_hashes
    scanner_stable = scanner_hash == scanner_post_hash
    runtime_stable = runtime_hash == runtime_post_hash
    config_stable = config_hash == config_post_hash
    version_stable = platform.python_version() == EXPECTED_PYTHON_VERSION
    identity_stable = (
        source_stable and scanner_stable and runtime_stable
        and config_stable and version_stable
    )
    if not source_stable:
        failures.append("source_changed_during_scan")
    if not scanner_stable:
        failures.append("checker_changed_during_scan")
    if not runtime_stable:
        failures.append("runtime_changed_during_scan")
    if not config_stable:
        failures.append("config_changed_during_scan")
    if not version_stable:
        failures.append("runtime_version_mismatch")
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
        "python_tool_request": "python@3.12.13",
        "mise_config_sha256_pre": config_hash,
        "mise_config_sha256_post": config_post_hash,
        "mise_config_stable": config_stable,
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
            "mise exec python@3.12.13 -- python -I -B "
            "standards/audits/http1-guardian/guardian_contract_check.py"
        ),
    }
    encoded = json.dumps(report, sort_keys=True, separators=(",", ":"))
    if len(encoded.encode("utf-8")) > 1024 * 1024:
        emit_report({"status": "failed", "class": "report_limit_rejected"}, report_path)
        return 1
    published = emit_report(report, report_path)
    return 0 if status == "passed" and published else 1


def cli_main() -> int:
    try:
        parser = argparse.ArgumentParser(add_help=True)
        parser.add_argument("--report")
        arguments = parser.parse_args()
        return main(arguments.report)
    except (KeyboardInterrupt, SystemExit, GeneratorExit):
        raise
    except BaseException:
        try:
            emit_report(
                {
                    "schema": 3,
                    "status": "failed",
                    "class": "internal_rejected",
                    "rerun_command": (
                        "mise exec python@3.12.13 -- python -I -B "
                        "standards/audits/http1-guardian/guardian_contract_check.py"
                    ),
                },
                None,
            )
        except BaseException:
            pass
        return 2


if __name__ == "__main__":
    raise SystemExit(cli_main())

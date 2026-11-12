#!/usr/bin/env python3

# SPDX-FileCopyrightText: 2026 the http contributors
# SPDX-License-Identifier: MIT OR Apache-2.0

"""Audit process roles which require atomic spawn-and-monitor creation.

The runtime contract relies on signal ordering from a worker to its owner. A
separate spawn followed by monitor leaves an interval in which a fast worker
can terminate before the monitor exists. This bounded audit keeps each fixed
role tied to an explicit source function and rejects a return to that pattern.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from dataclasses import dataclass
import os
from pathlib import Path
import re
import stat
import sys
import tempfile


ROOT = Path(__file__).resolve().parent.parent
MAX_SOURCE_BYTES = 4 * 1024 * 1024
MAX_TOOL_BYTES = 64 * 1024 * 1024
MAX_TOKENS = 500_000
EXPECTED_PYTHON_VERSION = "3.12.13"


@dataclass(frozen=True)
class Contract:
    path: str
    function: str
    required: tuple[str, ...]
    forbidden: tuple[str, ...]
    language: str = "gleam"


CONTRACTS = (
    Contract(
        path="src/http/internal/http3/server.gleam",
        function="start_accept",
        required=("spawn_link_monitor(",),
        forbidden=("process.spawn(",),
    ),
    Contract(
        path="src/http/internal/http3/server.gleam",
        function="listen",
        required=("spawn_monitor(",),
        forbidden=("process.spawn_unlinked(", "process.monitor(coordinator)"),
    ),
    Contract(
        path="src/http/internal/http3/server.gleam",
        function="accept_completed",
        required=("spawn_monitor(",),
        forbidden=("process.spawn_unlinked(", "process.monitor(pid)"),
    ),
    Contract(
        path="src/http/internal/http3/server.gleam",
        function="serve_request_body",
        required=("spawn_link_monitor(",),
        forbidden=("process.spawn(",),
    ),
    Contract(
        path="src/http/internal/http3/server.gleam",
        function="run_setup_work",
        required=("spawn_link_monitor(",),
        forbidden=("process.spawn(",),
    ),
    Contract(
        path="src/http/internal/http3/server.gleam",
        function="run_request_work",
        required=("spawn_link_monitor(",),
        forbidden=("process.spawn(",),
    ),
    Contract(
        path="src/http/internal/http3/server.gleam",
        function="bounded_cleanup_result",
        required=("spawn_link_monitor(",),
        forbidden=("process.spawn(",),
    ),
    Contract(
        path="src/http_server_ffi.erl",
        function="spawn_monitor",
        required=("erlang:spawn_monitor(",),
        forbidden=("erlang:spawn(", "erlang:monitor("),
        language="erlang",
    ),
    Contract(
        path="src/http_server_ffi.erl",
        function="spawn_link_monitor",
        required=("erlang:spawn_opt(", "[link, monitor]"),
        forbidden=("erlang:spawn(", "erlang:monitor("),
        language="erlang",
    ),
    Contract(
        path=(
            "packages/quic_core/src/quic_core/internal/tls/replay_guard.gleam"
        ),
        function="permits",
        required=("spawn_monitor(",),
        forbidden=("process.spawn_unlinked(", "process.monitor(worker)"),
    ),
    Contract(
        path="packages/quic_core/src/quic_core_process_ffi.erl",
        function="spawn_monitor",
        required=("erlang:spawn_monitor(",),
        forbidden=("erlang:spawn(", "erlang:monitor("),
        language="erlang",
    ),
)

HTTP1_GLEAM_PATH = "src/http/internal/http1/server.gleam"
HTTP1_FFI_PATH = "src/http_server_ffi.erl"
HTTP1_LOCAL_START = "start_http1_handler_guardian"
HTTP1_FOREIGN_START = "start_http1_handler_guardian"
HTTP1_START_ARITY = 10


@dataclass(frozen=True)
class GleamToken:
    kind: str
    value: str


def sanitise(source: str) -> str:
    output = list(source)
    index = 0
    state = "code"
    while index < len(source):
        current = source[index]
        following = source[index + 1] if index + 1 < len(source) else ""
        if state == "code":
            if current == '"':
                output[index] = " "
                state = "string"
            elif current == "/" and following == "/":
                output[index] = output[index + 1] = " "
                index += 1
                state = "comment"
        elif state == "string":
            if current == "\\" and following:
                if current != "\n":
                    output[index] = " "
                if following != "\n":
                    output[index + 1] = " "
                index += 1
            elif current == '"':
                output[index] = " "
                state = "code"
            elif current != "\n":
                output[index] = " "
        elif current == "\n":
            state = "code"
        else:
            output[index] = " "
        index += 1
    return "".join(output)


def gleam_tokens(source: str) -> list[GleamToken]:
    """Tokenize enough Gleam to bind an external declaration exactly.

    Comments and string contents cannot masquerade as annotations. The token
    limit is independent of the byte limit so adversarial punctuation remains
    finite.
    """
    tokens: list[GleamToken] = []
    index = 0
    while index < len(source):
        current = source[index]
        following = source[index + 1] if index + 1 < len(source) else ""
        if current.isspace():
            index += 1
            continue
        if current == "/" and following == "/":
            newline = source.find("\n", index + 2)
            index = len(source) if newline < 0 else newline + 1
            continue
        if current == '"':
            index += 1
            value: list[str] = []
            while index < len(source):
                current = source[index]
                if current == '"':
                    index += 1
                    break
                if current == "\\":
                    index += 1
                    if index >= len(source):
                        raise ValueError("unterminated_string")
                    value.append(source[index])
                    index += 1
                    continue
                value.append(current)
                index += 1
            else:
                raise ValueError("unterminated_string")
            tokens.append(GleamToken("string", "".join(value)))
        elif current.isalpha() or current == "_":
            end = index + 1
            while end < len(source) and (
                source[end].isalnum() or source[end] == "_"
            ):
                end += 1
            tokens.append(GleamToken("identifier", source[index:end]))
            index = end
        else:
            tokens.append(GleamToken("symbol", current))
            index += 1
        if len(tokens) > MAX_TOKENS:
            raise ValueError("token_limit_exceeded")
    return tokens


def erlang_tokens(source: str) -> list[GleamToken]:
    """Return bounded Erlang tokens while excluding comments and quoted decoys."""
    tokens: list[GleamToken] = []
    index = 0
    multi_symbols = ("=:=" , "=/=", "->", "=>", ":=", "=<", ">=", "<<", ">>")
    while index < len(source):
        current = source[index]
        if current.isspace():
            index += 1
            continue
        if current == "%":
            newline = source.find("\n", index + 1)
            index = len(source) if newline < 0 else newline + 1
            continue
        if current in ('"', "'"):
            quote = current
            index += 1
            value: list[str] = []
            while index < len(source):
                current = source[index]
                if current == quote:
                    index += 1
                    break
                if current == "\\":
                    index += 1
                    if index >= len(source):
                        raise ValueError("unterminated_quoted_token")
                    value.append(source[index])
                    index += 1
                    continue
                value.append(current)
                index += 1
            else:
                raise ValueError("unterminated_quoted_token")
            tokens.append(
                GleamToken("atom" if quote == "'" else "string", "".join(value))
            )
        elif current.isalpha() or current == "_":
            end = index + 1
            while end < len(source) and (
                source[end].isalnum() or source[end] in ("_", "@")
            ):
                end += 1
            tokens.append(GleamToken("identifier", source[index:end]))
            index = end
        elif current.isdigit():
            end = index + 1
            while end < len(source) and source[end].isdigit():
                end += 1
            tokens.append(GleamToken("number", source[index:end]))
            index = end
        else:
            symbol = next(
                (candidate for candidate in multi_symbols if source.startswith(candidate, index)),
                current,
            )
            tokens.append(GleamToken("symbol", symbol))
            index += len(symbol)
        if len(tokens) > MAX_TOKENS:
            raise ValueError("token_limit_exceeded")
    return tokens


def token_values(tokens: list[GleamToken]) -> list[str]:
    return [token.value for token in tokens]


def find_sequence(values: list[str], sequence: list[str], start: int = 0) -> int:
    if not sequence:
        return start
    limit = len(values) - len(sequence) + 1
    for index in range(start, max(start, limit)):
        if values[index : index + len(sequence)] == sequence:
            return index
    return -1


def find_top_level_sequence(
    values: list[str], sequence: list[str], start: int = 0
) -> int:
    depths = {"(": 0, "[": 0, "{": 0}
    closings = {")": "(", "]": "[", "}": "{"}
    for index, value in enumerate(values):
        if index >= start and all(depth == 0 for depth in depths.values()):
            if values[index : index + len(sequence)] == sequence:
                return index
        if value in depths:
            depths[value] += 1
        elif value in closings:
            opener = closings[value]
            depths[opener] = max(0, depths[opener] - 1)
    return -1


def matching_index(
    values: list[str], opening_index: int, opening: str, closing: str
) -> int:
    if opening_index < 0 or opening_index >= len(values):
        return -1
    if values[opening_index] != opening:
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


def split_arguments(values: list[str], opening_index: int) -> tuple[list[list[str]], int]:
    closing_index = matching_index(values, opening_index, "(", ")")
    if closing_index < 0:
        return [], -1
    arguments: list[list[str]] = []
    current: list[str] = []
    depths = {"(": 0, "[": 0, "{": 0}
    closings = {")": "(", "]": "[", "}": "{"}
    for value in values[opening_index + 1 : closing_index]:
        if value in depths:
            depths[value] += 1
        elif value in closings:
            opener = closings[value]
            depths[opener] -= 1
            if depths[opener] < 0:
                return [], -1
        if value == "," and all(depth == 0 for depth in depths.values()):
            arguments.append(current)
            current = []
        else:
            current.append(value)
    if current:
        arguments.append(current)
    if any(depth != 0 for depth in depths.values()):
        return [], -1
    return arguments, closing_index


def call_arguments(
    values: list[str], name: str, start: int = 0
) -> tuple[int, list[list[str]], int]:
    call_index = find_sequence(values, [name, "("], start)
    if call_index < 0:
        return -1, [], -1
    arguments, closing = split_arguments(values, call_index + 1)
    return call_index, arguments, closing


def qualified_call_arguments(
    values: list[str], module: str, name: str, start: int = 0
) -> tuple[int, list[list[str]], int]:
    call_index = find_sequence(values, [module, ":", name, "("], start)
    if call_index < 0:
        return -1, [], -1
    arguments, closing = split_arguments(values, call_index + 3)
    return call_index, arguments, closing


def exact_identifier(argument: list[str]) -> str | None:
    return argument[0] if len(argument) == 1 and re.fullmatch(r"[A-Za-z_][A-Za-z0-9_@]*", argument[0]) else None


def external_bindings(source: str, local_name: str) -> list[tuple[str, str, int]]:
    tokens = gleam_tokens(source)
    bindings: list[tuple[str, str, int]] = []
    index = 0
    while index + 10 < len(tokens):
        values = [token.value for token in tokens[index : index + 9]]
        if not (
            values[0:5] == ["@", "external", "(", "erlang", ","]
            and tokens[index + 5].kind == "string"
            and values[6] == ","
            and tokens[index + 7].kind == "string"
            and values[8] == ")"
        ):
            index += 1
            continue
        cursor = index + 9
        if cursor < len(tokens) and tokens[cursor].value == "pub":
            cursor += 1
        if (
            cursor + 2 >= len(tokens)
            or tokens[cursor].value != "fn"
            or tokens[cursor + 1].value != local_name
            or tokens[cursor + 2].value != "("
        ):
            index += 1
            continue
        depth = 1
        arity = 0
        cursor += 3
        while cursor < len(tokens) and depth > 0:
            value = tokens[cursor].value
            if value == "(":
                depth += 1
            elif value == ")":
                depth -= 1
            elif value == ":" and depth == 1:
                arity += 1
            cursor += 1
        if depth != 0:
            raise ValueError("unterminated_external_declaration")
        bindings.append(
            (tokens[index + 5].value, tokens[index + 7].value, arity)
        )
        index = cursor
    return bindings


def function_body(source: str, name: str) -> str | None:
    clean = sanitise(source)
    declaration = re.search(
        rf"(?m)^\s*(?:pub\s+)?fn\s+{re.escape(name)}\s*\(", clean
    )
    if declaration is None:
        return None
    opening = clean.find("{", declaration.end())
    if opening < 0:
        return None
    depth = 0
    for index in range(opening, len(clean)):
        if clean[index] == "{":
            depth += 1
        elif clean[index] == "}":
            depth -= 1
            if depth == 0:
                return clean[opening : index + 1]
    return None


def sanitise_erlang(source: str) -> str:
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
            elif current in ('"', "'"):
                quote = current
                output[index] = " "
                state = "quoted"
        elif state == "quoted":
            if current == "\\" and following:
                if current != "\n":
                    output[index] = " "
                if following != "\n":
                    output[index + 1] = " "
                index += 1
            elif current == quote:
                output[index] = " "
                state = "code"
            elif current != "\n":
                output[index] = " "
        elif current == "\n":
            state = "code"
        else:
            output[index] = " "
        index += 1
    return "".join(output)


def erlang_function_body(source: str, name: str) -> str | None:
    clean = sanitise_erlang(source)
    declarations = list(
        re.finditer(r"(?m)^([a-z][A-Za-z0-9_]*)\s*\(", clean)
    )
    target = next(
        (index for index, match in enumerate(declarations) if match.group(1) == name),
        None,
    )
    if target is None:
        return None
    declaration = declarations[target]
    following = next(
        (
            match
            for match in declarations[target + 1 :]
            if match.group(1) != name
        ),
        None,
    )
    end = len(clean) if following is None else following.start()
    return clean[declaration.start() : end]


def erlang_function_source(source: str, name: str) -> str | None:
    """Return one Erlang function region while retaining non-decoy atom tokens."""
    clean = sanitise_erlang(source)
    declarations = list(
        re.finditer(r"(?m)^([a-z][A-Za-z0-9_]*)\s*\(", clean)
    )
    target = next(
        (index for index, match in enumerate(declarations) if match.group(1) == name),
        None,
    )
    if target is None:
        return None
    declaration = declarations[target]
    following = next(
        (
            match
            for match in declarations[target + 1 :]
            if match.group(1) != name
        ),
        None,
    )
    end = len(clean) if following is None else following.start()
    return source[declaration.start() : end]


def gleam_function_values(source: str, name: str) -> list[str] | None:
    body = function_body(source, name)
    return None if body is None else token_values(gleam_tokens(body))


def erlang_function_values(source: str, name: str) -> list[str] | None:
    body = erlang_function_source(source, name)
    return None if body is None else token_values(erlang_tokens(body))


def erlang_parameters(values: list[str], name: str) -> list[str] | None:
    function_index = find_sequence(values, [name, "("])
    if function_index < 0:
        return None
    arguments, closing = split_arguments(values, function_index + 1)
    if closing < 0:
        return None
    parameters = [exact_identifier(argument) for argument in arguments]
    if any(parameter is None for parameter in parameters):
        return None
    return [parameter for parameter in parameters if parameter is not None]


def direct_pair_before(values: list[str], call_index: int) -> tuple[str, str] | None:
    if call_index < 6:
        return None
    prefix = values[call_index - 6 : call_index]
    if (
        len(prefix) == 6
        and prefix[0] == "{"
        and prefix[2] == ","
        and prefix[4:] == ["}", "="]
        and re.fullmatch(r"[A-Z_][A-Za-z0-9_@]*", prefix[1])
        and re.fullmatch(r"[A-Z_][A-Za-z0-9_@]*", prefix[3])
    ):
        return prefix[1], prefix[3]
    return None


def assigned_qualified_call(
    values: list[str], module: str, name: str, expected_arguments: list[list[str]]
) -> tuple[str, int] | None:
    cursor = 0
    matches: list[tuple[str, int]] = []
    while True:
        call_index, arguments, closing = qualified_call_arguments(
            values, module, name, cursor
        )
        if call_index < 0:
            break
        if (
            call_index >= 2
            and values[call_index - 1] == "="
            and re.fullmatch(r"[A-Z_][A-Za-z0-9_@]*", values[call_index - 2])
            and arguments == expected_arguments
        ):
            matches.append((values[call_index - 2], closing))
        cursor = max(call_index + 1, closing + 1)
    return matches[0] if len(matches) == 1 else None


@dataclass(frozen=True)
class ErlangExecution:
    fun_scopes: tuple[int | None, ...]
    branch_paths: tuple[tuple[tuple[int, int], ...], ...]


def erlang_block_opens(values: list[str], index: int) -> bool:
    if values[index] in {"case", "receive", "try", "if", "begin", "maybe"}:
        return True
    return (
        values[index] == "fun"
        and index + 1 < len(values)
        and values[index + 1] == "("
    )


def erlang_block_end(values: list[str], opening_index: int) -> int:
    if opening_index < 0 or not erlang_block_opens(values, opening_index):
        return -1
    depth = 0
    for index in range(opening_index, len(values)):
        if erlang_block_opens(values, index):
            depth += 1
        elif values[index] == "end":
            depth -= 1
            if depth == 0:
                return index
    return -1


def erlang_clause_spans(
    values: list[str], block_start: int
) -> list[tuple[int, int]]:
    """Return live clause-body spans for one Erlang control block."""
    block_end = erlang_block_end(values, block_start)
    if block_end < 0 or values[block_start] == "fun":
        return []
    cursor = block_start + 1
    if values[block_start] == "case":
        while cursor < block_end:
            if values[cursor] in ("(", "[", "{"):
                closing = {"(": ")", "[": "]", "{": "}"}[values[cursor]]
                cursor = matching_index(values, cursor, values[cursor], closing) + 1
                continue
            if erlang_block_opens(values, cursor):
                nested_end = erlang_block_end(values, cursor)
                if nested_end < 0:
                    return []
                cursor = nested_end + 1
                continue
            if values[cursor] == "of":
                cursor += 1
                break
            cursor += 1
    spans: list[tuple[int, int]] = []
    pattern_start = cursor
    while cursor < block_end:
        if values[cursor] in ("(", "[", "{"):
            closing = {"(": ")", "[": "]", "{": "}"}[values[cursor]]
            close = matching_index(values, cursor, values[cursor], closing)
            if close < 0:
                return []
            cursor = close + 1
            continue
        if erlang_block_opens(values, cursor):
            nested_end = erlang_block_end(values, cursor)
            if nested_end < 0:
                return []
            cursor = nested_end + 1
            continue
        if values[cursor] == "->":
            body_start = cursor + 1
            body_end = body_start
            while body_end < block_end:
                if values[body_end] in ("(", "[", "{"):
                    closing = {"(": ")", "[": "]", "{": "}"}[
                        values[body_end]
                    ]
                    close = matching_index(
                        values, body_end, values[body_end], closing
                    )
                    if close < 0:
                        return []
                    body_end = close + 1
                    continue
                if erlang_block_opens(values, body_end):
                    nested_end = erlang_block_end(values, body_end)
                    if nested_end < 0:
                        return []
                    body_end = nested_end + 1
                    continue
                if values[body_end] in (";", "after", "catch"):
                    break
                body_end += 1
            spans.append((body_start, body_end))
            if body_end >= block_end:
                break
            pattern_start = body_end + (1 if values[body_end] == ";" else 0)
            cursor = pattern_start
            continue
        cursor += 1
    return spans


def erlang_execution(values: list[str]) -> ErlangExecution:
    fun_intervals: list[tuple[int, int, int]] = []
    next_scope = 0
    for index in range(len(values)):
        if values[index] == "fun" and erlang_block_opens(values, index):
            end = erlang_block_end(values, index)
            if end < 0:
                raise ValueError("unterminated_fun_scope")
            fun_intervals.append((index, end, next_scope))
            next_scope += 1
    scopes: list[int | None] = [None] * len(values)
    for start, end, scope in sorted(
        fun_intervals, key=lambda item: item[1] - item[0], reverse=True
    ):
        for index in range(start + 1, end):
            scopes[index] = scope

    clause_intervals: list[tuple[int, int, tuple[int, int]]] = []
    for block_start in range(len(values)):
        if not erlang_block_opens(values, block_start) or values[block_start] == "fun":
            continue
        for ordinal, (start, end) in enumerate(
            erlang_clause_spans(values, block_start)
        ):
            clause_intervals.append((start, end, (block_start, ordinal)))
    paths: list[tuple[tuple[int, int], ...]] = []
    for index in range(len(values)):
        containing = [
            (start, end, branch)
            for start, end, branch in clause_intervals
            if start <= index < end
        ]
        containing.sort(key=lambda item: (-(item[1] - item[0]), item[0]))
        paths.append(tuple(item[2] for item in containing))
    return ErlangExecution(tuple(scopes), tuple(paths))


def execution_dominates(
    execution: ErlangExecution, producer: int, consumer: int
) -> bool:
    if producer < 0 or consumer < 0 or producer >= consumer:
        return False
    if execution.fun_scopes[producer] != execution.fun_scopes[consumer]:
        return False
    producer_path = execution.branch_paths[producer]
    consumer_path = execution.branch_paths[consumer]
    return consumer_path[: len(producer_path)] == producer_path


def calls_in_scope(
    values: list[str],
    execution: ErlangExecution,
    name: str,
    module: str | None = None,
    scope: int | None = None,
) -> list[tuple[int, list[list[str]], int]]:
    prefix = [name, "("] if module is None else [module, ":", name, "("]
    opening_offset = 1 if module is None else 3
    calls: list[tuple[int, list[list[str]], int]] = []
    cursor = 0
    while True:
        index = find_sequence(values, prefix, cursor)
        if index < 0:
            break
        arguments, closing = split_arguments(values, index + opening_offset)
        if closing < 0:
            break
        if execution.fun_scopes[index] == scope:
            calls.append((index, arguments, closing))
        cursor = max(index + 1, closing + 1)
    return calls


def assigned_calls_in_scope(
    values: list[str],
    execution: ErlangExecution,
    module: str,
    name: str,
    expected_arguments: list[list[str]],
    scope: int | None = None,
) -> list[tuple[str, int, int]]:
    matches: list[tuple[str, int, int]] = []
    for call_index, arguments, closing in calls_in_scope(
        values, execution, name, module, scope
    ):
        if (
            arguments == expected_arguments
            and call_index >= 2
            and values[call_index - 1] == "="
            and re.fullmatch(r"[A-Z_][A-Za-z0-9_@]*", values[call_index - 2])
            and execution.fun_scopes[call_index - 2] == scope
        ):
            matches.append((values[call_index - 2], call_index, closing))
    return matches


def pair_calls_in_scope(
    values: list[str],
    execution: ErlangExecution,
    module: str,
    name: str,
    scope: int | None = None,
) -> list[tuple[str, str, int, list[list[str]], int]]:
    matches: list[tuple[str, str, int, list[list[str]], int]] = []
    for call_index, arguments, closing in calls_in_scope(
        values, execution, name, module, scope
    ):
        pair = direct_pair_before(values, call_index)
        if pair is not None and execution.fun_scopes[call_index - 6] == scope:
            matches.append((pair[0], pair[1], call_index, arguments, closing))
    return matches


def top_level_token_spans(
    values: list[str], start: int, end: int, separator: str = ","
) -> list[tuple[int, int]]:
    """Split a bounded token interval without descending into syntax nodes."""
    spans: list[tuple[int, int]] = []
    segment_start = start
    index = start
    delimiters = {"(": ")", "[": "]", "{": "}"}
    while index < end:
        value = values[index]
        if value in delimiters:
            closing = matching_index(values, index, value, delimiters[value])
            if closing < 0 or closing >= end:
                return []
            index = closing + 1
            continue
        if erlang_block_opens(values, index):
            closing = erlang_block_end(values, index)
            if closing < 0 or closing >= end:
                return []
            index = closing + 1
            continue
        if value == separator:
            if segment_start < index:
                spans.append((segment_start, index))
            segment_start = index + 1
        index += 1
    if segment_start < end:
        spans.append((segment_start, end))
    return spans


def top_level_map_entries(
    values: list[str], opening: int, closing: int
) -> dict[str, list[str]] | None:
    if values[opening : opening + 2] != ["#", "{"] or closing <= opening + 1:
        return None
    entries: dict[str, list[str]] = {}
    for start, end in top_level_token_spans(values, opening + 2, closing):
        entry = values[start:end]
        if len(entry) < 3 or entry[1] != "=>" or entry[0] in entries:
            return None
        entries[entry[0]] = entry[2:]
    return entries


def direct_map_binding(
    values: list[str],
    execution: ErlangExecution,
    start: int,
    required: dict[str, str],
) -> tuple[str, int, int] | None:
    candidates: list[tuple[str, int, int]] = []
    for index in range(max(0, start), len(values) - 3):
        if (
            execution.fun_scopes[index] is None
            and re.fullmatch(r"[A-Z_][A-Za-z0-9_@]*", values[index])
            and values[index + 1 : index + 4] == ["=", "#", "{"]
        ):
            close = matching_index(values, index + 3, "{", "}")
            if close < 0:
                continue
            entries = top_level_map_entries(values, index + 2, close)
            if entries is not None and all(
                entries.get(key) == [value] for key, value in required.items()
            ):
                candidates.append((values[index], index, close))
    return candidates[0] if len(candidates) == 1 else None


def exact_top_level_expression(
    values: list[str], start: int, end: int, expected: list[str]
) -> bool:
    spans = top_level_token_spans(values, start, end)
    return bool(spans) and values[spans[-1][0] : spans[-1][1]] == expected


def control_clause_details(
    values: list[str], block_start: int
) -> list[tuple[list[str], int, int]]:
    """Return exact pattern/guard tokens and live body spans for case/receive."""
    block_end = erlang_block_end(values, block_start)
    if block_end < 0 or values[block_start] == "fun":
        return []
    cursor = block_start + 1
    if values[block_start] == "case":
        while cursor < block_end:
            if values[cursor] in ("(", "[", "{"):
                closing = {"(": ")", "[": "]", "{": "}"}[values[cursor]]
                close = matching_index(values, cursor, values[cursor], closing)
                if close < 0:
                    return []
                cursor = close + 1
                continue
            if erlang_block_opens(values, cursor):
                close = erlang_block_end(values, cursor)
                if close < 0:
                    return []
                cursor = close + 1
                continue
            if values[cursor] == "of":
                cursor += 1
                break
            cursor += 1
    pattern_start = cursor
    details: list[tuple[list[str], int, int]] = []
    while cursor < block_end:
        if values[cursor] in ("(", "[", "{"):
            closing = {"(": ")", "[": "]", "{": "}"}[values[cursor]]
            close = matching_index(values, cursor, values[cursor], closing)
            if close < 0:
                return []
            cursor = close + 1
            continue
        if erlang_block_opens(values, cursor):
            close = erlang_block_end(values, cursor)
            if close < 0:
                return []
            cursor = close + 1
            continue
        if values[cursor] == "->":
            body_start = cursor + 1
            body_end = body_start
            while body_end < block_end:
                if values[body_end] in ("(", "[", "{"):
                    closing = {"(": ")", "[": "]", "{": "}"}[values[body_end]]
                    close = matching_index(values, body_end, values[body_end], closing)
                    if close < 0:
                        return []
                    body_end = close + 1
                    continue
                if erlang_block_opens(values, body_end):
                    close = erlang_block_end(values, body_end)
                    if close < 0:
                        return []
                    body_end = close + 1
                    continue
                if values[body_end] in (";", "after", "catch"):
                    break
                body_end += 1
            details.append((values[pattern_start:cursor], body_start, body_end))
            if body_end >= block_end or values[body_end] in ("after", "catch"):
                break
            pattern_start = body_end + 1
            cursor = pattern_start
            continue
        cursor += 1
    return details


def receive_clause_spans(
    values: list[str], receive_index: int
) -> list[tuple[list[str], int, int]]:
    end = erlang_block_end(values, receive_index)
    if end < 0:
        return []
    spans = erlang_clause_spans(values, receive_index)
    results: list[tuple[list[str], int, int]] = []
    pattern_start = receive_index + 1
    for body_start, body_end in spans:
        arrow = body_start - 1
        results.append((values[pattern_start:arrow], body_start, body_end))
        if body_end < end and values[body_end] == ";":
            pattern_start = body_end + 1
        elif body_end < end and values[body_end] == "after":
            pattern_start = body_end
        else:
            pattern_start = body_end
    return results


def exact_live_tuple_present(
    values: list[str], execution: ErlangExecution, expected: list[str], start: int, end: int
) -> bool:
    for index in range(start, max(start, end - len(expected) + 1)):
        if (
            values[index : index + len(expected)] == expected
            and execution.fun_scopes[index] is None
        ):
            return True
    return False


def live_handler_down_finishes(
    values: list[str], function_name: str
) -> bool:
    """Prove the exact monitored handler DOWN reaches live final settlement.

    The proof deliberately binds both receiver values through top-level
    ``maps:get`` calls from the function's State parameter.  A similarly
    shaped DOWN in a nested fun, a different receive clause, or code placed
    after a non-returning expression cannot satisfy this contract.
    """
    parameters = erlang_parameters(values, function_name)
    if not parameters:
        return False
    state = parameters[0]
    execution = erlang_execution(values)
    handler_bindings = assigned_calls_in_scope(
        values, execution, "maps", "get", [["handler"], [state]]
    )
    monitor_bindings = assigned_calls_in_scope(
        values, execution, "maps", "get", [["handler_monitor"], [state]]
    )
    if len(handler_bindings) != 1 or len(monitor_bindings) != 1:
        return False
    handler, handler_index, _ = handler_bindings[0]
    monitor, monitor_index, _ = monitor_bindings[0]
    expected_pattern = [
        "{", "DOWN", ",", monitor, ",", "process", ",", handler, ",", "_", "}",
    ]
    matching_bodies: list[tuple[int, int]] = []
    for receive_index, value in enumerate(values):
        if value != "receive" or execution.fun_scopes[receive_index] is not None:
            continue
        for pattern, body_start, body_end in receive_clause_spans(
            values, receive_index
        ):
            if pattern == expected_pattern:
                matching_bodies.append((body_start, body_end))
    if len(matching_bodies) != 1:
        return False
    body_start, body_end = matching_bodies[0]
    expressions = top_level_token_spans(values, body_start, body_end)
    expected_finish = ["http1_handler_guardian_finish", "(", state, ")"]
    if (
        not expressions
        or values[expressions[-1][0] : expressions[-1][1]] != expected_finish
    ):
        return False
    finish_index = expressions[-1][0]
    if not (
        execution_dominates(execution, handler_index, finish_index)
        and execution_dominates(execution, monitor_index, finish_index)
    ):
        return False
    for start, end in expressions[:-1]:
        expression = values[start:end]
        if (
            expression[:2] in (["exit", "("], ["throw", "("], ["return", "("])
            or expression[:4] == ["erlang", ":", "error", "("]
        ):
            return False
    return True


def owner_down_converges(
    values: list[str], state: str, owner: str, owner_monitor: str
) -> bool:
    """Prove the exact owner DOWN clause enters the live settlement chain."""
    execution = erlang_execution(values)
    expected_pattern = [
        "{", "DOWN", ",", owner_monitor, ",", "process", ",", owner, ",", "_", "}",
    ]
    matching_bodies: list[tuple[int, int]] = []
    for receive_index, value in enumerate(values):
        if value != "receive" or execution.fun_scopes[receive_index] is not None:
            continue
        for pattern, body_start, body_end in receive_clause_spans(
            values, receive_index
        ):
            if pattern == expected_pattern:
                matching_bodies.append((body_start, body_end))
    if len(matching_bodies) != 1:
        return False
    start, end = matching_bodies[0]
    expressions = top_level_token_spans(values, start, end)
    if not expressions:
        return False
    final = values[expressions[-1][0] : expressions[-1][1]]
    if final == ["http1_handler_guardian_finish", "(", state, ")"]:
        return True
    if final[:2] != ["http1_handler_guardian_begin_termination", "("]:
        return False
    arguments, close = split_arguments(final, 1)
    if close != len(final) - 1 or len(arguments) != 4:
        return False
    first = arguments[0]
    if first != [state] and first[:3] != [state, "#", "{"]:
        return False
    return True


def inspect_http1_erlang_flow(ffi: str) -> list[str]:
    """Prove reachable, dominating value flow across the two Erlang spawns."""
    findings: list[str] = []
    start_values = erlang_function_values(ffi, HTTP1_FOREIGN_START)
    await_values = erlang_function_values(ffi, "http1_handler_guardian_await_ready")
    boot_values = erlang_function_values(ffi, "http1_handler_guardian_boot")
    handler_values = erlang_function_values(
        ffi, "http1_handler_guardian_start_handler"
    )
    active_values = erlang_function_values(ffi, "http1_handler_guardian_active")
    down_values = erlang_function_values(ffi, "http1_handler_guardian_down")
    terminating_values = erlang_function_values(
        ffi, "http1_handler_guardian_terminating_receive"
    )
    quarantine_values = erlang_function_values(
        ffi, "http1_handler_guardian_quarantine_receive"
    )
    finish_values = erlang_function_values(ffi, "http1_handler_guardian_finish")
    if any(
        values is None
        for values in (
            start_values,
            await_values,
            boot_values,
            handler_values,
            active_values,
            down_values,
            terminating_values,
            quarantine_values,
            finish_values,
        )
    ):
        return ["delegated_atomic_target_missing"]
    assert start_values is not None
    assert await_values is not None
    assert boot_values is not None
    assert handler_values is not None
    assert active_values is not None
    assert down_values is not None
    assert terminating_values is not None
    assert quarantine_values is not None
    assert finish_values is not None

    start_execution = erlang_execution(start_values)
    guardian_pairs = pair_calls_in_scope(
        start_values, start_execution, "erlang", "spawn_monitor"
    )
    if not guardian_pairs:
        findings.append("guardian_spawn_not_atomic")
    boot_in_closure = False
    guardian_flow: tuple[str, str] | None = None
    for guardian, guardian_monitor, spawn_index, arguments, spawn_close in guardian_pairs:
        if len(arguments) != 1:
            continue
        closure = arguments[0]
        if closure[:4] != ["fun", "(", ")", "->"] or closure[-1:] != ["end"]:
            continue
        closure_body = closure[4:-1]
        closure_execution = erlang_execution(closure_body)
        boot_calls = calls_in_scope(
            closure_body,
            closure_execution,
            "http1_handler_guardian_boot",
        )
        if len(boot_calls) != 1:
            continue
        _boot_index, boot_arguments, _boot_close = boot_calls[0]
        boot_in_closure = True
        owner = exact_identifier(boot_arguments[0]) if boot_arguments else None
        if owner is None:
            continue
        owner_assignments: list[int] = []
        for self_index, self_arguments, _self_close in calls_in_scope(
            start_values, start_execution, "self"
        ):
            if (
                not self_arguments
                and self_index >= 2
                and start_values[self_index - 2 : self_index] == [owner, "="]
            ):
                owner_assignments.append(self_index - 2)
        await_calls = calls_in_scope(
            start_values,
            start_execution,
            "http1_handler_guardian_await_ready",
        )
        matching_awaits = [
            (index, call_arguments)
            for index, call_arguments, _close in await_calls
            if len(call_arguments) >= 2
            and exact_identifier(call_arguments[0]) == guardian
            and exact_identifier(call_arguments[1]) == guardian_monitor
            and execution_dominates(start_execution, spawn_index, index)
        ]
        if (
            len(owner_assignments) == 1
            and execution_dominates(
                start_execution, owner_assignments[0], spawn_index
            )
            and len(matching_awaits) == 1
        ):
            guardian_flow = (guardian, guardian_monitor)
            break
    if not boot_in_closure:
        findings.append("guardian_boot_not_in_spawn_closure")
    if guardian_flow is None:
        findings.append("guardian_monitor_provenance_missing")

    await_parameters = erlang_parameters(
        await_values, "http1_handler_guardian_await_ready"
    )
    return_proven = False
    if await_parameters is not None and len(await_parameters) >= 3:
        guardian_parameter, monitor_parameter, ready_reference = await_parameters[:3]
        await_execution = erlang_execution(await_values)
        receive_blocks = [
            index
            for index, value in enumerate(await_values)
            if value == "receive" and await_execution.fun_scopes[index] is None
        ]
        for receive_index in receive_blocks:
            for pattern, body_start, body_end in receive_clause_spans(
                await_values, receive_index
            ):
                prefix = [
                    "{", ready_reference, ",", guardian_parameter, ","
                ]
                if pattern[: len(prefix)] != prefix or len(pattern) < 7:
                    continue
                commands = pattern[5]
                expected_return = [
                    "{", "ok", ",", "{", monitor_parameter, ",", commands, "}", "}"
                ]
                if exact_top_level_expression(
                    await_values, body_start, body_end, expected_return
                ):
                    return_proven = True
                    break
            if return_proven:
                break
    if not return_proven:
        findings.append("guardian_monitor_return_unproven")

    boot_parameters = erlang_parameters(boot_values, "http1_handler_guardian_boot")
    owner_chain = False
    owner_lifetime = False
    if boot_parameters:
        owner = boot_parameters[0]
        boot_execution = erlang_execution(boot_values)
        monitor_bindings = assigned_calls_in_scope(
            boot_values,
            boot_execution,
            "erlang",
            "monitor",
            [["process"], [owner]],
        )
        start_calls = calls_in_scope(
            boot_values,
            boot_execution,
            "http1_handler_guardian_start_handler",
        )
        if len(monitor_bindings) == 1 and start_calls:
            owner_monitor, monitor_index, _monitor_close = monitor_bindings[0]
            owner_chain = all(
                len(arguments) >= 2
                and exact_identifier(arguments[0]) == owner
                and exact_identifier(arguments[1]) == owner_monitor
                and execution_dominates(boot_execution, monitor_index, call_index)
                for call_index, arguments, _closing in start_calls
            )
            owner_demonitors = calls_in_scope(
                boot_values, boot_execution, "demonitor", "erlang"
            )
            premature_demonitor = any(
                arguments
                and exact_identifier(arguments[0]) == owner_monitor
                and execution_dominates(boot_execution, demonitor_index, start_index)
                for demonitor_index, arguments, _closing in owner_demonitors
                for start_index, _start_arguments, _start_close in start_calls
            )
            owner_lifetime = owner_chain and not premature_demonitor
    if not owner_chain:
        findings.append("guardian_owner_chain_unproven")
    if not owner_lifetime:
        findings.append("guardian_owner_monitor_lifetime_unproven")

    handler_execution = erlang_execution(handler_values)
    handler_pairs = pair_calls_in_scope(
        handler_values, handler_execution, "erlang", "spawn_opt"
    )
    handler_state: str | None = None
    state_top_level_proven = False
    handler_parameters = erlang_parameters(
        handler_values, "http1_handler_guardian_start_handler"
    )
    for handler, handler_monitor, spawn_index, arguments, _spawn_close in handler_pairs:
        if len(arguments) != 2 or arguments[1] != ["[", "link", ",", "monitor", "]"]:
            continue
        closure = arguments[0]
        if closure[:4] != ["fun", "(", ")", "->"] or closure[-1:] != ["end"]:
            continue
        closure_body = closure[4:-1]
        closure_execution = erlang_execution(closure_body)
        entry_calls = calls_in_scope(
            closure_body,
            closure_execution,
            "http1_handler_guardian_handler_entry",
        )
        if len(entry_calls) != 1:
            continue
        if handler_parameters is None or len(handler_parameters) < 2:
            continue
        owner_parameter, owner_monitor_parameter = handler_parameters[:2]
        state_binding = direct_map_binding(
            handler_values,
            handler_execution,
            spawn_index + 1,
            {
                "owner": owner_parameter,
                "owner_monitor": owner_monitor_parameter,
                "handler": handler,
                "handler_monitor": handler_monitor,
            },
        )
        if state_binding is None:
            continue
        state, state_index, _state_close = state_binding
        if not execution_dominates(handler_execution, spawn_index, state_index):
            continue
        active_calls = calls_in_scope(
            handler_values,
            handler_execution,
            "http1_handler_guardian_active",
        )
        if not active_calls or not all(
            len(call_arguments) == 1
            and exact_identifier(call_arguments[0]) == state
            and execution_dominates(handler_execution, state_index, call_index)
            for call_index, call_arguments, _closing in active_calls
        ):
            continue
        owner_demonitors = calls_in_scope(
            handler_values, handler_execution, "demonitor", "erlang"
        )
        if any(
            arguments
            and exact_identifier(arguments[0]) == owner_monitor_parameter
            and any(
                execution_dominates(handler_execution, call_index, active_index)
                for active_index, _active_arguments, _active_close in active_calls
            )
            for call_index, arguments, _closing in owner_demonitors
        ):
            owner_lifetime = False
            continue
        handler_state = state
        state_top_level_proven = True
        break
    if handler_state is None:
        findings.append("handler_spawn_not_atomic")
    if not state_top_level_proven:
        findings.append("handler_state_top_level_unproven")

    down_flow = False
    active_parameters = erlang_parameters(
        active_values, "http1_handler_guardian_active"
    )
    if handler_state is not None and active_parameters:
        state = active_parameters[0]
        active_execution = erlang_execution(active_values)
        owner_bindings = assigned_calls_in_scope(
            active_values,
            active_execution,
            "maps",
            "get",
            [["owner"], [state]],
        )
        owner_monitor_bindings = assigned_calls_in_scope(
            active_values,
            active_execution,
            "maps",
            "get",
            [["owner_monitor"], [state]],
        )
        handler_bindings = assigned_calls_in_scope(
            active_values,
            active_execution,
            "maps",
            "get",
            [["handler"], [state]],
        )
        monitor_bindings = assigned_calls_in_scope(
            active_values,
            active_execution,
            "maps",
            "get",
            [["handler_monitor"], [state]],
        )
        down_calls = calls_in_scope(
            active_values,
            active_execution,
            "http1_handler_guardian_down",
        )
        if len(handler_bindings) == 1 and len(monitor_bindings) == 1 and down_calls:
            active_handler, handler_index, _ = handler_bindings[0]
            active_monitor, monitor_index, _ = monitor_bindings[0]
            exact_bodies: list[tuple[int, int]] = []
            owner_bodies: list[tuple[int, int]] = []
            expected_pattern = [
                "{", "DOWN", ",", active_monitor, ",", "process", ",",
                active_handler, ",", "_", "}",
            ]
            receive_blocks = [
                index
                for index, value in enumerate(active_values)
                if value == "receive" and active_execution.fun_scopes[index] is None
            ]
            for receive_index in receive_blocks:
                for pattern, body_start, body_end in receive_clause_spans(
                    active_values, receive_index
                ):
                    if pattern == expected_pattern:
                        exact_bodies.append((body_start, body_end))
                    if (
                        len(owner_bindings) == 1
                        and len(owner_monitor_bindings) == 1
                        and pattern
                        == [
                            "{", "DOWN", ",", owner_monitor_bindings[0][0],
                            ",", "process", ",", owner_bindings[0][0], ",", "_", "}",
                        ]
                    ):
                        owner_bodies.append((body_start, body_end))
            exact_down_call = [
                "http1_handler_guardian_down", "(", state, ")"
            ]
            down_flow = bool(exact_bodies) and all(
                len(arguments) == 1
                and exact_identifier(arguments[0]) == state
                and execution_dominates(active_execution, handler_index, call_index)
                and execution_dominates(active_execution, monitor_index, call_index)
                and any(
                    start <= call_index < end
                    and active_values[start:end] == exact_down_call
                    for start, end in exact_bodies
                )
                for call_index, arguments, _closing in down_calls
            )
            if exact_bodies and not all(
                active_values[start:end] == exact_down_call
                for start, end in exact_bodies
            ):
                findings.append("handler_down_reachability_unproven")
            owner_branch_proven = (
                len(owner_bindings) == 1
                and len(owner_monitor_bindings) == 1
                and owner_down_converges(
                    active_values,
                    state,
                    owner_bindings[0][0],
                    owner_monitor_bindings[0][0],
                )
            )
            owner_lifetime = owner_lifetime and owner_branch_proven
            forbidden_live = calls_in_scope(
                active_values, active_execution, "send_subject"
            ) + calls_in_scope(
                active_values,
                active_execution,
                "http1_handler_guardian_publish_result",
            )
            down_execution = erlang_execution(down_values)
            live_publications = calls_in_scope(
                down_values,
                down_execution,
                "http1_handler_guardian_publish_result",
            )
            case_blocks = [
                index
                for index, value in enumerate(down_values)
                if value == "case" and down_execution.fun_scopes[index] is None
            ]
            publication_proven = False
            all_terminals_proven = False
            if len(case_blocks) == 1:
                details = control_clause_details(down_values, case_blocks[0])
                success_pattern = [
                    "{", "false", ",", "{", "some", ",", "Result", "}",
                    ",", "{", "some", ",", "ExitAt", "}", ",", "none", "}",
                    "when", "ExitAt", "=<", "Deadline",
                ]
                success = [item for item in details if item[0] == success_pattern]
                expected_publish = [
                    "http1_handler_guardian_publish_result", "(", "Events", ",",
                    "Result", ")",
                ]
                expected_finish = [
                    "http1_handler_guardian_finish", "(", "State", ")"
                ]
                if len(success) == 1:
                    _pattern, success_start, success_end = success[0]
                    expressions = top_level_token_spans(
                        down_values, success_start, success_end
                    )
                    publication_proven = (
                        len(expressions) == 2
                        and down_values[expressions[0][0] : expressions[0][1]]
                        == expected_publish
                        and down_values[expressions[1][0] : expressions[1][1]]
                        == expected_finish
                        and len(live_publications) == 1
                        and success_start <= live_publications[0][0] < success_end
                    )
                all_terminals_proven = len(details) >= 2 and all(
                    bool(expressions := top_level_token_spans(down_values, start, end))
                    and down_values[expressions[-1][0] : expressions[-1][1]]
                    == expected_finish
                    for _pattern, start, end in details
                )
            if not publication_proven or not all_terminals_proven:
                findings.append("handler_publication_reachability_unproven")
            down_flow = (
                down_flow
                and not forbidden_live
                and publication_proven
                and all_terminals_proven
            )

            terminal_down_proven = (
                live_handler_down_finishes(
                    terminating_values,
                    "http1_handler_guardian_terminating_receive",
                )
                and live_handler_down_finishes(
                    quarantine_values,
                    "http1_handler_guardian_quarantine_receive",
                )
            )
            down_flow = down_flow and terminal_down_proven

            lifecycle_demonitor = False
            for lifecycle_values in (
                active_values,
                down_values,
                terminating_values,
                quarantine_values,
            ):
                lifecycle_execution = erlang_execution(lifecycle_values)
                if calls_in_scope(
                    lifecycle_values,
                    lifecycle_execution,
                    "demonitor",
                    "erlang",
                ):
                    lifecycle_demonitor = True
                    break
            owner_lifetime = (
                owner_lifetime
                and terminal_down_proven
                and not lifecycle_demonitor
            )

            finish_execution = erlang_execution(finish_values)
            finish_parameters = erlang_parameters(
                finish_values, "http1_handler_guardian_finish"
            )
            finish_owner_gets = []
            finish_demonitors = []
            if finish_parameters:
                finish_state = finish_parameters[0]
                finish_owner_gets = calls_in_scope(
                    finish_values, finish_execution, "get", "maps"
                )
                finish_demonitors = calls_in_scope(
                    finish_values, finish_execution, "demonitor", "erlang"
                )
                owner_finish = any(
                    len(arguments) == 2
                    and arguments[0]
                    == ["maps", ":", "get", "(", "owner_monitor", ",", finish_state, ")"]
                    and arguments[1] == ["[", "flush", "]"]
                    for _index, arguments, _closing in finish_demonitors
                )
                owner_alive_get = any(
                    arguments == [["owner_alive"], [finish_state]]
                    for _index, arguments, _closing in finish_owner_gets
                )
                owner_lifetime = owner_lifetime and owner_finish and owner_alive_get
            else:
                owner_lifetime = False
    if not down_flow:
        findings.append("handler_down_to_terminal_flow_unproven")
    if not owner_lifetime:
        findings.append("guardian_owner_monitor_lifetime_unproven")
    return sorted(set(findings))


def dead_scope_composite_fixture() -> str:
    """A valid-token fixture whose convincing proofs are all unreachable."""
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
http1_handler_guardian_terminating_receive(State, Termination, Notify, Deadline) ->
    Handler = maps:get(handler, State),
    HandlerMonitor = maps:get(handler_monitor, State),
    receive
        {'DOWN', HandlerMonitor, process, Handler, _} ->
            http1_handler_guardian_finish(State)
    end.
http1_handler_guardian_quarantine_receive(State, Termination, Deadline) ->
    Handler = maps:get(handler, State),
    HandlerMonitor = maps:get(handler_monitor, State),
    receive
        {'DOWN', HandlerMonitor, process, Handler, _} ->
            http1_handler_guardian_finish(State)
    end.
http1_handler_guardian_down(State) ->
    http1_handler_guardian_publish_result(State, result).
http1_handler_guardian_finish(State) ->
    case maps:get(owner_alive, State) of
        true -> erlang:demonitor(maps:get(owner_monitor, State), [flush]);
        false -> ok
    end,
    ok.
http1_handler_guardian_publish_result(State, Result) -> {State, Result}.
'''


def inspect_contract(contract: Contract, source: str) -> list[str]:
    body = (
        erlang_function_body(source, contract.function)
        if contract.language == "erlang"
        else function_body(source, contract.function)
    )
    if body is None:
        return ["function_missing"]
    findings = [
        "required_atomic_spawn_missing"
        for token in contract.required
        if token not in body
    ]
    findings.extend(
        "separate_spawn_or_monitor_present"
        for token in contract.forbidden
        if token in body
    )
    return sorted(set(findings))


def inspect_http1_delegation(gleam: str, ffi: str) -> list[str]:
    """Prove exact value flow from Gleam through both atomic Erlang spawns."""
    findings: list[str] = []
    expected_binding = (
        "http_server_ffi",
        HTTP1_FOREIGN_START,
        HTTP1_START_ARITY,
    )
    if external_bindings(gleam, HTTP1_LOCAL_START) != [expected_binding]:
        findings.append("delegated_atomic_binding_mismatch")

    run_values = gleam_function_values(gleam, "run_handler")
    if run_values is None:
        return ["function_missing"]
    local_calls: list[int] = []
    cursor = 0
    while True:
        call_index, _arguments, closing = call_arguments(
            run_values, HTTP1_LOCAL_START, cursor
        )
        if call_index < 0:
            break
        local_calls.append(call_index)
        cursor = max(call_index + 1, closing + 1)
    assigned_calls: list[tuple[str, int, int]] = []
    for call_index in local_calls:
        arguments, closing = split_arguments(run_values, call_index + 1)
        if (
            call_index >= 3
            and run_values[call_index - 3] == "let"
            and re.fullmatch(
                r"[a-z_][A-Za-z0-9_]*", run_values[call_index - 2]
            )
            and run_values[call_index - 1] == "="
            and len(arguments) == HTTP1_START_ARITY
        ):
            assigned_calls.append((run_values[call_index - 2], call_index, closing))
    gleam_flow_proven = False
    if len(local_calls) == 1 and len(assigned_calls) == 1:
        result_name, _call_index, closing = assigned_calls[0]
        case_index = find_sequence(run_values, ["case", result_name, "{"], closing + 1)
        case_close = (
            matching_index(run_values, case_index + 2, "{", "}")
            if case_index >= 0
            else -1
        )
        if case_index >= 0 and case_close >= 0:
            branch = run_values[case_index + 3 : case_close]
            ok_index = find_top_level_sequence(
                branch, ["Ok", "(", "#", "("]
            )
            if (
                ok_index >= 0
                and ok_index + 9 < len(branch)
                and re.fullmatch(r"[a-z_][A-Za-z0-9_]*", branch[ok_index + 4])
                and branch[ok_index + 5] == ","
                and re.fullmatch(r"[a-z_][A-Za-z0-9_]*", branch[ok_index + 6])
                and branch[ok_index + 7 : ok_index + 11]
                == [")", ")", "-", ">"]
            ):
                monitor_name = branch[ok_index + 4]
                commands_name = branch[ok_index + 6]
                await_index, await_arguments, _await_close = call_arguments(
                    branch, "await_handler", ok_index + 11
                )
                next_branch_arrow = find_top_level_sequence(
                    branch, ["-", ">"], ok_index + 11
                )
                gleam_flow_proven = (
                    await_index >= 0
                    and len(await_arguments) == 9
                    and (
                        next_branch_arrow < 0
                        or await_index < next_branch_arrow
                    )
                    and exact_identifier(await_arguments[3]) == commands_name
                    and exact_identifier(await_arguments[5]) == monitor_name
                )
    if not gleam_flow_proven:
        findings.append("delegated_atomic_call_flow_unproven")
    if len(local_calls) != 1 or len(assigned_calls) != 1:
        findings.append("delegated_atomic_call_unused_or_ambiguous")
    if any(
        find_sequence(run_values, sequence) >= 0
        for sequence in (
            ["process", ".", "spawn_unlinked", "("],
            ["process", ".", "monitor", "("],
            ["spawn_monitor", "("],
        )
    ):
        findings.append("separate_spawn_or_monitor_present")

    clean_ffi = sanitise_erlang(ffi)
    exported = any(
        re.search(
            rf"\b{re.escape(HTTP1_FOREIGN_START)}\s*/\s*"
            rf"{HTTP1_START_ARITY}\b",
            block,
        )
        for block in re.findall(r"(?s)-export\s*\(\s*\[(.*?)\]\s*\)\s*\.", clean_ffi)
    )
    if not exported:
        findings.append("delegated_atomic_export_missing")

    findings.extend(inspect_http1_erlang_flow(ffi))
    return sorted(set(findings))


def safe_read_bytes(path: Path, maximum: int) -> tuple[bytes, str]:
    absolute = Path(os.path.abspath(path))
    before_path = os.lstat(absolute)
    reparse_flag = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0)
    attributes = getattr(before_path, "st_file_attributes", 0)
    if stat.S_ISLNK(before_path.st_mode) or (reparse_flag and attributes & reparse_flag):
        raise ValueError("file_identity_rejected")
    if not stat.S_ISREG(before_path.st_mode):
        raise ValueError("file_type_rejected")
    if before_path.st_size <= 0 or before_path.st_size > maximum:
        raise ValueError("file_limit_exceeded")
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
                raise ValueError("file_limit_exceeded")
            chunks.append(chunk)
        after_handle = os.fstat(handle.fileno())
    after_path = os.lstat(absolute)
    identity = lambda value: (
        value.st_dev,
        value.st_ino,
        value.st_size,
        value.st_mtime_ns,
    )
    if not (
        identity(before_path) == identity(before_handle)
        == identity(after_handle) == identity(after_path)
    ):
        raise ValueError("file_changed_during_read")
    data = b"".join(chunks)
    if len(data) != before_path.st_size:
        raise ValueError("partial_read_rejected")
    return data, hashlib.sha256(data).hexdigest()


def bounded_sha256(path: Path, maximum: int) -> str:
    return safe_read_bytes(path, maximum)[1]


def runtime_identity() -> dict[str, str]:
    executable = Path(sys.executable).resolve(strict=True)
    return {
        "tool_request": "python@3.12.13",
        "implementation": sys.implementation.name,
        "version": ".".join(str(part) for part in sys.version_info[:3]),
        "executable_sha256": bounded_sha256(executable, MAX_TOOL_BYTES),
        "mise_config_sha256": bounded_sha256(ROOT / ".mise.toml", MAX_SOURCE_BYTES),
    }


def audited_paths() -> list[str]:
    return sorted(
        {contract.path for contract in CONTRACTS}
        | {HTTP1_GLEAM_PATH, HTTP1_FFI_PATH}
    )


def source_snapshot() -> tuple[dict[str, str], dict[str, str], int, str]:
    sources: dict[str, str] = {}
    hashes: dict[str, str] = {}
    total = 0
    aggregate = hashlib.sha256()
    for relative in audited_paths():
        raw, digest = safe_read_bytes(ROOT / relative, MAX_SOURCE_BYTES)
        sources[relative] = raw.decode("utf-8", errors="strict")
        hashes[relative] = digest
        total += len(raw)
        aggregate.update(relative.encode("utf-8") + b"\0" + raw + b"\0")
    return sources, hashes, total, aggregate.hexdigest()


def stability_findings(
    source_pre: dict[str, str],
    source_post: dict[str, str],
    source_total_pre: int,
    source_total_post: int,
    source_aggregate_pre: str,
    source_aggregate_post: str,
    scanner_pre: str,
    scanner_post: str,
) -> list[str]:
    findings: list[str] = []
    if not (
        source_pre == source_post
        and source_total_pre == source_total_post
        and source_aggregate_pre == source_aggregate_post
    ):
        findings.append("source_changed_during_scan")
    if scanner_pre != scanner_post:
        findings.append("scanner_changed_during_scan")
    return findings


def audit() -> tuple[int, dict[str, object]]:
    scanner_path = Path(os.path.abspath(__file__))
    _scanner_pre_bytes, scanner_pre = safe_read_bytes(
        scanner_path, MAX_SOURCE_BYTES
    )
    sources, source_pre, total, aggregate_pre = source_snapshot()
    findings: list[dict[str, str]] = []
    for contract in CONTRACTS:
        findings.extend(
            {
                "path": contract.path,
                "function": contract.function,
                "rule": rule,
            }
            for rule in inspect_contract(contract, sources[contract.path])
        )
    findings.extend(
        {
            "path": HTTP1_GLEAM_PATH,
            "function": "run_handler",
            "rule": rule,
        }
        for rule in inspect_http1_delegation(
            sources[HTTP1_GLEAM_PATH], sources[HTTP1_FFI_PATH]
        )
    )
    _post_sources, source_post, post_total, aggregate_post = source_snapshot()
    _scanner_post_bytes, scanner_post = safe_read_bytes(
        scanner_path, MAX_SOURCE_BYTES
    )
    stability = stability_findings(
        source_pre, source_post, total, post_total, aggregate_pre,
        aggregate_post, scanner_pre, scanner_post
    )
    source_stable = "source_changed_during_scan" not in stability
    scanner_stable = "scanner_changed_during_scan" not in stability
    findings.extend(
        {
            "path": "<aggregate>" if rule.startswith("source_") else "<scanner>",
            "function": "audit",
            "rule": rule,
        }
        for rule in stability
    )
    runtime = runtime_identity()
    runtime_valid = (
        runtime.get("implementation") == "cpython"
        and runtime.get("version") == EXPECTED_PYTHON_VERSION
    )
    status = "Ready" if not findings and runtime_valid else "Failed"
    report: dict[str, object] = {
        "schema": 2,
        "kind": "audit",
        "status": status,
        "classification": (
            "passed" if status == "Ready" else (
                "runtime_version_mismatch"
                if not runtime_valid else "unsafe_spawn_monitor_sequence"
            )
        ),
        "completed_contracts": len(CONTRACTS) + 1,
        "source_files": len(sources),
        "source_bytes": total,
        "source_sha256_pre": source_pre,
        "source_sha256_post": source_post,
        "source_aggregate_sha256_pre": aggregate_pre,
        "source_aggregate_sha256_post": aggregate_post,
        "source_stable": source_stable,
        "scanner_sha256_pre": scanner_pre,
        "scanner_sha256_post": scanner_post,
        "scanner_stable": scanner_stable,
        "runtime": runtime,
        "limits": {
            "source_file_bytes": MAX_SOURCE_BYTES,
            "tool_bytes": MAX_TOOL_BYTES,
            "tokens": MAX_TOKENS,
            "report_bytes": 1024 * 1024,
        },
        "findings": findings,
        "rerun_command": (
            "mise exec python@3.12.13 -- python -I -B "
            "scripts/spawn_monitor_contract_audit.py"
        ),
    }
    return (0 if status == "Ready" else 1), report


def self_test_report() -> tuple[int, dict[str, object]]:
    scanner_path = Path(os.path.abspath(__file__))
    _scanner_pre_bytes, scanner_pre = safe_read_bytes(
        scanner_path, MAX_SOURCE_BYTES
    )
    contract = Contract(
        "fixture.gleam",
        "run_handler",
        ("spawn_monitor(",),
        ("process.spawn_unlinked(", "process.monitor(pid)"),
    )
    generic_good = """
fn run_handler() {
  let #(pid, monitor) = spawn_monitor(fn() { work() })
  await(pid, monitor)
}
"""
    generic_separate = """
fn run_handler() {
  let pid = process.spawn_unlinked(fn() { work() })
  let monitor = process.monitor(pid)
  await(pid, monitor)
}
"""
    erlang_contract = Contract(
        "fixture.erl",
        "spawn_link_monitor",
        ("erlang:spawn_opt(", "[link, monitor]"),
        ("erlang:spawn(", "erlang:monitor("),
        "erlang",
    )
    erlang_good = """
spawn_link_monitor(Fun) ->
    erlang:spawn_opt(Fun, [link, monitor]).
next_function() -> ok.
"""
    delegated_gleam = """
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
"""
    delegated_ffi = """
-export([start_http1_handler_guardian/10]).
start_http1_handler_guardian(A, B, C, D, E, F, G, H, I, J) ->
    ReadyReference = make_ref(),
    Owner = self(),
    {Guardian, GuardianMonitor} = erlang:spawn_monitor(fun() ->
        http1_handler_guardian_boot(Owner, B, C, D, E, F, G, H, I, J)
    end),
    http1_handler_guardian_await_ready(
        Guardian, GuardianMonitor, ReadyReference
    ).
http1_handler_guardian_await_ready(Guardian, GuardianMonitor, ReadyReference) ->
    receive
        {ReadyReference, Guardian, Commands, ReadyAt} ->
            {ok, {GuardianMonitor, Commands}}
    end.
http1_handler_guardian_boot(Owner, B, C, D, E, F, G, H, I, J) ->
    OwnerMonitor = erlang:monitor(process, Owner),
    http1_handler_guardian_start_handler(
        Owner, OwnerMonitor, B, C, D, E, F, G, H, I, J
    ).
http1_handler_guardian_start_handler(Owner, OwnerMonitor, B, C, D, E, F, G, H, I, J) ->
    {Handler, HandlerMonitor} = erlang:spawn_opt(fun() ->
        http1_handler_guardian_handler_entry(B, C, D)
    end, [link, monitor]),
    State = #{
        owner => Owner,
        owner_monitor => OwnerMonitor,
        owner_alive => true,
        events => B,
        handler => Handler,
        handler_monitor => HandlerMonitor,
        handler_deadline => 10,
        timed_out => false,
        result => {some, result},
        exit_at => {some, 0},
        failure_at => none
    },
    http1_handler_guardian_active(State).
http1_handler_guardian_handler_entry(B, C, D) ->
    {B, C, D}.
http1_handler_guardian_active(State) ->
    Owner = maps:get(owner, State),
    OwnerMonitor = maps:get(owner_monitor, State),
    Handler = maps:get(handler, State),
    HandlerMonitor = maps:get(handler_monitor, State),
    receive
        {'DOWN', OwnerMonitor, process, Owner, _} ->
            http1_handler_guardian_finish(State);
        {'DOWN', HandlerMonitor, process, Handler, _} ->
            http1_handler_guardian_down(State)
    end.
http1_handler_guardian_terminating_receive(State, Termination, Notify, Deadline) ->
    Handler = maps:get(handler, State),
    HandlerMonitor = maps:get(handler_monitor, State),
    receive
        {'DOWN', HandlerMonitor, process, Handler, _} ->
            http1_handler_guardian_finish(State)
    end.
http1_handler_guardian_quarantine_receive(State, Termination, Deadline) ->
    Handler = maps:get(handler, State),
    HandlerMonitor = maps:get(handler_monitor, State),
    receive
        {'DOWN', HandlerMonitor, process, Handler, _} ->
            http1_handler_guardian_finish(State)
    end.
http1_handler_guardian_down(State) ->
    Deadline = maps:get(handler_deadline, State),
    Events = maps:get(events, State),
    case {
        maps:get(timed_out, State), maps:get(result, State),
        maps:get(exit_at, State), maps:get(failure_at, State)
    } of
        {false, {some, Result}, {some, ExitAt}, none}
          when ExitAt =< Deadline ->
            http1_handler_guardian_publish_result(Events, Result),
            http1_handler_guardian_finish(State);
        {_TimedOut, _Result, _ExitAt, _FailureAt} ->
            http1_handler_guardian_finish(State)
    end.
http1_handler_guardian_finish(State) ->
    case maps:get(owner_alive, State) of
        true -> erlang:demonitor(maps:get(owner_monitor, State), [flush]);
        false -> ok
    end,
    ok.
http1_handler_guardian_publish_result(Events, Result) ->
    {Events, Result}.
next_function() -> ok.
"""

    controls: list[dict[str, object]] = []

    def record(name: str, expected: list[str], observed: list[str]) -> None:
        expected_sorted = sorted(set(expected))
        observed_sorted = sorted(set(observed))
        controls.append(
            {
                "name": name,
                "expected": expected_sorted,
                "observed": observed_sorted,
                "passed": expected_sorted == observed_sorted,
            }
        )

    record("generic_atomic_good", [], inspect_contract(contract, generic_good))
    record(
        "generic_spawn_monitor_gap",
        ["required_atomic_spawn_missing", "separate_spawn_or_monitor_present"],
        inspect_contract(contract, generic_separate),
    )
    record("generic_erlang_atomic_good", [], inspect_contract(erlang_contract, erlang_good))
    record("delegated_good", [], inspect_http1_delegation(delegated_gleam, delegated_ffi))
    record(
        "dead_scope_wrong_receiver_composite",
        [
            "guardian_monitor_provenance_missing",
            "guardian_owner_chain_unproven",
            "guardian_owner_monitor_lifetime_unproven",
            "handler_down_to_terminal_flow_unproven",
            "handler_spawn_not_atomic",
            "handler_state_top_level_unproven",
        ],
        inspect_http1_delegation(
            delegated_gleam, dead_scope_composite_fixture()
        ),
    )
    dead_owner = delegated_ffi.replace(
        "    Owner = self(),",
        "    Owner = A,\n"
        "    _DeadOwner = fun() -> Owner = self() end,",
        1,
    )
    record(
        "dead_owner_scope",
        ["guardian_monitor_provenance_missing"],
        inspect_http1_delegation(delegated_gleam, dead_owner),
    )
    dead_state = delegated_ffi.replace(
        "    http1_handler_guardian_active(State).\n"
        "http1_handler_guardian_handler_entry",
        "    _DeadActive = fun() ->\n"
        "        http1_handler_guardian_active(State)\n"
        "    end,\n"
        "    WrongState = #{owner => Owner, owner_monitor => OwnerMonitor},\n"
        "    http1_handler_guardian_active(WrongState).\n"
        "http1_handler_guardian_handler_entry",
        1,
    )
    record(
        "dead_state_scope",
        [
            "handler_down_to_terminal_flow_unproven",
            "handler_spawn_not_atomic",
            "handler_state_top_level_unproven",
        ],
        inspect_http1_delegation(delegated_gleam, dead_state),
    )
    dead_down = delegated_ffi.replace(
        "        {'DOWN', HandlerMonitor, process, Handler, _} ->\n"
        "            http1_handler_guardian_down(State)\n"
        "    end.",
        "        {'DOWN', HandlerMonitor, process, Handler, _} -> ok\n"
        "    end,\n"
        "    _DeadDown = fun() -> http1_handler_guardian_down(State) end.",
        1,
    )
    record(
        "dead_down_scope",
        ["handler_down_to_terminal_flow_unproven"],
        inspect_http1_delegation(delegated_gleam, dead_down),
    )
    record(
        "wrong_external_module",
        ["delegated_atomic_binding_mismatch"],
        inspect_http1_delegation(
            delegated_gleam.replace('"http_server_ffi"', '"other_module"', 1),
            delegated_ffi,
        ),
    )
    record(
        "wrong_external_function",
        ["delegated_atomic_binding_mismatch"],
        inspect_http1_delegation(
            delegated_gleam.replace(
                '"start_http1_handler_guardian"', '"other_start"', 1
            ),
            delegated_ffi,
        ),
    )
    unused = delegated_gleam.replace(
        "let started = start_http1_handler_guardian(1, 2, 3, 4, 5, 6, 7, 8, 9, 10)",
        "start_http1_handler_guardian(1, 2, 3, 4, 5, 6, 7, 8, 9, 10)\n"
        "  let started = Error(Nil)",
        1,
    )
    record(
        "unused_exact_call",
        [
            "delegated_atomic_call_flow_unproven",
            "delegated_atomic_call_unused_or_ambiguous",
        ],
        inspect_http1_delegation(unused, delegated_ffi),
    )
    different_ok = delegated_gleam.replace(
        "Ok(#(guardian_monitor, guardian_commands)) ->\n"
        "      await_handler(a, b, c, guardian_commands, e, guardian_monitor, g, h, i)",
        "Ok(#(different_monitor, different_commands)) ->\n"
        "      await_handler(a, b, c, guardian_commands, e, guardian_monitor, g, h, i)",
        1,
    )
    record(
        "different_ok_binding",
        ["delegated_atomic_call_flow_unproven"],
        inspect_http1_delegation(different_ok, delegated_ffi),
    )
    await_other_branch = delegated_gleam.replace(
        "Ok(#(guardian_monitor, guardian_commands)) ->\n"
        "      await_handler(a, b, c, guardian_commands, e, guardian_monitor, g, h, i)\n"
        "    Error(_) -> Nil",
        "Ok(#(guardian_monitor, guardian_commands)) -> Nil\n"
        "    Error(_) ->\n"
        "      await_handler(a, b, c, guardian_commands, e, guardian_monitor, g, h, i)",
        1,
    )
    record(
        "await_in_different_case_branch",
        ["delegated_atomic_call_flow_unproven"],
        inspect_http1_delegation(await_other_branch, delegated_ffi),
    )
    different_spawn = delegated_ffi.replace(
        "{Guardian, GuardianMonitor} = erlang:spawn_monitor(fun() ->\n"
        "        http1_handler_guardian_boot(Owner, B, C, D, E, F, G, H, I, J)\n"
        "    end),",
        "{Decoy, DecoyMonitor} = erlang:spawn_monitor(fun() -> ok end),\n"
        "    Guardian = erlang:spawn(fun() ->\n"
        "        http1_handler_guardian_boot(Owner, B, C, D, E, F, G, H, I, J)\n"
        "    end),\n"
        "    GuardianMonitor = erlang:monitor(process, Guardian),\n"
        "    _ = {Decoy, DecoyMonitor},",
        1,
    )
    record(
        "different_guardian_spawn",
        ["guardian_boot_not_in_spawn_closure", "guardian_monitor_provenance_missing"],
        inspect_http1_delegation(delegated_gleam, different_spawn),
    )
    boot_outside = delegated_ffi.replace(
        "{Guardian, GuardianMonitor} = erlang:spawn_monitor(fun() ->\n"
        "        http1_handler_guardian_boot(Owner, B, C, D, E, F, G, H, I, J)\n"
        "    end),",
        "{Guardian, GuardianMonitor} = erlang:spawn_monitor(fun() -> ok end),\n"
        "    http1_handler_guardian_boot(Owner, B, C, D, E, F, G, H, I, J),",
        1,
    )
    record(
        "boot_outside_guardian_closure",
        ["guardian_boot_not_in_spawn_closure", "guardian_monitor_provenance_missing"],
        inspect_http1_delegation(delegated_gleam, boot_outside),
    )
    unrelated_spawn_opt = delegated_ffi.replace(
        "{Handler, HandlerMonitor} = erlang:spawn_opt(fun() ->\n"
        "        http1_handler_guardian_handler_entry(B, C, D)\n"
        "    end, [link, monitor]),",
        "_ = erlang:spawn_opt(fun() -> ok end, [link, monitor]),\n"
        "    Handler = erlang:spawn_link(fun() ->\n"
        "        http1_handler_guardian_handler_entry(B, C, D)\n"
        "    end),\n"
        "    HandlerMonitor = erlang:monitor(process, Handler),",
        1,
    )
    record(
        "unrelated_handler_spawn_opt",
        [
            "handler_down_to_terminal_flow_unproven",
            "handler_spawn_not_atomic",
            "handler_state_top_level_unproven",
        ],
        inspect_http1_delegation(delegated_gleam, unrelated_spawn_opt),
    )
    old_non_atomic = delegated_gleam.replace(
        "let started = start_http1_handler_guardian(1, 2, 3, 4, 5, 6, 7, 8, 9, 10)",
        "let pid = process.spawn_unlinked(fn() { work() })\n"
        "  let monitor = process.monitor(pid)\n"
        "  let started = Error(Nil)",
        1,
    )
    record(
        "old_non_atomic",
        [
            "delegated_atomic_call_flow_unproven",
            "delegated_atomic_call_unused_or_ambiguous",
            "separate_spawn_or_monitor_present",
        ],
        inspect_http1_delegation(old_non_atomic, delegated_ffi),
    )
    different_return = delegated_ffi.replace(
        "{ok, {GuardianMonitor, Commands}}",
        "{ok, {DifferentMonitor, Commands}}",
        1,
    )
    record(
        "different_monitor_return",
        ["guardian_monitor_return_unproven"],
        inspect_http1_delegation(delegated_gleam, different_return),
    )
    owner_not_forwarded = delegated_ffi.replace(
        "Owner, OwnerMonitor, B, C, D, E, F, G, H, I, J",
        "Owner, DifferentOwnerMonitor, B, C, D, E, F, G, H, I, J",
        1,
    )
    record(
        "owner_monitor_not_forwarded",
        [
            "guardian_owner_chain_unproven",
            "guardian_owner_monitor_lifetime_unproven",
        ],
        inspect_http1_delegation(delegated_gleam, owner_not_forwarded),
    )
    handler_monitor_not_stored = delegated_ffi.replace(
        "handler_monitor => HandlerMonitor",
        "handler_monitor => DifferentHandlerMonitor",
        1,
    )
    record(
        "handler_monitor_not_stored",
        [
            "handler_down_to_terminal_flow_unproven",
            "handler_spawn_not_atomic",
            "handler_state_top_level_unproven",
        ],
        inspect_http1_delegation(delegated_gleam, handler_monitor_not_stored),
    )
    handler_down_other_monitor = delegated_ffi.replace(
        "{'DOWN', HandlerMonitor, process, Handler, _}",
        "{'DOWN', DifferentHandlerMonitor, process, Handler, _}",
        1,
    )
    record(
        "handler_down_uses_other_monitor",
        ["handler_down_to_terminal_flow_unproven"],
        inspect_http1_delegation(delegated_gleam, handler_down_other_monitor),
    )
    down_call_other_clause = delegated_ffi.replace(
        "{'DOWN', HandlerMonitor, process, Handler, _} ->\n"
        "            http1_handler_guardian_down(State)",
        "{'DOWN', HandlerMonitor, process, Handler, _} -> ok;\n"
        "        {'EXIT', Handler, _} ->\n"
        "            http1_handler_guardian_down(State)",
        1,
    )
    record(
        "down_call_in_different_clause",
        [
            "handler_down_reachability_unproven",
            "handler_down_to_terminal_flow_unproven",
        ],
        inspect_http1_delegation(delegated_gleam, down_call_other_clause),
    )
    return_decoy = delegated_ffi.replace(
        "            {ok, {GuardianMonitor, Commands}}",
        "            _ValidDecoy = {ok, {GuardianMonitor, Commands}},\n"
        "            {ok, {DifferentMonitor, Commands}}",
        1,
    )
    record(
        "guardian_return_after_valid_decoy",
        ["guardian_monitor_return_unproven"],
        inspect_http1_delegation(delegated_gleam, return_decoy),
    )
    owner_demonitor = delegated_ffi.replace(
        "    http1_handler_guardian_start_handler(\n"
        "        Owner, OwnerMonitor, B, C, D, E, F, G, H, I, J\n"
        "    ).",
        "    erlang:demonitor(OwnerMonitor, [flush]),\n"
        "    http1_handler_guardian_start_handler(\n"
        "        Owner, OwnerMonitor, B, C, D, E, F, G, H, I, J\n"
        "    ).",
        1,
    )
    record(
        "owner_demonitor_before_handler",
        ["guardian_owner_monitor_lifetime_unproven"],
        inspect_http1_delegation(delegated_gleam, owner_demonitor),
    )
    owner_demonitor_before_publication = delegated_ffi.replace(
        "            http1_handler_guardian_publish_result(Events, Result),",
        "            erlang:demonitor("
        "maps:get(owner_monitor, State), [flush]),\n"
        "            http1_handler_guardian_publish_result(Events, Result),",
        1,
    )
    record(
        "owner_demonitor_before_publication",
        [
            "guardian_owner_monitor_lifetime_unproven",
            "handler_down_to_terminal_flow_unproven",
            "handler_publication_reachability_unproven",
        ],
        inspect_http1_delegation(
            delegated_gleam, owner_demonitor_before_publication
        ),
    )
    nested_state = delegated_ffi.replace(
        "        handler => Handler,\n"
        "        handler_monitor => HandlerMonitor,",
        "        handler_pair => #{\n"
        "            handler => Handler,\n"
        "            handler_monitor => HandlerMonitor\n"
        "        },",
        1,
    )
    record(
        "nested_handler_state",
        [
            "handler_down_to_terminal_flow_unproven",
            "handler_spawn_not_atomic",
            "handler_state_top_level_unproven",
        ],
        inspect_http1_delegation(delegated_gleam, nested_state),
    )
    exact_down = "            http1_handler_guardian_down(State)"
    for control_name, terminal in (
        ("exit_before_handler_down", "exit(handler_down_decoy),\n"),
        ("throw_before_handler_down", "throw(handler_down_decoy),\n"),
        ("return_before_handler_down", "return(handler_down_decoy),\n"),
    ):
        unreachable_down = delegated_ffi.replace(
            exact_down,
            "            " + terminal + exact_down,
            1,
        )
        record(
            control_name,
            [
                "handler_down_reachability_unproven",
                "handler_down_to_terminal_flow_unproven",
            ],
            inspect_http1_delegation(delegated_gleam, unreachable_down),
        )
    publication_decoy = delegated_ffi.replace(
        "            http1_handler_guardian_publish_result(Events, Result),",
        "            case false of\n"
        "                true -> http1_handler_guardian_publish_result(Events, Result);\n"
        "                false -> ok\n"
        "            end,",
        1,
    )
    record(
        "publication_in_unreachable_branch",
        [
            "handler_down_to_terminal_flow_unproven",
            "handler_publication_reachability_unproven",
        ],
        inspect_http1_delegation(delegated_gleam, publication_decoy),
    )
    lexical_decoys = """
// @external(erlang, "http_server_ffi", "start_http1_handler_guardian")
const decoy = "@external(erlang, http_server_ffi, start_http1_handler_guardian)"
fn start_http1_handler_guardian(a: Int) { a }
"""
    record(
        "lexical_decoys",
        [],
        ["binding_present"] if external_bindings(lexical_decoys, HTTP1_LOCAL_START) else [],
    )
    record(
        "source_drift_rejected",
        ["source_changed_during_scan"],
        stability_findings(
            {"source": "before"}, {"source": "after"}, 1, 1,
            "aggregate", "aggregate", "scanner", "scanner"
        ),
    )
    record(
        "scanner_drift_rejected",
        ["scanner_changed_during_scan"],
        stability_findings(
            {"source": "same"}, {"source": "same"}, 1, 1,
            "aggregate", "aggregate", "before", "after"
        ),
    )
    atomic_observed: list[str] = []
    try:
        with tempfile.TemporaryDirectory(prefix="spawn-monitor-self-test-") as directory:
            destination = Path(directory) / "report.json"
            expected_payload = b'{"classification":"passed","schema":2}\n'
            atomic_publish(destination, expected_payload)
            observed_payload, _observed_digest = safe_read_bytes(
                destination, 1024 * 1024
            )
            if observed_payload != expected_payload:
                atomic_observed.append("atomic_report_readback_failed")
    except (OSError, ValueError):
        atomic_observed.append("atomic_report_readback_failed")
    record("atomic_report_readback", [], atomic_observed)

    _scanner_post_bytes, scanner_post = safe_read_bytes(
        scanner_path, MAX_SOURCE_BYTES
    )
    scanner_stable = scanner_pre == scanner_post
    controls_green = all(control["passed"] is True for control in controls)
    runtime = runtime_identity()
    runtime_valid = (
        runtime.get("implementation") == "cpython"
        and runtime.get("version") == EXPECTED_PYTHON_VERSION
    )
    status = (
        "Ready" if controls_green and scanner_stable and runtime_valid
        else "Failed"
    )
    failed_names = [
        str(control["name"])
        for control in controls
        if control["passed"] is not True
    ]
    report: dict[str, object] = {
        "schema": 2,
        "kind": "self_test",
        "status": status,
        "classification": (
            "passed"
            if status == "Ready"
            else (
                failed_names[0]
                if failed_names
                else (
                    "scanner_changed_during_scan"
                    if not scanner_stable else "runtime_version_mismatch"
                )
            )
        ),
        "completed_controls": len(controls),
        "controls": controls,
        "scanner_sha256_pre": scanner_pre,
        "scanner_sha256_post": scanner_post,
        "scanner_stable": scanner_stable,
        "runtime": runtime,
        "limits": {
            "source_file_bytes": MAX_SOURCE_BYTES,
            "tool_bytes": MAX_TOOL_BYTES,
            "tokens": MAX_TOKENS,
            "report_bytes": 1024 * 1024,
        },
        "rerun_command": (
            "mise exec python@3.12.13 -- python -I -B "
            "scripts/spawn_monitor_contract_audit.py --self-test"
        ),
    }
    return (0 if status == "Ready" else 1), report


def atomic_publish(path: Path, payload: bytes) -> None:
    if len(payload) <= 0 or len(payload) > 1024 * 1024:
        raise ValueError("report_limit_exceeded")
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
        existing = os.lstat(destination)
        if stat.S_ISLNK(existing.st_mode) or (
            reparse_flag
            and getattr(existing, "st_file_attributes", 0) & reparse_flag
        ):
            raise ValueError("report_identity_rejected")
    temporary_name = ""
    try:
        with tempfile.NamedTemporaryFile(
            mode="wb", prefix=".spawn-monitor-report-", suffix=".tmp",
            dir=destination.parent, delete=False
        ) as temporary:
            temporary_name = temporary.name
            temporary.write(payload)
            temporary.flush()
            os.fsync(temporary.fileno())
        os.replace(temporary_name, destination)
        temporary_name = ""
        written, _digest = safe_read_bytes(destination, 1024 * 1024)
        if written != payload:
            raise ValueError("report_readback_mismatch")
    finally:
        if temporary_name:
            try:
                os.unlink(temporary_name)
            except FileNotFoundError:
                pass


def emit_report(report: dict[str, object], report_path: str | None) -> None:
    payload = json.dumps(
        report, sort_keys=True, separators=(",", ":"), ensure_ascii=True
    ).encode("utf-8") + b"\n"
    if report_path is not None:
        atomic_publish(Path(report_path), payload)
    sys.stdout.buffer.write(payload)
    sys.stdout.buffer.flush()


def main() -> int:
    parser = argparse.ArgumentParser(add_help=True)
    parser.add_argument("--self-test", action="store_true")
    parser.add_argument("--report")
    arguments = parser.parse_args()
    try:
        if arguments.self_test:
            status, report = self_test_report()
        else:
            status, report = audit()
        emit_report(report, arguments.report)
        return status
    except (AssertionError, OSError, UnicodeError, ValueError):
        failure_report: dict[str, object] = {
            "schema": 2,
            "kind": "self_test" if arguments.self_test else "audit",
            "status": "Failed",
            "classification": "validation_failed",
            "rerun_command": (
                "mise exec python@3.12.13 -- python -I -B "
                "scripts/spawn_monitor_contract_audit.py"
                + (" --self-test" if arguments.self_test else "")
            ),
        }
        try:
            scanner_hash = bounded_sha256(
                Path(os.path.abspath(__file__)), MAX_SOURCE_BYTES
            )
            failure_report.update(
                {
                    "scanner_sha256_pre": scanner_hash,
                    "scanner_sha256_post": scanner_hash,
                    "scanner_stable": True,
                    "runtime": runtime_identity(),
                }
            )
        except (OSError, ValueError):
            pass
        emit_report(failure_report, None)
        return 2


def cli_main() -> int:
    try:
        return main()
    except (KeyboardInterrupt, SystemExit, GeneratorExit):
        raise
    except BaseException:
        failure = {
            "schema": 2,
            "kind": "cli",
            "status": "Failed",
            "classification": "internal_rejected",
            "rerun_command": (
                "mise exec python@3.12.13 -- python -I -B "
                "scripts/spawn_monitor_contract_audit.py"
            ),
        }
        try:
            emit_report(failure, None)
        except BaseException:
            pass
        return 2


if __name__ == "__main__":
    raise SystemExit(cli_main())

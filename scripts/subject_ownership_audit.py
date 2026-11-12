#!/usr/bin/env python3

# SPDX-FileCopyrightText: 2026 the http contributors
# SPDX-License-Identifier: MIT OR Apache-2.0

"""Reject receiving a Gleam Subject from a different process scope.

`gleam/erlang/process.Subject` is tied to the mailbox of the process which
creates it. Passing it to another process for sending is valid. Receiving or
selecting it there silently waits on the wrong mailbox and can turn a test
fixture defect into a transport timeout. This bounded source audit covers
direct asynchronous entry points and exact callback contracts whose closures
are stored before a child executes them. Unknown callback ownership fails
closed instead of being silently treated as the caller's process.
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
from typing import Iterable


ROOT = Path(__file__).resolve().parent.parent
SOURCE_ROOTS = (
    ROOT / "src",
    ROOT / "test",
    ROOT / "packages" / "http3" / "src",
    ROOT / "packages" / "http3" / "test",
    ROOT / "packages" / "quic_core" / "src",
    ROOT / "packages" / "quic_core" / "test",
)
MAX_FILE_BYTES = 4 * 1024 * 1024
MAX_TOTAL_BYTES = 64 * 1024 * 1024
MAX_FINDINGS = 256
MAX_TOOL_BYTES = 64 * 1024 * 1024
MAX_TOKENS_PER_FILE = 500_000
MAX_LINES_PER_FILE = 200_000
MAX_REGIONS_PER_FILE = 50_000
MAX_BINDINGS_PER_FILE = 100_000
MAX_CALLBACK_CALLS_PER_FILE = 10_000
MAX_CALLBACK_ARGUMENT_BYTES = 256 * 1024
MAX_ALIAS_DEPTH = 32
MAX_REPORT_BYTES = 256 * 1024
MAX_SOURCE_FILES = 20_000
MAX_INVENTORY_ENTRIES = 100_000
MAX_PATH_BYTES = 1024

FUNCTION = re.compile(r"(?m)^\s*(?:pub\s+)?fn\s+[a-z][A-Za-z0-9_]*\s*\(")
FUNCTION_DEFINITION = re.compile(
    r"(?m)^\s*(?:pub\s+)?fn\s+([a-z][A-Za-z0-9_]*)\s*\("
)
ASYNC = re.compile(
    r"\b(?:process\.(?:spawn|spawn_unlinked)|"
    r"(?:[a-z][A-Za-z0-9_]*\.)?start_task)\s*\(\s*fn\b[^{}]{0,1024}\{",
    re.MULTILINE,
)
NAMED_CLOSURE = re.compile(
    r"\blet\s+([a-z][A-Za-z0-9_]*)\s*=\s*fn\b[^{}]{0,1024}\{",
    re.MULTILINE,
)
IMPORT = re.compile(
    r"(?m)^\s*import\s+([a-z][A-Za-z0-9_/]*)"
    r"(?:\s+as\s+([a-z][A-Za-z0-9_]*))?"
)
CALLBACK_CALL = re.compile(
    r"\b(?:(?P<qualifier>[a-z][A-Za-z0-9_]*)\s*\.\s*)?"
    r"(?P<function>with_accept_probe)\s*\("
)
CALLBACK_REFERENCE = re.compile(
    r"\blet\s+[a-z][A-Za-z0-9_]*\s*=\s*"
    r"(?:(?:[a-z][A-Za-z0-9_]*)\s*\.\s*)?with_accept_probe\b"
    r"(?!\s*\()"
)
SIMPLE_NAME = re.compile(r"^[a-z][A-Za-z0-9_]*$")
TOKEN = re.compile(r"[A-Za-z_][A-Za-z0-9_]*|\d+|\|>|==|!=|<=|>=|->|[^\s]")
ASYNC_REFERENCE = re.compile(
    r"\b(?:process\.(?:spawn|spawn_unlinked)|"
    r"(?:[a-z][A-Za-z0-9_]*\.)?start_task)\s*\(\s*"
    r"([a-z][A-Za-z0-9_]*)\s*[,)]",
    re.MULTILINE,
)
CHILD_LAUNCH = re.compile(
    r"\b(?:[a-z][A-Za-z0-9_]*\.)?"
    r"(?:spawn_monitor|spawn_link_monitor)\s*\(\s*fn\b[^{}]{0,1024}\{",
    re.MULTILINE,
)
BINDING = re.compile(
    r"\blet\s+([a-z][A-Za-z0-9_]*)\s*=\s*"
    r"(process\.new_subject\s*\(\s*\)|[a-z][A-Za-z0-9_]*)"
)
RECEIVE = re.compile(
    r"\bprocess\.(?:receive|receive_forever)\s*\(\s*([a-z][A-Za-z0-9_]*)"
)
SELECT = re.compile(
    r"\bprocess\.select(?:_map)?\s*\(\s*([a-z][A-Za-z0-9_]*)"
)
RECEIVE_ANY = re.compile(r"\bprocess\.(?:receive|receive_forever)\s*\(")
SELECT_ANY = re.compile(r"\bprocess\.select(?:_map)?\s*\(")
SIMPLE_ALIAS = re.compile(
    r"\blet\s+([a-z][A-Za-z0-9_]*)\s*=\s*"
    r"([a-z][A-Za-z0-9_]*)\b(?!\s*[.(])"
)


@dataclass(frozen=True)
class Region:
    start: int
    end: int


@dataclass(frozen=True)
class Finding:
    path: str
    line: int
    rule: str


@dataclass(frozen=True)
class CallbackContract:
    module: str
    function: str
    callback_from_end: int
    stored_field: str
    executor_function: str
    executor_access: str


@dataclass(frozen=True)
class FileIdentity:
    device: int
    inode: int
    size: int
    modified_ns: int


# Config.accept_request is populated by this exact function and invoked inside start_accept's atomic acceptor child.
CALLBACK_CONTRACTS = (
    CallbackContract(
        module="http/internal/http3/server",
        function="with_accept_probe",
        callback_from_end=0,
        stored_field="accept_request",
        executor_function="start_accept",
        executor_access="runtime.config.accept_request",
    ),
)


def sanitise(source: str) -> str:
    """Remove strings and line comments while retaining offsets/newlines."""
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
        else:
            if current == "\n":
                state = "code"
            else:
                output[index] = " "
        index += 1
    return "".join(output)


def matching_brace(source: str, opening: int) -> int | None:
    depth = 0
    for index in range(opening, len(source)):
        if source[index] == "{":
            depth += 1
        elif source[index] == "}":
            depth -= 1
            if depth == 0:
                return index + 1
    return None


def regions(source: str, pattern: re.Pattern[str]) -> list[Region]:
    found: list[Region] = []
    for match in pattern.finditer(source):
        opening = source.rfind("{", match.start(), match.end())
        if opening < 0:
            opening = source.find("{", match.end(), min(len(source), match.end() + 4096))
        if opening < 0:
            continue
        end = matching_brace(source, opening)
        if end is not None:
            found.append(Region(opening, end))
    return found


def containing(position: int, candidates: Iterable[Region]) -> Region | None:
    matches = [item for item in candidates if item.start < position < item.end]
    return min(matches, key=lambda item: item.end - item.start, default=None)


def named_async_regions(source: str, functions: list[Region]) -> list[Region]:
    """Resolve a locally bound closure passed directly to an async launcher."""
    closures: dict[str, list[tuple[int, Region]]] = {}
    for match in NAMED_CLOSURE.finditer(source):
        opening = source.rfind("{", match.start(), match.end())
        end = matching_brace(source, opening) if opening >= 0 else None
        if end is not None:
            closures.setdefault(match.group(1), []).append(
                (match.start(), Region(opening, end))
            )

    asynchronous: list[Region] = []
    for launch in ASYNC_REFERENCE.finditer(source):
        launch_function = containing(launch.start(), functions)
        candidates = [
            item
            for item in closures.get(launch.group(1), [])
            if item[0] < launch.start()
            and containing(item[0], functions) == launch_function
        ]
        if candidates:
            asynchronous.append(max(candidates, key=lambda item: item[0])[1])
    return asynchronous


def import_aliases(source: str) -> dict[str, str]:
    aliases: dict[str, str] = {}
    for match in IMPORT.finditer(source):
        module = match.group(1)
        alias = match.group(2) or module.rsplit("/", 1)[-1]
        if alias in aliases:
            raise ValueError("import_alias_collision")
        aliases[alias] = module
    return aliases


def matching_parenthesis(source: str, opening: int) -> int | None:
    parentheses = 0
    braces = 0
    brackets = 0
    for index in range(opening, len(source)):
        current = source[index]
        if current == "(" and braces >= 0 and brackets >= 0:
            parentheses += 1
        elif current == ")" and braces >= 0 and brackets >= 0:
            parentheses -= 1
            if parentheses == 0:
                return index
            if parentheses < 0:
                return None
        elif current == "{":
            braces += 1
        elif current == "}":
            braces -= 1
            if braces < 0:
                return None
        elif current == "[":
            brackets += 1
        elif current == "]":
            brackets -= 1
            if brackets < 0:
                return None
    return None


def argument_regions(source: str, opening: int, closing: int) -> list[Region]:
    """Split one call without accepting unbounded or malformed arguments."""
    if closing - opening > MAX_CALLBACK_ARGUMENT_BYTES:
        raise ValueError("callback_argument_limit_exceeded")
    arguments: list[Region] = []
    start = opening + 1
    parentheses = 0
    braces = 0
    brackets = 0
    for index in range(start, closing):
        current = source[index]
        if current == "(":
            parentheses += 1
        elif current == ")":
            parentheses -= 1
        elif current == "{":
            braces += 1
        elif current == "}":
            braces -= 1
        elif current == "[":
            brackets += 1
        elif current == "]":
            brackets -= 1
        elif current == "," and parentheses == braces == brackets == 0:
            arguments.append(Region(start, index))
            start = index + 1
        if min(parentheses, braces, brackets) < 0:
            raise ValueError("callback_argument_unbalanced")
    if parentheses != 0 or braces != 0 or brackets != 0:
        raise ValueError("callback_argument_unbalanced")
    if source[start:closing].strip():
        arguments.append(Region(start, closing))
    return arguments


def named_closures(source: str) -> dict[str, list[tuple[int, Region]]]:
    closures: dict[str, list[tuple[int, Region]]] = {}
    for match in NAMED_CLOSURE.finditer(source):
        opening = source.rfind("{", match.start(), match.end())
        end = matching_brace(source, opening) if opening >= 0 else None
        if end is not None:
            closures.setdefault(match.group(1), []).append(
                (match.start(), Region(opening, end))
            )
    return closures


def named_functions(source: str) -> dict[str, list[tuple[int, Region]]]:
    definitions: dict[str, list[tuple[int, Region]]] = {}
    for match in FUNCTION_DEFINITION.finditer(source):
        opening = source.find("{", match.end(), min(len(source), match.end() + 4096))
        end = matching_brace(source, opening) if opening >= 0 else None
        if end is not None:
            definitions.setdefault(match.group(1), []).append(
                (match.start(), Region(opening, end))
            )
    return definitions


def closure_reference(
    name: str,
    before: int,
    function: Region | None,
    closures: dict[str, list[tuple[int, Region]]],
    functions_by_name: dict[str, list[tuple[int, Region]]],
    aliases: dict[str, list[tuple[int, str]]],
    seen: frozenset[tuple[str, int]] = frozenset(),
) -> Region | None:
    candidates = [
        item
        for item in closures.get(name, [])
        if item[0] < before
        and (function is None or containing(item[0], [function]) == function)
    ]
    if candidates:
        return max(candidates, key=lambda item: item[0])[1]
    alias_candidates = [
        item
        for item in aliases.get(name, [])
        if item[0] < before
        and (function is None or containing(item[0], [function]) == function)
    ]
    if alias_candidates:
        position, target = max(alias_candidates, key=lambda item: item[0])
        marker = (name, position)
        if marker in seen or len(seen) >= MAX_ALIAS_DEPTH:
            return None
        return closure_reference(
            target,
            position,
            function,
            closures,
            functions_by_name,
            aliases,
            seen | frozenset((marker,)),
        )
    definitions = functions_by_name.get(name, [])
    if len(definitions) == 1:
        return definitions[0][1]
    return None


def callback_argument_region(
    source: str,
    argument: Region,
    call_position: int,
    call_function: Region | None,
    closures: dict[str, list[tuple[int, Region]]],
    functions_by_name: dict[str, list[tuple[int, Region]]],
    aliases: dict[str, list[tuple[int, str]]],
) -> Region | None:
    text = source[argument.start : argument.end]
    leading = len(text) - len(text.lstrip())
    start = argument.start + leading
    stripped = text.strip()
    if stripped.startswith("fn"):
        opening = source.find("{", start, argument.end)
        end = matching_brace(source, opening) if opening >= 0 else None
        if end is not None and end <= argument.end:
            return Region(opening, end)
        return None
    if SIMPLE_NAME.fullmatch(stripped):
        return closure_reference(
            stripped,
            call_position,
            call_function,
            closures,
            functions_by_name,
            aliases,
        )
    return None


def callback_execution_regions(
    path: str,
    source: str,
    functions: list[Region],
) -> tuple[dict[Region, str], list[Finding]]:
    """Resolve exact child callback contracts and fail closed on ambiguity."""
    imports = import_aliases(source)
    closures = named_closures(source)
    functions_by_name = named_functions(source)
    aliases: dict[str, list[tuple[int, str]]] = {}
    for match in SIMPLE_ALIAS.finditer(source):
        aliases.setdefault(match.group(1), []).append(
            (match.start(), match.group(2))
        )

    owners: dict[Region, str] = {}
    findings = [
        Finding(
            path,
            line_number(source, reference.start()),
            "execution_owner_unproven",
        )
        for reference in CALLBACK_REFERENCE.finditer(source)
    ]
    calls = 0
    for call in CALLBACK_CALL.finditer(source):
        prefix = source[max(0, call.start() - 16) : call.start()]
        if re.search(r"\bfn\s*$", prefix):
            continue
        calls += 1
        if calls > MAX_CALLBACK_CALLS_PER_FILE:
            raise ValueError("callback_call_limit_exceeded")
        opening = source.rfind("(", call.start(), call.end())
        closing = matching_parenthesis(source, opening) if opening >= 0 else None
        if closing is None:
            raise ValueError("callback_call_unbalanced")
        arguments = argument_regions(source, opening, closing)
        qualifier = call.group("qualifier")
        module = imports.get(qualifier) if qualifier is not None else None
        contract = next(
            (
                item
                for item in CALLBACK_CONTRACTS
                if item.module == module and item.function == call.group("function")
            ),
            None,
        )
        callback_from_end = contract.callback_from_end if contract else 0
        argument_index = len(arguments) - callback_from_end - 1
        if argument_index < 0:
            findings.append(
                Finding(
                    path,
                    line_number(source, call.start()),
                    "execution_owner_unproven",
                )
            )
            continue
        region = callback_argument_region(
            source,
            arguments[argument_index],
            call.start(),
            containing(call.start(), functions),
            closures,
            functions_by_name,
            aliases,
        )
        if region is None:
            findings.append(
                Finding(
                    path,
                    line_number(source, call.start()),
                    "execution_owner_unproven",
                )
            )
        elif contract is not None:
            owners[region] = "child"
        elif any(
            pattern.search(source, region.start, region.end)
            for pattern in (RECEIVE_ANY, SELECT_ANY)
        ):
            owners[region] = "unproven"
    return owners, findings


def subject_origin(
    name: str,
    before: int,
    function: Region,
    bindings: dict[str, list[tuple[int, str]]],
    seen: frozenset[tuple[str, int]] = frozenset(),
) -> int | None:
    """Resolve direct Subject construction and simple aliases at a use site."""
    candidates = [
        item
        for item in bindings.get(name, [])
        if item[0] < before and function.start < item[0] < function.end
    ]
    if not candidates:
        return None
    position, expression = max(candidates, key=lambda item: item[0])
    marker = (name, position)
    if marker in seen or len(seen) >= MAX_ALIAS_DEPTH:
        return None
    if expression.startswith("process.new_subject"):
        return position
    return subject_origin(
        expression,
        position,
        function,
        bindings,
        seen | frozenset((marker,)),
    )


def line_number(source: str, position: int) -> int:
    return source.count("\n", 0, position) + 1


def inspect_text(path: str, source: str) -> list[Finding]:
    clean = sanitise(source)
    if clean.count("\n") + 1 > MAX_LINES_PER_FILE:
        raise ValueError("source_line_limit_exceeded")
    if sum(1 for _ in TOKEN.finditer(clean)) > MAX_TOKENS_PER_FILE:
        raise ValueError("source_token_limit_exceeded")
    functions = regions(clean, FUNCTION)
    direct_async = regions(clean, ASYNC) + named_async_regions(clean, functions)
    callback_owners, callback_findings = callback_execution_regions(
        path, clean, functions
    )
    asynchronous = list(dict.fromkeys([*direct_async, *callback_owners]))
    if len(functions) + len(asynchronous) > MAX_REGIONS_PER_FILE:
        raise ValueError("source_region_limit_exceeded")
    bindings: dict[str, list[tuple[int, str]]] = {}
    binding_count = 0
    for match in BINDING.finditer(clean):
        binding_count += 1
        if binding_count > MAX_BINDINGS_PER_FILE:
            raise ValueError("source_binding_limit_exceeded")
        bindings.setdefault(match.group(1), []).append(
            (match.start(), match.group(2))
        )

    findings: list[Finding] = list(callback_findings)
    simple_uses: set[int] = set()
    for rule, pattern in (
        ("foreign_subject_receive", RECEIVE),
        ("foreign_subject_select", SELECT),
    ):
        for use in pattern.finditer(clean):
            simple_uses.add(use.start())
            name = use.group(1)
            use_function = containing(use.start(), functions)
            use_owner = containing(use.start(), asynchronous)
            if use_function is None or use_owner is None:
                continue
            if callback_owners.get(use_owner) == "unproven":
                findings.append(
                    Finding(
                        path,
                        line_number(clean, use.start()),
                        "execution_owner_unproven",
                    )
                )
                continue
            declaration = subject_origin(
                name, use.start(), use_function, bindings
            )
            if declaration is None:
                if use_owner in callback_owners:
                    findings.append(
                        Finding(
                            path,
                            line_number(clean, use.start()),
                            "execution_owner_unproven",
                        )
                    )
                continue
            declaration_owner = containing(declaration, asynchronous)
            if declaration_owner != use_owner:
                findings.append(
                    Finding(path, line_number(clean, use.start()), rule)
                )
    for pattern in (RECEIVE_ANY, SELECT_ANY):
        for use in pattern.finditer(clean):
            if use.start() in simple_uses:
                continue
            use_owner = containing(use.start(), asynchronous)
            if use_owner in callback_owners:
                findings.append(
                    Finding(
                        path,
                        line_number(clean, use.start()),
                        "execution_owner_unproven",
                    )
                )
    unique = sorted(
        set(findings), key=lambda item: (item.path, item.line, item.rule)
    )
    if len(unique) > MAX_FINDINGS:
        raise ValueError("finding_limit_exceeded")
    return unique


def callback_contract_findings(sources: dict[str, str]) -> list[Finding]:
    """Bind every trusted callback contract to its current executor source."""
    findings: list[Finding] = []
    for contract in CALLBACK_CONTRACTS:
        relative = f"src/{contract.module}.gleam"
        source = sources.get(relative)
        if source is None:
            findings.append(Finding(relative, 1, "execution_owner_unproven"))
            continue
        clean = sanitise(source)
        definitions = named_functions(clean)
        setters = definitions.get(contract.function, [])
        executors = definitions.get(contract.executor_function, [])
        if len(setters) != 1 or len(executors) != 1:
            findings.append(Finding(relative, 1, "execution_owner_unproven"))
            continue
        setter_position, setter = setters[0]
        setter_header = clean[setter_position : setter.start]
        setter_body = clean[setter.start : setter.end]
        stored = re.search(
            rf"\bConfig\s*\(.{{0,4096}}\b{re.escape(contract.stored_field)}"
            rf"\s*:\s*[,)]",
            setter_body,
            re.DOTALL,
        )
        parameter_is_bound = len(
            re.findall(
                rf"\b{re.escape(contract.stored_field)}\s*:", setter_header
            )
        ) == 1 and not re.search(
            rf"\blet\s+{re.escape(contract.stored_field)}\s*=", setter_body
        )
        executor_position, executor = executors[0]
        child_regions = [
            region
            for region in regions(clean, CHILD_LAUNCH)
            if containing(region.start + 1, [executor]) == executor
        ]
        field_use = re.compile(
            rf"\b{re.escape(contract.executor_access)}\s*\("
        )
        executed_in_child = any(
            containing(use.start(), child_regions) is not None
            for use in field_use.finditer(clean, executor.start, executor.end)
        )
        if stored is None or not parameter_is_bound or not executed_in_child:
            line = line_number(
                clean,
                setter_position
                if stored is None or not parameter_is_bound
                else executor_position,
            )
            findings.append(
                Finding(relative, line, "execution_owner_unproven")
            )
    return findings


def link_like(path: Path) -> bool:
    information = os.lstat(path)
    attributes = getattr(information, "st_file_attributes", 0)
    reparse = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0)
    junction = getattr(path, "is_junction", lambda: False)()
    return stat.S_ISLNK(information.st_mode) or bool(attributes & reparse) or junction


def file_identity(information: os.stat_result) -> FileIdentity:
    return FileIdentity(
        device=information.st_dev,
        inode=information.st_ino,
        size=information.st_size,
        modified_ns=information.st_mtime_ns,
    )


def stable_source_read(path: Path) -> tuple[bytes, FileIdentity]:
    if link_like(path):
        raise ValueError("source_reparse_point_rejected")
    with path.open("rb") as handle:
        before = os.fstat(handle.fileno())
        if not stat.S_ISREG(before.st_mode):
            raise ValueError("source_not_regular_file")
        if before.st_size > MAX_FILE_BYTES:
            raise ValueError("source_file_limit_exceeded")
        raw = handle.read(MAX_FILE_BYTES + 1)
        after = os.fstat(handle.fileno())
    if len(raw) > MAX_FILE_BYTES:
        raise ValueError("source_file_limit_exceeded")
    identity = file_identity(before)
    if identity != file_identity(after) or identity != file_identity(os.lstat(path)):
        raise ValueError("source_changed_during_read")
    return raw, identity


def identity_unchanged(path: Path, expected: FileIdentity) -> bool:
    try:
        return not link_like(path) and file_identity(os.lstat(path)) == expected
    except OSError:
        return False


def source_files() -> list[Path]:
    files: list[Path] = []
    entries = 0
    for source_root in SOURCE_ROOTS:
        if not source_root.exists():
            raise ValueError("source_root_missing")
        if not source_root.is_dir() or link_like(source_root):
            raise ValueError("source_root_rejected")
        for current, directories, names in os.walk(source_root, followlinks=False):
            current_path = Path(current)
            entries += len(directories) + len(names)
            if entries > MAX_INVENTORY_ENTRIES:
                raise ValueError("source_inventory_entry_limit_exceeded")
            if link_like(current_path):
                raise ValueError("source_reparse_point_rejected")
            current_relative = current_path.relative_to(ROOT).as_posix()
            if len(current_relative.encode("utf-8")) > MAX_PATH_BYTES:
                raise ValueError("source_path_limit_exceeded")
            for directory in directories:
                if link_like(current_path / directory):
                    raise ValueError("source_reparse_point_rejected")
            for name in names:
                if not name.endswith(".gleam"):
                    continue
                path = current_path / name
                if link_like(path):
                    raise ValueError("source_reparse_point_rejected")
                relative = path.relative_to(ROOT).as_posix()
                if len(relative.encode("utf-8")) > MAX_PATH_BYTES:
                    raise ValueError("source_path_limit_exceeded")
                files.append(path)
                if len(files) > MAX_SOURCE_FILES:
                    raise ValueError("source_file_count_limit_exceeded")
    ordered = sorted(files, key=lambda item: item.relative_to(ROOT).as_posix())
    normalised = [item.relative_to(ROOT).as_posix().casefold() for item in ordered]
    if len(normalised) != len(set(normalised)):
        raise ValueError("source_path_collision")
    return ordered


def bounded_file_sha256(path: Path, maximum: int) -> str:
    digest = hashlib.sha256()
    consumed = 0
    with path.open("rb") as handle:
        while chunk := handle.read(1024 * 1024):
            consumed += len(chunk)
            if consumed > maximum:
                raise ValueError("tool_file_limit_exceeded")
            digest.update(chunk)
    return digest.hexdigest()


def report_identity(expected_scanner_sha256: str) -> dict[str, object]:
    scanner_sha256 = bounded_file_sha256(Path(__file__), MAX_FILE_BYTES)
    if scanner_sha256 != expected_scanner_sha256:
        raise ValueError("scanner_changed_during_run")
    return {
        "scanner_sha256": scanner_sha256,
        "runtime": {
            "implementation": sys.implementation.name,
            "version": ".".join(str(part) for part in sys.version_info[:3]),
            "executable_sha256": bounded_file_sha256(
                Path(sys.executable), MAX_TOOL_BYTES
            ),
        },
        "scope": [path.relative_to(ROOT).as_posix() for path in SOURCE_ROOTS],
        "limits": {
            "file_bytes": MAX_FILE_BYTES,
            "total_bytes": MAX_TOTAL_BYTES,
            "findings": MAX_FINDINGS,
            "tokens_per_file": MAX_TOKENS_PER_FILE,
            "lines_per_file": MAX_LINES_PER_FILE,
            "regions_per_file": MAX_REGIONS_PER_FILE,
            "callback_calls_per_file": MAX_CALLBACK_CALLS_PER_FILE,
            "callback_argument_bytes": MAX_CALLBACK_ARGUMENT_BYTES,
            "alias_depth": MAX_ALIAS_DEPTH,
            "source_files": MAX_SOURCE_FILES,
            "inventory_entries": MAX_INVENTORY_ENTRIES,
            "report_bytes": MAX_REPORT_BYTES,
        },
        "rerun_command": "python -I -B scripts/subject_ownership_audit.py",
    }


def emit_report(report: dict[str, object]) -> None:
    encoded = json.dumps(report, sort_keys=True, separators=(",", ":"))
    if len(encoded.encode("utf-8")) > MAX_REPORT_BYTES:
        raise ValueError("report_limit_exceeded")
    print(encoded)


def audit() -> int:
    scanner_sha256 = bounded_file_sha256(Path(__file__), MAX_FILE_BYTES)
    digest = hashlib.sha256()
    findings: list[Finding] = []
    total = 0
    files = source_files()
    sources: dict[str, str] = {}
    identities: dict[Path, FileIdentity] = {}
    for path in files:
        relative = path.relative_to(ROOT).as_posix()
        raw, identity = stable_source_read(path)
        identities[path] = identity
        total += len(raw)
        if total > MAX_TOTAL_BYTES:
            raise ValueError("source_inventory_limit_exceeded")
        source = raw.decode("utf-8", errors="strict")
        sources[relative] = source
        digest.update(relative.encode("utf-8") + b"\0" + raw + b"\0")
        findings.extend(inspect_text(relative, source))
        if len(findings) > MAX_FINDINGS:
            raise ValueError("finding_limit_exceeded")
    findings.extend(callback_contract_findings(sources))
    findings = sorted(
        set(findings), key=lambda item: (item.path, item.line, item.rule)
    )
    if len(findings) > MAX_FINDINGS:
        raise ValueError("finding_limit_exceeded")
    if not all(identity_unchanged(path, identity) for path, identity in identities.items()):
        raise ValueError("source_changed_during_run")
    identity = report_identity(scanner_sha256)
    if findings:
        rules = {finding.rule for finding in findings}
        if rules == {"execution_owner_unproven"}:
            classification = "execution_owner_unproven"
        elif "execution_owner_unproven" in rules:
            classification = "subject_ownership_contract_failed"
        else:
            classification = "subject_owner_mismatch"
        report = {
            "schema": 1,
            "status": "Failed",
            "classification": classification,
            "completed_files": len(files),
            "source_bytes": total,
            "source_sha256": digest.hexdigest(),
            "findings": [finding.__dict__ for finding in findings],
            **identity,
        }
        emit_report(report)
        return 1
    report = {
        "schema": 1,
        "status": "Ready",
        "classification": "passed",
        "completed_files": len(files),
        "source_bytes": total,
        "source_sha256": digest.hexdigest(),
        "findings": [],
        **identity,
    }
    emit_report(report)
    return 0


def self_test() -> int:
    good = """
pub fn valid() {
  let outward = process.new_subject()
  process.spawn_unlinked(fn() {
    let local = process.new_subject()
    process.send(outward, local)
    process.receive(local, within: 10)
  })
}
"""
    shadowed = """
pub fn valid_shadow() {
  let gate = process.new_subject()
  process.spawn(fn() {
    let gate = process.new_subject()
    process.receive_forever(gate)
  })
  process.receive(gate, within: 10)
}
"""
    separate_functions = """
pub fn first() { let ready = process.new_subject() }
pub fn second() {
  process.spawn(fn() { process.receive(ready, within: 10) })
}
"""
    bad_receive = """
pub fn invalid_receive() {
  let gate = process.new_subject()
  process.spawn_unlinked(fn() { process.receive(gate, within: 10) })
}
"""
    bad_select = """
pub fn invalid_select() {
  let replies = process.new_subject()
  process.spawn(fn() {
    process.new_selector() |> process.select_map(replies, fn(value) { value })
  })
}
"""
    bad_task = """
pub fn invalid_task() {
  let decisions = process.new_subject()
  http_test_support.start_task(fn() {
    process.receive(decisions, within: 10)
  })
}
"""
    bad_named_task = """
pub fn invalid_named_task() {
  let decisions = process.new_subject()
  let wait = fn() { process.receive(decisions, within: 10) }
  http_test_support.start_task(wait)
}
"""
    bad_alias = """
pub fn invalid_alias() {
  let original = process.new_subject()
  let alias = original
  process.spawn(fn() { process.receive(alias, within: 10) })
}
"""
    unrelated_shadow = """
pub fn valid_unrelated_shadow() {
  let gate = process.new_subject()
  process.spawn(fn() {
    let gate = unrelated_value
    process.receive(gate, within: 10)
  })
}
"""
    bad_callback = """
import http/internal/http3/server as adapter
pub fn invalid_callback(config) {
  let decisions = process.new_subject()
  adapter.with_accept_probe(config, fn(_) {
    process.receive(decisions, within: 10)
  })
}
"""
    good_callback_handshake = """
import http/internal/http3/server as adapter
pub fn valid_callback(config) {
  let attempts = process.new_subject()
  adapter.with_accept_probe(config, fn(_) {
    let decision = process.new_subject()
    process.send(attempts, decision)
    process.receive(decision, within: 10)
  })
}
"""
    bad_named_callback = """
import http/internal/http3/server as adapter
pub fn invalid_named_callback(config) {
  let decisions = process.new_subject()
  let wait = fn(_) { process.receive(decisions, within: 10) }
  adapter.with_accept_probe(config, wait)
}
"""
    bad_aliased_callback = """
import http/internal/http3/server as adapter
pub fn invalid_aliased_callback(config) {
  let decisions = process.new_subject()
  let wait = fn(_) { process.receive(decisions, within: 10) }
  let installed = wait
  adapter.with_accept_probe(config, installed)
}
"""
    bad_pipeline_callback = """
import http/internal/http3/server as adapter
pub fn invalid_pipeline_callback(config) {
  let decisions = process.new_subject()
  config
  |> adapter.with_accept_probe(fn(_) {
    process.receive(decisions, within: 10)
  })
}
"""
    unresolved_callback = """
import http/internal/http3/server as adapter
pub fn unresolved(config) {
  adapter.with_accept_probe(config, imported_callback)
}
"""
    spoofed_callback = """
import unrelated/server as adapter
pub fn unresolved_owner(config) {
  let decisions = process.new_subject()
  adapter.with_accept_probe(config, fn(_) {
    process.receive(decisions, within: 10)
  })
}
"""
    safe_spoofed_sender = """
import unrelated/server as adapter
pub fn sender_only(config) {
  let outward = process.new_subject()
  adapter.with_accept_probe(config, fn(_) { process.send(outward, Nil) })
}
"""
    complex_receiver = """
import http/internal/http3/server as adapter
pub fn unresolved_receiver(config, state) {
  adapter.with_accept_probe(config, fn(_) {
    process.receive(state.decisions, within: 10)
  })
}
"""
    named_function_callback = """
import http/internal/http3/server as adapter
fn wait(decisions) { process.receive(decisions, within: 10) }
pub fn unresolved_parameter(config) {
  adapter.with_accept_probe(config, wait)
}
"""
    ignored_text = """
pub fn ignored(config) {
  let text = "adapter.with_accept_probe(config, fn(_) { process.receive(gate) })"
  // adapter.with_accept_probe(config, fn(_) { process.receive(gate) })
  text
}
"""
    cyclic_callback_alias = """
import http/internal/http3/server as adapter
pub fn cyclic(config) {
  let first = second
  let second = first
  adapter.with_accept_probe(config, first)
}
"""
    aliased_sink = """
import http/internal/http3/server as adapter
pub fn unresolved_sink(config) {
  let install = adapter.with_accept_probe
  install(config, fn(_) { Nil })
}
"""
    assert inspect_text("good.gleam", good) == []
    assert inspect_text("shadowed.gleam", shadowed) == []
    assert inspect_text("separate.gleam", separate_functions) == []
    receive_findings = inspect_text("receive.gleam", bad_receive)
    select_findings = inspect_text("select.gleam", bad_select)
    task_findings = inspect_text("task.gleam", bad_task)
    named_task_findings = inspect_text("named_task.gleam", bad_named_task)
    alias_findings = inspect_text("alias.gleam", bad_alias)
    callback_findings = inspect_text("callback.gleam", bad_callback)
    named_callback_findings = inspect_text(
        "named_callback.gleam", bad_named_callback
    )
    aliased_callback_findings = inspect_text(
        "aliased_callback.gleam", bad_aliased_callback
    )
    pipeline_callback_findings = inspect_text(
        "pipeline_callback.gleam", bad_pipeline_callback
    )
    unresolved_findings = inspect_text("unresolved.gleam", unresolved_callback)
    spoofed_findings = inspect_text("spoofed.gleam", spoofed_callback)
    complex_findings = inspect_text("complex.gleam", complex_receiver)
    named_function_findings = inspect_text(
        "named_function.gleam", named_function_callback
    )
    cyclic_findings = inspect_text("cyclic.gleam", cyclic_callback_alias)
    aliased_sink_findings = inspect_text("aliased_sink.gleam", aliased_sink)
    assert [item.rule for item in receive_findings] == [
        "foreign_subject_receive"
    ]
    assert [item.rule for item in select_findings] == [
        "foreign_subject_select"
    ]
    assert [item.rule for item in task_findings] == ["foreign_subject_receive"]
    assert [item.rule for item in named_task_findings] == [
        "foreign_subject_receive"
    ]
    assert [item.rule for item in alias_findings] == [
        "foreign_subject_receive"
    ]
    assert inspect_text("unrelated_shadow.gleam", unrelated_shadow) == []
    assert receive_findings[0].line == 4
    assert [item.rule for item in callback_findings] == [
        "foreign_subject_receive"
    ]
    assert inspect_text("handshake.gleam", good_callback_handshake) == []
    assert [item.rule for item in named_callback_findings] == [
        "foreign_subject_receive"
    ]
    assert [item.rule for item in aliased_callback_findings] == [
        "foreign_subject_receive"
    ]
    assert [item.rule for item in pipeline_callback_findings] == [
        "foreign_subject_receive"
    ]
    assert [item.rule for item in unresolved_findings] == [
        "execution_owner_unproven"
    ]
    assert [item.rule for item in spoofed_findings] == [
        "execution_owner_unproven"
    ]
    assert inspect_text("sender.gleam", safe_spoofed_sender) == []
    assert [item.rule for item in complex_findings] == [
        "execution_owner_unproven"
    ]
    assert [item.rule for item in named_function_findings] == [
        "execution_owner_unproven"
    ]
    assert inspect_text("ignored.gleam", ignored_text) == []
    assert [item.rule for item in cyclic_findings] == [
        "execution_owner_unproven"
    ]
    assert [item.rule for item in aliased_sink_findings] == [
        "execution_owner_unproven"
    ]
    token_limit_rejected = False
    try:
        inspect_text(
            "token_limit.gleam",
            "pub fn bounded() { " + ("value " * (MAX_TOKENS_PER_FILE + 1)) + "}",
        )
    except ValueError as failure:
        token_limit_rejected = str(failure) == "source_token_limit_exceeded"
    assert token_limit_rejected
    argument_limit_rejected = False
    try:
        inspect_text(
            "argument_limit.gleam",
            "import http/internal/http3/server as adapter\n"
            "pub fn bounded(config) { adapter.with_accept_probe("
            + ("x" * (MAX_CALLBACK_ARGUMENT_BYTES + 1))
            + ", fn(_) { Nil }) }",
        )
    except ValueError as failure:
        argument_limit_rejected = str(failure) == "callback_argument_limit_exceeded"
    assert argument_limit_rejected
    assert set(callback_findings[0].__dict__) == {"path", "line", "rule"}
    contract_relative = "src/http/internal/http3/server.gleam"
    contract_raw, _ = stable_source_read(ROOT / contract_relative)
    contract_source = contract_raw.decode("utf-8", errors="strict")
    assert callback_contract_findings({contract_relative: contract_source}) == []
    storage_mutant = contract_source.replace(
        "Config(..config, accept_request:)", "Config(..config)", 1
    )
    assert [
        item.rule
        for item in callback_contract_findings(
            {contract_relative: storage_mutant}
        )
    ] == ["execution_owner_unproven"]
    executor_mutant = contract_source.replace(
        "spawn_link_monitor(fn() {\n"
        "          process_role.set(process_role.Http3Acceptor)",
        "run_guarded(fn() {\n"
        "          process_role.set(process_role.Http3Acceptor)",
        1,
    )
    assert [
        item.rule
        for item in callback_contract_findings(
            {contract_relative: executor_mutant}
        )
    ] == ["execution_owner_unproven"]
    print("subject_ownership_audit self_test passed=true controls=29")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(add_help=True)
    parser.add_argument("--self-test", action="store_true")
    arguments = parser.parse_args()
    try:
        return self_test() if arguments.self_test else audit()
    except (AssertionError, OSError, UnicodeError, ValueError):
        print(
            "subject_ownership_audit failed=true classification=validation_failed",
            file=sys.stderr,
        )
        return 2


if __name__ == "__main__":
    raise SystemExit(main())

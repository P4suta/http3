#!/usr/bin/env python3

# SPDX-FileCopyrightText: 2026 the http contributors
# SPDX-License-Identifier: MIT OR Apache-2.0

"""Apply the independently reviewed RFC 9114 dispositions deterministically.

This evidence helper is deliberately fail closed.  It accepts only the exact
canonical inventory, candidate inventory, and independent review that were
audited together.  It rewrites only the RFC9114 object in requirements.json,
leaving every other standard byte-for-byte unchanged.
"""

from __future__ import annotations

import copy
import hashlib
import json
import os
import platform
from pathlib import Path
from pathlib import PurePosixPath
import re
import stat
import sys
import tempfile
from typing import Any, Callable, Protocol


ROOT = Path(__file__).resolve().parents[3]
REQUIREMENTS = ROOT / "standards" / "requirements.json"
AUDIT_DIRECTORY = Path(__file__).resolve().parent
CANDIDATE = AUDIT_DIRECTORY / "candidate-inventory.json"
REVIEW = AUDIT_DIRECTORY / "independent-review.json"
SOURCE_MANIFEST = AUDIT_DIRECTORY / "reviewed-source-manifest.json"
INVALIDATION_CHAIN = AUDIT_DIRECTORY / "invalidation-chain.json"
ARTIFACT_MANIFEST = AUDIT_DIRECTORY / "artifact-manifest.json"
LAUNCHER = AUDIT_DIRECTORY / "launcher.py"
EVIDENCE_GATE = AUDIT_DIRECTORY / "evidence_gate.py"
EVIDENCE_DIRECTORY = (
    ROOT / "build" / "root-validation" / "rfc9114-strict-inventory"
)

EXPECTED_INPUTS = {
    "requirements": "6d9c34e9311c73cc9540b5b51a133c755d6225d88015068169a44369842bf533",
    "candidate": "ee42fef95798249cecf1b333cbf613a7ffa7f7a302cd0d3a7e438bd9efbf1243",
    "review": "74cc3dc2db970c4eb3a36e9fd73f11886fbc80dfdc3ab3aa510a5b0b0170fbb9",
}
EXPECTED_OUTPUT_SHA256 = "76bdca016340f90dc8a75157b5fc4b04951e151eae3ed1cd000000ba0cd7115a"
EXPECTED_SOURCE_MANIFEST_SHA256 = (
    "8d047bee7cd06e314449c525a6a32d6d090e53c886ddd42bb4472b99712f699a"
)
EXPECTED_INVALIDATION_CHAIN_SHA256 = (
    "52d00f658761d717ca02f27f46b83bdeffdeef41571da6ee6deae2f88716a342"
)
LOCAL_FROZEN_PYTHON = {
    "implementation": "cpython",
    "version": "3.12.14",
    "sha256": "dd5f8d19f6755d6491ee7c4bef2fe35ddd521334cc3ca3ed8fc93ebcadf135d0",
}
MISE_PYTHON_VERSION = "3.12.13"
MISE_CONFIG = ROOT / ".mise.toml"
CANDIDATE_REVIEW_KEY = (
    "build/root-validation/rfc9114-requirements-inventory/inventory.json"
)
CANONICAL_FIELDS = (
    "id",
    "section",
    "source_line",
    "source_column",
    "source_occurrence",
    "source_clause_sha256",
    "level",
    "roles",
)
EXPECTED_COUNTS = {"Implemented": 31, "NotApplicable": 36, "Open": 148}
MAX_INPUT_BYTES = 32 * 1024 * 1024
MAX_ROWS = 1000
EVIDENCE_PATH_PATTERN = re.compile(
    r"^(?:src|test|packages/(?:http3|quic_core)/(?:src|test))/"
    r"[A-Za-z0-9_./-]+\.gleam$"
)
SYMBOL_PATTERN = re.compile(r"^[A-Za-z][A-Za-z0-9_]*$")
RUN_ID_PATTERN = re.compile(r"^[0-9a-f]{32}$")


class TransactionHook(Protocol):
    def __call__(self, boundary: str, target: Path) -> None: ...


class Rejected(ValueError):
    """A typed, non-secret audit rejection."""


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def read_bounded(path: Path) -> bytes:
    with path.open("rb") as handle:
        data = handle.read(MAX_INPUT_BYTES + 1)
        if len(data) > MAX_INPUT_BYTES or handle.read(1):
            raise Rejected("input_too_large")
    return data


def path_is_link(path: Path) -> bool:
    return path.is_symlink() or (
        hasattr(os.path, "isjunction") and os.path.isjunction(path)
    )


def stable_regular_bytes(path: Path, category: str) -> bytes:
    try:
        before = path.stat(follow_symlinks=False)
        if path_is_link(path) or not stat.S_ISREG(before.st_mode):
            raise Rejected(f"{category}_not_regular")
        with path.open("rb") as handle:
            opened_before = os.fstat(handle.fileno())
            data = handle.read(MAX_INPUT_BYTES + 1)
            opened_after = os.fstat(handle.fileno())
        after = path.stat(follow_symlinks=False)
    except Rejected:
        raise
    except FileNotFoundError as error:
        raise Rejected(f"{category}_missing") from error
    except OSError as error:
        raise Rejected(f"{category}_read_failed") from error
    if len(data) > MAX_INPUT_BYTES:
        raise Rejected(f"{category}_too_large")
    fingerprint = lambda value: (
        value.st_dev,
        value.st_ino,
        value.st_mode,
        value.st_size,
        value.st_mtime_ns,
    )
    if not (
        fingerprint(before)
        == fingerprint(opened_before)
        == fingerprint(opened_after)
        == fingerprint(after)
    ):
        raise Rejected(f"{category}_changed")
    return data


def checked_repository_path(path: Path, category: str) -> Path:
    root = ROOT.resolve(strict=True)
    current = Path(path.anchor)
    for part in path.resolve(strict=False).parts[1:]:
        current = current / part
        if current.exists() and path_is_link(current):
            raise Rejected(f"{category}_link")
    try:
        resolved = path.resolve(strict=False)
        resolved.relative_to(root)
    except (OSError, ValueError) as error:
        raise Rejected(f"{category}_escape") from error
    return resolved


def exact_file_bytes(
    paths: tuple[Path, ...], expected: tuple[bytes, ...], category: str
) -> tuple[bytes, ...]:
    observed = tuple(read_bounded(path) for path in paths)
    if observed != expected:
        raise Rejected(category)
    return observed


def decode_object(data: bytes, category: str) -> dict[str, Any]:
    try:
        value = json.loads(data)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise Rejected(f"{category}_invalid_json") from error
    if not isinstance(value, dict):
        raise Rejected(f"{category}_not_object")
    return value


def validated_citation(citation: Any) -> tuple[str, str]:
    if not isinstance(citation, dict) or set(citation) != {"path", "symbol"}:
        raise Rejected("evidence_citation_invalid")
    path = citation.get("path")
    symbol = citation.get("symbol")
    if not isinstance(path, str) or not EVIDENCE_PATH_PATTERN.fullmatch(path):
        raise Rejected("evidence_path_invalid")
    pure = PurePosixPath(path)
    if (
        pure.is_absolute()
        or pure.as_posix() != path
        or any(part in {"", ".", ".."} for part in pure.parts)
    ):
        raise Rejected("evidence_path_invalid")
    if not isinstance(symbol, str) or not SYMBOL_PATTERN.fullmatch(symbol):
        raise Rejected("evidence_symbol_invalid")
    return path, symbol


def resolved_source_path(relative: str) -> Path:
    pure = PurePosixPath(relative)
    current = ROOT
    for part in pure.parts:
        current = current / part
        if current.is_symlink() or (
            hasattr(os.path, "isjunction") and os.path.isjunction(current)
        ):
            raise Rejected("evidence_path_link")
    try:
        resolved = current.resolve(strict=True)
        resolved.relative_to(ROOT.resolve(strict=True))
    except (FileNotFoundError, OSError, ValueError) as error:
        raise Rejected("evidence_path_missing") from error
    return resolved


def stable_source_bytes(relative: str) -> tuple[bytes, os.stat_result]:
    path = resolved_source_path(relative)
    try:
        before = path.stat()
        if not stat.S_ISREG(before.st_mode):
            raise Rejected("evidence_path_not_regular")
        with path.open("rb") as handle:
            opened_before = os.fstat(handle.fileno())
            data = handle.read(MAX_INPUT_BYTES + 1)
            opened_after = os.fstat(handle.fileno())
        after = path.stat()
    except Rejected:
        raise
    except OSError as error:
        raise Rejected("evidence_source_read_failed") from error
    if len(data) > MAX_INPUT_BYTES:
        raise Rejected("evidence_source_too_large")
    fingerprint = lambda value: (
        value.st_dev,
        value.st_ino,
        value.st_mode,
        value.st_size,
        value.st_mtime_ns,
    )
    if not (
        fingerprint(before)
        == fingerprint(opened_before)
        == fingerprint(opened_after)
        == fingerprint(after)
    ):
        raise Rejected("evidence_source_changed")
    return data, after


def gleam_tokens(source: bytes) -> list[str]:
    try:
        text = source.decode("utf-8")
    except UnicodeDecodeError as error:
        raise Rejected("evidence_source_not_utf8") from error
    tokens: list[str] = []
    index = 0
    while index < len(text):
        character = text[index]
        if character.isspace():
            index += 1
        elif character == "/" and index + 1 < len(text) and text[index + 1] == "/":
            newline = text.find("\n", index + 2)
            index = len(text) if newline < 0 else newline + 1
        elif character == '"':
            index += 1
            escaped = False
            while index < len(text):
                current = text[index]
                index += 1
                if escaped:
                    escaped = False
                elif current == "\\":
                    escaped = True
                elif current == '"':
                    break
        elif character.isalpha() or character == "_":
            end = index + 1
            while end < len(text) and (text[end].isalnum() or text[end] == "_"):
                end += 1
            tokens.append(text[index:end])
            index = end
        else:
            tokens.append(character)
            index += 1
        if len(tokens) > 1_000_000:
            raise Rejected("evidence_source_token_limit")
    return tokens


def gleam_function_arities(source: bytes) -> dict[str, int]:
    tokens = gleam_tokens(source)
    functions: dict[str, int] = {}
    index = 0
    while index + 2 < len(tokens):
        if (
            tokens[index] == "fn"
            and SYMBOL_PATTERN.fullmatch(tokens[index + 1])
            and tokens[index + 2] == "("
        ):
            name = tokens[index + 1]
            depth = 1
            cursor = index + 3
            commas = 0
            has_parameter = False
            while cursor < len(tokens) and depth > 0:
                token = tokens[cursor]
                if token == "(":
                    depth += 1
                elif token == ")":
                    depth -= 1
                elif depth == 1:
                    if token == ",":
                        commas += 1
                    else:
                        has_parameter = True
                cursor += 1
            if depth != 0:
                raise Rejected("evidence_function_unterminated")
            arity = commas + 1 if has_parameter else 0
            if name in functions:
                raise Rejected("evidence_function_duplicate")
            functions[name] = arity
            index = cursor
        else:
            index += 1
    return functions


def candidate_symbol_contracts(
    candidate: dict[str, Any], implemented_ids: set[str]
) -> tuple[int, dict[tuple[str, str], int]]:
    rows = candidate.get("rows")
    if not isinstance(rows, list):
        raise Rejected("candidate_rows_invalid")
    references = 0
    contracts: dict[tuple[str, str], int] = {}
    for row in rows:
        if not isinstance(row, dict) or row.get("id") not in implemented_ids:
            continue
        expected: list[tuple[str, str, str]] = []
        for key, kind in (
            ("candidate_implementation", "implementation"),
            ("candidate_tests", "test"),
        ):
            citations = row.get(key)
            if not isinstance(citations, list) or not citations:
                raise Rejected("candidate_evidence_missing")
            for citation in citations:
                path, symbol = validated_citation(citation)
                expected.append((kind, path, symbol))
        validations = row.get("evidence_symbol_validation")
        if not isinstance(validations, list) or len(validations) != len(expected):
            raise Rejected("candidate_symbol_validation_mismatch")
        observed: list[tuple[str, str, str]] = []
        for validation in validations:
            if not isinstance(validation, dict):
                raise Rejected("candidate_symbol_validation_invalid")
            identity = (
                validation.get("kind"),
                validation.get("path"),
                validation.get("symbol"),
            )
            observed.append(identity)
            declared = validation.get("declared_arity")
            if (
                validation.get("language") != "gleam"
                or validation.get("exists") is not True
                or validation.get("symbol_exists") is not True
                or validation.get("arity_match") is not True
                or not isinstance(declared, int)
                or declared < 0
            ):
                raise Rejected("candidate_symbol_validation_invalid")
            if validation.get("kind") == "test" and (
                validation.get("expected_arity") != 0 or declared != 0
            ):
                raise Rejected("candidate_test_arity_invalid")
            key = (identity[1], identity[2])
            prior = contracts.get(key)
            if prior is not None and prior != declared:
                raise Rejected("candidate_symbol_arity_conflict")
            contracts[key] = declared
        if observed != expected:
            raise Rejected("candidate_symbol_validation_mismatch")
        references += len(expected)
    if not contracts or references < len(contracts):
        raise Rejected("candidate_source_contract_empty")
    return references, contracts


def source_manifest_object(
    reviewed_requirements: bytes,
    candidate_bytes: bytes,
    review_bytes: bytes,
) -> dict[str, Any]:
    requirements = decode_object(reviewed_requirements, "manifest_requirements")
    candidate = decode_object(candidate_bytes, "manifest_candidate")
    rows = locate_rfc9114(requirements).get("requirements")
    if not isinstance(rows, list):
        raise Rejected("requirements_rows_invalid")
    implemented_ids = {
        row.get("id")
        for row in rows
        if isinstance(row, dict) and row.get("disposition") == "Implemented"
    }
    if len(implemented_ids) != EXPECTED_COUNTS["Implemented"]:
        raise Rejected("implemented_id_count_mismatch")
    reference_count, contracts = candidate_symbol_contracts(
        candidate, implemented_ids
    )
    by_path: dict[str, list[tuple[str, int]]] = {}
    for (path, symbol), arity in contracts.items():
        by_path.setdefault(path, []).append((symbol, arity))
    files: list[dict[str, Any]] = []
    aggregate_parts: list[bytes] = []
    for relative in sorted(by_path):
        source, metadata = stable_source_bytes(relative)
        functions = gleam_function_arities(source)
        symbols: list[dict[str, Any]] = []
        for symbol, expected_arity in sorted(by_path[relative]):
            if functions.get(symbol) != expected_arity:
                raise Rejected("current_evidence_symbol_mismatch")
            symbols.append({"symbol": symbol, "arity": expected_arity})
        file_sha256 = digest(source)
        files.append(
            {
                "path": relative,
                "bytes": metadata.st_size,
                "sha256": file_sha256,
                "symbols": symbols,
            }
        )
        aggregate_parts.append(
            encoded_object(
                {
                    "path": relative,
                    "bytes": metadata.st_size,
                    "sha256": file_sha256,
                    "symbols": symbols,
                }
            )
        )
    aggregate = digest(b"\n".join(aggregate_parts))
    return {
        "schema": 1,
        "manifest_kind": "rfc9114_reviewed_evidence_sources",
        "standard": "RFC9114",
        "reviewed_requirements_sha256": digest(reviewed_requirements),
        "candidate_sha256": digest(candidate_bytes),
        "review_sha256": digest(review_bytes),
        "implemented_requirements": len(implemented_ids),
        "citation_references": reference_count,
        "unique_citations": len(contracts),
        "source_files": len(files),
        "source_aggregate_sha256": aggregate,
        "files": files,
    }


def checked_source_manifest(
    reviewed_requirements: bytes,
    candidate_bytes: bytes,
    review_bytes: bytes,
    manifest_bytes: bytes,
) -> dict[str, Any]:
    if digest(manifest_bytes) != EXPECTED_SOURCE_MANIFEST_SHA256:
        raise Rejected("source_manifest_identity_mismatch")
    observed = decode_object(manifest_bytes, "source_manifest")
    expected = source_manifest_object(
        reviewed_requirements, candidate_bytes, review_bytes
    )
    if observed != expected:
        raise Rejected("current_evidence_source_mismatch")
    return expected


def exact_index(rows: list[dict[str, Any]], category: str) -> dict[str, dict[str, Any]]:
    if not 0 < len(rows) <= MAX_ROWS:
        raise Rejected(f"{category}_row_count")
    indexed: dict[str, dict[str, Any]] = {}
    for row in rows:
        if not isinstance(row, dict) or not isinstance(row.get("id"), str):
            raise Rejected(f"{category}_row_invalid")
        identifier = row["id"]
        if identifier in indexed:
            raise Rejected(f"{category}_duplicate_id")
        indexed[identifier] = row
    return indexed


def locate_rfc9114(requirements: dict[str, Any]) -> dict[str, Any]:
    standards = requirements.get("standards")
    if not isinstance(standards, list):
        raise Rejected("standards_invalid")
    matches = [item for item in standards if isinstance(item, dict) and item.get("id") == "RFC9114"]
    if len(matches) != 1:
        raise Rejected("rfc9114_cardinality")
    return matches[0]


def checked_inputs(
    requirements_bytes: bytes,
    candidate_bytes: bytes,
    review_bytes: bytes,
    *,
    enforce_hashes: bool = True,
) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any]]:
    observed = {
        "requirements": digest(requirements_bytes),
        "candidate": digest(candidate_bytes),
        "review": digest(review_bytes),
    }
    if enforce_hashes and observed != EXPECTED_INPUTS:
        raise Rejected("input_identity_mismatch")
    requirements = decode_object(requirements_bytes, "requirements")
    candidate = decode_object(candidate_bytes, "candidate")
    review = decode_object(review_bytes, "review")
    if requirements.get("schema") != 4:
        raise Rejected("requirements_schema")
    if candidate.get("schema") != 1 or candidate.get("standard") != "RFC9114":
        raise Rejected("candidate_schema")
    if review.get("schema") != 1:
        raise Rejected("review_schema")
    if review.get("hashes", {}).get("standards/requirements.json") != observed["requirements"]:
        raise Rejected("review_requirements_identity")
    if review.get("hashes", {}).get(CANDIDATE_REVIEW_KEY) != observed["candidate"]:
        raise Rejected("review_candidate_identity")
    return requirements, candidate, review


def reviewed_rfc9114(
    requirements: dict[str, Any], candidate: dict[str, Any], review: dict[str, Any]
) -> dict[str, Any]:
    canonical = locate_rfc9114(requirements)
    canonical_rows = canonical.get("requirements")
    candidate_rows = candidate.get("rows")
    assessments = review.get("assessments")
    if not all(isinstance(value, list) for value in (canonical_rows, candidate_rows, assessments)):
        raise Rejected("row_collections_invalid")
    canonical_by_id = exact_index(canonical_rows, "canonical")
    candidate_by_id = exact_index(candidate_rows, "candidate")
    assessment_by_id = exact_index(assessments, "assessment")
    if len(canonical_by_id) != 215 or set(canonical_by_id) != set(candidate_by_id):
        raise Rejected("canonical_candidate_set_mismatch")
    if len(assessment_by_id) != 161 or not set(assessment_by_id) <= set(canonical_by_id):
        raise Rejected("assessment_set_mismatch")
    if review.get("recommended_counts") != EXPECTED_COUNTS:
        raise Rejected("review_recommended_counts_mismatch")
    if review.get("canonical_comparison", {}).get("fields") != list(
        CANONICAL_FIELDS
    ):
        raise Rejected("review_canonical_fields_mismatch")

    rows: list[dict[str, Any]] = []
    counts = {key: 0 for key in EXPECTED_COUNTS}
    evidence_paths: set[str] = set()
    for canonical_row in canonical_rows:
        identifier = canonical_row["id"]
        candidate_row = candidate_by_id[identifier]
        for field in CANONICAL_FIELDS:
            if (
                field not in canonical_row
                or field not in candidate_row
                or canonical_row[field] != candidate_row[field]
            ):
                raise Rejected("canonical_field_mismatch")
        assessment = assessment_by_id.get(identifier)
        if assessment is None:
            if candidate_row.get("audited_disposition") != "Open":
                raise Rejected("unassessed_non_open")
            disposition = "Open"
            reason = candidate_row.get("remaining_gap") or candidate_row.get("rationale")
        else:
            assessment_matches = (
                assessment.get("section") == candidate_row.get("section")
                and assessment.get("level") == candidate_row.get("level")
                and assessment.get("roles") == candidate_row.get("roles")
                and assessment.get("source_occurrence")
                == candidate_row.get("source_occurrence")
                and assessment.get("submitted_disposition")
                == candidate_row.get("audited_disposition")
                and assessment.get("candidate_implementation")
                == candidate_row.get("candidate_implementation")
                and assessment.get("candidate_tests")
                == candidate_row.get("candidate_tests")
            )
            if not assessment_matches:
                raise Rejected("assessment_candidate_mismatch")
            disposition = assessment.get("recommended_disposition")
            if disposition == "Implemented":
                if assessment.get("evidence_specificity_score") != 3:
                    raise Rejected("implemented_without_direct_evidence")
            reason = assessment.get("required_test") or assessment.get("assessment")
        if disposition not in counts or not isinstance(reason, (str, type(None))):
            raise Rejected("review_disposition_invalid")

        row = {field: copy.deepcopy(canonical_row[field]) for field in CANONICAL_FIELDS}
        summary = candidate_row.get("normative_text_summary")
        if not isinstance(summary, str) or not summary.strip():
            raise Rejected("summary_missing")
        row["summary"] = summary
        row["disposition"] = disposition
        if disposition == "Implemented":
            implementation = copy.deepcopy(candidate_row.get("candidate_implementation"))
            tests = copy.deepcopy(candidate_row.get("candidate_tests"))
            if not isinstance(implementation, list) or not implementation:
                raise Rejected("implementation_evidence_missing")
            if not isinstance(tests, list) or not tests:
                raise Rejected("test_evidence_missing")
            row["implementation"] = implementation
            row["tests"] = tests
            for citation in implementation + tests:
                path, _symbol = validated_citation(citation)
                evidence_paths.add(path)
        else:
            if not isinstance(reason, str) or not reason.strip():
                raise Rejected("reason_missing")
            row["reason"] = reason
        rows.append(row)
        counts[disposition] += 1

    if counts != EXPECTED_COUNTS:
        raise Rejected("reviewed_counts_mismatch")
    if [row["source_occurrence"] for row in rows] != list(range(1, 216)):
        raise Rejected("occurrences_not_contiguous")

    result = copy.deepcopy(canonical)
    result["map_complete"] = False
    result["evidence"] = sorted(evidence_paths)
    result["requirements"] = rows
    return result


def rfc9114_text_span(text: str) -> tuple[int, int]:
    marker = '    "id": "RFC9114"'
    marker_at = text.find(marker)
    if marker_at < 0 or text.find(marker, marker_at + 1) >= 0:
        raise Rejected("rfc9114_text_marker")
    start = text.rfind("  {", 0, marker_at)
    if start < 0:
        raise Rejected("rfc9114_text_start")
    depth = 0
    in_string = False
    escaped = False
    end = -1
    for index in range(start, len(text)):
        character = text[index]
        if in_string:
            if escaped:
                escaped = False
            elif character == "\\":
                escaped = True
            elif character == '"':
                in_string = False
            continue
        if character == '"':
            in_string = True
        elif character == "{":
            depth += 1
        elif character == "}":
            depth -= 1
            if depth == 0:
                end = index + 1
                break
    if end < 0:
        raise Rejected("rfc9114_text_end")
    return start, end


def splice_standard(original: bytes, replacement: dict[str, Any]) -> bytes:
    try:
        text = original.decode("utf-8")
    except UnicodeDecodeError as error:
        raise Rejected("requirements_not_utf8") from error
    start, end = rfc9114_text_span(text)
    rendered = json.dumps(replacement, ensure_ascii=False, indent=2)
    rendered = "\n".join("  " + line for line in rendered.splitlines())
    output = (text[:start] + rendered + text[end:]).encode("utf-8")
    decoded = decode_object(output, "rendered_requirements")
    if locate_rfc9114(decoded) != replacement:
        raise Rejected("rendered_roundtrip_mismatch")
    output_text = output.decode("utf-8")
    output_start, output_end = rfc9114_text_span(output_text)
    if (
        text[:start] != output_text[:output_start]
        or text[end:] != output_text[output_end:]
    ):
        raise Rejected("outside_rfc9114_bytes_changed")
    return output


def assert_rendered_identity(output: bytes, expected: str = EXPECTED_OUTPUT_SHA256) -> None:
    if digest(output) != expected:
        raise Rejected("rendered_identity_mismatch")


def build_output(
    requirements_bytes: bytes,
    candidate_bytes: bytes,
    review_bytes: bytes,
    *,
    enforce_hashes: bool = True,
) -> bytes:
    requirements, candidate, review = checked_inputs(
        requirements_bytes, candidate_bytes, review_bytes, enforce_hashes=enforce_hashes
    )
    replacement = reviewed_rfc9114(requirements, candidate, review)
    return splice_standard(requirements_bytes, replacement)


def encoded_object(value: dict[str, Any]) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")


def rebound_review(review: dict[str, Any], requirements: bytes, candidate: bytes) -> bytes:
    rebound = copy.deepcopy(review)
    hashes = rebound.get("hashes")
    if not isinstance(hashes, dict):
        raise Rejected("review_hashes_invalid")
    hashes["standards/requirements.json"] = digest(requirements)
    hashes[CANDIDATE_REVIEW_KEY] = digest(candidate)
    return encoded_object(rebound)


def disposition_counts(requirements: dict[str, Any]) -> dict[str, int]:
    rows = locate_rfc9114(requirements).get("requirements")
    if not isinstance(rows, list):
        raise Rejected("requirements_rows_invalid")
    observed: dict[str, int] = {}
    for row in rows:
        if not isinstance(row, dict) or not isinstance(row.get("disposition"), str):
            raise Rejected("requirements_disposition_invalid")
        disposition = row["disposition"]
        observed[disposition] = observed.get(disposition, 0) + 1
    return observed


def validate_post_state(
    requirements_bytes: bytes,
    candidate_bytes: bytes,
    review_bytes: bytes,
    *,
    enforce_hashes: bool = True,
) -> dict[str, int]:
    observed = {
        "requirements": digest(requirements_bytes),
        "candidate": digest(candidate_bytes),
        "review": digest(review_bytes),
    }
    if enforce_hashes:
        if observed["requirements"] != EXPECTED_OUTPUT_SHA256:
            raise Rejected("post_requirements_identity_mismatch")
        if observed["candidate"] != EXPECTED_INPUTS["candidate"]:
            raise Rejected("post_candidate_identity_mismatch")
        if observed["review"] != EXPECTED_INPUTS["review"]:
            raise Rejected("post_review_identity_mismatch")
    requirements = decode_object(requirements_bytes, "post_requirements")
    candidate = decode_object(candidate_bytes, "post_candidate")
    review = decode_object(review_bytes, "post_review")
    if requirements.get("schema") != 4:
        raise Rejected("requirements_schema")
    if candidate.get("schema") != 1 or candidate.get("standard") != "RFC9114":
        raise Rejected("candidate_schema")
    if review.get("schema") != 1:
        raise Rejected("review_schema")
    hashes = review.get("hashes")
    if not isinstance(hashes, dict):
        raise Rejected("review_hashes_invalid")
    if hashes.get("standards/requirements.json") != EXPECTED_INPUTS["requirements"]:
        raise Rejected("review_requirements_identity")
    if hashes.get(CANDIDATE_REVIEW_KEY) != EXPECTED_INPUTS["candidate"]:
        raise Rejected("review_candidate_identity")
    expected = reviewed_rfc9114(requirements, candidate, review)
    if locate_rfc9114(requirements) != expected:
        raise Rejected("strict_block_mismatch")
    counts = disposition_counts(requirements)
    if counts != EXPECTED_COUNTS:
        raise Rejected("reviewed_counts_mismatch")
    return counts


def expect_rejection(name: str, expected: str, operation: Callable[[], None]) -> None:
    try:
        operation()
    except Rejected as error:
        if str(error) != expected:
            raise Rejected(f"control_wrong_category:{name}:{error}") from error
    else:
        raise Rejected(f"hostile_fixture_accepted:{name}")


def semantic_self_test(
    requirements: bytes,
    candidate: bytes,
    review: bytes,
    source_manifest: bytes,
    *,
    exact_pre_state: bool,
) -> tuple[int, list[dict[str, str]]]:
    controls: list[dict[str, str]] = []
    if exact_pre_state:
        baseline_review = review
        output = build_output(requirements, candidate, review)
        identity_operation = lambda: build_output(requirements + b" ", candidate, review)
        identity_category = "input_identity_mismatch"
    else:
        review_object = decode_object(review, "post_review_fixture")
        baseline_review = rebound_review(review_object, requirements, candidate)
        output = build_output(
            requirements, candidate, baseline_review, enforce_hashes=False
        )
        identity_operation = lambda: validate_post_state(
            requirements + b" ", candidate, review
        )
        identity_category = "post_requirements_identity_mismatch"
    controls.append({"name": "baseline_render", "observed": "accepted"})
    observed = disposition_counts(decode_object(output, "self_test_output"))
    if observed != EXPECTED_COUNTS:
        raise Rejected("self_test_counts")
    controls.append({"name": "reviewed_counts", "observed": "accepted"})
    assert_rendered_identity(output)
    controls.append({"name": "rendered_identity", "observed": "accepted"})
    checked_source_manifest(output, candidate, review, source_manifest)
    controls.append({"name": "reviewed_source_manifest", "observed": "accepted"})

    expect_rejection(
        "wrong_expected_output",
        "rendered_identity_mismatch",
        lambda: assert_rendered_identity(output, "0" * 64),
    )
    controls.append(
        {"name": "wrong_expected_output", "observed": "rendered_identity_mismatch"}
    )
    expect_rejection(
        "source_manifest_identity",
        "source_manifest_identity_mismatch",
        lambda: checked_source_manifest(
            output, candidate, review, source_manifest + b" "
        ),
    )
    controls.append(
        {
            "name": "source_manifest_identity",
            "observed": "source_manifest_identity_mismatch",
        }
    )

    expect_rejection("source_identity", identity_category, identity_operation)
    controls.append({"name": "source_identity", "observed": identity_category})

    candidate_object = decode_object(candidate, "candidate_fixture")
    baseline_review_object = decode_object(baseline_review, "review_fixture")

    duplicate = copy.deepcopy(candidate_object)
    duplicate["rows"].append(copy.deepcopy(duplicate["rows"][0]))
    duplicate_bytes = encoded_object(duplicate)
    duplicate_review = rebound_review(
        baseline_review_object, requirements, duplicate_bytes
    )
    expect_rejection(
        "duplicate_candidate_id",
        "candidate_duplicate_id",
        lambda: build_output(
            requirements, duplicate_bytes, duplicate_review, enforce_hashes=False
        ),
    )
    controls.append(
        {"name": "duplicate_candidate_id", "observed": "candidate_duplicate_id"}
    )

    missing = copy.deepcopy(baseline_review_object)
    missing["assessments"] = missing["assessments"][:-1]
    expect_rejection(
        "missing_assessment",
        "assessment_set_mismatch",
        lambda: build_output(
            requirements, candidate, encoded_object(missing), enforce_hashes=False
        ),
    )
    controls.append(
        {"name": "missing_assessment", "observed": "assessment_set_mismatch"}
    )

    weak = copy.deepcopy(baseline_review_object)
    direct = next(
        item
        for item in weak["assessments"]
        if item["recommended_disposition"] == "Implemented"
    )
    direct["evidence_specificity_score"] = 2
    expect_rejection(
        "weak_implemented",
        "implemented_without_direct_evidence",
        lambda: build_output(
            requirements, candidate, encoded_object(weak), enforce_hashes=False
        ),
    )
    controls.append(
        {
            "name": "weak_implemented",
            "observed": "implemented_without_direct_evidence",
        }
    )

    review_citation_drift = copy.deepcopy(baseline_review_object)
    reviewed_direct = next(
        item
        for item in review_citation_drift["assessments"]
        if item["recommended_disposition"] == "Implemented"
    )
    reviewed_direct["candidate_tests"][0]["symbol"] = "review_only_decoy_test"
    expect_rejection(
        "review_candidate_citation_drift",
        "assessment_candidate_mismatch",
        lambda: build_output(
            requirements,
            candidate,
            encoded_object(review_citation_drift),
            enforce_hashes=False,
        ),
    )
    controls.append(
        {
            "name": "review_candidate_citation_drift",
            "observed": "assessment_candidate_mismatch",
        }
    )

    direct_assessment = next(
        item
        for item in baseline_review_object["assessments"]
        if item["recommended_disposition"] == "Implemented"
    )
    direct_id = direct_assessment["id"]
    traversal_candidate = copy.deepcopy(candidate_object)
    traversal_row = next(
        item for item in traversal_candidate["rows"] if item["id"] == direct_id
    )
    traversal_row["candidate_tests"][0]["path"] = "../../private/secret.gleam"
    traversal_row["evidence_symbol_validation"][-1]["path"] = (
        "../../private/secret.gleam"
    )
    traversal_bytes = encoded_object(traversal_candidate)
    traversal_review_object = copy.deepcopy(baseline_review_object)
    traversal_assessment = next(
        item
        for item in traversal_review_object["assessments"]
        if item["id"] == direct_id
    )
    traversal_assessment["candidate_tests"][0]["path"] = (
        "../../private/secret.gleam"
    )
    traversal_review = rebound_review(
        traversal_review_object, requirements, traversal_bytes
    )
    expect_rejection(
        "traversal_citation",
        "evidence_path_invalid",
        lambda: build_output(
            requirements, traversal_bytes, traversal_review, enforce_hashes=False
        ),
    )
    controls.append(
        {"name": "traversal_citation", "observed": "evidence_path_invalid"}
    )

    no_test = copy.deepcopy(candidate_object)
    next(item for item in no_test["rows"] if item["id"] == direct_id)[
        "candidate_tests"
    ] = []
    no_test_bytes = encoded_object(no_test)
    no_test_review_object = copy.deepcopy(baseline_review_object)
    next(
        item
        for item in no_test_review_object["assessments"]
        if item["id"] == direct_id
    )["candidate_tests"] = []
    no_test_review = rebound_review(
        no_test_review_object, requirements, no_test_bytes
    )
    expect_rejection(
        "missing_test_evidence",
        "test_evidence_missing",
        lambda: build_output(
            requirements, no_test_bytes, no_test_review, enforce_hashes=False
        ),
    )
    controls.append(
        {"name": "missing_test_evidence", "observed": "test_evidence_missing"}
    )

    absent_candidate = copy.deepcopy(candidate_object)
    absent_row = next(
        item for item in absent_candidate["rows"] if item["id"] == direct_id
    )
    absent_row["candidate_tests"][0]["symbol"] = "missing_reviewed_symbol_test"
    absent_row["evidence_symbol_validation"][-1]["symbol"] = (
        "missing_reviewed_symbol_test"
    )
    absent_bytes = encoded_object(absent_candidate)
    absent_review_object = copy.deepcopy(baseline_review_object)
    absent_assessment = next(
        item
        for item in absent_review_object["assessments"]
        if item["id"] == direct_id
    )
    absent_assessment["candidate_tests"][0]["symbol"] = (
        "missing_reviewed_symbol_test"
    )
    absent_review = rebound_review(
        absent_review_object, requirements, absent_bytes
    )

    def render_absent_symbol_manifest() -> None:
        absent_output = build_output(
            requirements, absent_bytes, absent_review, enforce_hashes=False
        )
        source_manifest_object(absent_output, absent_bytes, absent_review)

    expect_rejection(
        "missing_current_symbol",
        "current_evidence_symbol_mismatch",
        render_absent_symbol_manifest,
    )
    controls.append(
        {
            "name": "missing_current_symbol",
            "observed": "current_evidence_symbol_mismatch",
        }
    )
    controls.extend(infrastructure_self_test(output))
    validate_control_inventory(controls, exact_pre_state)
    return len(controls), controls


def invoke_hook(
    hook: TransactionHook | None, boundary: str, target: Path
) -> None:
    if hook is not None:
        hook(boundary, target)


def fsync_parent(path: Path) -> None:
    """Persist directory metadata where the platform exposes that operation."""

    if os.name != "posix":
        return
    try:
        descriptor = os.open(path.parent, os.O_RDONLY)
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
    except OSError as error:
        raise Rejected("directory_sync_failed") from error


def durable_new_file(path: Path, data: bytes, *, mode: int = 0o600) -> None:
    """Create a durable file without replacing any existing name."""

    descriptor: int | None = None
    try:
        descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, mode)
        with os.fdopen(descriptor, "wb") as handle:
            descriptor = None
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        fsync_parent(path)
    except FileExistsError as error:
        raise Rejected("exclusive_create_conflict") from error
    except Rejected:
        raise
    except OSError as error:
        raise Rejected("exclusive_create_failed") from error
    finally:
        if descriptor is not None:
            os.close(descriptor)


def atomic_generated_write(
    path: Path,
    data: bytes,
    *,
    hook: TransactionHook | None = None,
    boundary_prefix: str = "generated",
) -> None:
    """Durably replace a generated artifact while exposing failure boundaries."""

    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{path.name}.", suffix=".tmp", dir=path.parent
    )
    temporary = Path(temporary_name)
    replaced = False
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        invoke_hook(hook, f"{boundary_prefix}_after_stage", path)
        invoke_hook(hook, f"{boundary_prefix}_before_replace", path)
        os.replace(temporary, path)
        replaced = True
        fsync_parent(path)
        invoke_hook(hook, f"{boundary_prefix}_after_replace", path)
        if read_bounded(path) != data:
            raise Rejected("generated_write_readback_mismatch")
    except Rejected:
        raise
    except OSError as error:
        raise Rejected("generated_write_failed") from error
    finally:
        if not replaced:
            try:
                temporary.unlink(missing_ok=True)
            except OSError:
                pass


class ExclusiveDirectoryLock:
    """A fail-closed repository-local lock with identity-safe release."""

    def __init__(self, path: Path, token: bytes):
        self.path = path
        self.owner = path / "owner"
        self.token = token
        self.held = False

    def acquire(self) -> None:
        try:
            os.mkdir(self.path)
        except FileExistsError as error:
            raise Rejected("exclusive_lock_busy") from error
        except OSError as error:
            raise Rejected("exclusive_lock_failed") from error
        try:
            durable_new_file(self.owner, self.token)
            self.held = True
        except Exception:
            try:
                os.rmdir(self.path)
            except OSError:
                pass
            raise

    def release(self) -> None:
        if not self.held:
            return
        if read_bounded(self.owner) != self.token:
            raise Rejected("exclusive_lock_identity_mismatch")
        try:
            self.owner.unlink()
            os.rmdir(self.path)
            fsync_parent(self.path)
        except OSError as error:
            raise Rejected("exclusive_lock_release_failed") from error
        self.held = False


class LosslessTargetTransaction:
    """Claim, inspect, and publish a target without overwriting a racing value.

    Original and intended bytes are durable before the target is claimed.  The
    existing target name is atomically moved into the recovery directory, and
    publication uses an exclusive hard link.  Any value written by another
    process is either moved into recovery or left at the target; it is never
    replaced by this transaction after it appears.
    """

    def __init__(
        self,
        target: Path,
        expected: bytes,
        intended: bytes,
        recovery_root: Path,
        run_id: str,
        *,
        hook: TransactionHook | None = None,
    ):
        if not RUN_ID_PATTERN.fullmatch(run_id):
            raise Rejected("transaction_run_id_invalid")
        self.target = target
        self.expected = expected
        self.intended = intended
        self.recovery_root = recovery_root
        self.directory = recovery_root / f"run-{run_id}"
        self.original_path = self.directory / "original.bin"
        self.intended_path = self.directory / "intended.bin"
        self.claimed_path = self.directory / "claimed.bin"
        self.published_path = self.directory / "published.bin"
        self.concurrent_path = self.directory / "concurrent-target.bin"
        self.journal_path = self.directory / "transaction.json"
        self.hook = hook
        self.lock = ExclusiveDirectoryLock(
            recovery_root / ".target-claim-lock",
            f"rfc9114:{run_id}\n".encode("ascii"),
        )
        self.state = "new"
        self.owns_directory = False
        self.target_mode = 0o600

    def journal_bytes(
        self, status: str, classification: str | None = None
    ) -> bytes:
        record = {
            "schema": 1,
            "transaction_kind": "rfc9114_lossless_target_replace",
            "run_id": self.directory.name.removeprefix("run-"),
            "status": status,
            "target": "standards/requirements.json",
            "original_sha256": digest(self.expected),
            "intended_sha256": digest(self.intended),
            "failure_classification": classification,
        }
        return (json.dumps(record, indent=2) + "\n").encode("utf-8")

    def journal(self, status: str, classification: str | None = None) -> None:
        atomic_generated_write(
            self.journal_path,
            self.journal_bytes(status, classification),
        )

    def replace(self) -> None:
        checked_repository_path(self.target, "transaction_target_path")
        checked_repository_path(self.recovery_root, "transaction_recovery_path")
        self.recovery_root.mkdir(parents=True, exist_ok=True)
        target_metadata = self.target.stat(follow_symlinks=False)
        self.target_mode = stat.S_IMODE(target_metadata.st_mode)
        if target_metadata.st_dev != self.recovery_root.stat().st_dev:
            raise Rejected("transaction_cross_device_rejected")
        self.lock.acquire()
        try:
            os.mkdir(self.directory)
            self.owns_directory = True
        except FileExistsError as error:
            raise Rejected("transaction_recovery_conflict") from error
        except OSError as error:
            raise Rejected("transaction_recovery_create_failed") from error
        durable_new_file(self.original_path, self.expected)
        durable_new_file(self.intended_path, self.intended, mode=self.target_mode)
        self.journal("Preparing")
        self.state = "prepared"
        invoke_hook(self.hook, "after_recovery", self.target)
        if stable_regular_bytes(self.target, "transaction_target") != self.expected:
            raise Rejected("transaction_target_identity_mismatch")
        invoke_hook(self.hook, "after_expected_validation", self.target)
        try:
            os.replace(self.target, self.claimed_path)
            fsync_parent(self.target)
        except OSError as error:
            raise Rejected("transaction_claim_failed") from error
        self.state = "claimed"
        if stable_regular_bytes(self.claimed_path, "transaction_claimed") != self.expected:
            raise Rejected("transaction_claimed_identity_mismatch")
        invoke_hook(self.hook, "after_claim", self.target)
        invoke_hook(self.hook, "before_publish", self.target)
        try:
            os.link(self.intended_path, self.target)
            fsync_parent(self.target)
        except FileExistsError as error:
            raise Rejected("transaction_publish_conflict") from error
        except OSError as error:
            raise Rejected("transaction_publish_link_failed") from error
        self.state = "published"
        invoke_hook(self.hook, "after_publish", self.target)
        if stable_regular_bytes(self.target, "transaction_published") != self.intended:
            raise Rejected("transaction_post_publish_identity_mismatch")
        invoke_hook(self.hook, "before_commit", self.target)
        if stable_regular_bytes(self.target, "transaction_published") != self.intended:
            raise Rejected("transaction_precommit_identity_mismatch")
        self.journal("Published")

    def rollback(self, classification: str) -> None:
        """Restore only an unchanged value and retain every competing value."""

        if self.state in {"claimed", "published"}:
            try:
                current = stable_regular_bytes(
                    self.target, "transaction_rollback_target"
                )
            except Rejected as error:
                if str(error) == "transaction_rollback_target_missing":
                    current = None
                elif str(error) == "transaction_rollback_target_not_regular":
                    current = b"__concurrent_non_regular_target__"
                else:
                    raise
            except FileNotFoundError:
                current = None
            if current == self.intended:
                if self.published_path.exists():
                    raise Rejected("transaction_recovery_name_conflict")
                try:
                    os.replace(self.target, self.published_path)
                    fsync_parent(self.target)
                except OSError as error:
                    raise Rejected("transaction_preserve_published_failed") from error
                current = None
            elif current is not None:
                if (
                    current != b"__concurrent_non_regular_target__"
                    and not self.concurrent_path.exists()
                ):
                    durable_new_file(self.concurrent_path, current)

            if current is None and not self.target.exists():
                restore = (
                    stable_regular_bytes(
                        self.claimed_path, "transaction_rollback_claimed"
                    )
                    if self.claimed_path.exists() and not path_is_link(self.claimed_path)
                    else self.expected
                )
                try:
                    durable_new_file(self.target, restore, mode=self.target_mode)
                except Rejected as error:
                    if str(error) != "exclusive_create_conflict":
                        raise
        if self.owns_directory and self.directory.exists():
            self.journal("Rejected", classification)
        self.state = "rejected"
        self.lock.release()

    def commit(self) -> None:
        if (
            self.state != "published"
            or stable_regular_bytes(self.target, "transaction_commit_target")
            != self.intended
        ):
            raise Rejected("transaction_commit_identity_mismatch")
        self.journal("Committed")
        self.lock.release()
        self.state = "committed"


def rerun_command(mode: str) -> str:
    return "python -I -B standards/audits/rfc9114/launcher.py " + mode


def configured_mise_python(data: bytes) -> str:
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError as error:
        raise Rejected("mise_config_not_utf8") from error
    matches = re.findall(r'^python\s*=\s*"([0-9]+\.[0-9]+\.[0-9]+)"\s*$', text, re.M)
    if matches != [MISE_PYTHON_VERSION]:
        raise Rejected("mise_python_configuration_mismatch")
    return matches[0]


def checked_python_identity(identity: dict[str, str]) -> dict[str, str]:
    if (
        set(identity) != {"implementation", "version", "sha256", "identity_kind"}
        or identity.get("implementation") != "cpython"
        or not re.fullmatch(r"[0-9a-f]{64}", identity.get("sha256", ""))
    ):
        raise Rejected("audit_python_identity_mismatch")
    if identity.get("version") == MISE_PYTHON_VERSION:
        if identity.get("identity_kind") != "mise_configured":
            raise Rejected("audit_python_identity_mismatch")
    elif {
        "implementation": identity.get("implementation"),
        "version": identity.get("version"),
        "sha256": identity.get("sha256"),
    } == LOCAL_FROZEN_PYTHON:
        if identity.get("identity_kind") != "local_frozen":
            raise Rejected("audit_python_identity_mismatch")
    else:
        raise Rejected("audit_python_identity_mismatch")
    return identity


def audited_python_identity() -> dict[str, str]:
    configured = os.environ.get("HTTP_AUDIT_PYTHON")
    try:
        running_path = Path(sys.executable).resolve(strict=True)
    except (OSError, ValueError) as error:
        raise Rejected("audit_python_path_invalid") from error
    if configured:
        try:
            configured_path = Path(configured).resolve(strict=True)
        except (OSError, ValueError) as error:
            raise Rejected("audit_python_path_invalid") from error
        if configured_path != running_path:
            raise Rejected("audit_python_executable_mismatch")
    if sys.flags.isolated != 1 or sys.flags.dont_write_bytecode != 1:
        raise Rejected("audit_python_flags_mismatch")
    version = ".".join(str(value) for value in sys.version_info[:3])
    executable_sha256 = digest(read_bounded(running_path))
    kind = (
        "mise_configured"
        if version == MISE_PYTHON_VERSION
        else "local_frozen"
    )
    identity = {
        "implementation": sys.implementation.name,
        "version": version,
        "sha256": executable_sha256,
        "identity_kind": kind,
    }
    configured_mise_python(read_bounded(MISE_CONFIG))
    return checked_python_identity(identity)


def checked_invalidation_chain(data: bytes) -> dict[str, Any]:
    if digest(data) != EXPECTED_INVALIDATION_CHAIN_SHA256:
        raise Rejected("invalidation_chain_identity_mismatch")
    chain = decode_object(data, "invalidation_chain")
    entries = chain.get("entries")
    if (
        chain.get("schema") != 1
        or chain.get("chain_kind")
        != "rfc9114_review_application_invalidation_chain"
        or chain.get("standard") != "RFC9114"
        or chain.get("current_generation") != 3
        or not isinstance(entries, list)
        or [entry.get("generation") for entry in entries if isinstance(entry, dict)]
        != [1, 2]
        or any(entry.get("status") != "Rejected" for entry in entries)
    ):
        raise Rejected("invalidation_chain_contract_mismatch")
    return chain


def checked_artifact_manifest(
    data: bytes,
    *,
    tool_snapshot: bytes,
    launcher_snapshot: bytes,
    gate_snapshot: bytes,
    mise_snapshot: bytes,
) -> dict[str, Any]:
    manifest = decode_object(data, "artifact_manifest")
    artifacts = manifest.get("artifacts")
    expected = {
        "standards/audits/rfc9114/apply_review.py": digest(tool_snapshot),
        "standards/audits/rfc9114/launcher.py": digest(launcher_snapshot),
        "standards/audits/rfc9114/evidence_gate.py": digest(gate_snapshot),
        "standards/audits/rfc9114/candidate-inventory.json": EXPECTED_INPUTS[
            "candidate"
        ],
        "standards/audits/rfc9114/independent-review.json": EXPECTED_INPUTS[
            "review"
        ],
        "standards/audits/rfc9114/reviewed-source-manifest.json": (
            EXPECTED_SOURCE_MANIFEST_SHA256
        ),
        "standards/audits/rfc9114/invalidation-chain.json": (
            EXPECTED_INVALIDATION_CHAIN_SHA256
        ),
        "standards/audits/rfc9114/review-v1-invalidated.json": (
            "97385909eb2f695b751889a0a3e5d212fb53b6193b183de8e3fdbafd22903009"
        ),
        ".mise.toml": digest(mise_snapshot),
    }
    if (
        manifest.get("schema") != 1
        or manifest.get("manifest_kind") != "rfc9114_strict_inventory_canonical_inputs"
        or manifest.get("standard") != "RFC9114"
        or manifest.get("generation") != 3
        or manifest.get("expected_requirements_before_sha256")
        != EXPECTED_INPUTS["requirements"]
        or manifest.get("expected_requirements_after_sha256")
        != EXPECTED_OUTPUT_SHA256
        or manifest.get("release_policy")
        != {
            "pre_review_self_test_status": "StaticReady",
            "release_eligible_statuses": ["Ready"],
            "independent_review_required": True,
        }
        or manifest.get("python")
        != {
            "implementation": "cpython",
            "mise_version": MISE_PYTHON_VERSION,
            "local_frozen_identity": LOCAL_FROZEN_PYTHON,
        }
        or not isinstance(artifacts, list)
    ):
        raise Rejected("artifact_manifest_contract_mismatch")
    observed: dict[str, str] = {}
    for item in artifacts:
        if (
            not isinstance(item, dict)
            or set(item) != {"path", "sha256"}
            or not isinstance(item.get("path"), str)
            or not isinstance(item.get("sha256"), str)
            or item["path"] in observed
        ):
            raise Rejected("artifact_manifest_entry_invalid")
        observed[item["path"]] = item["sha256"]
    if observed != expected:
        raise Rejected("artifact_manifest_identity_mismatch")
    return manifest


def checked_launch_binding() -> dict[str, Any]:
    binding = globals().get("__audit_launch__")
    if not isinstance(binding, dict) or set(binding) != {
        "schema",
        "tool_relative_path",
        "tool_snapshot",
        "tool_sha256",
        "launcher_relative_path",
        "launcher_snapshot",
        "launcher_sha256",
        "gate_snapshot",
        "gate_sha256",
        "artifact_manifest_snapshot",
        "mise_config_snapshot",
        "python_implementation",
        "python_version",
        "python_executable_sha256",
    }:
        raise Rejected("audit_launch_binding_missing")
    tool_snapshot = binding.get("tool_snapshot")
    launcher_snapshot = binding.get("launcher_snapshot")
    gate_snapshot = binding.get("gate_snapshot")
    manifest_snapshot = binding.get("artifact_manifest_snapshot")
    mise_snapshot = binding.get("mise_config_snapshot")
    if (
        binding.get("schema") != 1
        or binding.get("tool_relative_path")
        != "standards/audits/rfc9114/apply_review.py"
        or binding.get("launcher_relative_path")
        != "standards/audits/rfc9114/launcher.py"
        or not isinstance(tool_snapshot, bytes)
        or not isinstance(launcher_snapshot, bytes)
        or not isinstance(gate_snapshot, bytes)
        or not isinstance(manifest_snapshot, bytes)
        or not isinstance(mise_snapshot, bytes)
        or binding.get("tool_sha256") != digest(tool_snapshot)
        or binding.get("launcher_sha256") != digest(launcher_snapshot)
        or binding.get("gate_sha256") != digest(gate_snapshot)
        or binding.get("python_implementation") != sys.implementation.name
        or binding.get("python_version")
        != ".".join(str(value) for value in sys.version_info[:3])
        or binding.get("python_executable_sha256")
        != digest(read_bounded(Path(sys.executable).resolve(strict=True)))
    ):
        raise Rejected("audit_launch_binding_invalid")
    checked_artifact_manifest(
        manifest_snapshot,
        tool_snapshot=tool_snapshot,
        launcher_snapshot=launcher_snapshot,
        gate_snapshot=gate_snapshot,
        mise_snapshot=mise_snapshot,
    )
    if read_bounded(AUDIT_DIRECTORY / "apply_review.py") != tool_snapshot:
        raise Rejected("audit_tool_disk_drift")
    if read_bounded(LAUNCHER) != launcher_snapshot:
        raise Rejected("audit_launcher_disk_drift")
    if read_bounded(EVIDENCE_GATE) != gate_snapshot:
        raise Rejected("audit_gate_disk_drift")
    if read_bounded(ARTIFACT_MANIFEST) != manifest_snapshot:
        raise Rejected("artifact_manifest_disk_drift")
    if read_bounded(MISE_CONFIG) != mise_snapshot:
        raise Rejected("mise_config_disk_drift")
    configured_mise_python(mise_snapshot)
    return binding


def lifecycle_report(
    mode: str, run_id: str, status: str, classification: str | None
) -> bytes:
    report = {
        "schema": 2,
        "report_kind": "rfc9114_strict_inventory_review_application",
        "status": status,
        "shareable": status not in {"Running"},
        "mode": mode,
        "run_id": run_id,
        "failure_classification": classification,
        "rerun_command": rerun_command(mode),
    }
    return (json.dumps(report, indent=2) + "\n").encode("utf-8")


def consume_report_pair(
    directory: Path,
    mode: str,
    *,
    expected_run_id: str | None = None,
    require_controls: bool = False,
) -> dict[str, Any]:
    try:
        canonical = read_bounded(directory / "report.json")
        per_mode = read_bounded(directory / f"report-{mode}.json")
    except FileNotFoundError as error:
        raise Rejected("report_pair_missing") from error
    if canonical != per_mode:
        raise Rejected("report_pair_bytes_mismatch")
    report = decode_object(canonical, "report_pair")
    if (
        report.get("schema") != 2
        or report.get("report_kind")
        != "rfc9114_strict_inventory_review_application"
        or report.get("mode") != mode
        or report.get("status") == "Running"
        or report.get("shareable") is not True
        or not isinstance(report.get("run_id"), str)
        or not RUN_ID_PATTERN.fullmatch(report["run_id"])
    ):
        raise Rejected("report_pair_contract_mismatch")
    if expected_run_id is not None and report["run_id"] != expected_run_id:
        raise Rejected("report_pair_run_mismatch")
    if require_controls:
        exact_pre_state = report.get("source_state_before") == "pre_review"
        expected_statuses = {
            ("red", "pre_review"): "ObservedRed",
            ("red", "reviewed"): "UnexpectedGreen",
            ("self-test", "pre_review"): "StaticReady",
            ("self-test", "reviewed"): "Ready",
            ("apply", "pre_review"): "Ready",
            ("apply", "reviewed"): "Ready",
        }
        if expected_statuses.get((mode, report.get("source_state_before"))) != report.get(
            "status"
        ):
            raise Rejected("report_status_policy_mismatch")
        validate_control_inventory(report.get("self_test_controls"), exact_pre_state)
        completion = report.get("completion")
        if (
            not isinstance(completion, dict)
            or completion.get("self_test_controls_completed")
            != len(expected_control_inventory(exact_pre_state))
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
            journal_object = decode_object(journal, "transaction_journal")
            if (
                journal_object.get("status") != "Committed"
                or journal_object.get("run_id") != report["run_id"]
            ):
                raise Rejected("report_transaction_not_committed")
        elif transaction != {"required": False}:
            raise Rejected("report_transaction_unexpected")
    return report


class ReportPublisher:
    """Keep the canonical report authoritative throughout publication."""

    def __init__(self, directory: Path, mode: str, run_id: str):
        self.directory = directory
        self.mode = mode
        self.run_id = run_id
        self.lock = ExclusiveDirectoryLock(
            directory / ".report-publication-lock",
            f"rfc9114-report:{run_id}\n".encode("ascii"),
        )
        self.started = False

    def begin(self) -> None:
        self.directory.mkdir(parents=True, exist_ok=True)
        self.lock.acquire()
        running = lifecycle_report(self.mode, self.run_id, "Running", None)
        atomic_generated_write(
            self.directory / "report.json",
            running,
            boundary_prefix="running_canonical",
        )
        if read_bounded(self.directory / "report.json") != running:
            raise Rejected("canonical_running_invalidation_failed")
        self.started = True

    def stage_final(
        self, report: bytes, *, hook: TransactionHook | None = None
    ) -> None:
        decoded = decode_object(report, "publication_report")
        if (
            decoded.get("mode") != self.mode
            or decoded.get("run_id") != self.run_id
            or decoded.get("status") == "Running"
            or decoded.get("shareable") is not True
        ):
            raise Rejected("publication_report_contract_mismatch")
        atomic_generated_write(
            self.directory / f"report-{self.mode}.json",
            report,
            hook=hook,
            boundary_prefix="per_mode",
        )
        if read_bounded(self.directory / f"report-{self.mode}.json") != report:
            raise Rejected("per_mode_report_not_durable")
        invoke_hook(hook, "after_per_mode_durable", self.directory / "report.json")

    def complete_final(
        self, report: bytes, *, hook: TransactionHook | None = None
    ) -> None:
        decoded = decode_object(report, "publication_report")
        atomic_generated_write(
            self.directory / "report.json",
            report,
            hook=hook,
            boundary_prefix="canonical",
        )
        consume_report_pair(
            self.directory,
            self.mode,
            expected_run_id=self.run_id,
            require_controls=decoded.get("status")
            in {"Ready", "StaticReady", "ObservedRed", "UnexpectedGreen"},
        )

    def publish_final(
        self, report: bytes, *, hook: TransactionHook | None = None
    ) -> None:
        self.stage_final(report, hook=hook)
        self.complete_final(report, hook=hook)

    def publish_rejected(self, classification: str) -> None:
        self.publish_final(
            lifecycle_report(
                self.mode, self.run_id, "Rejected", safe_category(classification)
            )
        )

    def close(self) -> None:
        self.lock.release()


def safe_category(value: str) -> str:
    return value if re.fullmatch(r"[a-z0-9_:]{1,160}", value) else "typed_rejection"


BASE_CONTROL_NAMES = (
    ("baseline_render", "accepted"),
    ("reviewed_counts", "accepted"),
    ("rendered_identity", "accepted"),
    ("reviewed_source_manifest", "accepted"),
    ("wrong_expected_output", "rendered_identity_mismatch"),
    ("source_manifest_identity", "source_manifest_identity_mismatch"),
    ("source_identity", "__SOURCE_IDENTITY__"),
    ("duplicate_candidate_id", "candidate_duplicate_id"),
    ("missing_assessment", "assessment_set_mismatch"),
    ("weak_implemented", "implemented_without_direct_evidence"),
    ("review_candidate_citation_drift", "assessment_candidate_mismatch"),
    ("traversal_citation", "evidence_path_invalid"),
    ("missing_test_evidence", "test_evidence_missing"),
    ("missing_current_symbol", "current_evidence_symbol_mismatch"),
)

INFRASTRUCTURE_CONTROL_NAMES = (
    ("comment_string_symbol_decoys", "rejected"),
    ("python_identity_drift", "audit_python_identity_mismatch"),
    ("wrong_replacement_identity", "rejected_without_write"),
    ("transaction_after_recovery", "transaction_target_identity_mismatch_preserved"),
    (
        "transaction_after_expected_validation",
        "transaction_claimed_identity_mismatch_preserved",
    ),
    ("transaction_after_claim", "transaction_publish_conflict_preserved"),
    ("transaction_before_publish", "transaction_publish_conflict_preserved"),
    (
        "transaction_after_publish",
        "transaction_post_publish_identity_mismatch_preserved",
    ),
    (
        "transaction_before_commit",
        "transaction_precommit_identity_mismatch_preserved",
    ),
    ("transaction_success", "committed"),
    ("report_stale_ready_invalidation", "canonical_running_first"),
    ("report_per_mode_after_stage", "canonical_running"),
    ("report_per_mode_before_replace", "canonical_running"),
    ("report_per_mode_after_replace", "canonical_running_mode_durable"),
    ("report_after_per_mode_durable", "canonical_running_mode_durable"),
    ("report_canonical_after_stage", "canonical_running_mode_durable"),
    ("report_canonical_before_replace", "canonical_running_mode_durable"),
    ("report_canonical_after_replace", "final_pair_durable"),
    ("report_pair_missing", "report_pair_missing"),
    ("report_pair_tampered", "report_pair_bytes_mismatch"),
    ("report_pair_substituted", "report_pair_contract_mismatch"),
    ("report_pair_stale_run", "report_pair_run_mismatch"),
    ("post_publication_input_drift", "input_drift_after_publication"),
    ("post_publication_source_drift", "evidence_source_drift_after_publication"),
    ("post_publication_tool_drift", "audit_tool_drift_after_publication"),
    ("post_publication_launcher_drift", "audit_launcher_drift_after_publication"),
    ("exclusive_lock_busy", "exclusive_lock_busy"),
    ("mandatory_inventory_empty", "control_inventory_count_mismatch"),
    ("mandatory_inventory_missing", "control_inventory_count_mismatch"),
    ("mandatory_inventory_substituted", "control_inventory_entry_mismatch"),
    ("exact_inventory", "accepted"),
)


def expected_control_inventory(exact_pre_state: bool) -> tuple[tuple[str, str], ...]:
    source_identity = (
        "input_identity_mismatch"
        if exact_pre_state
        else "post_requirements_identity_mismatch"
    )
    base = tuple(
        (name, source_identity if observed == "__SOURCE_IDENTITY__" else observed)
        for name, observed in BASE_CONTROL_NAMES
    )
    return base + INFRASTRUCTURE_CONTROL_NAMES


def validate_inventory_exact(
    value: Any, expected: tuple[tuple[str, str], ...]
) -> None:
    if not isinstance(value, list) or len(value) != len(expected):
        raise Rejected("control_inventory_count_mismatch")
    observed: list[tuple[str, str]] = []
    for item in value:
        if (
            not isinstance(item, dict)
            or set(item) != {"name", "observed"}
            or not isinstance(item.get("name"), str)
            or not isinstance(item.get("observed"), str)
        ):
            raise Rejected("control_inventory_entry_invalid")
        observed.append((item["name"], item["observed"]))
    if tuple(observed) != expected:
        raise Rejected("control_inventory_entry_mismatch")


def validate_control_inventory(value: Any, exact_pre_state: bool) -> None:
    validate_inventory_exact(value, expected_control_inventory(exact_pre_state))


def require_equal(expected: Any, observed: Any, category: str) -> None:
    if observed != expected:
        raise Rejected(category)


def replace_external(path: Path, data: bytes) -> None:
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{path.name}.external-", dir=path.parent
    )
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
        fsync_parent(path)
    finally:
        try:
            temporary.unlink(missing_ok=True)
        except OSError:
            pass


def transaction_race_control(
    directory: Path,
    boundary: str,
    expected_category: str,
) -> None:
    case = directory / boundary
    case.mkdir()
    target = case / "target.json"
    original = b'{"state":"original"}\n'
    intended = b'{"state":"intended"}\n'
    concurrent = f'{{"state":"concurrent-{boundary}"}}\n'.encode("ascii")
    durable_new_file(target, original)

    def inject(observed_boundary: str, observed_target: Path) -> None:
        if observed_boundary == boundary:
            replace_external(observed_target, concurrent)

    run_id = digest(boundary.encode("ascii"))[:32]
    transaction = LosslessTargetTransaction(
        target,
        original,
        intended,
        case / "recovery",
        run_id,
        hook=inject,
    )
    try:
        transaction.replace()
    except Rejected as error:
        category = str(error)
        transaction.rollback(category)
        if category != expected_category:
            raise Rejected(f"transaction_control_wrong_category:{boundary}") from error
    else:
        raise Rejected(f"transaction_control_accepted:{boundary}")

    recovery = transaction.directory
    if (
        read_bounded(recovery / "original.bin") != original
        or read_bounded(recovery / "intended.bin") != intended
        or read_bounded(target) != concurrent
    ):
        raise Rejected(f"transaction_control_value_lost:{boundary}")
    retained = []
    for path in (transaction.claimed_path, transaction.concurrent_path):
        if path.exists():
            retained.append(read_bounded(path))
    if original not in retained and read_bounded(recovery / "original.bin") != original:
        raise Rejected(f"transaction_control_original_lost:{boundary}")


def report_boundary_control(directory: Path, boundary: str) -> str:
    case = directory / boundary
    case.mkdir()
    run_id = digest(("report:" + boundary).encode("ascii"))[:32]
    old = lifecycle_report("self-test", "f" * 32, "Ready", None)
    atomic_generated_write(case / "report.json", old)
    publisher = ReportPublisher(case, "self-test", run_id)
    publisher.begin()
    running = decode_object(read_bounded(case / "report.json"), "running_fixture")
    if running.get("status") != "Running" or running.get("run_id") != run_id:
        raise Rejected("report_control_running_missing")
    final = lifecycle_report("self-test", run_id, "Rejected", "fixture_rejection")

    def inject(observed_boundary: str, _target: Path) -> None:
        if observed_boundary == boundary:
            raise Rejected("injected_publication_failure")

    expect_rejection(
        boundary,
        "injected_publication_failure",
        lambda: publisher.publish_final(final, hook=inject),
    )
    canonical = read_bounded(case / "report.json")
    canonical_object = decode_object(canonical, "canonical_fixture")
    mode_path = case / "report-self-test.json"
    try:
        if boundary == "canonical_after_replace":
            consume_report_pair(case, "self-test", expected_run_id=run_id)
            result = "final_pair_durable"
        else:
            if canonical_object.get("status") != "Running":
                raise Rejected("report_control_canonical_not_running")
            mode_durable = mode_path.exists() and read_bounded(mode_path) == final
            result = (
                "canonical_running_mode_durable"
                if mode_durable
                else "canonical_running"
            )
    finally:
        publisher.close()
    return result


def infrastructure_self_test(_output: bytes) -> list[dict[str, str]]:
    controls: list[dict[str, str]] = []
    decoy_source = (
        b'// pub fn comment_decoy() { Nil }\n'
        b'pub const text = "fn string_decoy() { Nil }"\n'
        b'pub fn live(first: Int, callback: fn(Int, Int) -> Int) { Nil }\n'
    )
    if gleam_function_arities(decoy_source) != {"live": 2}:
        raise Rejected("gleam_symbol_tokenizer_control_failed")
    controls.append(
        {"name": "comment_string_symbol_decoys", "observed": "rejected"}
    )

    wrong_python = {
        "implementation": "cpython",
        "version": "3.12.14",
        "sha256": "0" * 64,
        "identity_kind": "local_frozen",
    }
    expect_rejection(
        "python_identity_drift",
        "audit_python_identity_mismatch",
        lambda: checked_python_identity(wrong_python),
    )
    controls.append(
        {
            "name": "python_identity_drift",
            "observed": "audit_python_identity_mismatch",
        }
    )

    EVIDENCE_DIRECTORY.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(
        prefix=".rfc9114-v3-self-test-", dir=EVIDENCE_DIRECTORY
    ) as temporary_name:
        directory = Path(temporary_name)
        wrong_target = directory / "wrong-replacement.json"
        original = b'{"state":"original"}\n'
        intended = b'{"state":"intended"}\n'
        durable_new_file(wrong_target, original)
        expect_rejection(
            "wrong_replacement_identity",
            "rendered_identity_mismatch",
            lambda: assert_rendered_identity(intended, "0" * 64),
        )
        if read_bounded(wrong_target) != original:
            raise Rejected("wrong_replacement_control_modified_target")
        controls.append(
            {
                "name": "wrong_replacement_identity",
                "observed": "rejected_without_write",
            }
        )

        race_cases = (
            (
                "after_recovery",
                "transaction_target_identity_mismatch",
                "transaction_target_identity_mismatch_preserved",
            ),
            (
                "after_expected_validation",
                "transaction_claimed_identity_mismatch",
                "transaction_claimed_identity_mismatch_preserved",
            ),
            (
                "after_claim",
                "transaction_publish_conflict",
                "transaction_publish_conflict_preserved",
            ),
            (
                "before_publish",
                "transaction_publish_conflict",
                "transaction_publish_conflict_preserved",
            ),
            (
                "after_publish",
                "transaction_post_publish_identity_mismatch",
                "transaction_post_publish_identity_mismatch_preserved",
            ),
            (
                "before_commit",
                "transaction_precommit_identity_mismatch",
                "transaction_precommit_identity_mismatch_preserved",
            ),
        )
        for boundary, category, observed in race_cases:
            transaction_race_control(directory, boundary, category)
            controls.append({"name": f"transaction_{boundary}", "observed": observed})

        success_case = directory / "transaction-success"
        success_case.mkdir()
        success_target = success_case / "target.json"
        durable_new_file(success_target, original)
        success = LosslessTargetTransaction(
            success_target,
            original,
            intended,
            success_case / "recovery",
            "1" * 32,
        )
        success.replace()
        success.commit()
        if (
            read_bounded(success_target) != intended
            or decode_object(
                read_bounded(success.journal_path), "transaction_success_journal"
            ).get("status")
            != "Committed"
        ):
            raise Rejected("transaction_success_control_failed")
        controls.append({"name": "transaction_success", "observed": "committed"})

        stale_case = directory / "stale-ready"
        stale_case.mkdir()
        atomic_generated_write(
            stale_case / "report.json",
            lifecycle_report("self-test", "e" * 32, "Ready", None),
        )
        stale_publisher = ReportPublisher(stale_case, "self-test", "2" * 32)
        stale_publisher.begin()
        stale_running = decode_object(
            read_bounded(stale_case / "report.json"), "stale_running"
        )
        stale_publisher.close()
        if (
            stale_running.get("status") != "Running"
            or stale_running.get("run_id") != "2" * 32
        ):
            raise Rejected("stale_ready_invalidation_failed")
        controls.append(
            {
                "name": "report_stale_ready_invalidation",
                "observed": "canonical_running_first",
            }
        )

        report_boundaries = (
            "per_mode_after_stage",
            "per_mode_before_replace",
            "per_mode_after_replace",
            "after_per_mode_durable",
            "canonical_after_stage",
            "canonical_before_replace",
            "canonical_after_replace",
        )
        for boundary in report_boundaries:
            observed = report_boundary_control(directory, boundary)
            controls.append({"name": f"report_{boundary}", "observed": observed})

        pair_run_id = "3" * 32
        pair_final = lifecycle_report(
            "self-test", pair_run_id, "Rejected", "fixture_rejection"
        )

        missing_case = directory / "pair-missing"
        missing_case.mkdir()
        atomic_generated_write(missing_case / "report.json", pair_final)
        expect_rejection(
            "report_pair_missing",
            "report_pair_missing",
            lambda: consume_report_pair(missing_case, "self-test"),
        )
        controls.append(
            {"name": "report_pair_missing", "observed": "report_pair_missing"}
        )

        tampered_case = directory / "pair-tampered"
        tampered_case.mkdir()
        atomic_generated_write(tampered_case / "report.json", pair_final)
        atomic_generated_write(
            tampered_case / "report-self-test.json", pair_final + b" "
        )
        expect_rejection(
            "report_pair_tampered",
            "report_pair_bytes_mismatch",
            lambda: consume_report_pair(tampered_case, "self-test"),
        )
        controls.append(
            {
                "name": "report_pair_tampered",
                "observed": "report_pair_bytes_mismatch",
            }
        )

        substituted_case = directory / "pair-substituted"
        substituted_case.mkdir()
        substituted = lifecycle_report(
            "red", pair_run_id, "Rejected", "fixture_rejection"
        )
        atomic_generated_write(substituted_case / "report.json", substituted)
        atomic_generated_write(
            substituted_case / "report-self-test.json", substituted
        )
        expect_rejection(
            "report_pair_substituted",
            "report_pair_contract_mismatch",
            lambda: consume_report_pair(substituted_case, "self-test"),
        )
        controls.append(
            {
                "name": "report_pair_substituted",
                "observed": "report_pair_contract_mismatch",
            }
        )

        stale_run_case = directory / "pair-stale-run"
        stale_run_case.mkdir()
        atomic_generated_write(stale_run_case / "report.json", pair_final)
        atomic_generated_write(
            stale_run_case / "report-self-test.json", pair_final
        )
        expect_rejection(
            "report_pair_stale_run",
            "report_pair_run_mismatch",
            lambda: consume_report_pair(
                stale_run_case, "self-test", expected_run_id="4" * 32
            ),
        )
        controls.append(
            {
                "name": "report_pair_stale_run",
                "observed": "report_pair_run_mismatch",
            }
        )

        expect_rejection(
            "post_publication_input_drift",
            "input_drift_after_publication",
            lambda: require_equal(
                b"expected", b"changed", "input_drift_after_publication"
            ),
        )
        controls.append(
            {
                "name": "post_publication_input_drift",
                "observed": "input_drift_after_publication",
            }
        )
        expect_rejection(
            "post_publication_source_drift",
            "evidence_source_drift_after_publication",
            lambda: require_equal(
                {"sha256": "expected"},
                {"sha256": "changed"},
                "evidence_source_drift_after_publication",
            ),
        )
        controls.append(
            {
                "name": "post_publication_source_drift",
                "observed": "evidence_source_drift_after_publication",
            }
        )
        expect_rejection(
            "post_publication_tool_drift",
            "audit_tool_drift_after_publication",
            lambda: require_equal(
                digest(b"expected"),
                digest(b"changed"),
                "audit_tool_drift_after_publication",
            ),
        )
        controls.append(
            {
                "name": "post_publication_tool_drift",
                "observed": "audit_tool_drift_after_publication",
            }
        )
        expect_rejection(
            "post_publication_launcher_drift",
            "audit_launcher_drift_after_publication",
            lambda: require_equal(
                digest(b"expected"),
                digest(b"changed"),
                "audit_launcher_drift_after_publication",
            ),
        )
        controls.append(
            {
                "name": "post_publication_launcher_drift",
                "observed": "audit_launcher_drift_after_publication",
            }
        )

        lock_path = directory / "lock-busy"
        first_lock = ExclusiveDirectoryLock(lock_path, b"first\n")
        first_lock.acquire()
        second_lock = ExclusiveDirectoryLock(lock_path, b"second\n")
        try:
            expect_rejection(
                "exclusive_lock_busy", "exclusive_lock_busy", second_lock.acquire
            )
        finally:
            first_lock.release()
        controls.append(
            {"name": "exclusive_lock_busy", "observed": "exclusive_lock_busy"}
        )

        inventory_fixture = (
            ("fixture_alpha", "accepted"),
            ("fixture_beta", "typed_rejection"),
        )
        inventory_value = [
            {"name": name, "observed": observed}
            for name, observed in inventory_fixture
        ]
        expect_rejection(
            "mandatory_inventory_empty",
            "control_inventory_count_mismatch",
            lambda: validate_inventory_exact([], inventory_fixture),
        )
        controls.append(
            {
                "name": "mandatory_inventory_empty",
                "observed": "control_inventory_count_mismatch",
            }
        )
        expect_rejection(
            "mandatory_inventory_missing",
            "control_inventory_count_mismatch",
            lambda: validate_inventory_exact(inventory_value[:-1], inventory_fixture),
        )
        controls.append(
            {
                "name": "mandatory_inventory_missing",
                "observed": "control_inventory_count_mismatch",
            }
        )
        substituted_inventory = copy.deepcopy(inventory_value)
        substituted_inventory[1]["observed"] = "accepted"
        expect_rejection(
            "mandatory_inventory_substituted",
            "control_inventory_entry_mismatch",
            lambda: validate_inventory_exact(
                substituted_inventory, inventory_fixture
            ),
        )
        controls.append(
            {
                "name": "mandatory_inventory_substituted",
                "observed": "control_inventory_entry_mismatch",
            }
        )
        validate_inventory_exact(inventory_value, inventory_fixture)
        controls.append({"name": "exact_inventory", "observed": "accepted"})

    return controls


def checked_mode(arguments: list[str]) -> str:
    allowed = {"red", "render", "apply", "self-test"}
    if len(arguments) != 1 or arguments[0] not in allowed:
        raise Rejected("invalid_arguments")
    return arguments[0]


def platform_identity() -> dict[str, str]:
    return {
        "system": platform.system().lower(),
        "release": platform.release(),
        "machine": platform.machine().lower(),
    }


def post_publication_validate(result: dict[str, Any]) -> None:
    expected_requirements = result["expected_requirements_after"]
    expected_files = (
        expected_requirements,
        result["candidate"],
        result["review"],
        result["source_manifest_bytes"],
        result["invalidation_chain_bytes"],
        result["artifact_manifest_bytes"],
        result["mise_config_bytes"],
    )
    exact_file_bytes(
        (
            REQUIREMENTS,
            CANDIDATE,
            REVIEW,
            SOURCE_MANIFEST,
            INVALIDATION_CHAIN,
            ARTIFACT_MANIFEST,
            MISE_CONFIG,
        ),
        expected_files,
        "input_drift_after_publication",
    )
    if result["source_state"] == "pre_review":
        checked_inputs(
            result["requirements_before"],
            result["candidate"],
            result["review"],
        )
    else:
        validate_post_state(
            expected_requirements, result["candidate"], result["review"]
        )
    checked_invalidation_chain(result["invalidation_chain_bytes"])
    current_source = checked_source_manifest(
        result["output"],
        result["candidate"],
        result["review"],
        result["source_manifest_bytes"],
    )
    require_equal(
        result["source_contract"],
        current_source,
        "evidence_source_drift_after_publication",
    )
    binding = checked_launch_binding()
    require_equal(
        result["tool_sha256"],
        binding["tool_sha256"],
        "audit_tool_drift_after_publication",
    )
    require_equal(
        result["launcher_sha256"],
        binding["launcher_sha256"],
        "audit_launcher_drift_after_publication",
    )
    require_equal(
        result["gate_sha256"],
        binding["gate_sha256"],
        "audit_gate_drift_after_publication",
    )
    require_equal(
        result["python_identity"],
        audited_python_identity(),
        "execution_identity_drift_after_publication",
    )
    require_equal(
        result["platform_identity"],
        platform_identity(),
        "platform_identity_drift_after_publication",
    )


def prepare_result(
    mode: str,
    run_id: str,
    transaction_holder: list[LosslessTargetTransaction],
) -> dict[str, Any]:
    binding = checked_launch_binding()
    python_identity = audited_python_identity()
    current_platform = platform_identity()
    requirements = read_bounded(REQUIREMENTS)
    candidate = read_bounded(CANDIDATE)
    review = read_bounded(REVIEW)
    source_manifest_bytes = read_bounded(SOURCE_MANIFEST)
    invalidation_chain_bytes = read_bounded(INVALIDATION_CHAIN)
    artifact_manifest_bytes = read_bounded(ARTIFACT_MANIFEST)
    mise_config_bytes = read_bounded(MISE_CONFIG)
    checked_invalidation_chain(invalidation_chain_bytes)
    checked_artifact_manifest(
        artifact_manifest_bytes,
        tool_snapshot=binding["tool_snapshot"],
        launcher_snapshot=binding["launcher_snapshot"],
        gate_snapshot=binding["gate_snapshot"],
        mise_snapshot=mise_config_bytes,
    )
    configured_mise_python(mise_config_bytes)

    source_sha256 = digest(requirements)
    if source_sha256 == EXPECTED_INPUTS["requirements"]:
        source_state = "pre_review"
        output = build_output(requirements, candidate, review)
        controls_completed, controls = semantic_self_test(
            requirements,
            candidate,
            review,
            source_manifest_bytes,
            exact_pre_state=True,
        )
    elif source_sha256 == EXPECTED_OUTPUT_SHA256:
        source_state = "reviewed"
        validate_post_state(requirements, candidate, review)
        output = requirements
        controls_completed, controls = semantic_self_test(
            requirements,
            candidate,
            review,
            source_manifest_bytes,
            exact_pre_state=False,
        )
    else:
        raise Rejected("requirements_state_identity_mismatch")
    assert_rendered_identity(output)
    source_contract = checked_source_manifest(
        output, candidate, review, source_manifest_bytes
    )

    current = decode_object(requirements, "current")
    before_counts = disposition_counts(current)
    after_counts = before_counts
    after_state = source_state
    applied_now = False
    failure_classification: str | None = None
    expected_requirements_after = requirements

    if mode == "red":
        status = (
            "ObservedRed"
            if source_state == "pre_review" and before_counts != EXPECTED_COUNTS
            else "UnexpectedGreen"
        )
        failure_classification = (
            "review_not_applied" if status == "ObservedRed" else "red_not_observed"
        )
    elif mode == "render":
        status = "Rendered"
    elif mode == "apply":
        if source_state == "pre_review":
            exact_file_bytes(
                (
                    REQUIREMENTS,
                    CANDIDATE,
                    REVIEW,
                    SOURCE_MANIFEST,
                    INVALIDATION_CHAIN,
                    ARTIFACT_MANIFEST,
                    MISE_CONFIG,
                ),
                (
                    requirements,
                    candidate,
                    review,
                    source_manifest_bytes,
                    invalidation_chain_bytes,
                    artifact_manifest_bytes,
                    mise_config_bytes,
                ),
                "input_drift_before_apply",
            )
            guarded_output = build_output(requirements, candidate, review)
            assert_rendered_identity(guarded_output)
            if guarded_output != output:
                raise Rejected("rendered_output_drift_before_apply")
            require_equal(
                source_contract,
                checked_source_manifest(
                    guarded_output, candidate, review, source_manifest_bytes
                ),
                "evidence_source_drift_before_apply",
            )
            transaction = LosslessTargetTransaction(
                REQUIREMENTS,
                requirements,
                output,
                EVIDENCE_DIRECTORY / "transactions",
                run_id,
            )
            transaction_holder.append(transaction)
            transaction.replace()
            applied_now = True
        expected_requirements_after = output
        after_counts = validate_post_state(
            read_bounded(REQUIREMENTS), candidate, review
        )
        after_state = "reviewed"
        status = "Ready"
    else:
        status = "Ready" if source_state == "reviewed" else "StaticReady"
        if status == "StaticReady":
            failure_classification = "application_pending"

    result = {
        "mode": mode,
        "run_id": run_id,
        "status": status,
        "source_state": source_state,
        "source_state_after": after_state,
        "applied_now": applied_now,
        "requirements_before": requirements,
        "expected_requirements_after": expected_requirements_after,
        "candidate": candidate,
        "review": review,
        "source_manifest_bytes": source_manifest_bytes,
        "invalidation_chain_bytes": invalidation_chain_bytes,
        "artifact_manifest_bytes": artifact_manifest_bytes,
        "mise_config_bytes": mise_config_bytes,
        "output": output,
        "source_contract": source_contract,
        "python_identity": python_identity,
        "platform_identity": current_platform,
        "tool_sha256": binding["tool_sha256"],
        "launcher_sha256": binding["launcher_sha256"],
        "gate_sha256": binding["gate_sha256"],
        "before_counts": before_counts,
        "after_counts": after_counts,
        "controls": controls,
        "controls_completed": controls_completed,
        "failure_classification": failure_classification,
        "transaction": transaction_holder[0] if transaction_holder else None,
    }
    return result


def result_report(result: dict[str, Any]) -> bytes:
    source_contract = result["source_contract"]
    python_identity = result["python_identity"]
    transaction = result["transaction"]
    if transaction is None:
        target_transaction = {"required": False}
    else:
        relative_journal = transaction.journal_path.relative_to(ROOT).as_posix()
        target_transaction = {
            "required": True,
            "run_id": result["run_id"],
            "journal": relative_journal,
            "committed_journal_sha256": digest(
                transaction.journal_bytes("Committed")
            ),
        }
    report = {
        "schema": 2,
        "report_kind": "rfc9114_strict_inventory_review_application",
        "status": result["status"],
        "shareable": True,
        "mode": result["mode"],
        "run_id": result["run_id"],
        "source_state_before": result["source_state"],
        "source_state_after": result["source_state_after"],
        "applied_now": result["applied_now"],
        "input_sha256": {
            "requirements": digest(result["requirements_before"]),
            "candidate": digest(result["candidate"]),
            "review": digest(result["review"]),
            "reviewed_source_manifest": digest(result["source_manifest_bytes"]),
            "invalidation_chain": digest(result["invalidation_chain_bytes"]),
            "artifact_manifest": digest(result["artifact_manifest_bytes"]),
            "mise_config": digest(result["mise_config_bytes"]),
            "tool_snapshot": result["tool_sha256"],
            "launcher_snapshot": result["launcher_sha256"],
            "gate_snapshot": result["gate_sha256"],
            "python_executable": python_identity["sha256"],
        },
        "expected_output_sha256": EXPECTED_OUTPUT_SHA256,
        "before_counts": result["before_counts"],
        "after_counts": result["after_counts"],
        "reviewed_counts": EXPECTED_COUNTS,
        "rendered_sha256": digest(result["output"]),
        "result_requirements_sha256": digest(
            result["expected_requirements_after"]
        ),
        "reviewed_source_evidence": {
            "source_files": source_contract["source_files"],
            "citation_references": source_contract["citation_references"],
            "unique_citations": source_contract["unique_citations"],
            "source_aggregate_sha256": source_contract[
                "source_aggregate_sha256"
            ],
        },
        "scope": {
            "standard": "RFC9114",
            "canonical_rows": 215,
            "independently_assessed_rows": 161,
        },
        "completion": {
            "rows_completed": 215,
            "self_test_controls_completed": result["controls_completed"],
        },
        "self_test_controls": result["controls"],
        "failure_classification": result["failure_classification"],
        "python": python_identity,
        "execution_platform": result["platform_identity"],
        "execution_binding": {
            "isolated": True,
            "bytecode_disabled": True,
            "mise_python_version": MISE_PYTHON_VERSION,
            "local_frozen_python": python_identity["identity_kind"]
            == "local_frozen",
        },
        "target_transaction": target_transaction,
        "rerun_environment": {
            "selector": "python_command_resolved_by_the_outer_environment",
            "optional_consistency_variable": "HTTP_AUDIT_PYTHON",
            "executable_sha256": python_identity["sha256"],
        },
        "rerun_command": rerun_command(result["mode"]),
    }
    return (json.dumps(report, indent=2) + "\n").encode("utf-8")


def execute() -> int:
    mode = checked_mode(sys.argv[1:])
    run_id = digest(os.urandom(32))[:32]
    publisher: ReportPublisher | None = None
    transaction_holder: list[LosslessTargetTransaction] = []
    if mode != "render":
        publisher = ReportPublisher(EVIDENCE_DIRECTORY, mode, run_id)
    try:
        if publisher is not None:
            publisher.begin()
        result = prepare_result(mode, run_id, transaction_holder)
        if mode == "render":
            post_publication_validate(result)
            sys.stdout.buffer.write(result["output"])
            sys.stdout.buffer.flush()
            post_publication_validate(result)
            return 0

        report = result_report(result)
        assert publisher is not None
        publisher.stage_final(report)
        post_publication_validate(result)
        if transaction_holder:
            transaction_holder[0].commit()
        publisher.complete_final(report)
        post_publication_validate(result)
        consume_report_pair(
            EVIDENCE_DIRECTORY,
            mode,
            expected_run_id=run_id,
            require_controls=True,
        )
        print(
            f"rfc9114_strict_inventory status={result['status']} "
            f"controls={result['controls_completed']} "
            f"implemented={EXPECTED_COUNTS['Implemented']} "
            f"not_applicable={EXPECTED_COUNTS['NotApplicable']} "
            f"open={EXPECTED_COUNTS['Open']}"
        )
        return 0 if result["status"] in {"Ready", "StaticReady", "ObservedRed"} else 1
    except Rejected as error:
        category = safe_category(str(error))
        if transaction_holder:
            transaction = transaction_holder[0]
            if transaction.state not in {"rejected", "committed"}:
                try:
                    transaction.rollback(category)
                except Exception:
                    category = "transaction_rollback_failed"
        if publisher is not None and publisher.started:
            try:
                publisher.publish_rejected(category)
            except Exception:
                category = "evidence_publication_failed"
        print(
            f"rfc9114_strict_inventory status=Rejected category={category}",
            file=sys.stderr,
        )
        return 1
    except Exception:
        category = "unexpected_internal_failure"
        if transaction_holder:
            transaction = transaction_holder[0]
            if transaction.state not in {"rejected", "committed"}:
                try:
                    transaction.rollback(category)
                except Exception:
                    category = "transaction_rollback_failed"
        if publisher is not None and publisher.started:
            try:
                publisher.publish_rejected(category)
            except Exception:
                category = "evidence_publication_failed"
        print(
            f"rfc9114_strict_inventory status=Rejected category={category}",
            file=sys.stderr,
        )
        return 1
    finally:
        if publisher is not None:
            try:
                publisher.close()
            except Exception:
                pass


if __name__ == "__main__":
    raise SystemExit(execute())

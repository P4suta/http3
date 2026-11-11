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
from pathlib import PurePosixPath
import re
from typing import Any, Callable

EXPECTED_INPUTS = {
    "requirements": "6d9c34e9311c73cc9540b5b51a133c755d6225d88015068169a44369842bf533",
    "candidate": "ee42fef95798249cecf1b333cbf613a7ffa7f7a302cd0d3a7e438bd9efbf1243",
    "review": "74cc3dc2db970c4eb3a36e9fd73f11886fbc80dfdc3ab3aa510a5b0b0170fbb9",
}
EXPECTED_OUTPUT_SHA256 = "76bdca016340f90dc8a75157b5fc4b04951e151eae3ed1cd000000ba0cd7115a"
EXPECTED_SOURCE_MANIFEST_SHA256 = (
    "8d047bee7cd06e314449c525a6a32d6d090e53c886ddd42bb4472b99712f699a"
)
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
MAX_ROWS = 1000
EVIDENCE_PATH_PATTERN = re.compile(
    r"^(?:src|test|packages/(?:http3|quic_core)/(?:src|test))/"
    r"[A-Za-z0-9_./-]+\.gleam$"
)
SYMBOL_PATTERN = re.compile(r"^[A-Za-z][A-Za-z0-9_]*$")


class Rejected(ValueError):
    """A typed, non-secret audit rejection."""


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def decode_object(data: bytes, category: str) -> dict[str, Any]:
    def closed_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        value: dict[str, Any] = {}
        for key, item in pairs:
            if key in value:
                raise Rejected(f"{category}_duplicate_key")
            value[key] = item
        return value

    try:
        value = json.loads(data, object_pairs_hook=closed_pairs)
    except Rejected:
        raise
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


def stable_source_bytes(_relative: str) -> tuple[bytes, Any]:
    """Fail closed until the v4 descriptor-bound reader is injected."""

    raise Rejected("domain_io_not_bound")


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


def infrastructure_self_test(_output: bytes) -> list[dict[str, str]]:
    raise Rejected("domain_infrastructure_not_bound")


def validate_control_inventory(_value: Any, _exact_pre_state: bool) -> None:
    raise Rejected("domain_inventory_not_bound")


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

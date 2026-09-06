#!/usr/bin/env python3
"""Pinned pylsqpack half of the bidirectional QPACK differential gate."""

from __future__ import annotations

import hashlib
import json
import sys
import tempfile
from pathlib import Path
from typing import Any

import pylsqpack


EXPECTED_VERSION = "0.3.24"
SCHEMA = 1
CAPACITY = 512
BLOCKED_STREAMS = 8


def repository_root() -> Path:
    return Path(__file__).resolve().parents[4]


def require(condition: bool, message: str) -> None:
    if not condition:
        raise RuntimeError(message)


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def header_json(headers: list[tuple[bytes, bytes]]) -> list[dict[str, str]]:
    return [{"name": name.hex(), "value": value.hex()} for name, value in headers]


def headers_from_json(values: list[dict[str, str]]) -> list[tuple[bytes, bytes]]:
    headers: list[tuple[bytes, bytes]] = []
    for value in values:
        name = bytes.fromhex(value["name"])
        field_value = bytes.fromhex(value["value"])
        require(bool(name), "empty header name")
        headers.append((name, field_value))
    return headers


def write_json(path: Path, value: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    encoded = json.dumps(value, sort_keys=True, separators=(",", ":"))
    path.write_text(encoded + "\n", encoding="utf-8")


def oracle_header_sets() -> list[tuple[str, list[tuple[bytes, bytes]]]]:
    return [
        (
            "static-request",
            [
                (b":method", b"GET"),
                (b":scheme", b"https"),
                (b":authority", b"example.com"),
                (b":path", b"/"),
                (b"accept-encoding", b"gzip, deflate, br"),
            ],
        ),
        (
            "literal-huffman",
            [
                (b"x-qpack-differential", b"alpha.example.test/one"),
                (b"cache-control", b"no-cache"),
            ],
        ),
        (
            "repeat-alpha-seed",
            [(b"x-repeat", b"alpha"), (b"cache-control", b"no-cache")],
        ),
        (
            "repeat-alpha-dynamic",
            [(b"x-repeat", b"alpha"), (b"cache-control", b"no-cache")],
        ),
        (
            "repeat-alpha-known",
            [(b"x-repeat", b"alpha"), (b"cache-control", b"no-cache")],
        ),
        (
            "repeat-beta-seed",
            [(b"x-repeat", b"alpha"), (b"x-other", b"beta")],
        ),
        (
            "repeat-beta-dynamic",
            [(b"x-repeat", b"alpha"), (b"x-other", b"beta")],
        ),
        (
            "binary-literal",
            [(b"x-binary", bytes([0, 255, 127, 1])), (b":method", b"POST")],
        ),
        (
            "long-value-seed",
            [(b"x-long", b"0123456789abcdef" * 12)],
        ),
        (
            "long-value-dynamic",
            [(b"x-long", b"0123456789abcdef" * 12)],
        ),
    ]


def generate(path: Path) -> None:
    require(pylsqpack.__version__ == EXPECTED_VERSION, "unexpected pylsqpack version")
    encoder = pylsqpack.Encoder()
    decoder = pylsqpack.Decoder(CAPACITY, BLOCKED_STREAMS)
    prefix = encoder.apply_settings(CAPACITY, BLOCKED_STREAMS)
    require(decoder.feed_encoder(prefix) == [], "settings unblocked a stream")

    steps: list[dict[str, Any]] = []
    blocked_cases = 0
    dynamic_steps = 0
    for index, (case_id, headers) in enumerate(oracle_header_sets()):
        stream_id = index * 4
        encoder_stream, field_section = encoder.encode(stream_id, headers)
        if encoder_stream:
            dynamic_steps += 1
            try:
                control, decoded = decoder.feed_header(stream_id, field_section)
            except pylsqpack.StreamBlocked:
                delivery = "header_first"
                blocked_cases += 1
                unblocked = decoder.feed_encoder(encoder_stream)
                require(stream_id in unblocked, f"{case_id}: stream was not unblocked")
                control, decoded = decoder.resume_header(stream_id)
            else:
                delivery = "header_before_encoder_unblocked"
                require(
                    decoder.feed_encoder(encoder_stream) == [],
                    f"{case_id}: unexpected unblocked stream",
                )
        else:
            delivery = "encoder_first"
            control, decoded = decoder.feed_header(stream_id, field_section)

        require(decoded == headers, f"{case_id}: pylsqpack self-round-trip mismatch")
        if control:
            encoder.feed_decoder(control)
        steps.append(
            {
                "id": case_id,
                "stream_id": stream_id,
                "delivery": delivery,
                "encoder_stream": encoder_stream.hex(),
                "field_section": field_section.hex(),
                "decoder_stream": control.hex(),
                "headers": header_json(headers),
            }
        )

    require(blocked_cases >= 2, "oracle corpus lost blocked-stream coverage")
    require(dynamic_steps >= 2, "oracle corpus lost dynamic-table coverage")
    lock = repository_root() / "packages/http3/test/interop/requirements.lock"
    write_json(
        path,
        {
            "schema": SCHEMA,
            "direction": "pylsqpack-to-http3",
            "oracle": {
                "name": "pylsqpack",
                "version": pylsqpack.__version__,
                "requirements_lock": "packages/http3/test/interop/requirements.lock",
                "requirements_lock_sha256": sha256(lock),
            },
            "configuration": {
                "maximum_table_capacity": CAPACITY,
                "maximum_blocked_streams": BLOCKED_STREAMS,
            },
            "encoder_stream_prefix": prefix.hex(),
            "steps": steps,
        },
    )


def verify(source: Path, report: Path) -> None:
    require(pylsqpack.__version__ == EXPECTED_VERSION, "unexpected pylsqpack version")
    document = json.loads(source.read_text(encoding="utf-8"))
    require(document.get("schema") == SCHEMA, "invalid implementation schema")
    require(document.get("direction") == "http3-to-pylsqpack", "wrong direction")
    configuration = document["configuration"]
    capacity = configuration["maximum_table_capacity"]
    blocked_streams = configuration["maximum_blocked_streams"]
    require(capacity == CAPACITY, "capacity drift")
    require(blocked_streams == BLOCKED_STREAMS, "blocked-stream drift")
    decoder = pylsqpack.Decoder(capacity, blocked_streams)

    blocked_cases = 0
    fields = 0
    control_bytes = 0
    seen_streams: set[int] = set()
    for step in document["steps"]:
        stream_id = step["stream_id"]
        require(stream_id not in seen_streams, "duplicate stream ID")
        seen_streams.add(stream_id)
        encoder_stream = bytes.fromhex(step["encoder_stream"])
        field_section = bytes.fromhex(step["field_section"])
        expected = headers_from_json(step["headers"])
        delivery = step["delivery"]
        if delivery == "header_first":
            try:
                decoder.feed_header(stream_id, field_section)
            except pylsqpack.StreamBlocked:
                blocked_cases += 1
            else:
                raise RuntimeError(f"{step['id']}: expected StreamBlocked")
            unblocked = decoder.feed_encoder(encoder_stream)
            require(stream_id in unblocked, f"{step['id']}: stream not unblocked")
            control, decoded = decoder.resume_header(stream_id)
        elif delivery == "encoder_first":
            require(
                decoder.feed_encoder(encoder_stream) == [],
                f"{step['id']}: unexpected unblocked stream",
            )
            control, decoded = decoder.feed_header(stream_id, field_section)
        else:
            raise RuntimeError(f"{step['id']}: invalid delivery mode")
        require(decoded == expected, f"{step['id']}: header mismatch")
        fields += len(decoded)
        control_bytes += len(control)

    require(blocked_cases >= 2, "implementation corpus lost blocked coverage")
    write_json(
        report,
        {
            "schema": SCHEMA,
            "status": "Ready",
            "direction": "http3-to-pylsqpack",
            "oracle": {"name": "pylsqpack", "version": pylsqpack.__version__},
            "cases": len(document["steps"]),
            "fields": fields,
            "blocked_cases": blocked_cases,
            "decoder_control_bytes": control_bytes,
            "implementation_sha256": sha256(source),
        },
    )


def self_test() -> None:
    require(pylsqpack.__version__ == EXPECTED_VERSION, "unexpected pylsqpack version")
    with tempfile.TemporaryDirectory(prefix="qpack-oracle-self-test-") as temporary:
        path = Path(temporary) / "oracle.json"
        generate(path)
        document = json.loads(path.read_text(encoding="utf-8"))
        require(document["schema"] == SCHEMA, "self-test schema mismatch")
        require(len(document["steps"]) == len(oracle_header_sets()), "case loss")
        require(
            sum(step["delivery"] == "header_first" for step in document["steps"])
            >= 2,
            "blocked self-test coverage lost",
        )
    print("pylsqpack oracle self-test ok")


def main(arguments: list[str]) -> None:
    if arguments == ["--self-test"]:
        self_test()
    elif len(arguments) == 2 and arguments[0] == "generate":
        generate(Path(arguments[1]))
        print(f"pylsqpack oracle corpus written: {arguments[1]}")
    elif len(arguments) == 3 and arguments[0] == "verify":
        verify(Path(arguments[1]), Path(arguments[2]))
        print(f"pylsqpack verified http3 corpus: {arguments[2]}")
    else:
        raise RuntimeError(
            "usage: qpack_oracle.py --self-test | generate OUTPUT | "
            "verify INPUT REPORT"
        )


if __name__ == "__main__":
    try:
        main(sys.argv[1:])
    except Exception as error:
        print(f"qpack oracle failed: {error}", file=sys.stderr)
        raise SystemExit(1) from error

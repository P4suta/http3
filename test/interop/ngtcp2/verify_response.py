#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 the http contributors
# SPDX-License-Identifier: MIT OR Apache-2.0
"""Check the actual curl HTTP/3 response without publishing its contents."""
from pathlib import Path
import sys


def require(condition):
    if not condition:
        raise ValueError("independent_http3_response_mismatch")


def bounded(path, limit):
    with Path(path).open("rb") as source:
        data = source.read(limit + 1)
    require(len(data) <= limit)
    return data


def verify(summary, headers, body, expected):
    require(summary == b"3 200\n" and body == expected and len(body) <= 131072)
    require(len(headers) <= 65536)
    lines = [line.lower() for line in headers.split(b"\r\n") if line]
    require([line for line in lines if line.startswith(b"http/")] in
            ([b"http/3 200"], [b"http/3 200 "]))
    require([line for line in lines if line.startswith(b"x-response-finished:")] == [b"x-response-finished: yes"])


def self_test():
    valid = (b"3 200\n", b"HTTP/3 200\r\ncontent-type: application/octet-stream\r\n\r\nx-response-finished: yes\r\n\r\n", b"body", b"body")
    verify(*valid)
    # curl 8.22 writes the empty reason-phrase separator in its textual dump;
    # HTTP/3 itself carries only the :status field, independently checked above.
    verify(valid[0], valid[1].replace(b"HTTP/3 200\r\n", b"HTTP/3 200 \r\n"), *valid[2:])
    bad = [
        (b"2 200\n", *valid[1:]),
        (b"3 404\n", *valid[1:]),
        (valid[0], valid[1].replace(b"HTTP/3 200", b"HTTP/3 500"), *valid[2:]),
        (valid[0], valid[1] + b"HTTP/3 200\r\n", *valid[2:]),
        (valid[0], valid[1].replace(b"x-response-finished: yes", b""), *valid[2:]),
        (valid[0], valid[1] + b"x-response-finished: yes\r\n", *valid[2:]),
        (*valid[:2], b"bod", valid[3]),
        (valid[0], b"x" * 65537, *valid[2:]),
        (valid[0], valid[1].replace(b"HTTP/3 200", b"HTTP/3 200  "), *valid[2:]),
        (valid[0], valid[1].replace(b"HTTP/3 200", b"HTTP/3 200 unverified"), *valid[2:]),
    ]
    for case in bad:
        try:
            verify(*case)
        except ValueError:
            continue
        raise AssertionError("invalid_independent_response_accepted")
    print("ngtcp2 response oracle: 12 contracts passed")


if __name__ == "__main__":
    if sys.argv[1:] == ["--self-test"]:
        self_test()
    else:
        require(len(sys.argv) == 5)
        verify(bounded(sys.argv[1], 32), bounded(sys.argv[2], 65536),
               bounded(sys.argv[3], 131072), bounded(sys.argv[4], 131072))

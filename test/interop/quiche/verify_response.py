#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 the http contributors
# SPDX-License-Identifier: MIT OR Apache-2.0
"""Validate bounded local quiche output; never publish peer response contents."""
import copy
import json
from pathlib import Path
import re
import sys


def validate(document, header_events, expected):
    [entry] = document["entries"]
    response = entry["response"]
    assert bytes(response["body"]) == expected
    headers = [(header["name"], header["value"]) for header in response["headers"]]
    assert ("x-response-finished", "yes") in headers
    # Upstream 0.29.3 replaces its JSON headers when trailers arrive.
    # Its common-module debug event records the initial block independently.
    statuses = re.findall(
        r'got response headers \[\(":status", "([0-9]{3})"\).* on stream id 0',
        header_events)
    assert statuses == ["200"]


def bounded_read(path, maximum):
    with Path(path).open("rb") as source:
        data = source.read(maximum + 1)
    assert len(data) <= maximum
    return data


def self_test():
    document = {"entries": [{"response": {"body": [111, 107],
        "headers": [{"name": "x-response-finished", "value": "yes"}]}}]}
    observed = 'got response headers [(":status", "200")] on stream id 0\n'
    validate(document, observed, b"ok")
    for event in ["", observed.replace("200", "500"), observed + observed,
                  observed.replace("stream id 0", "stream id 4")]:
        try:
            validate(document, event, b"ok")
        except AssertionError:
            continue
        raise AssertionError("invalid status event accepted")
    for field, value in [("body", [111]), ("headers", [])]:
        altered = copy.deepcopy(document)
        altered["entries"][0]["response"][field] = value
        try:
            validate(altered, observed, b"ok")
        except AssertionError:
            continue
        raise AssertionError("incomplete response accepted")
    print("quiche local response oracle: 7 contracts passed")


if __name__ == "__main__":
    if sys.argv[1:] == ["--self-test"]:
        self_test()
    else:
        validate(json.loads(bounded_read(sys.argv[1], 1048576)),
                 bounded_read(sys.argv[2], 8388608).decode("utf-8"),
                 bounded_read(sys.argv[3], 131072))

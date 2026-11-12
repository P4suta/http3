# SPDX-FileCopyrightText: 2026 the http contributors
# SPDX-License-Identifier: MIT OR Apache-2.0
"""Strict browser observation contracts; no page or WebDriver text is retained."""


def validate_rejection(value):
    expected = {"certificate_rejected": True, "net_error": -202,
                "http_response_observed": False}
    if (type(value) is not dict or set(value) != set(expected)
            or any(type(value[key]) is not type(item) or value[key] != item
                   for key, item in expected.items())):
        raise ValueError("invalid_browser_rejection")
    return dict(value)


def validate_observation(value, protocol):
    expected = {"status": 201, "bytes": 72250, "payload_valid": True,
                "next_hop": {1: "http/1.1", 2: "h2", 3: "h3"}.get(protocol),
                "secure_context": True, "aborted": True, "abort_name": "AbortError"}
    if (type(protocol) is not int or protocol not in (1, 2, 3)
            or type(value) is not dict or set(value) != set(expected)
            or any(type(value[key]) is not type(item) or value[key] != item
                   for key, item in expected.items())):
        raise ValueError("invalid_browser_observation")
    return dict(value)

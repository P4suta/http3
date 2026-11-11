# SPDX-FileCopyrightText: 2026 the http contributors
# SPDX-License-Identifier: MIT OR Apache-2.0
"""Exact, payload-free browser and opposite-server completion contracts."""
import sys
sys.dont_write_bytecode = True
import hashlib
import re
from oracle import validate_observation, validate_rejection


def require(condition):
    if not condition:
        raise ValueError("invalid_browser_receipt")


def scenario(protocol, trusted):
    require(type(protocol) is int and protocol in (1, 2, 3) and type(trusted) is bool)
    return "h" + str(protocol) + (" body status and abort" if trusted else " untrusted certificate refused")


def nonce_for(run_id, protocol, trusted):
    require(type(run_id) is str and re.fullmatch(r"[a-f0-9]{64}", run_id) is not None)
    return hashlib.sha256((run_id + "\0" + scenario(protocol, trusted)).encode()).hexdigest()[:32]


def browser(value, nonce, protocol, trusted):
    expected = {"schema": 1, "nonce": nonce, "protocol": protocol, "trusted": trusted,
        "browser_sandbox": False, "container_seccomp": True, "non_root": True,
        "network_loopback_only": True, "tls_verification": True}
    require(type(value) is dict and set(value) == set(expected) | {"observation", "ownership"})
    require(all(type(value[key]) is type(item) and value[key] == item for key, item in expected.items()))
    ownership = value["ownership"]
    require(type(ownership) is dict and set(ownership) == {"children_observed", "children_joined"})
    require(all(type(item) is int and 1 <= item <= 256 for item in ownership.values())
            and ownership["children_observed"] == ownership["children_joined"])
    if trusted:
        validate_observation(value["observation"], protocol)
    else:
        validate_rejection(value["observation"])
    return value


def native(value, nonce, protocol, trusted):
    expected = {"schema": 1, "nonce": nonce, "protocol": protocol, "stopped": True,
        "document_requests": 1, "body_requests": 1, "body_bytes_pulled": 72250,
        "body_eof": 1, "body_cleanup": 1, "abort_requests": 1,
        "abort_source_entered": 1, "abort_source_cancelled": 1, "abort_pull_down": True}
    if not trusted:
        for key in expected.keys() - {"schema", "nonce", "protocol", "stopped"}:
            expected[key] = False if key == "abort_pull_down" else 0
    require(type(value) is dict and value == expected
            and all(type(value[key]) is type(item) for key, item in expected.items()))
    return value


def completion(value, timeout):
    expected = {"outcome": "completed", "exit_status": 0, "exit_observed": True,
        "controlled_shutdown": False, "stdout_bytes": 0, "stderr_bytes": 0}
    require(type(value) is dict and set(value) == set(expected) | {"elapsed_milliseconds"})
    require(all(type(value[key]) is type(item) and value[key] == item for key, item in expected.items()))
    require(type(timeout) is int and 0 < timeout <= 120
            and type(value["elapsed_milliseconds"]) is int
            and 0 <= value["elapsed_milliseconds"] <= (timeout + 5) * 1000)
    return value

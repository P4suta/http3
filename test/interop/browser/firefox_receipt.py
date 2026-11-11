# SPDX-FileCopyrightText: 2026 the http contributors
# SPDX-License-Identifier: MIT OR Apache-2.0
"""Exact Firefox observations; routing policy never substitutes for TLS trust."""
from oracle import validate_observation
from receipt import require


def browser(value, nonce, protocol, trusted):
    expected = {"schema": 1, "nonce": nonce, "protocol": protocol, "trusted": trusted,
        "browser_sandbox": "default", "container_seccomp": True, "non_root": True,
        "network_loopback_only": True, "tls_verification": True, "maximum_threads": 512,
        "thread_limit_hits": 0, "oom_kills": 0,
        "h3_forced_mapping": protocol == 3, "h3_private_root_policy": protocol == 3}
    require(type(value) is dict and set(value) == set(expected) | {"observation", "ownership", "thread_peak"})
    require(all(type(value[key]) is type(item) and value[key] == item for key, item in expected.items()))
    require(type(value["thread_peak"]) is int and 1 <= value["thread_peak"] <= 512)
    ownership = value["ownership"]
    require(type(ownership) is dict and set(ownership) == {"children_observed", "children_joined"})
    require(all(type(item) is int and 1 <= item <= 256 for item in ownership.values())
            and ownership["children_observed"] == ownership["children_joined"])
    if trusted:
        validate_observation(value["observation"], protocol)
    else:
        require(type(value["observation"]) is dict and value["observation"] == {
            "certificate_rejected": True, "webdriver_error": "insecure certificate"}
            and type(value["observation"]["certificate_rejected"]) is bool)
    return value

# SPDX-FileCopyrightText: 2026 the http contributors
# SPDX-License-Identifier: MIT OR Apache-2.0
"""Project only the actual certificate-verifier failure from a finite NetLog."""
import json


def certificate_rejected(data):
    try:
        if type(data) is not bytes or not 0 < len(data) <= 8_388_608:
            raise ValueError()
        def unique(pairs):
            value = {}
            for key, item in pairs:
                if key in value:
                    raise ValueError()
                value[key] = item
            return value
        value = json.loads(data, object_pairs_hook=unique)
        event_type = value["constants"]["logEventTypes"]["CERT_VERIFIER_JOB"]
        events = value["events"]
        if (type(event_type) is not int or not 0 < event_type <= 65535
                or type(events) is not list or len(events) > 65536):
            raise ValueError()
        return any(type(event) is dict and type(event.get("type")) is int
                   and event["type"] == event_type and type(event.get("phase")) is int
                   and event["phase"] == 2 and type(event.get("params")) is dict
                   and type(event["params"].get("net_error")) is int
                   and event["params"]["net_error"] == -202 for event in events)
    except (ValueError, TypeError, KeyError, RecursionError):
        raise ValueError("invalid_browser_netlog") from None

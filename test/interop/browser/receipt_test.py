# SPDX-FileCopyrightText: 2026 the http contributors
# SPDX-License-Identifier: MIT OR Apache-2.0
import sys
sys.dont_write_bytecode = True
import copy
import unittest
from receipt import browser, native, completion, nonce_for, scenario

NONCE = "a" * 32


def observed(protocol=1, trusted=True):
    observation = ({"status": 201, "bytes": 72250, "payload_valid": True,
        "next_hop": {1: "http/1.1", 2: "h2", 3: "h3"}[protocol],
        "secure_context": True, "aborted": True, "abort_name": "AbortError"} if trusted else
        {"certificate_rejected": True, "net_error": -202, "http_response_observed": False})
    return {"schema": 1, "nonce": NONCE, "protocol": protocol, "trusted": trusted,
        "observation": observation, "ownership": {"children_observed": 8, "children_joined": 8},
        "browser_sandbox": False, "container_seccomp": True, "non_root": True,
        "network_loopback_only": True, "tls_verification": True}


def served(protocol=1, trusted=True):
    value = {"schema": 1, "nonce": NONCE, "protocol": protocol, "stopped": True,
        "document_requests": 1, "body_requests": 1, "body_bytes_pulled": 72250,
        "body_eof": 1, "body_cleanup": 1, "abort_requests": 1,
        "abort_source_entered": 1, "abort_source_cancelled": 1, "abort_pull_down": True}
    if not trusted:
        for key in value.keys() - {"schema", "nonce", "protocol", "stopped"}:
            value[key] = False if key == "abort_pull_down" else 0
    return value


def completed():
    return {"outcome": "completed", "exit_status": 0, "exit_observed": True,
        "controlled_shutdown": False, "elapsed_milliseconds": 10,
        "stdout_bytes": 0, "stderr_bytes": 0}


class Receipts(unittest.TestCase):
    def test_all_six_exact_contracts(self):
        for protocol in (1, 2, 3):
            for trusted in (True, False):
                self.assertEqual(observed(protocol, trusted), browser(observed(protocol, trusted), NONCE, protocol, trusted))
                self.assertEqual(served(protocol, trusted), native(served(protocol, trusted), NONCE, protocol, trusted))
        self.assertEqual(completed(), completion(completed(), 50))

    def test_browser_each_required_fact_is_enforced(self):
        original = observed()
        for key in original:
            bad = copy.deepcopy(original)
            bad.pop(key)
            with self.subTest(field=key), self.assertRaises(ValueError):
                browser(bad, NONCE, 1, True)
        for key, value in [("schema", True), ("nonce", "b" * 32), ("protocol", True),
            ("trusted", 1), ("browser_sandbox", True), ("tls_verification", False),
            ("non_root", False), ("container_seccomp", False), ("network_loopback_only", False)]:
            bad = copy.deepcopy(original); bad[key] = value
            with self.subTest(field=key), self.assertRaises(ValueError):
                browser(bad, NONCE, 1, True)

    def test_child_completion_and_private_values_are_refused(self):
        for ownership in [{"children_observed": 0, "children_joined": 0},
            {"children_observed": 8, "children_joined": 7},
            {"children_observed": 257, "children_joined": 257},
            {"children_observed": True, "children_joined": True},
            {"children_observed": 8, "children_joined": 8, "pid": 999}]:
            bad = observed(); bad["ownership"] = ownership
            with self.assertRaises(ValueError): browser(bad, NONCE, 1, True)
        for field in ("private", "certificate", "arguments", "stderr"):
            bad = observed(); bad[field] = "private-browser-marker"
            with self.assertRaises(ValueError): browser(bad, NONCE, 1, True)

    def test_browser_does_not_accept_native_or_wrong_protocol_result(self):
        with self.assertRaises(ValueError): browser(served(), NONCE, 1, True)
        with self.assertRaises(ValueError): browser(observed(2), NONCE, 1, True)
        with self.assertRaises(ValueError): browser(observed(1, False), NONCE, 1, True)

    def test_native_each_work_cleanup_fact_and_type_is_enforced(self):
        for trusted in (True, False):
            original = served(1, trusted)
            for key, value in original.items():
                bad = copy.deepcopy(original)
                bad[key] = (not value if type(value) is bool else value + 1 if type(value) is int else "b" * 32)
                with self.subTest(field=key, trusted=trusted), self.assertRaises(ValueError):
                    native(bad, NONCE, 1, trusted)
            bad = copy.deepcopy(original); bad["schema"] = True
            with self.assertRaises(ValueError): native(bad, NONCE, 1, trusted)
            bad = copy.deepcopy(original); bad["private"] = "private-native-marker"
            with self.assertRaises(ValueError): native(bad, NONCE, 1, trusted)

    def test_no_work_missing_native_report_and_failure_phase_are_not_success(self):
        for bad in [None, {}, {"schema": 1, "nonce": NONCE, "failure_phase": 4}, served(1, False)]:
            with self.assertRaises(ValueError): native(bad, NONCE, 1, True)

    def test_failed_unjoined_private_or_late_vm_is_refused(self):
        for key, value in [("outcome", "timeout"), ("exit_status", 1), ("exit_status", False),
            ("exit_observed", False), ("controlled_shutdown", True), ("stdout_bytes", 1),
            ("stderr_bytes", 1), ("elapsed_milliseconds", 55001), ("elapsed_milliseconds", -1)]:
            bad = completed(); bad[key] = value
            with self.subTest(field=key), self.assertRaises(ValueError): completion(bad, 50)
        bad = completed(); bad["private"] = "private-completion-marker"
        with self.assertRaises(ValueError): completion(bad, 50)

    def test_nonce_binds_run_protocol_and_trust_scope(self):
        values = [nonce_for("a" * 64, p, t) for p in (1, 2, 3) for t in (True, False)]
        self.assertEqual(6, len(set(values)))
        self.assertNotIn(nonce_for("b" * 64, 1, True), values)
        for invalid in ("A" * 64, "a" * 32, "private"):
            with self.assertRaises(ValueError): nonce_for(invalid, 1, True)
        with self.assertRaises(ValueError): scenario(True, True)


if __name__ == "__main__":
    unittest.main()

# SPDX-FileCopyrightText: 2026 the http contributors
# SPDX-License-Identifier: MIT OR Apache-2.0
import base64
import io
import json
import os
from pathlib import Path
import tempfile
import time
import unittest
from unittest.mock import patch
import zipfile
if os.name == "posix":
    import firefox_worker as worker
from firefox_receipt import browser

NONCE = "a" * 32


def receipt(protocol=3, trusted=True):
    observation = {"status": 201, "bytes": 72250, "payload_valid": True,
        "next_hop": {1: "http/1.1", 2: "h2", 3: "h3"}[protocol], "secure_context": True,
        "aborted": True, "abort_name": "AbortError"} if trusted else {
            "certificate_rejected": True, "webdriver_error": "insecure certificate"}
    return {"schema": 1, "nonce": NONCE, "protocol": protocol, "trusted": trusted,
        "browser_sandbox": "default", "container_seccomp": True, "non_root": True,
        "network_loopback_only": True, "tls_verification": True, "maximum_threads": 512,
        "thread_limit_hits": 0, "oom_kills": 0, "thread_peak": 320,
        "h3_forced_mapping": protocol == 3, "h3_private_root_policy": protocol == 3,
        "observation": observation, "ownership": {"children_observed": 12, "children_joined": 12}}


class FirefoxTests(unittest.TestCase):
    def test_all_six_exact_receipts(self):
        for protocol in (1, 2, 3):
            for trusted in (True, False):
                self.assertEqual(browser(receipt(protocol, trusted), NONCE, protocol, trusted)["protocol"], protocol)

    def test_private_missing_or_false_scalar_receipts_are_rejected(self):
        for key, value in receipt().items():
            broken = receipt()
            broken.pop(key)
            with self.subTest(missing=key), self.assertRaises(ValueError):
                browser(broken, NONCE, 3, True)
            if type(value) is bool:
                broken = receipt()
                broken[key] = not value
                with self.subTest(false=key), self.assertRaises(ValueError):
                    browser(broken, NONCE, 3, True)
        for key in ("cookie", "exception", "origin", "certificate"):
            broken = receipt()
            broken[key] = "private-canary"
            with self.subTest(private=key), self.assertRaises(ValueError):
                browser(broken, NONCE, 3, True)

    def test_limits_and_actual_join_are_required(self):
        for key, values in {"maximum_threads": [256, 513, True], "thread_peak": [0, 513, True],
                            "thread_limit_hits": [1, False], "oom_kills": [1, False]}.items():
            for value in values:
                broken = receipt()
                broken[key] = value
                with self.subTest(key=key, value=value), self.assertRaises(ValueError):
                    browser(broken, NONCE, 3, True)
        broken = receipt()
        broken["ownership"]["children_joined"] = 11
        with self.assertRaises(ValueError):
            browser(broken, NONCE, 3, True)

    def test_negative_requires_actual_certificate_error(self):
        for observation in ({"certificate_rejected": True},
                            {"certificate_rejected": 1, "webdriver_error": "insecure certificate"},
                            {"certificate_rejected": True, "webdriver_error": "timeout"},
                            {"certificate_rejected": True, "webdriver_error": "insecure certificate", "message": "private"}):
            broken = receipt(3, False)
            broken["observation"] = observation
            with self.assertRaises(ValueError):
                browser(broken, NONCE, 3, False)

    @unittest.skipUnless(os.name == "posix", "Firefox process fixture requires Linux")
    def test_routing_preferences_preserve_private_trust_separation(self):
        for protocol in (1, 2, 3):
            prefs = worker.preferences(protocol, 8443)
            self.assertFalse(prefs["security.enterprise_roots.enabled"])
            self.assertEqual(prefs["network.http.http3.enable"], protocol == 3)
            if protocol == 3:
                self.assertFalse(prefs["network.http.http3.disable_when_third_party_roots_found"])
                self.assertTrue(prefs["network.http.http3.force-use-alt-svc-mapping-for-testing"])
                self.assertEqual(prefs["network.http.http3.alt-svc-mapping-for-testing"], 'localhost;h3=":8443"')
            else:
                self.assertNotIn("network.http.http3.disable_when_third_party_roots_found", prefs)

    @unittest.skipUnless(os.name == "posix", "Firefox process fixture requires Linux")
    def test_profile_contains_only_trust_database(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "cert9.db").write_bytes(b"test database")
            (root / "key4.db").write_bytes(b"private-key-canary")
            encoded = base64.b64decode(worker.encoded_profile(root), validate=True)
            with zipfile.ZipFile(io.BytesIO(encoded)) as archive:
                self.assertEqual(archive.namelist(), ["cert9.db"])
                self.assertNotIn(b"private-key-canary", archive.read("cert9.db"))

    @unittest.skipUnless(os.name == "posix", "Firefox process fixture requires Linux")
    def test_driver_does_not_promote_other_failures_to_certificate_rejection(self):
        for name, certificate in (("insecure certificate", True), ("timeout", False), ("private-canary", False)):
            raw = json.dumps({"value": {"error": name, "message": "private-certificate"}}).encode()
            with patch.object(worker.urllib.request, "urlopen", return_value=io.BytesIO(raw)):
                with self.assertRaises(worker.DriverError) as observed:
                    worker.Driver(1, time.monotonic() + 1).command("GET", "/status")
                self.assertEqual(observed.exception.certificate, certificate)
                self.assertNotIn("private", str(observed.exception))

    @unittest.skipUnless(os.name == "posix", "Firefox process fixture requires Linux")
    def test_driver_deadline_and_duplicate_fields_are_rejected(self):
        with self.assertRaises(ValueError):
            worker.Driver(1, time.monotonic() - 1).command("GET", "/status")
        raw = b'{"value":{"error":"timeout","error":"insecure certificate"}}'
        with patch.object(worker.urllib.request, "urlopen", return_value=io.BytesIO(raw)):
            with self.assertRaises(ValueError):
                worker.Driver(1, time.monotonic() + 1).command("GET", "/status")


if __name__ == "__main__":
    unittest.main()

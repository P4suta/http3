# SPDX-FileCopyrightText: 2026 the http contributors
# SPDX-License-Identifier: MIT OR Apache-2.0
import sys
sys.dont_write_bytecode = True
import unittest
from oracle import validate_observation, validate_rejection


def valid(protocol=2):
    return {"status": 201, "bytes": 72250, "payload_valid": True,
            "next_hop": {1: "http/1.1", 2: "h2", 3: "h3"}[protocol],
            "secure_context": True, "aborted": True, "abort_name": "AbortError"}


class ObservationContract(unittest.TestCase):
    def test_untrusted_ca_requires_the_actual_certificate_failure(self):
        expected = {"certificate_rejected": True, "net_error": -202,
                    "http_response_observed": False}
        self.assertEqual(expected, validate_rejection(expected))
        for key, replacement in [("certificate_rejected", False),
                                  ("net_error", -356),
                                  ("net_error", "PRIVATE_CERTIFICATE_MARKER"),
                                  ("http_response_observed", True)]:
            value = dict(expected); value[key] = replacement
            with self.subTest(field=key), self.assertRaisesRegex(ValueError, "invalid_browser_rejection"):
                validate_rejection(value)
        for value in [{}, dict(expected, private="PRIVATE_CERTIFICATE_MARKER"),
                      dict(expected, certificate_rejected=1), dict(expected, net_error=-202.0)]:
            with self.assertRaisesRegex(ValueError, "invalid_browser_rejection"):
                validate_rejection(value)

    def test_complete_observations_preserve_exact_public_scalars(self):
        for protocol in (1, 2, 3):
            self.assertEqual(valid(protocol), validate_observation(valid(protocol), protocol))

    def test_every_observation_is_causal(self):
        mutations = {"status": 200, "bytes": 72249, "payload_valid": False,
                     "next_hop": "http/1.1", "secure_context": False,
                     "aborted": False, "abort_name": "TypeError"}
        for key, replacement in mutations.items():
            with self.subTest(field=key):
                value = valid(); value[key] = replacement
                with self.assertRaises(ValueError):
                    validate_observation(value, 2)

    def test_missing_private_and_wrong_types_are_rejected(self):
        candidates = []
        for key in valid():
            value = valid(); del value[key]; candidates.append(value)
        value = valid(); value["private"] = "PRIVATE_BROWSER_MARKER"; candidates.append(value)
        for key in ("payload_valid", "secure_context", "aborted"):
            value = valid(); value[key] = 1; candidates.append(value)
        value = valid(); value["status"] = 201.0; candidates.append(value)
        value = valid(); value["bytes"] = 72250.0; candidates.append(value)
        for index, value in enumerate(candidates):
            with self.subTest(case=index):
                with self.assertRaises(ValueError):
                    validate_observation(value, 2)

    def test_failure_never_exposes_page_or_driver_values(self):
        value = valid(); value["next_hop"] = "PRIVATE_BROWSER_MARKER"
        try:
            validate_observation(value, 2)
        except ValueError as failure:
            self.assertEqual("invalid_browser_observation", str(failure))
        else:
            self.fail("malformed browser observation was accepted")


if __name__ == "__main__":
    unittest.main()

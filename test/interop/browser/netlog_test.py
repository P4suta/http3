# SPDX-FileCopyrightText: 2026 the http contributors
# SPDX-License-Identifier: MIT OR Apache-2.0
import sys
sys.dont_write_bytecode = True
import json
import unittest
from netlog import certificate_rejected


def log(events):
    return json.dumps({"constants": {"logEventTypes": {"CERT_VERIFIER_JOB": 91}},
                       "events": events}).encode()


class CertificateCause(unittest.TestCase):
    def test_only_completed_certificate_verification_can_establish_rejection(self):
        event = {"type": 91, "phase": 2, "params": {"net_error": -202,
                 "private_certificate": "PRIVATE_BROWSER_CERTIFICATE"}}
        self.assertIs(True, certificate_rejected(log([event])))
        for replacement in [dict(event, phase=1), dict(event, type=92),
                            dict(event, params={"net_error": -356}),
                            dict(event, params={"net_error": -202.0})]:
            self.assertIs(False, certificate_rejected(log([replacement])))

    def test_duplicate_truncated_and_oversized_logs_are_rejected_without_values(self):
        invalid = [b'{"events":[],"events":[]}', log([])[:-1], b" " * (8388608 + 1)]
        for data in invalid:
            with self.assertRaisesRegex(ValueError, "invalid_browser_netlog"):
                certificate_rejected(data)


if __name__ == "__main__":
    unittest.main()

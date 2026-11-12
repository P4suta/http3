# SPDX-FileCopyrightText: 2026 the http contributors
# SPDX-License-Identifier: MIT OR Apache-2.0
import sys
sys.dont_write_bytecode = True
import hashlib
import json
from pathlib import Path
import unittest
from receipt import scenario

ROOT = Path(__file__).resolve().parents[3]


class Registration(unittest.TestCase):
    def test_firefox_pins_routing_policy_and_six_scopes_are_registered(self):
        profile = json.loads((ROOT / "standards/interop-profile.json").read_bytes())
        peers = [peer for peer in profile["peers"] if peer["id"] == "firefox"]
        expected = {"id": "firefox", "roles": ["client"], "pin": "firefox 155.0.1",
            "identity_kind": "browser", "build_target": "http", "fixture": "test/interop/browser/firefox_worker.py",
            "lock": "test/interop/browser/firefox-pins.json", "evidence": "test/interop/browser/firefox_run.sh",
            "lock_sha256": hashlib.sha256((ROOT / "test/interop/browser/firefox-pins.json").read_bytes()).hexdigest(),
            "browser_policy": {"h3_route": "explicit-loopback-alt-svc", "private_roots_allow_h3": True,
                               "tls_verification": True, "maximum_threads": 512, "sandbox": "default"},
            "scenarios": [{"role": "client", "scenario": scenario(p, t)} for p in (1, 2, 3) for t in (True, False)]}
        self.assertEqual([expected], peers)

    def test_exact_pinned_six_scenario_profile_is_registered(self):
        profile = json.loads((ROOT / "standards/interop-profile.json").read_bytes())
        peers = [peer for peer in profile["peers"] if peer["id"] == "chromium"]
        expected = {"id": "chromium", "roles": ["client"], "pin": "chromium 153.0.8010.36",
            "identity_kind": "browser", "build_target": "http", "fixture": "test/interop/browser/browser_worker.py",
            "lock": "test/interop/browser/pins.json", "evidence": "test/interop/browser/run.sh",
            "lock_sha256": hashlib.sha256((ROOT / "test/interop/browser/pins.json").read_bytes()).hexdigest(),
            "scenarios": [{"role": "client", "scenario": scenario(p, t)} for p in (1, 2, 3) for t in (True, False)]}
        self.assertEqual([expected], peers)


if __name__ == "__main__":
    unittest.main()

#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 the http contributors
# SPDX-License-Identifier: MIT OR Apache-2.0
"""Cross-platform contracts for browser interoperability run ownership."""

import io
import signal
import sys
sys.dont_write_bytecode = True

from pathlib import Path
import unittest
from unittest import mock

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

import run as browser_run
import firefox_run


class BrowserRunContract(unittest.TestCase):
    def test_begin_accepts_only_the_exact_run_id_receipt(self):
        run_id = "a" * 64
        with mock.patch.object(browser_run, "audit", return_value=(run_id + "\n").encode("ascii")):
            self.assertEqual(browser_run.begin("chromium", "pin"), run_id)
        for output in [run_id.encode("ascii"), (run_id + "\nextra\n").encode("ascii"),
                       ("g" * 64 + "\n").encode("ascii"), b"\xff\n"]:
            with self.subTest(output=output), \
                    mock.patch.object(browser_run, "audit", return_value=output):
                with self.assertRaisesRegex(ValueError, "invalid_interop_begin_receipt"):
                    browser_run.begin("chromium", "pin")

    def test_failure_is_run_scoped_typed_and_silent_before_begin(self):
        run_id = "b" * 64
        with mock.patch.object(browser_run, "audit") as audit:
            browser_run.record_active_failure("firefox", None, "execution")
            audit.assert_not_called()
            browser_run.record_active_failure("firefox", run_id, "verification", 143)
            audit.assert_called_once_with([
                "--driver-failure", "firefox", run_id, "verification", "143"])

    def test_failure_exit_status_preserves_cancellation(self):
        self.assertEqual(browser_run.failure_exit_status(SystemExit(130)), 130)
        self.assertEqual(browser_run.failure_exit_status(SystemExit(143)), 143)
        self.assertEqual(browser_run.failure_exit_status(KeyboardInterrupt()), 130)
        for error in [SystemExit(0), SystemExit(256), SystemExit("private"), RuntimeError("private")]:
            with self.subTest(error=type(error).__name__):
                self.assertEqual(browser_run.failure_exit_status(error), 1)

        class HostileExit(SystemExit):
            def __getattribute__(self, _name):
                raise RuntimeError("private-canary")

        self.assertEqual(browser_run.failure_exit_status(HostileExit(143)), 1)

    def test_signal_handler_uses_the_canonical_shell_status(self):
        with self.assertRaises(SystemExit) as stopped:
            browser_run.interrupted(signal.SIGTERM, None)
        self.assertEqual(stopped.exception.code, 143)

    def test_chromium_cli_records_scoped_signal_failure_and_preserves_status(self):
        run_id = "c" * 64
        browser_run.ACTIVE_RUN_ID = run_id
        browser_run.ACTIVE_PHASE = "execution"
        with mock.patch.object(browser_run, "install_signal_handlers"), \
                mock.patch.object(browser_run, "main", side_effect=SystemExit(143)), \
                mock.patch.object(browser_run, "record_active_failure") as record, \
                mock.patch.object(browser_run.sys, "stderr"):
            self.assertEqual(browser_run.cli(), 143)
        record.assert_called_once_with("chromium", run_id, "execution", 143)
        browser_run.ACTIVE_RUN_ID = None

    def test_firefox_cli_records_scoped_interrupt_and_preserves_status(self):
        run_id = "d" * 64
        firefox_run.ACTIVE_RUN_ID = run_id
        firefox_run.ACTIVE_PHASE = "verification"
        with mock.patch.object(firefox_run, "install_signal_handlers"), \
                mock.patch.object(firefox_run, "main", side_effect=KeyboardInterrupt()), \
                mock.patch.object(firefox_run, "record_active_failure") as record, \
                mock.patch.object(firefox_run.sys, "stderr"):
            self.assertEqual(firefox_run.cli(), 130)
        record.assert_called_once_with("firefox", run_id, "verification", 130)
        firefox_run.ACTIVE_RUN_ID = None

    def test_arbitrary_browser_failure_is_redacted(self):
        run_id = "e" * 64
        browser_run.ACTIVE_RUN_ID = run_id
        browser_run.ACTIVE_PHASE = "setup"
        stderr = io.StringIO()
        with mock.patch.object(browser_run, "install_signal_handlers"), \
                mock.patch.object(browser_run, "main", side_effect=RuntimeError("private-canary")), \
                mock.patch.object(browser_run, "record_active_failure", side_effect=RuntimeError("other-private")), \
                mock.patch.object(browser_run.sys, "stderr", stderr):
            self.assertEqual(browser_run.cli(), 1)
        self.assertEqual(stderr.getvalue(), "Chromium interoperability failed\n")
        browser_run.ACTIVE_RUN_ID = None

    def test_browser_failure_status_survives_a_broken_diagnostic_sink(self):
        class BrokenSink:
            def write(self, _value):
                raise RuntimeError("private-canary")

            def flush(self):
                raise RuntimeError("private-canary")

        for module, status, error in [
                (browser_run, 1, RuntimeError("private-canary")),
                (firefox_run, 130, KeyboardInterrupt())]:
            with self.subTest(module=module.__name__), \
                    mock.patch.object(module, "install_signal_handlers"), \
                    mock.patch.object(module, "main", side_effect=error), \
                    mock.patch.object(module, "record_active_failure",
                                      side_effect=RuntimeError("private-canary")), \
                    mock.patch.object(module.sys, "stderr", BrokenSink()):
                self.assertEqual(module.cli(), status)


if __name__ == "__main__":
    unittest.main()

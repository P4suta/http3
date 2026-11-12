# SPDX-FileCopyrightText: 2026 the http contributors
# SPDX-License-Identifier: MIT OR Apache-2.0
import sys
sys.dont_write_bytecode = True
import argparse
import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest import mock
import native_runner
sys.path.insert(0, str(Path(__file__).resolve().parents[3] / "scripts"))
from process_supervisor import owned_run


class NativeExecution(unittest.TestCase):
    def test_cli_preserves_cancellation_when_the_diagnostic_sink_fails(self):
        class BrokenSink:
            def write(self, _value):
                raise RuntimeError("private-native-marker")

            def flush(self):
                raise RuntimeError("private-native-marker")

        with mock.patch.object(native_runner, "install_signal_handlers"), \
                mock.patch.object(native_runner, "main", side_effect=SystemExit(143)), \
                mock.patch.object(native_runner.sys, "stderr", BrokenSink()):
            self.assertEqual(native_runner.cli([]), 143)

    def exercise(self, body, *, short_deadline=False, change_source=False):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "test/interop/browser/http_browser_interop.erl"
            source.parent.mkdir(parents=True)
            source.write_text('-module(http_browser_interop).\n-export([run/5]).\n'
                + 'run(_Protocol,_Ready,_Stop,Result,Nonce)-> _={Result,Nonce},' + body + '.\n')
            beams = root / "build/dev/erlang/http/ebin"; beams.mkdir(parents=True)
            compiled = owned_run(["erlc", "-o", str(beams), str(source)], timeout=10,
                max_output_bytes=0, stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL, check=False)
            self.assertTrue(compiled.returncode == 0)
            report = root / "build/interop/peers/chromium.json"
            report.parent.mkdir(parents=True)
            report.write_text(json.dumps({"schema": 2, "status": "Running", "run_id": "a" * 64, "source_sha256": "b" * 64}))
            args = argparse.Namespace(protocol=1, trust="trusted", evidence=str(root / "evidence.json"),
                result=str(root / "result.json"), ready=str(root / "ready"), stop=str(root / "stop"))
            actual_collect = native_runner.collect
            def controlled(command, seconds, **options):
                self.assertEqual(50, seconds)
                if change_source:
                    source.write_text(source.read_text() + "% changed during execution\n")
                return actual_collect(command, 0.2 if short_deadline else seconds, **options)
            with mock.patch.object(native_runner, "ROOT", root), mock.patch.object(native_runner, "collect", controlled):
                status = native_runner.run(args)
            data = Path(args.evidence).read_bytes()
            self.assertFalse(b"private-native-marker" in data)
            return status, json.loads(data)

    def test_zero_exit_without_work_cannot_publish_success(self):
        status, record = self.exercise("ok")
        self.assertEqual(1, status)
        self.assertEqual("Failed", record["status"])
        self.assertIsNone(record["child"])
        self.assertEqual(0, record["completion"]["exit_status"])
        self.assertIs(record["completion"]["exit_observed"], True)

    def test_private_vm_output_is_discarded_and_refused(self):
        status, record = self.exercise('io:put_chars("private-native-marker"),ok')
        self.assertEqual(1, status)
        self.assertEqual("Failed", record["status"])
        self.assertGreater(record["completion"]["stdout_bytes"], 0)

    def test_timeout_kills_and_joins_actual_vm(self):
        status, record = self.exercise("receive after 60000->ok end", short_deadline=True)
        self.assertEqual(1, status)
        self.assertEqual("timeout", record["completion"]["outcome"])
        self.assertIs(record["completion"]["exit_observed"], True)

    def test_only_known_failure_phase_can_be_retained(self):
        for fields, accepted in [('failure_phase=>4', True), ('failure_phase=>255', False),
            ('failure_phase=>4,private=><<"private-native-marker">>', False)]:
            with self.subTest(case=accepted):
                body = 'ok=file:write_file(Result,json:encode(#{schema=>1,nonce=>Nonce,' + fields + '})),ok'
                status, record = self.exercise(body)
                self.assertEqual(1, status)
                self.assertEqual("Failed", record["status"])
                self.assertEqual(accepted, record["child"] is not None)

    def test_changed_source_prevents_valid_shaped_terminal_publication(self):
        body = ('ok=file:write_file(Result,json:encode(#{schema=>1,nonce=>Nonce,protocol=>1,stopped=>true,'
            'document_requests=>1,body_requests=>1,body_bytes_pulled=>72250,body_eof=>1,body_cleanup=>1,'
            'abort_requests=>1,abort_source_entered=>1,abort_source_cancelled=>1,abort_pull_down=>true})),ok')
        status, record = self.exercise(body, change_source=True)
        self.assertEqual(1, status)
        self.assertEqual("Failed", record["status"])
        self.assertIsNone(record["child"])


if __name__ == "__main__":
    unittest.main()

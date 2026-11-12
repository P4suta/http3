#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 the http contributors
# SPDX-License-Identifier: MIT OR Apache-2.0
import contextlib
import io
import json
import os
from pathlib import Path
import shutil
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock

import native_runner


class NativeRecordTests(unittest.TestCase):
    def test_cli_preserves_cancellation_when_the_diagnostic_sink_fails(self):
        class BrokenSink:
            def write(self, _value):
                raise RuntimeError("private-native-marker")

            def flush(self):
                raise RuntimeError("private-native-marker")

        arguments = ["--role", "client", "--beam", "unused", "--evidence", "unused",
                     "--result", "unused", "--port", "1", "--target", "1"]
        with mock.patch.object(native_runner, "install_signal_handlers"), \
                mock.patch.object(native_runner, "run", side_effect=SystemExit(143)), \
                mock.patch.object(native_runner.sys, "stderr", BrokenSink()):
            self.assertEqual(native_runner.cli(arguments), 143)

    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.path = Path(self.directory.name) / "record.json"
        self.nonce = "ab" * 16

    def record(self):
        return {"schema": 1, "nonce": self.nonce, "completed_flows": 2,
                "completed_datagrams": 16, "completed_rejections": 1, "workers_down": True}

    def write(self, record):
        self.path.write_text(json.dumps(record), encoding="utf-8")

    def test_complete_terminal(self):
        self.write(self.record())
        self.assertTrue(native_runner.terminal(self.path, self.nonce) == self.record())

    def test_failure_phase_is_preserved_without_raw_values(self):
        self.write({"schema": 1, "nonce": self.nonce, "failure_phase": 17})
        result = native_runner.terminal(self.path, self.nonce)
        self.assertEqual(result["failure_phase"], 17)
        for code in [0, 256, True, "private-native-marker"]:
            self.write({"schema": 1, "nonce": self.nonce, "failure_phase": code})
            with self.assertRaises(ValueError):
                native_runner.terminal(self.path, self.nonce)

    def test_missing_no_work_stale_and_unjoined_terminal(self):
        with self.assertRaises(FileNotFoundError):
            native_runner.terminal(self.path, self.nonce)
        for key, value in [("nonce", "cd" * 16), ("completed_flows", 0),
                           ("completed_datagrams", 15), ("completed_rejections", 0),
                           ("workers_down", False), ("schema", True),
                           ("completed_datagrams", 16.0)]:
            changed = self.record()
            changed[key] = value
            self.write(changed)
            with self.assertRaises(ValueError):
                native_runner.terminal(self.path, self.nonce)

    def test_private_unknown_duplicate_and_oversized_terminal(self):
        changed = self.record()
        changed["private"] = "private-native-marker"
        self.write(changed)
        with self.assertRaises(ValueError):
            native_runner.terminal(self.path, self.nonce)
        encoded = json.dumps(self.record())
        self.path.write_text(encoded[:-1] + ', "schema": 1}', encoding="utf-8")
        with self.assertRaises(ValueError):
            native_runner.terminal(self.path, self.nonce)
        self.path.write_bytes(b" " * 2049)
        with self.assertRaises(ValueError):
            native_runner.terminal(self.path, self.nonce)

    def test_readiness_is_bounded_typed_and_exact(self):
        self.assertFalse(native_runner.readiness(self.path))
        self.write({"port": 1234, "target": 2345})
        with contextlib.redirect_stdout(io.StringIO()) as output:
            self.assertTrue(native_runner.readiness(self.path))
        self.assertEqual(len(output.getvalue().splitlines()), 2)
        for record in [{"port": True, "target": 1}, {"port": 1.0, "target": 2},
                       {"port": 0, "target": 2}, {"port": 1, "target": 65536},
                       {"port": 1, "target": 2, "private": "private-native-marker"}, []]:
            self.write(record)
            with self.assertRaises(ValueError):
                native_runner.readiness(self.path)
        self.path.write_text('{"port":1,"port":2,"target":3}', encoding="utf-8")
        with self.assertRaises(ValueError):
            native_runner.readiness(self.path)
        self.path.write_bytes(b" " * 257)
        with self.assertRaises(ValueError):
            native_runner.readiness(self.path)


# Synthetic child programs test supervision only.
# They cannot produce an interoperability report: that also requires the current real fixture's fresh build manifest, a completed independent peer, and the scenario oracle.
CONTROL_SOURCE = r'''
-module(http_masque_interop).
-export([run_client/4]).
run_client(Mode, _, Path, Nonce) ->
    Record = #{schema => 1, nonce => Nonce, completed_flows => 2,
               completed_datagrams => 16, completed_rejections => 1,
               workers_down => true},
    case Mode of
        1 -> ok;
        2 -> write(Path, Record#{nonce := <<"stale-native-nonce">>});
        3 -> write(Path, Record), io:put_chars("private-native-marker"), ok;
        4 -> write(Path, Record), receive stop -> ok end;
        5 -> flood();
        6 ->
            write(Path, Record),
            Source = filename:join([filename:dirname(Path), "test", "interop",
                                   "masquego", "http_masque_interop.erl"]),
            file:write_file(Source, <<"changed-source">>);
        7 -> write(Path, #{schema => 1, nonce => Nonce, failure_phase => 17}),
             error(controlled_failure);
        8 ->
            true = lists:all(fun(Key) -> os:getenv(Key) =:= false end,
                       ["ERL_AFLAGS", "ERL_FLAGS", "ERL_ZFLAGS", "ERL_LIBS"]),
            "0" = os:getenv("ERL_CRASH_DUMP_BYTES"),
            "0" = os:getenv("ERL_CRASH_DUMP_SECONDS"),
            write(Path, Record)
    end.
write(Path, Record) -> file:write_file(Path, json:encode(Record), [exclusive]).
flood() -> io:put_chars(binary:copy(<<"private-native-marker">>, 4096)), flood().
'''


@unittest.skipUnless(os.name == "posix" and shutil.which("erl") and shutil.which("erlc"),
                     "actual child controls require POSIX and the pinned Erlang tools")
class NativeProcessTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.compiled = tempfile.TemporaryDirectory()
        directory = Path(cls.compiled.name)
        source = directory / "http_masque_interop.erl"
        source.write_text(CONTROL_SOURCE, encoding="utf-8")
        completion, output = native_runner.collect(
            [shutil.which("erlc"), "-Werror", "-o", str(directory), str(source)], 10, limit=65536)
        if completion["exit_status"] != 0 or output:
            cls.compiled.cleanup()
            raise AssertionError("controlled fixture compilation failed")
        cls.beam = (directory / "http_masque_interop.beam").read_bytes()

    @classmethod
    def tearDownClass(cls):
        cls.compiled.cleanup()

    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.root = Path(directory.name)
        source = self.root / "test/interop/masquego/http_masque_interop.erl"
        source.parent.mkdir(parents=True)
        source.write_text(CONTROL_SOURCE, encoding="utf-8")
        beam = self.root / "build/dev/erlang/http/ebin/http_masque_interop.beam"
        beam.parent.mkdir(parents=True)
        beam.write_bytes(self.beam)
        self.evidence = self.root / "evidence.json"
        peer = self.root / "build/interop/peers/masque-independent.json"
        native_runner.write_json_atomic(peer, {"schema": 2, "status": "Running",
            "run_id": "ab" * 16, "source_sha256": "cd" * 32})
        self.args = SimpleNamespace(role="client", seconds=1, beam=str(beam),
            result=str(self.root / "terminal.json"), evidence=str(self.evidence),
            port=8, target=1234, readiness=None, stop=None)

    def execute(self, mode):
        self.args.port = mode
        output = io.StringIO()
        with mock.patch.object(native_runner, "ROOT", self.root), \
                contextlib.redirect_stdout(output), contextlib.redirect_stderr(output):
            status = native_runner.run(self.args)
        record = json.loads(self.evidence.read_bytes())
        self.assertTrue(output.getvalue() == "")
        self.assertTrue("private-native-marker" not in self.evidence.read_text())
        self.assertTrue(record["completion"]["exit_observed"] is True)
        self.assertTrue(record["completion"]["elapsed_milliseconds"] < 6000)
        return status, record

    def test_actual_vm_exit_and_loader_environment(self):
        overrides = {key: "private-native-marker" for key in
                     ("ERL_AFLAGS", "ERL_FLAGS", "ERL_ZFLAGS", "ERL_LIBS")}
        with mock.patch.dict(os.environ, overrides):
            status, record = self.execute(8)
            self.assertTrue(all(os.environ[key] == value for key, value in overrides.items()))
        self.assertTrue(status == 0 and record["status"] == "Passed")

    def test_exit_zero_without_work_cannot_pass(self):
        status, record = self.execute(1)
        self.assertTrue(status == 1 and record["child"] is None)
        self.assertTrue(record["completion"]["exit_status"] == 0)

    def test_forged_stale_completion_cannot_pass(self):
        status, record = self.execute(2)
        self.assertTrue(status == 1 and record["child"] is None)

    def test_private_output_with_valid_terminal_cannot_pass(self):
        status, record = self.execute(3)
        self.assertTrue(status == 1 and record["child"] is not None)
        self.assertTrue(record["completion"]["stdout_bytes"] > 0)

    def test_valid_terminal_before_stall_cannot_pass(self):
        status, record = self.execute(4)
        self.assertTrue(status == 1 and record["child"] is not None)
        self.assertTrue(record["completion"]["outcome"] == "timeout")

    def test_private_flood_is_bounded_and_reaped(self):
        status, record = self.execute(5)
        self.assertTrue(status == 1 and record["status"] == "Failed")
        self.assertTrue(record["completion"]["outcome"] == "output_limit")
        self.assertTrue(record["completion"]["stdout_bytes"] <= 2 * 65536)

    def test_source_changed_by_running_child_cannot_pass(self):
        status, record = self.execute(6)
        self.assertTrue(status == 1 and record["child"] is not None)
        self.assertTrue(record["completion"]["exit_status"] == 0)

    def test_bounded_failure_phase_survives_child_failure(self):
        status, record = self.execute(7)
        self.assertTrue(status == 1 and record["child"]["failure_phase"] == 17)
        self.assertTrue(record["completion"]["exit_status"] == 1)


if __name__ == "__main__":
    unittest.main()

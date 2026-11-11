#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 the http contributors
# SPDX-License-Identifier: MIT OR Apache-2.0
import io
import signal
import sys
sys.dont_write_bytecode = True
import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
import unittest
from unittest import mock
import interop_notice as notice
from interop_peer import collect
from process_supervisor import owned_popen

ROOT = Path(__file__).resolve().parents[1]


class CliBoundary(unittest.TestCase):
    def invoke(self, error):
        stderr = io.StringIO()
        with mock.patch.object(notice, "install_signal_handlers"), \
                mock.patch.object(notice, "main", side_effect=error), \
                mock.patch.object(notice.sys, "stderr", stderr):
            status = notice.cli([])
        return status, stderr.getvalue()

    def test_failure_codes_are_finite_and_arbitrary_values_are_redacted(self):
        self.assertEqual(self.invoke(notice.Failure(3)),
                         (1, "interop notification failed: 3\n"))
        self.assertEqual(self.invoke(notice.Failure("private-canary")),
                         (1, "interop notification failed: 6\n"))
        self.assertEqual(self.invoke(RuntimeError("private-canary")),
                         (1, "interop notification failed: 6\n"))

        class HostileFailure(notice.Failure):
            def __getattribute__(self, _name):
                raise RuntimeError("private-canary")

        self.assertEqual(self.invoke(HostileFailure(1)),
                         (1, "interop notification failed: 6\n"))

    def test_cancellation_status_is_preserved(self):
        self.assertEqual(self.invoke(SystemExit(143)),
                         (143, "interop notification failed: 6\n"))
        self.assertEqual(self.invoke(KeyboardInterrupt()),
                         (130, "interop notification failed: 6\n"))
        with self.assertRaises(SystemExit) as stopped:
            notice.interrupted(signal.SIGTERM, None)
        self.assertEqual(stopped.exception.code, 143)

    def test_broken_failure_sink_cannot_change_exit_status(self):
        class BrokenSink:
            def write(self, _value):
                raise OSError("private-canary")

            def flush(self):
                raise OSError("private-canary")

        with mock.patch.object(notice, "install_signal_handlers"), \
                mock.patch.object(notice, "main", side_effect=RuntimeError("private-canary")), \
                mock.patch.object(notice.sys, "stderr", BrokenSink()):
            self.assertEqual(notice.cli([]), 1)


class Readiness(unittest.TestCase):
    @unittest.skipUnless(os.name == "posix", "bounded reader collector uses POSIX")
    def test_real_reader_ignores_an_unfinished_port_record(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "ready"
            with path.open("wb") as writer:
                writer.write(b"PORT=12"); writer.flush()
                program = ('import sys;sys.path.insert(0,sys.argv[1]);import interop_notice;'
                    'sys.exit(0 if interop_notice.read_fields(sys.argv[2],["PORT"]) is None else 1)')
                done, _ = collect([sys.executable, "-I", "-B", "-c", program, str(ROOT / "scripts"), str(path)], 3)
                self.assertEqual(done["exit_status"], 0)
                writer.write(b"345\n"); writer.flush()
            self.assertEqual(notice.read_fields(path, ["PORT"]), [12345])

    def test_complete_fields_and_only_public_scalars(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "ready"
            path.write_bytes(b"private-canary\nPORT=443\nTARGET=1234\nready=1\n")
            self.assertEqual(notice.read_fields(path, ["PORT", "TARGET", "ready"]), [443, 1234, 1])

    @unittest.skipUnless(hasattr(os, "mkfifo"), "POSIX special-file control")
    def test_special_file_readiness_cannot_block_the_deadline(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "ready"
            os.mkfifo(path)
            program = ('import sys;sys.path.insert(0,sys.argv[1]);import interop_notice;'
                '\ntry: interop_notice.read_fields(sys.argv[2],["PORT"])'
                '\nexcept interop_notice.Failure: sys.exit(0)'
                '\nsys.exit(1)')
            done, output = collect([sys.executable, "-I", "-B", "-c", program,
                str(ROOT / "scripts"), str(path)], 1, limit=4096)
            self.assertEqual(done["outcome"], "completed")
            self.assertEqual(done["exit_status"], 0)
            self.assertEqual(len(output), 0)

    def test_duplicate_malformed_and_excessive_records_are_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "ready"
            for raw in (b"PORT=1\nPORT=2\n", b"PORT=0\n", b"PORT=65536\n",
                        b"PORT=private-canary\n", b"PORT=1 " + b"\n", b"x" * (notice.MAX_LOG + 1)):
                path.write_bytes(raw)
                with self.assertRaises(notice.Failure):
                    notice.read_fields(path, ["PORT"])

    def test_hardlink_and_changed_path_identity_are_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "source"
            source.write_bytes(b"PORT=443\n")
            linked = root / "linked"
            os.link(source, linked)
            with self.assertRaises(notice.Failure):
                notice.read_fields(linked, ["PORT"])
            linked.unlink()
            source.unlink()

            path = root / "ready"
            path.write_bytes(b"PORT=443\n")
            current = os.stat(path, follow_symlinks=False)

            class ChangedIdentity:
                st_mode = current.st_mode
                st_nlink = current.st_nlink
                st_dev = current.st_dev
                st_ino = current.st_ino + 1

            with mock.patch.object(notice.os, "stat", return_value=ChangedIdentity()):
                with self.assertRaises(notice.Failure):
                    notice.read_fields(path, ["PORT"])

    @unittest.skipUnless(os.name == "posix", "open-file replacement requires POSIX")
    def test_actual_path_replacement_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            path = root / "ready"
            replacement = root / "replacement"
            path.write_bytes(b"PORT=443\n")
            replacement.write_bytes(b"PORT=444\n")
            original_read = notice.os.read
            replaced = False

            def replace_after_read(descriptor, count):
                nonlocal replaced
                data = original_read(descriptor, count)
                if not replaced:
                    replaced = True
                    os.replace(replacement, path)
                return data

            with mock.patch.object(notice.os, "read", side_effect=replace_after_read):
                with self.assertRaises(notice.Failure):
                    notice.read_fields(path, ["PORT"])

    def test_publication_preserves_owned_and_foreign_files_on_failure(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "stop"
            pending = path.with_name("stop.pending")
            pending.write_bytes(b"existing")
            with self.assertRaises(FileExistsError):
                notice.publish(path, "complete")
            self.assertEqual(pending.read_bytes(), b"existing")
            pending.unlink()
            with mock.patch.object(notice.os, "link", side_effect=OSError):
                with self.assertRaises(OSError):
                    notice.publish(path, "complete")
            self.assertEqual(len(list(Path(directory).iterdir())), 0)
            with self.assertRaises(notice.Failure):
                notice.publish(path, "private-marker")
            self.assertEqual(len(list(Path(directory).iterdir())), 0)

    @unittest.skipUnless(hasattr(os, "pidfd_open"), "Linux peer lifetime")
    def test_late_readiness_is_rejected_at_absolute_deadline(self):
        with mock.patch.object(notice.time, "monotonic", side_effect=[0., 0., 2.]), \
                mock.patch.object(notice, "read_fields", return_value=[443]):
            with self.assertRaises(notice.Failure) as observed:
                notice.wait("unused", os.getpid(), 1, ["PORT"])
            self.assertEqual(observed.exception.code, 5)

    @unittest.skipUnless(hasattr(os, "pidfd_open"), "Linux peer lifetime")
    def test_deadline_and_dead_peer_are_distinct_and_close_descriptors(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "ready"
            before = len(list(Path("/proc/self/fd").iterdir()))
            with self.assertRaises(notice.Failure) as observed:
                notice.wait(path, os.getpid(), .02, ["PORT"])
            self.assertEqual(observed.exception.code, 5)
            child = owned_popen([sys.executable, "-I", "-B", "-c", "pass"])
            child.wait(timeout=3)
            with self.assertRaises(notice.Failure) as observed:
                notice.wait(path, child.pid, 1, ["PORT"])
            self.assertEqual(observed.exception.code, 4)
            self.assertEqual(before, len(list(Path("/proc/self/fd").iterdir())))


@unittest.skipUnless(os.name == "posix", "bounded native collector uses POSIX")
class NativePublication(unittest.TestCase):
    def test_compiled_native_writer_and_bounded_readers(self):
        compiler, runtime = shutil.which("erlc"), shutil.which("erl")
        self.assertTrue(bool(compiler and runtime), "native_toolchain_required")
        environment = os.environ.copy()
        for name in ("ERL_AFLAGS", "ERL_FLAGS", "ERL_ZFLAGS", "ERL_LIBS"):
            environment.pop(name, None)
        environment["ERL_CRASH_DUMP_BYTES"] = "0"
        environment["ERL_CRASH_DUMP_SECONDS"] = "0"
        sources = ["scripts/interop_notice_test.erl",
            "test/interop/browser/http_browser_interop.erl",
            "test/interop/masquego/http_masque_interop.erl",
            "test/interop/nghttp2/http_nghttp2_interop.erl",
            "test/interop/ohttpgo/http_ohttp_interop.erl",
            "test/interop/quiche/http_quiche_interop.erl"]
        with tempfile.TemporaryDirectory() as directory:
            done, output = collect([compiler, "-Werror", "-o", directory,
                *[str(ROOT / source) for source in sources]], 30, env=environment)
            self.assertEqual(done["outcome"], "completed")
            self.assertEqual(done["exit_status"], 0, "native_compile_failed")
            self.assertEqual(len(output), 0)
            done, output = collect([runtime, "+S", "2:2", "+SDcpu", "1", "+SDio", "1",
                "+A", "2", "-noshell", "-noinput", "-pa", directory, "-eval",
                "try ok=interop_notice_test:test(),halt(0) catch _:_ -> halt(1) end."],
                15, env=environment)
            self.assertEqual(done["outcome"], "completed")
            self.assertEqual(done["exit_status"], 0, "native_notice_control_failed")
            self.assertEqual(output, b"native notice controls: atomic visibility, existing record, write failure and bound verified\n")


@unittest.skipUnless(os.name == "posix", "actual Bash fixture functions")
class CurlPrivacy(unittest.TestCase):
    def function(self, name):
        source = (ROOT / "test/interop/curl/run.sh").read_text()
        found = re.search(r"^" + name + r"\(\) \{.*?^\}", source, re.M | re.S)
        self.assertIsNotNone(found)
        return found.group()

    def exercise(self, name, commands):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "peer.log").write_text("private-peer-canary\n")
            script = root / "check.sh"
            script.write_text('set -u\nrepository_root=$1\npeer_log=$2\n' + self.function(name) + '\n' + commands)
            done, output = collect(["bash", str(script), str(ROOT), str(root / "peer.log")], 5, limit=4096)
            self.assertEqual(done["exit_status"], 1)
            self.assertTrue(b"private-peer-canary" not in output)
            self.assertTrue(b"private-response-canary" not in output)
            return output

    def test_dead_peer_readiness_never_emits_native_log(self):
        self.exercise("wait_for_field", 'true & peer_process=$!\nwait "$peer_process"\nwait_for_field h1_port\n')

    def test_response_mismatch_never_emits_peer_body_or_native_log(self):
        self.exercise("assert_equal", "assert_equal fixed expected private-response-canary\n")

    def test_lower_fixture_does_not_republish_raw_failure_files(self):
        source = (ROOT / "packages/http3/test/interop/run.sh").read_text()
        found = re.search(r"^preserve_failure\(\) \{.*?^\}", source, re.M | re.S)
        self.assertIsNotNone(found)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            work = root / "work"; work.mkdir()
            for name in ("peer.log", "peer.qlog", "peer.sqlog"):
                (work / name).write_text("private-peer-canary")
            binary = root / "bin"; binary.mkdir()
            producer = binary / "escript"
            producer.write_text("#!/bin/sh\nprintf private-producer-canary\n")
            producer.chmod(0o755)
            script = root / "check.sh"
            script.write_text('set -u\nrepository_root=$1\nwork_directory=$2\nfailure_directory=$3\nmode=all\n'
                'export PATH="$4:$PATH"\nclean_failure_directory(){ :; }\n'
                + found.group() + '\npreserve_failure 7\n')
            done, output = collect(["bash", str(script), str(ROOT / "packages/http3"),
                str(work), str(root / "failure"), str(binary)], 5, limit=4096)
            self.assertEqual(done["exit_status"], 0)
            self.assertTrue(b"private-producer-canary" not in output)
            retained = [path for path in (root / "failure").rglob("*") if path.is_file()]
            self.assertFalse(any(b"private-peer-canary" in path.read_bytes() for path in retained))

    def test_lower_foreground_peer_output_stays_private_and_preserves_exit(self):
        source = (ROOT / "packages/http3/test/interop/run.sh").read_text()
        found = re.search(r"^run_logged\(\) \{.*?^\}", source, re.M | re.S)
        self.assertIsNotNone(found)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            script = root / "check.sh"
            script.write_text('set -uo pipefail\n' + found.group()
                + "\npeer(){ exec bash -c 'printf private-peer-canary; printf private-peer-canary >&2; exit 7'; }\n"
                + 'run_logged "$1" peer\nstatus=$?\nprintf complete >"$2"\nexit "$status"\n')
            done, output = collect(["bash", str(script), str(root / "private.log"),
                str(root / "complete")], 5, limit=4096)
            self.assertEqual(done["exit_status"], 7)
            self.assertEqual(len(output), 0)
            self.assertTrue((root / "complete").exists())
            self.assertEqual((root / "private.log").read_bytes().count(b"private-peer-canary"), 2)


if __name__ == "__main__":
    unittest.main()

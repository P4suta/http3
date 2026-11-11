# SPDX-FileCopyrightText: 2026 the http contributors
# SPDX-License-Identifier: MIT OR Apache-2.0
"""Actual Linux process controls; assertion output contains fixed facts only."""
import os
import inspect
from pathlib import Path
import select
import signal
import subprocess
import sys
sys.dont_write_bytecode = True
import tempfile
import threading
import time
import unittest
from unittest import mock
import browser_worker
import owned
from owned import OwnedChildren

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / "scripts"))
from interop_peer import collect
from process_supervisor import owned_popen


def publish_pid_notice(path, pid):
    path = Path(path)
    pending = path.with_name(path.name + ".pending")
    try:
        with pending.open("x", encoding="ascii") as stream:
            stream.write(str(pid) + "\n")
        os.replace(pending, path)
    finally:
        pending.unlink(missing_ok=True)


def helper_source(source):
    directory = Path(browser_worker.__file__).resolve().parent
    if Path(owned.__file__).resolve().parent != directory:
        raise ValueError("browser_fixture_source_mismatch")
    # Match the modules loaded by this test, including a deliberate mutant overlay.
    # Child interpreters must not depend on cwd or ambient PYTHONPATH.
    return ("import sys,os\nfrom pathlib import Path\nsys.dont_write_bytecode=True\nsys.path.insert(0,"
            + repr(str(directory)) + ")\n" + inspect.getsource(publish_pid_notice) + "\n" + source)


def helper_command(source, *arguments):
    return [sys.executable, "-I", "-B", "-c", helper_source(source), *arguments]


class WorkerOwnership(unittest.TestCase):
    def test_pid_notice_is_unpublished_until_its_complete_line_is_closed(self):
        entered, release = threading.Event(), threading.Event()
        closing, close_release = threading.Event(), threading.Event()
        failed = []
        original_open = Path.open

        class PausedWrite:
            def __init__(self, stream):
                self.stream = stream

            def __enter__(self):
                return self

            def __exit__(self, *arguments):
                closing.set()
                if not close_release.wait(2):
                    raise ValueError("fixture_close_barrier_timeout")
                return self.stream.__exit__(*arguments)

            def write(self, value):
                entered.set()
                if not release.wait(2):
                    raise ValueError("fixture_publication_barrier_timeout")
                return self.stream.write(value)

        def open_at_barrier(path, mode="r", *arguments, **keywords):
            stream = original_open(path, mode, *arguments, **keywords)
            return PausedWrite(stream) if mode in ("w", "x") else stream

        with tempfile.TemporaryDirectory() as directory:
            ready = Path(directory) / "ready"

            def publish():
                try:
                    publish_pid_notice(ready, 1234)
                except BaseException:
                    failed.append(True)

            with mock.patch.object(Path, "open", open_at_barrier):
                publisher = threading.Thread(target=publish)
                publisher.start()
                try:
                    reached = entered.wait(2)
                    published_early = ready.exists()
                    observed_bytes = len(ready.read_bytes()) if published_early else 0
                    release.set()
                    close_reached = closing.wait(2)
                    published_before_close = ready.exists()
                finally:
                    release.set()
                    close_release.set()
                    publisher.join(timeout=3)
            self.assertTrue(reached)
            self.assertTrue(close_reached)
            self.assertFalse(publisher.is_alive())
            self.assertEqual(len(failed), 0)
            self.assertFalse(published_early, "partial_pid_notice_published")
            self.assertFalse(published_before_close, "unclosed_pid_notice_published")
            self.assertEqual(observed_bytes, 0)
            self.assertTrue(ready.read_bytes() == b"1234\n")
            self.assertEqual(len(list(Path(directory).iterdir())), 1)

    def test_helper_imports_ignore_an_ambient_module_path(self):
        with tempfile.TemporaryDirectory() as directory:
            for module in ("browser_worker", "owned"):
                (Path(directory) / (module + ".py")).write_text(
                    "raise ValueError('ambient_module_selected')\n")
            completion, output = collect(helper_command(
                "import browser_worker,owned\n"
                "from pathlib import Path\n"
                "assert Path(browser_worker.__file__).resolve().parent == Path(sys.path[0])\n"
                "assert Path(owned.__file__).resolve().parent == Path(sys.path[0])\n"),
                5, env={**os.environ, "PYTHONPATH": directory})
            self.assertEqual(completion["outcome"], "completed")
            self.assertEqual(completion["exit_status"], 0)
            self.assertTrue(completion["exit_observed"])
            self.assertEqual(len(output), 0)

    def test_parent_change_during_pidfd_open_rejects_before_work_and_closes_the_fd(self):
        before = len(list(Path("/proc/self/fd").iterdir()))
        parent = os.getppid()
        with mock.patch.object(owned.os, "getppid", side_effect=[parent, parent + 1]):
            with self.assertRaisesRegex(ValueError, "browser_owner_exited"):
                owned._owner_descriptor()
        self.assertEqual(before, len(list(Path("/proc/self/fd").iterdir())))

    def test_private_unknown_result_fields_cannot_reach_a_cli_receipt(self):
        value = {"observation": {"status": 201, "bytes": 72250, "payload_valid": True,
            "next_hop": "http/1.1", "secure_context": True, "aborted": True,
            "abort_name": "AbortError"}, "ownership": {"children_observed": 1, "children_joined": 1},
            "browser_sandbox": False, "container_seccomp": True, "non_root": True,
            "network_loopback_only": True, "tls_verification": True, "private": "private-page-token"}
        with tempfile.TemporaryDirectory() as directory:
            result = Path(directory) / "result"
            with mock.patch.object(browser_worker, "run", return_value=value):
                with self.assertRaisesRegex(ValueError, "^browser_owned_work_failed$"):
                    browser_worker.main(["1", "trusted", "443", str(result), "a" * 32])
            self.assertFalse(result.exists())

    def test_real_collector_output_limit_cancels_the_separate_session_children(self):
        helper = """
import os,pathlib,sys
import browser_worker
from owned import OwnedChildren
def work(*_):
    owner=OwnedChildren()
    try:
        child=owner.start([sys.executable,'-c','import time; time.sleep(60)'])
        publish_pid_notice(sys.argv[1], child.pid)
        while True: os.write(1,b'private-page-token'*4096)
    finally: owner.close()
browser_worker.run=work
try: browser_worker.main(['1','trusted','443',sys.argv[2],'a'*32])
except BaseException: sys.exit(1)
"""
        with tempfile.TemporaryDirectory() as directory:
            ready = Path(directory) / "ready"
            owner = OwnedChildren()
            descriptor = None
            try:
                completion, output = collect(helper_command(helper, str(ready),
                                             str(Path(directory) / "result")), 5, limit=4096)
                self.assertEqual(completion["outcome"], "output_limit")
                self.assertTrue(completion["exit_observed"] and len(output) <= 4096)
                self.assertTrue(ready.exists())
                try:
                    descriptor = os.pidfd_open(int(ready.read_text()))
                except ProcessLookupError:
                    return
                exited, _, _ = select.select([descriptor], [], [], 4)
                self.assertTrue(bool(exited))
            finally:
                if descriptor is not None:
                    os.close(descriptor)
                owner.close()

    def test_late_queued_success_cannot_pass_the_absolute_controller_deadline(self):
        helper = """
import os,pathlib,signal,sys,time
import owned
directory=pathlib.Path(sys.argv[1])
original=owned.select.select
paused=False
controller_pid=os.getpid()
def select_barrier(readers,*arguments):
    global paused
    if os.getpid()==controller_pid and len(readers)==3 and not paused:
        paused=True
        (directory/'paused').write_text('1')
        os.kill(os.getpid(),signal.SIGSTOP)
    return original(readers,*arguments)
owned.select.select=select_barrier
def work():
    while not (directory/'release').exists(): time.sleep(0.01)
    return {'value':True}
try:
    owned.supervise(work,lambda value:value,1)
    (directory/'result').write_text('unexpected')
    sys.exit(0)
except BaseException: sys.exit(1)
"""
        with tempfile.TemporaryDirectory() as directory:
            owner = OwnedChildren()
            child = owner.start(helper_command(helper, directory))
            try:
                paused = Path(directory) / "paused"
                deadline = time.monotonic() + 3
                while not paused.exists() and time.monotonic() < deadline:
                    time.sleep(0.01)
                self.assertTrue(paused.exists())
                (Path(directory) / "release").write_text("1")
                time.sleep(1.1)
                child.send_signal(signal.SIGCONT)
                child.wait(timeout=3)
                self.assertEqual(child.returncode, 1)
                self.assertFalse((Path(directory) / "result").exists())
            finally:
                owner.close()

    def test_external_collector_death_cancels_the_cli_and_its_descendants(self):
        worker = """
import pathlib,sys,time
import browser_worker
from owned import OwnedChildren
def work(*_):
    owner=OwnedChildren()
    try:
        child=owner.start([sys.executable,'-c','import time; time.sleep(60)'])
        publish_pid_notice(sys.argv[1], child.pid)
        while True: time.sleep(0.02)
    finally: owner.close()
browser_worker.run=work
try: browser_worker.main(['1','trusted','443',sys.argv[2],'a'*32])
except BaseException: sys.exit(1)
"""
        parent = """
import pathlib,subprocess,sys,time
child=subprocess.Popen([sys.executable,'-I','-B','-c',sys.argv[1],sys.argv[2],sys.argv[3]],
                       start_new_session=True,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
publish_pid_notice(sys.argv[4], child.pid)
while True: time.sleep(0.02)
"""
        with tempfile.TemporaryDirectory() as directory:
            ready = Path(directory) / "ready"
            cli_ready = Path(directory) / "cli"
            owner = OwnedChildren()
            descriptors = []
            try:
                child = owner.start(helper_command(parent, helper_source(worker), str(ready),
                                     str(Path(directory) / "result"), str(cli_ready)))
                deadline = time.monotonic() + 3
                while not ready.exists() and time.monotonic() < deadline:
                    time.sleep(0.01)
                self.assertTrue(ready.exists() and cli_ready.exists())
                descriptors = [os.pidfd_open(int(path.read_text())) for path in (ready, cli_ready)]
                child.kill(); child.wait(timeout=3)
                deadline = time.monotonic() + 4
                for descriptor in descriptors:
                    exited, _, _ = select.select([descriptor], [], [], max(0, deadline-time.monotonic()))
                    self.assertTrue(bool(exited))
            finally:
                for descriptor in descriptors:
                    os.close(descriptor)
                owner.close()

    def test_actual_success_joins_an_unclaimed_detached_descendant_before_return(self):
        retained = []
        with tempfile.TemporaryDirectory() as directory:
            ready = Path(directory) / "ready"

            def work():
                child = owned_popen([sys.executable, "-c", "import time; time.sleep(60)"],
                    start_new_session=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                retained.append(child)
                publish_pid_notice(ready, child.pid)
                return {"value": True}

            result, summary = owned.supervise(work, lambda value: value, 2)
            self.assertEqual(result, {"value": True})
            self.assertEqual(summary, {"children_observed": 3, "children_joined": 3})
            self.assertFalse(Path("/proc/" + str(int(ready.read_text()))).exists())

    def test_stopped_run_child_and_its_detached_descendant_are_joined_at_deadline(self):
        retained = []
        with tempfile.TemporaryDirectory() as directory:
            ready = Path(directory) / "ready"

            def work():
                child = owned_popen([sys.executable, "-c", "import time; time.sleep(60)"],
                    start_new_session=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                retained.append(child)
                publish_pid_notice(ready, child.pid)
                os.kill(os.getpid(), signal.SIGSTOP)

            started = time.monotonic()
            with self.assertRaisesRegex(TimeoutError, "browser_deadline"):
                owned.supervise(work, lambda value: value, 1)
            self.assertLess(time.monotonic() - started, 6)
            self.assertTrue(ready.exists())
            self.assertFalse(Path("/proc/" + str(int(ready.read_text()))).exists())

    def test_private_callback_exception_is_projected_and_its_children_are_joined(self):
        retained = []
        with tempfile.TemporaryDirectory() as directory:
            ready = Path(directory) / "ready"

            def work():
                child = owned_popen([sys.executable, "-c", "import time; time.sleep(60)"],
                    start_new_session=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                retained.append(child)
                publish_pid_notice(ready, child.pid)
                raise ValueError("private-page-certificate-token")

            with self.assertRaisesRegex(ValueError, "^browser_owned_work_failed$"):
                owned.supervise(work, lambda value: value, 2)
            self.assertFalse(Path("/proc/" + str(int(ready.read_text()))).exists())

    def test_pre_fork_setup_failure_closes_every_allocated_descriptor(self):
        before = len(list(Path("/proc/self/fd").iterdir()))
        with mock.patch.object(owned, "OwnedChildren", side_effect=ValueError("setup_injected")):
            with self.assertRaisesRegex(ValueError, "setup_injected"):
                owned.supervise(lambda: {"value": True}, lambda value: value, 1)
        self.assertEqual(before, len(list(Path("/proc/self/fd").iterdir())))

    def test_cleanup_failure_closes_the_private_result_descriptor(self):
        class FailedCleanup(OwnedChildren):
            def close(self):
                super().close()
                raise ValueError("cleanup_injected")

        before = len(list(Path("/proc/self/fd").iterdir()))
        with mock.patch.object(owned, "OwnedChildren", FailedCleanup):
            with self.assertRaisesRegex(ValueError, "cleanup_injected"):
                owned.supervise(lambda: {"value": True}, lambda value: value, 1)
        self.assertEqual(before, len(list(Path("/proc/self/fd").iterdir())))

    def test_killed_cli_owner_still_joins_its_detached_browser_child(self):
        self._assert_owner_exit_joins(signal.SIGKILL)

    def test_terminated_cli_owner_still_joins_its_detached_browser_child(self):
        self._assert_owner_exit_joins(signal.SIGTERM)

    def test_cli_death_still_joins_a_stopped_run_child_and_detached_descendant(self):
        self._assert_owner_exit_joins(signal.SIGKILL, stop_run=True)

    def _assert_owner_exit_joins(self, number, stop_run=False):
        helper = """
import os,pathlib,signal,sys,time
import browser_worker
from owned import OwnedChildren
ready=pathlib.Path(sys.argv[1])
def work(*_):
    owner=OwnedChildren()
    try:
        child=owner.start([sys.executable,'-c','import time; time.sleep(60)'])
        publish_pid_notice(ready, child.pid)
        while True: time.sleep(0.02)
    finally: owner.close()
browser_worker.run=work
try: browser_worker.main(['1','trusted','443',sys.argv[2],'a'*32])
except BaseException: sys.exit(1)
"""
        if stop_run:
            helper = helper.replace("while True: time.sleep(0.02)",
                "publish_pid_notice(ready.with_suffix('.run'), os.getpid()); os.kill(os.getpid(),signal.SIGSTOP)")
        with tempfile.TemporaryDirectory() as directory:
            ready = Path(directory) / "ready"
            owner = OwnedChildren()
            descriptor = None
            try:
                child = owner.start(helper_command(helper, str(ready),
                                     str(Path(directory) / "result")))
                deadline = time.monotonic() + 3
                while not ready.exists() and time.monotonic() < deadline:
                    time.sleep(0.01)
                self.assertTrue(ready.exists())
                descriptor = os.pidfd_open(int(ready.read_text()))
                if stop_run:
                    run_ready = ready.with_suffix(".run")
                    deadline = time.monotonic() + 1
                    stopped = False
                    while time.monotonic() < deadline:
                        if run_ready.exists():
                            status = Path("/proc/" + str(int(run_ready.read_text())) + "/status").read_text()
                            stopped = any(line.startswith("State:") and "T" in line for line in status.splitlines())
                            if stopped:
                                break
                        time.sleep(0.01)
                    self.assertTrue(stopped)
                child.send_signal(number)
                child.wait(timeout=3)
                exited, _, _ = select.select([descriptor], [], [], 4)
                self.assertTrue(bool(exited))
            finally:
                if descriptor is not None:
                    os.close(descriptor)
                owner.close()

    def test_profile_cleanup_starts_only_after_the_browser_children_exit(self):
        temporary = tempfile.TemporaryDirectory
        launched = []
        observed = []

        class Directory:
            def __enter__(self):
                self.inner = temporary()
                return self.inner.__enter__()

            def __exit__(self, *arguments):
                observed.append(bool(launched) and all(child.poll() is not None for child in launched))
                return self.inner.__exit__(*arguments)

        class Children(OwnedChildren):
            def start(self, _command, *, env=None):
                child = super().start([sys.executable, "-c", "import time; time.sleep(60)"], env=env)
                launched.append(child)
                return child

        with mock.patch.object(browser_worker, "isolation"), \
                mock.patch.object(browser_worker, "OwnedChildren", Children), \
                mock.patch.object(browser_worker.tempfile, "TemporaryDirectory", lambda **_: Directory()), \
                mock.patch.object(browser_worker.subprocess, "run"), \
                mock.patch.object(browser_worker.Driver, "command", side_effect=KeyboardInterrupt):
            with self.assertRaises(KeyboardInterrupt):
                browser_worker.run(1, False, 443)
        self.assertEqual(observed, [True])


if __name__ == "__main__":
    unittest.main()

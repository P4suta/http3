# SPDX-FileCopyrightText: 2026 the http contributors
# SPDX-License-Identifier: MIT OR Apache-2.0
import os
import pathlib
import signal
import subprocess
import sys
sys.dont_write_bytecode = True
import tempfile
import time
import unittest
from unittest import mock
import owned
from owned import OwnedChildren
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[3] / "scripts"))
from process_supervisor import owned_popen


class DescendantOwnership(unittest.TestCase):
    def test_cancellation_during_join_is_delivered_only_after_actual_reaping(self):
        owner = OwnedChildren()
        child = owner.start([sys.executable, "-c", "import time; time.sleep(60)"])
        previous = signal.getsignal(signal.SIGTERM)
        original_select = owned.select.select
        sent = False

        def cancelled(_number, _frame):
            raise InterruptedError("cancel_injected")

        def interrupt_join(*arguments):
            nonlocal sent
            if not sent:
                sent = True
                os.kill(os.getpid(), signal.SIGTERM)
            return original_select(*arguments)

        try:
            signal.signal(signal.SIGTERM, cancelled)
            with mock.patch.object(owned.select, "select", interrupt_join):
                with self.assertRaisesRegex(InterruptedError, "cancel_injected"):
                    owner.close()
            self.assertFalse(pathlib.Path(f"/proc/{child.pid}").exists())
        finally:
            signal.signal(signal.SIGTERM, previous)
            child.kill(); child.wait(timeout=3)
            owner.close()

    def test_census_saturation_rejects_only_after_joining_all_current_children(self):
        owner = OwnedChildren()
        first = owner.start([sys.executable, "-c", "import time; time.sleep(60)"])
        extra = owned_popen([sys.executable, "-c", "import time; time.sleep(60)"],
                                 stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        try:
            # A deterministic cumulative-counter boundary, with real live children: the limit must not interrupt the cleanup walk.
            owner.observed = 256
            with self.assertRaisesRegex(ValueError, "browser_child_limit"):
                owner.close()
            self.assertTrue(first.poll() is not None and extra.poll() is not None)
        finally:
            first.kill(); first.wait(timeout=3)
            extra.kill(); extra.wait(timeout=3)
            owner.observed = 0
            try: owner.close()
            except ValueError: pass

    def test_close_is_terminal_and_cannot_restart_a_new_child(self):
        owner = OwnedChildren()
        first = owner.close()
        self.assertEqual(first, owner.close())
        with self.assertRaisesRegex(ValueError, "browser_already_closed"):
            owner.start([sys.executable, "-c", "pass"])

    def test_failed_launch_still_restores_ownership(self):
        owner = OwnedChildren()
        with self.assertRaises(OSError):
            owner.start(["/http-browser-missing-executable"])
        result = owner.close()
        self.assertEqual(result, {"children_observed": 0, "children_joined": 0})

    def test_detached_child_is_joined_after_its_parent_exits(self):
        with tempfile.TemporaryDirectory() as directory:
            ready = pathlib.Path(directory) / "ready"
            owner = OwnedChildren()
            child = owner.start([sys.executable, "-c",
                "import os,time,sys; p=os.fork(); "
                "os._exit(0) if p else None; os.setsid(); "
                "open(sys.argv[1],'w').write(str(os.getpid())); time.sleep(60)", str(ready)])
            detached = None
            try:
                deadline = time.monotonic() + 3
                while not ready.exists():
                    self.assertLess(time.monotonic(), deadline)
                    time.sleep(0.01)
                detached = int(ready.read_text())
                child.wait(timeout=3)
                summary = owner.close()
                self.assertGreaterEqual(summary["children_observed"], 2)
                self.assertEqual(summary["children_observed"], summary["children_joined"])
                self.assertFalse(pathlib.Path(f"/proc/{detached}").exists())
            finally:
                if detached is not None:
                    try: os.kill(detached, signal.SIGKILL)
                    except ProcessLookupError: pass
                    try: os.waitpid(detached, 0)
                    except ChildProcessError: pass

    def test_preexisting_child_is_never_claimed(self):
        foreign = owned_popen([sys.executable, "-c", "import time; time.sleep(60)"],
                                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        try:
            owner = OwnedChildren()
            owner.start([sys.executable, "-c", "import time; time.sleep(60)"])
            summary = owner.close()
            self.assertEqual(1, summary["children_joined"])
            self.assertIsNone(foreign.poll())
        finally:
            foreign.kill(); foreign.wait(timeout=3)


if __name__ == "__main__":
    unittest.main()

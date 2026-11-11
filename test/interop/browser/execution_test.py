# SPDX-FileCopyrightText: 2026 the http contributors
# SPDX-License-Identifier: MIT OR Apache-2.0
import sys
sys.dont_write_bytecode = True
import os
from pathlib import Path
import select
import subprocess
import tempfile
import time
import unittest
from unittest import mock
import execution
sys.path.insert(0, str(Path(__file__).resolve().parents[3] / "scripts"))
from process_supervisor import owned_popen


READER = '''import os,select,sys,time
path=sys.argv[1]
assert select.select([sys.stdin],[],[],3)[0]
assert sys.stdin.readline()=='check\\n'
def valid():
 try:
  with open(path,'rb')as source:return source.read(33)==b'untrusted-complete'
 except FileNotFoundError:return None
first=valid()
print('absent'if first is None else'complete'if first else'partial',flush=True)
deadline=time.monotonic()+3
while first is None and time.monotonic()<deadline:
 time.sleep(.001);first=valid()
sys.exit(0 if first is True else 1)
'''


class CompletionPublication(unittest.TestCase):
    @unittest.skipUnless(os.name == "posix", "pipe readiness uses POSIX select")
    def test_native_reader_never_observes_a_created_but_empty_completion(self):
        with tempfile.TemporaryDirectory() as directory:
            stop = Path(directory) / "stop"
            child = owned_popen([sys.executable, "-I", "-B", "-c", READER, str(stop)],
                stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
            original = Path.open
            observations = []

            def checkpoint(path, *args, **kwargs):
                stream = original(path, *args, **kwargs)
                if args and args[0] == "x":
                    child.stdin.write(b"check\n"); child.stdin.flush()
                    if not select.select([child.stdout], [], [], 3)[0]:
                        raise AssertionError("reader_checkpoint_timeout")
                    observations.append(child.stdout.readline().strip())
                return stream

            try:
                with mock.patch.object(Path, "open", checkpoint):
                    execution.publish_stop(stop, False)
                self.assertEqual(observations, [b"absent"])
                self.assertEqual(child.wait(timeout=3), 0)
                self.assertEqual(stop.read_bytes(), b"untrusted-complete")
            finally:
                if child.poll() is None:
                    child.kill(); child.wait(timeout=2)
                child.stdin.close(); child.stdout.close()

    def test_existing_completion_is_never_replaced(self):
        with tempfile.TemporaryDirectory() as directory:
            stop = Path(directory) / "stop"
            stop.write_bytes(b"existing")
            with self.assertRaises(FileExistsError):
                execution.publish_stop(stop, False)
            self.assertEqual(stop.read_bytes(), b"existing")
            self.assertEqual(len(list(Path(directory).iterdir())), 1)


if __name__ == "__main__":
    unittest.main()

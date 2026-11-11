#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 the http contributors
# SPDX-License-Identifier: MIT OR Apache-2.0
"""Host-only actual Docker controls; no daemon socket enters the browser."""
import sys
sys.dont_write_bytecode = True
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import time
import unittest
import container_owner
sys.path.insert(0, str(Path(__file__).resolve().parents[3] / "scripts"))
from process_supervisor import owned_popen

IMAGE = None


class ActualDaemon(unittest.TestCase):
    def setUp(self):
        self.docker = shutil.which('docker')
        self.assertTrue(sys.platform == 'linux' and os.getuid() != 0 and self.docker is not None)
        self.directory = tempfile.TemporaryDirectory()
        self.root = Path(self.directory.name)
        self.container = container_owner.Container(self.docker, IMAGE, self.root, 5, True,
                                                   mount_source=False)

    def tearDown(self):
        self.container.remove()
        self.directory.cleanup()

    def test_success_returns_only_after_actual_container_removal(self):
        result = container_owner.supervise(self.container, ['python3', '-c', 'pass'])
        self.assertTrue(result['passed'] and result['removed'])
        self.assertFalse(self.container.exists(time.monotonic()+5))

    def test_actual_daemon_work_is_stopped_and_removed_at_deadline(self):
        result = container_owner.supervise(self.container, ['python3', '-c', 'import time;time.sleep(30)'])
        self.assertEqual(result['failure_phase'], 3)
        self.assertTrue(result['removed'])
        self.assertFalse(self.container.exists(time.monotonic()+5))

    def test_killed_cli_owner_leaves_no_actual_daemon_container(self):
        path = self.root/'identity'
        program = ('import sys;sys.path.insert(0,sys.argv[1]);import container_owner,json;from pathlib import Path;'
            'root=Path(sys.argv[2]);c=container_owner.Container(sys.argv[3],sys.argv[4],root,30,True,mount_source=False);'
            '(root/"identity").write_text(json.dumps({"name":c.name,"nonce":c.nonce}));'
            'container_owner.supervise(c,["python3","-c","import time;time.sleep(30)"])')
        child = owned_popen([sys.executable, '-I', '-B', '-c', program,
            str(Path(container_owner.__file__).resolve().parent), str(self.root), self.docker, IMAGE],
            stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            start_new_session=True)
        try:
            deadline = time.monotonic()+10
            while not path.exists() and time.monotonic()<deadline and child.poll() is None:
                time.sleep(.02)
            self.assertTrue(path.exists())
            identity = json.loads(path.read_text())
            self.container.name, self.container.nonce = identity['name'], identity['nonce']
            running = False
            while time.monotonic()<deadline and child.poll() is None:
                status, output, _ = self.container.call(['inspect', '--format', '{{.State.Running}}',
                    self.container.name], min(deadline,time.monotonic()+2), cleanup=True)
                if status == 0 and output.strip() == b'true':
                    running = True
                    break
                time.sleep(.02)
            self.assertTrue(running)
            child.kill(); child.wait(timeout=2)
            deadline = time.monotonic()+10
            while self.container.exists(deadline) and time.monotonic()<deadline:
                time.sleep(.05)
            self.assertFalse(self.container.exists(time.monotonic()+2))
        finally:
            if child.poll() is None:
                child.kill(); child.wait(timeout=2)


if __name__ == '__main__':
    if len(sys.argv) != 2:
        sys.exit(2)
    IMAGE = sys.argv.pop()
    unittest.main()

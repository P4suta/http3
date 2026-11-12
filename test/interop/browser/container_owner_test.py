# SPDX-FileCopyrightText: 2026 the http contributors
# SPDX-License-Identifier: MIT OR Apache-2.0
"""Real CLI/owner processes with a deterministic, detached daemon fixture."""
import sys
sys.dont_write_bytecode = True
import json
import os
from pathlib import Path
import select
import signal
import subprocess
import tempfile
import time
import unittest
from unittest import mock
import container_owner
from owned import OwnedChildren

DOCKER = '''#!/usr/bin/python3
import json,os,pathlib,signal,subprocess,sys,time
d=pathlib.Path(__file__).parent
state=d/'state'; mode=(d/'mode').read_text()
a=sys.argv[1:]
if a[0]=='create':
    (d/'arguments').write_text(json.dumps(a))
    child=subprocess.Popen([sys.executable,'-c','import time;time.sleep(30)'],
        start_new_session=True,stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
    label=a[a.index('--label')+1].split('=',1)[1]
    state.write_text(json.dumps({'pid':child.pid,'label':label}))
    if mode=='create_stall':
        while True: time.sleep(.01)
    print('1'*64)
elif a[0]=='container':
    if state.exists(): print('1'*64)
elif a[0]=='inspect':
    label=json.loads(state.read_text())['label']
    if mode=='duplicate':
        print('{"http.browser.owner":"foreign","http.browser.owner":"'+label+'"}')
        sys.exit(0)
    print(json.dumps({'http.browser.owner':'foreign' if mode=='foreign' else label}))
elif a[0]=='rm':
    if mode=='cleanup_error': sys.exit(1)
    value=json.loads(state.read_text())
    try:
        fd=os.pidfd_open(value['pid']); os.kill(value['pid'],signal.SIGKILL)
        import select
        if not select.select([fd],[],[],2)[0]: sys.exit(1)
        os.close(fd)
    except ProcessLookupError: pass
    state.unlink()
elif a[0]=='start':
    (d/'started').write_text(str(os.getpid()))
    if mode in ('success','foreign','duplicate','cleanup_error'): sys.exit(0)
    if mode=='flood':
        while True: os.write(1,b'private-container-output'*4096)
    if mode=='stopped': os.kill(os.getpid(),signal.SIGSTOP)
    while True: time.sleep(.01)
else: sys.exit(2)
'''


class DaemonOwnership(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.root = Path(self.directory.name)
        self.docker = self.root / 'docker'
        self.docker.write_text(DOCKER)
        self.docker.chmod(0o755)
        self.owner = OwnedChildren()

    def tearDown(self):
        self.owner.close()
        self.directory.cleanup()

    def run_case(self, mode, seconds=2, maximum_threads=256):
        (self.root / 'mode').write_text(mode)
        return container_owner.supervise(container_owner.Container(str(self.docker), 'fixture:1',
            self.root, seconds, True, maximum_threads=maximum_threads), ['true'])

    def test_firefox_thread_and_shared_memory_budgets_are_explicit(self):
        self.assertTrue(self.run_case('success', maximum_threads=512)['passed'])
        arguments = json.loads((self.root / 'arguments').read_text())
        self.assertEqual(arguments[arguments.index('--pids-limit') + 1], '512')
        self.assertEqual(arguments[arguments.index('--shm-size') + 1], '256m')
        self.assertEqual(arguments[arguments.index('--network') + 1], 'none')
        self.assertFalse((self.root / 'state').exists())

    def test_unknown_or_boolean_thread_budget_is_rejected_before_daemon_call(self):
        for maximum_threads in (True, 0, 255, 513, '512'):
            with self.assertRaises(container_owner.Failure):
                self.run_case('success', maximum_threads=maximum_threads)
        self.assertFalse((self.root / 'arguments').exists())

    def test_success_removes_the_daemon_container_before_return(self):
        result = self.run_case('success')
        self.assertEqual(result, {'schema': 1, 'passed': True, 'removed': True, 'failure_phase': 0})
        self.assertFalse((self.root / 'state').exists())

    def test_deadline_joins_attaching_cli_and_removes_detached_daemon(self):
        started = time.monotonic()
        result = self.run_case('stall', .2)
        self.assertEqual(result, {'schema': 1, 'passed': False, 'removed': True, 'failure_phase': 3})
        self.assertLess(time.monotonic()-started, 3)
        self.assertFalse((self.root / 'state').exists())

    def test_output_flood_is_discarded_and_daemon_is_removed(self):
        result = self.run_case('flood')
        self.assertFalse(result['passed'])
        self.assertTrue(result['removed'])
        self.assertFalse((self.root / 'state').exists())

    def test_cleanup_error_cannot_publish_success(self):
        result = self.run_case('cleanup_error')
        self.assertEqual(result, {'schema': 1, 'passed': False, 'removed': False, 'failure_phase': 4})

    def test_foreign_nonce_refuses_destructive_cleanup(self):
        result = self.run_case('foreign')
        self.assertEqual(result['failure_phase'], 4)
        self.assertFalse(result['removed'])
        self.assertTrue((self.root / 'state').exists())

    def test_duplicate_owner_labels_refuse_destructive_cleanup(self):
        result = self.run_case('duplicate')
        self.assertFalse(result['removed'])
        self.assertTrue((self.root / 'state').exists())

    def test_parent_descriptor_setup_failure_closes_the_caller_descriptor(self):
        before = len(list(Path('/proc/self/fd').iterdir()))
        original = os.pidfd_open
        opened = []
        def open_once(pid):
            if opened:
                raise OSError('controlled_descriptor_failure')
            descriptor = original(pid)
            opened.append(descriptor)
            return descriptor
        try:
            with mock.patch.object(container_owner.os, 'pidfd_open', side_effect=open_once):
                with self.assertRaises(OSError):
                    self.run_case('success')
            self.assertEqual(before, len(list(Path('/proc/self/fd').iterdir())))
        finally:
            for descriptor in opened:
                try: os.close(descriptor)
                except OSError: pass

    def test_caller_death_removes_a_container_even_when_its_attaching_cli_stops(self):
        self.owner_death('stopped', 'started')

    def test_caller_death_during_create_recovers_the_owned_container_by_nonce(self):
        self.owner_death('create_stall', 'state')

    def owner_death(self, mode, checkpoint):
        (self.root / 'mode').write_text(mode)
        module = str(Path(container_owner.__file__).resolve().parent)
        program = ('import sys;sys.path.insert(0,sys.argv[1]);import container_owner;from pathlib import Path;'
            'root=Path(sys.argv[2]);container_owner.supervise(container_owner.Container('
            'str(root/"docker"),"fixture:1",root,10,True),["true"])')
        child = self.owner.start([sys.executable, '-I', '-B', '-c', program, module, str(self.root)])
        deadline = time.monotonic()+3
        while not (self.root/checkpoint).exists() and time.monotonic()<deadline:
            time.sleep(.01)
        self.assertTrue((self.root/checkpoint).exists())
        pid = json.loads((self.root/'state').read_text())['pid']
        descriptor = os.pidfd_open(pid)
        try:
            child.kill(); child.wait(timeout=2)
            self.assertTrue(bool(select.select([descriptor], [], [], 5)[0]))
            deadline = time.monotonic()+2
            while (self.root/'state').exists() and time.monotonic()<deadline:
                time.sleep(.01)
            self.assertFalse((self.root/'state').exists())
        finally:
            os.close(descriptor)

    def test_private_or_inconsistent_receipt_is_rejected(self):
        for record in [dict(schema=1, passed=True, removed=False, failure_phase=0),
                       dict(schema=1, passed=True, removed=True, failure_phase=3),
                       dict(schema=1, passed=True, removed=True, failure_phase=0, private='private-token')]:
            with self.assertRaises(container_owner.Failure):
                container_owner.validate(record)


if __name__ == '__main__':
    unittest.main()

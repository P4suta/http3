#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 the http contributors
# SPDX-License-Identifier: MIT OR Apache-2.0
"""Run the native drivers' actual EXIT cleanup against private failure canaries.

The receipt producer has separate Erlang controls. Here only that producer is
replaced, so the shell's argument contract, retained files, output, cleanup and
original exit status can be checked without downloading or running a peer.
"""
import json
import os
from pathlib import Path
import re
import selectors
import shlex
import shutil
import signal
import subprocess
import tempfile
import time
import unittest
from process_supervisor import owned_popen


ROOT = Path(__file__).resolve().parents[1]
PEERS = {
    "curl": "curl-h1-h2",
    "nghttp2": "nghttp2-h2",
    "ngtcp2": "ngtcp2-nghttp3-h3",
    "quiche": "quiche-h3",
    "ohttpgo": "ohttp-go",
    "ohttpts": "ohttp-typescript",
    "masquego": "masque-independent",
}
CANARY = b"private-native-cleanup-canary"
OUTPUT_LIMIT = 65536
RUN_ID = "a" * 64


def function(source, name, required=True):
    match = re.search(r"^" + name + r"\(\) \{\n.*?^\}", source, re.M | re.S)
    if match is None:
        if required:
            raise AssertionError("driver_function_missing")
        return ""
    return match[0]


def bounded_child(arguments, root, environment):
    child = owned_popen(arguments, cwd=root, env=environment,
        stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT, start_new_session=True)
    output = bytearray()
    deadline = time.monotonic() + 10
    complete = False
    try:
        with selectors.DefaultSelector() as selector:
            selector.register(child.stdout, selectors.EVENT_READ)
            while selector.get_map():
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    break
                for key, _ in selector.select(min(remaining, 0.1)):
                    chunk = os.read(key.fd, 4096)
                    if not chunk:
                        selector.unregister(key.fileobj)
                    elif len(output) + len(chunk) > OUTPUT_LIMIT:
                        return None, b"", False
                    else:
                        output.extend(chunk)
            if not selector.get_map():
                remaining = deadline - time.monotonic()
                if remaining > 0:
                    child.wait(timeout=remaining)
                    complete = True
        return child.returncode, bytes(output), complete
    finally:
        # Only this new session belongs to the fixture.
        # Kill any descendants,
        # including when the shell has already exited but a pipe remains open.
        if child.poll() is None:
            child.kill()
        child.wait(timeout=2)
        child.stdout.close()


def cleanup_observation(driver, status=7, producer_fails=False, source=None,
                        signal_name=None):
    if source is None:
        source = (ROOT / "test" / "interop" / driver / "run.sh").read_text()
    with tempfile.TemporaryDirectory(prefix="http-cleanup-control-") as directory:
        root = Path(directory)
        temporary = root / "tmp"
        temporary.mkdir()
        work_prefix = "masque" if driver == "masquego" else driver
        work = temporary / ("http-" + work_prefix + "-interop.ABCDEF")
        work.mkdir()
        (work / (CANARY.decode() + ".log")).write_bytes(CANARY * 4096)
        (work / "stderr.log").write_bytes(CANARY)
        binaries = root / "bin"
        binaries.mkdir()
        producer = binaries / "escript"
        producer.write_text("""#!/usr/bin/env python3
import json, os, pathlib, sys
args = sys.argv[1:]
root = pathlib.Path.cwd()
if os.environ['PRODUCER_FAILS'] == '1':
    print('private-native-cleanup-canary', file=sys.stderr)
    sys.exit(19)
(root / 'invocation.json').write_text(json.dumps(args))
if len(args) == 6 and args[:2] == ['scripts/interop_audit.escript', '--driver-failure']:
    path = root / 'build' / 'interop' / 'failures' / args[2] / 'driver.json'
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps({'run_id': args[3], 'phase': args[4], 'exit_status': int(args[5])}))
""")
        producer.chmod(0o700)
        # Observe the actual finite timeout arguments; then invoke GNU timeout.
        timer = binaries / "timeout"
        timer.write_text("#!/usr/bin/env python3\nimport json, os, pathlib, sys\n"
            "pathlib.Path('timeout.json').write_text(json.dumps(sys.argv[1:4]))\n"
            "os.execv(" + repr(shutil.which("timeout")) + ", ['timeout'] + sys.argv[1:])\n")
        timer.chmod(0o700)
        if signal_name is None:
            action = "exit " + str(status)
            expected_status = status
        else:
            expected_status = {"INT": 130, "TERM": 143}[signal_name]
            action = "kill -" + signal_name + " \"$$\"\nexit 99"
        setup = "\n".join([
            "set -Eeuo pipefail",
            "repository_root=" + shlex.quote(str(root)),
            "work_directory=" + shlex.quote(str(work)),
            "temporary_root=" + shlex.quote(str(temporary)),
            "failure_directory=" + shlex.quote(str(root / "build" / "interop-curl-failure")),
            "peer_process=''",
            "interop_run_id=" + shlex.quote(RUN_ID),
            "declare -A children=()" if driver.startswith("ohttp") or driver == "masquego"
            else "declare -a children=()",
            function(source, "clean_failure_directory", required=False),
            function(source, "preserve_failure", required=False),
            function(source, "cleanup"),
            "trap cleanup EXIT",
            "trap 'exit 130' INT",
            "trap 'exit 143' TERM",
            action,
        ])
        script = root / "cleanup.sh"
        script.write_text(setup)
        environment = os.environ.copy()
        environment.update(PATH=str(binaries) + os.pathsep + environment["PATH"],
            TMPDIR=str(temporary), PRODUCER_FAILS="1" if producer_fails else "0",
            PYTHONDONTWRITEBYTECODE="1")
        exit_status, output, joined = bounded_child(["bash", str(script)], root, environment)
        private = CANARY in output
        retained = 0
        for path in (root / "build").rglob("*"):
            retained += 1
            if retained > 256:
                raise AssertionError("retained_file_count_exceeded")
            private = private or CANARY.decode() in path.name
            if path.is_file():
                if path.stat().st_size > OUTPUT_LIMIT:
                    private = True
                else:
                    private = private or CANARY in path.read_bytes()
        invocation = root / "invocation.json"
        timer_record = root / "timeout.json"
        expected = ["scripts/interop_audit.escript", "--driver-failure", PEERS[driver],
                    RUN_ID, "cleanup", str(expected_status)]
        return {
            "private": private, "exit_preserved": exit_status == expected_status,
            "work_removed": not work.exists(), "joined": joined,
            "producer_called": invocation.exists() and json.loads(invocation.read_text()) == expected,
            "bounded": timer_record.exists() and json.loads(timer_record.read_text()) ==
                ["--signal=TERM", "--kill-after=5s", "60s"],
            "fallback": output == b"interop driver failure record unavailable\n",
            "silent": not output,
        }


class DriverSourceContract(unittest.TestCase):
    def test_every_active_shell_cleanup_uses_bounded_run_scoped_failure(self):
        for driver, peer in PEERS.items():
            with self.subTest(driver=driver):
                source = (ROOT / "test" / "interop" / driver / "run.sh").read_text()
                cleanup = function(source, "cleanup")
                self.assertIn("timeout --signal=TERM --kill-after=5s 60s escript", cleanup)
                self.assertIn("trap cleanup EXIT\n", source)
                self.assertIn("trap 'exit 130' INT", source)
                self.assertIn("trap 'exit 143' TERM", source)
                self.assertNotIn("trap cleanup EXIT INT TERM", source)
                self.assertIn('if [[ ! "$interop_run_id" =~ ^[0-9a-f]{64}$ ]]; then', source)
                self.assertIn('echo "interop run id is unavailable" >&2', source)
                pattern = (r"--driver-failure\s+" + re.escape(peer)
                           + r"\s+\"\$interop_run_id\"\s+cleanup\s+\"\$(?:status|exit_status)\"")
                self.assertRegex(cleanup, pattern)
                self.assertIn("interop driver failure record unavailable", cleanup)

    def test_http3_multi_peer_cleanup_preserves_each_started_run(self):
        source = (ROOT / "packages/http3/test/interop/run.sh").read_text()
        preserve = function(source, "preserve_failure")
        cleanup = function(source, "cleanup")
        self.assertIn("peers=(aioquic-h3 quic-go-h3)", preserve)
        self.assertIn("timeout --signal=TERM --kill-after=5s 60s", preserve)
        self.assertRegex(
            preserve,
            r"--driver-failure\s+\"\$peer\"\s+\"\$run_id\"\s+cleanup\s+\"\$status\"",
        )
        self.assertIn('preserve_failure "$exit_status"', cleanup)
        self.assertIn("interop driver failure record unavailable", preserve)
        self.assertIn("trap cleanup EXIT\n", source)
        self.assertIn("trap 'exit 130' INT", source)
        self.assertIn("trap 'exit 143' TERM", source)
        self.assertNotIn("trap cleanup EXIT INT TERM", source)
        require_run_id = function(source, "require_run_id")
        self.assertIn('[[ ! "$1" =~ ^[0-9a-f]{64}$ ]]', require_run_id)
        self.assertEqual(source.count("require_run_id \"${interop_run_ids["), 2)

    def test_repeat_campaign_cannot_swallow_interrupt_or_termination(self):
        source = (ROOT / "packages/http3/test/interop/campaign.sh").read_text()
        self.assertIn("trap cleanup EXIT\n", source)
        self.assertIn("trap 'exit 130' INT", source)
        self.assertIn("trap 'exit 143' TERM", source)
        self.assertNotIn("trap cleanup EXIT INT TERM", source)


@unittest.skipUnless(os.name == "posix" and shutil.which("bash") and shutil.which("timeout"),
                     "requires POSIX Bash and GNU timeout; Windows skips do not qualify")
class NativeCleanup(unittest.TestCase):
    def test_private_logs_and_paths_are_never_retained_or_printed(self):
        for driver in PEERS:
            with self.subTest(driver=driver):
                observation = cleanup_observation(driver)
                self.assertFalse(observation["private"])
                self.assertTrue(observation["joined"])
                self.assertTrue(observation["work_removed"])

    def test_typed_failure_uses_bounded_producer_and_preserves_original_status(self):
        for driver in PEERS:
            for status in [1, 7, 130, 143, 255]:
                with self.subTest(driver=driver, status=status):
                    observation = cleanup_observation(driver, status)
                    for key in ["producer_called", "bounded", "exit_preserved", "joined", "silent"]:
                        self.assertTrue(observation[key], key)

    def test_failed_producer_is_redacted_and_cannot_replace_original_failure(self):
        for driver in PEERS:
            with self.subTest(driver=driver):
                observation = cleanup_observation(driver, producer_fails=True)
                self.assertFalse(observation["private"])
                for key in ["fallback", "bounded", "exit_preserved", "joined", "work_removed"]:
                    self.assertTrue(observation[key], key)

    def test_signals_publish_their_canonical_status_and_preserve_it(self):
        for driver in PEERS:
            for signal_name in ["INT", "TERM"]:
                with self.subTest(driver=driver, signal=signal_name):
                    observation = cleanup_observation(driver, signal_name=signal_name)
                    for key in ["producer_called", "bounded", "exit_preserved", "joined", "silent"]:
                        self.assertTrue(observation[key], key)

    def test_success_does_not_publish_failure(self):
        for driver in PEERS:
            with self.subTest(driver=driver):
                observation = cleanup_observation(driver, status=0)
                for key in ["producer_called", "bounded", "private"]:
                    self.assertFalse(observation[key], key)
                for key in ["exit_preserved", "joined", "silent", "work_removed"]:
                    self.assertTrue(observation[key], key)


if __name__ == "__main__":
    unittest.main()

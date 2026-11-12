#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 the http contributors
# SPDX-License-Identifier: MIT OR Apache-2.0
"""Join the Docker container independently of the attaching CLI's lifetime."""
import sys
sys.dont_write_bytecode = True
import argparse
import json
import os
from pathlib import Path
import re
import select
import selectors
import shutil
import signal
import subprocess
import time
import uuid
sys.path.insert(0, str(Path(__file__).resolve().parents[3] / "scripts"))
from process_supervisor import owned_popen

LABEL = "http.browser.owner"
MAX_OUTPUT = 1048576


class Failure(Exception):
    pass


def unique_object(pairs):
    value = {}
    for key, item in pairs:
        if key in value:
            raise Failure()
        value[key] = item
    return value


class Container:
    def __init__(self, docker, image, root, seconds, isolated, parents=(), *, mount_source=True, maximum_threads=256):
        self.docker, self.image, self.root = docker, image, root
        self.seconds, self.isolated, self.parents = seconds, isolated, parents
        self.mount_source = mount_source
        if type(maximum_threads) is not int or maximum_threads not in (256, 512):
            raise Failure()
        self.maximum_threads = maximum_threads
        self.nonce = uuid.uuid4().hex
        self.name = "http-browser-" + self.nonce
        self.cancelled = False
        self.deadline = time.monotonic() + seconds

    def interrupted(self):
        return self.cancelled or bool(self.parents and select.select(self.parents, [], [], 0)[0])

    def call(self, arguments, until, *, cleanup=False):
        if time.monotonic() >= until or (not cleanup and self.interrupted()):
            raise Failure()
        child = owned_popen([self.docker, *arguments], stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, start_new_session=True)
        data = [bytearray(), bytearray()]
        try:
            with selectors.DefaultSelector() as selector:
                for index, stream in enumerate((child.stdout, child.stderr)):
                    os.set_blocking(stream.fileno(), False)
                    selector.register(stream, selectors.EVENT_READ, index)
                while selector.get_map() or child.poll() is None:
                    if time.monotonic() >= until or (not cleanup and self.interrupted()):
                        raise Failure()
                    for key, _ in selector.select(min(.05, max(0, until-time.monotonic()))):
                        chunk = os.read(key.fileobj.fileno(), 65536)
                        if chunk:
                            data[key.data].extend(chunk)
                            if sum(map(len, data)) > MAX_OUTPUT:
                                raise Failure()
                        else:
                            selector.unregister(key.fileobj)
                return child.wait(timeout=1), bytes(data[0]), bytes(data[1])
        finally:
            if child.poll() is None:
                child.kill()
                child.wait(timeout=2)
            child.stdout.close()
            child.stderr.close()

    def exists(self, until):
        status, output, _ = self.call(["container", "ls", "--all", "--no-trunc",
            "--filter", "name=^/" + self.name + "$", "--format", "{{.ID}}"], until, cleanup=True)
        if status != 0:
            raise Failure()
        if not output.strip():
            return False
        if re.fullmatch(rb"[0-9a-f]{64}\n?", output) is None:
            raise Failure()
        return True

    def remove(self):
        until = time.monotonic() + 20
        if not self.exists(until):
            return True
        status, output, _ = self.call(["inspect", "--format", "{{json .Config.Labels}}", self.name],
            until, cleanup=True)
        if status != 0 or len(output) > 4096:
            raise Failure()
        labels = json.loads(output, object_pairs_hook=unique_object)
        if type(labels) is not dict or labels.get(LABEL) != self.nonce:
            raise Failure()
        status, _, _ = self.call(["rm", "--force", self.name], until, cleanup=True)
        if status != 0 or self.exists(until):
            raise Failure()
        return True

    def run(self, command):
        phase, passed, removed = 1, False, False
        old = {number: signal.signal(number, lambda *_: setattr(self, "cancelled", True))
               for number in (signal.SIGTERM, signal.SIGINT)}
        try:
            phase = 2
            arguments = ["create", "--name", self.name, "--label", LABEL + "=" + self.nonce,
                "--init", "--log-driver", "none", "--user", str(os.getuid()) + ":" + str(os.getgid()),
                "--cap-drop", "ALL", "--security-opt", "no-new-privileges", "--pids-limit", str(self.maximum_threads),
                "--memory", "2g", "--env", "HOME=/tmp/http-browser-home",
                "--env", "ERL_FLAGS=+S 2:2 +SDcpu 1 +SDio 1 +A 2"]
            if self.maximum_threads == 512:
                arguments.extend(["--shm-size", "256m"])
            if self.mount_source:
                arguments.extend(["--mount", "type=bind,source=" + str(self.root) + ",target=/work"])
            if self.isolated:
                arguments.extend(["--network", "none", "--env", "HTTP_BROWSER_SKIP_FRESH_BUILD=1"])
            arguments.extend([self.image, *command])
            status, output, _ = self.call(arguments, min(self.deadline, time.monotonic()+30))
            if status != 0 or re.fullmatch(rb"[0-9a-f]{64}\n?", output) is None:
                raise Failure()
            phase = 3
            status, _, _ = self.call(["start", "--attach", self.name], self.deadline)
            if status != 0 or self.interrupted() or time.monotonic() >= self.deadline:
                raise Failure()
            passed = True
        except BaseException:
            passed = False
        finally:
            try:
                removed = self.remove()
            except BaseException:
                phase, removed = 4, False
            for number, handler in old.items():
                signal.signal(number, handler)
        return {"schema": 1, "passed": passed and removed, "removed": removed,
                "failure_phase": 0 if passed and removed else phase}


def validate(record):
    if type(record) is not dict or set(record) != {"schema", "passed", "removed", "failure_phase"} \
            or type(record["schema"]) is not int or record["schema"] != 1 \
            or any(type(record[key]) is not bool for key in ("passed", "removed")) \
            or type(record["failure_phase"]) is not int or not 0 <= record["failure_phase"] <= 4 \
            or record["passed"] != (record["removed"] and record["failure_phase"] == 0):
        raise Failure()
    return record


def supervise(container, command):
    """The controller survives caller death; it alone owns daemon cleanup."""
    caller = parent = read = write = None
    child = None
    descriptor = None
    try:
        caller = os.pidfd_open(os.getpid())
        parent_pid = os.getppid()
        parent = os.pidfd_open(parent_pid)
        read, write = os.pipe()
        if os.getppid() != parent_pid:
            raise Failure()
        child = os.fork()
        if child == 0:
            try:
                os.setsid()
                os.close(read)
                container.parents = (caller, parent)
                result = validate(container.run(command))
                os.write(write, json.dumps(result, separators=(",", ":")).encode())
                os._exit(0)
            except BaseException:
                os._exit(1)
        os.close(write)
        write = None
        os.close(caller)
        caller = None
        descriptor = os.pidfd_open(child)
        deadline = time.monotonic() + container.seconds + 25
        data = bytearray()
        os.set_blocking(read, False)
        while time.monotonic() < deadline:
            ready, _, _ = select.select([read, descriptor], [], [], max(0, min(.1, deadline-time.monotonic())))
            if read in ready:
                data.extend(os.read(read, 4097))
                if len(data) > 4096:
                    raise Failure()
            if descriptor in ready:
                _, status = os.waitpid(child, 0)
                child = None
                if status != 0:
                    raise Failure()
                return validate(json.loads(data))
        raise Failure()
    finally:
        if child:
            try: os.kill(child, signal.SIGTERM)
            except ProcessLookupError: pass
            if descriptor is not None and not select.select([descriptor], [], [], 22)[0]:
                try: os.kill(child, signal.SIGKILL)
                except ProcessLookupError: pass
            os.waitpid(child, 0)
        for fd in (caller, parent, read, write, descriptor):
            if fd is not None:
                os.close(fd)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--image", required=True)
    parser.add_argument("--phase", choices=("build", "run"), required=True)
    parser.add_argument("--peer", choices=("chromium", "firefox"), default="chromium")
    args = parser.parse_args()
    if sys.platform != "linux" or os.getuid() == 0 \
            or re.fullmatch(r"[a-z0-9][a-z0-9:._/-]{1,128}", args.image) is None:
        raise Failure()
    root = Path(__file__).resolve().parents[3]
    docker = shutil.which("docker")
    if docker is None or "," in str(root):
        raise Failure()
    isolated = args.phase == "run"
    command = ["bash", "-c", 'mkdir -p "$HOME"; bash scripts/fresh_build.sh http']
    if isolated:
        command = ["bash", "test/interop/browser/" + ("firefox_run_inside.sh" if args.peer == "firefox" else "run_inside.sh")]
    record = supervise(Container(docker, args.image, root, 600 if isolated else 300, isolated,
                                 maximum_threads=512 if args.peer == "firefox" else 256), command)
    if not record["passed"]:
        raise Failure()


if __name__ == "__main__":
    try:
        main()
    except SystemExit:
        raise
    except BaseException:
        print("Browser container execution or cleanup failed", file=sys.stderr)
        sys.exit(1)

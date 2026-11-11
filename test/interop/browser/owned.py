# SPDX-FileCopyrightText: 2026 the http contributors
# SPDX-License-Identifier: MIT OR Apache-2.0
"""Linux descendant ownership for a bounded, isolated browser execution."""
import ctypes
from contextlib import contextmanager
import json
import os
from pathlib import Path
import select
import signal
import subprocess
import threading
import time
import sys
sys.path.insert(0, str(Path(__file__).resolve().parents[3] / "scripts"))
from process_supervisor import owned_popen


@contextmanager
def _defer_cancellation():
    previous = {}
    pending = None

    def defer(number, _frame):
        nonlocal pending
        pending = number

    try:
        for number in (signal.SIGTERM, signal.SIGINT):
            previous[number] = signal.signal(number, defer)
        yield
    finally:
        for number, handler in previous.items():
            signal.signal(number, handler)
        if pending is not None:
            handler = previous[pending]
            if callable(handler):
                handler(pending, None)
            elif handler == signal.SIG_DFL:
                os.kill(os.getpid(), pending)


def children():
    with Path(f"/proc/{os.getpid()}/task/{os.getpid()}/children").open("rb") as source:
        data = source.read(8193)
    fields = data.split()
    if len(data) > 8192 or len(fields) > 256 or any(not item.isdigit() for item in fields):
        raise ValueError("browser_child_limit")
    return {int(item) for item in fields}


class OwnedChildren:
    """One browser worker owns every child it creates until actual exit.

    The worker runs in its own process, with no concurrent unrelated child
    creation. Linux subreaping retains double-forked Crashpad/browser helpers;
    pidfds keep cleanup tied to the exact process despite identifier reuse.
    """
    def __init__(self):
        if not hasattr(os, "pidfd_open") or not hasattr(signal, "pidfd_send_signal"):
            raise ValueError("browser_ownership_unavailable")
        self.libc = ctypes.CDLL(None, use_errno=True)
        previous = ctypes.c_int()
        if self.libc.prctl(37, ctypes.byref(previous), 0, 0, 0) != 0:
            raise ValueError("browser_ownership_unavailable")
        self.previous = previous.value
        if self.libc.prctl(36, 1, 0, 0, 0) != 0:
            raise ValueError("browser_ownership_unavailable")
        self.baseline = children()
        self.identities = {}
        self.observed = 0
        self.joined = 0
        self.child = None
        self.closed = False
        self.saturated = False

    def _capture(self, closing=False):
        for pid in children() - self.baseline - set(self.identities):
            if self.observed >= 256:
                self.saturated = True
                if not closing:
                    raise ValueError("browser_child_limit")
            if len(self.identities) >= 256:
                self.saturated = True
                break
            try:
                descriptor = os.pidfd_open(pid)
            except ProcessLookupError:
                continue
            self.identities[pid] = descriptor
            self.observed = min(257, self.observed + 1)

    def start(self, command, *, env=None):
        if self.closed:
            raise ValueError("browser_already_closed")
        if self.child is not None:
            raise ValueError("browser_already_started")
        self.child = owned_popen(command, stdout=subprocess.DEVNULL,
                                      stderr=subprocess.DEVNULL, start_new_session=True,
                                      env=env)
        self._capture()
        return self.child

    def close(self):
        # A second cancellation must not interrupt actual waitpid/pidfd retirement.
        # Deliver it after the finite cleanup, never discard it.
        with _defer_cancellation():
            return self._close()

    def _close(self):
        if self.closed:
            if self.saturated:
                raise ValueError("browser_child_limit")
            return {"children_observed": self.observed, "children_joined": self.joined}
        deadline = time.monotonic() + 5
        while True:
            self._capture(closing=True)
            for descriptor in self.identities.values():
                try: signal.pidfd_send_signal(descriptor, signal.SIGKILL)
                except ProcessLookupError: pass
            for pid, descriptor in list(self.identities.items()):
                readable, _, _ = select.select([descriptor], [], [], 0)
                if not readable:
                    continue
                if self.child is not None and pid == self.child.pid:
                    self.child.wait(timeout=max(0.001, deadline - time.monotonic()))
                else:
                    try:
                        reaped, _ = os.waitpid(pid, os.WNOHANG)
                        if reaped == 0: continue
                    except ChildProcessError:
                        # A non-adopted child can only have been reaped by its still-owned parent.
                        # Its pidfd independently proves exit.
                        pass
                os.close(descriptor)
                del self.identities[pid]
                self.joined += 1
            if not self.identities and not (children() - self.baseline):
                break
            if time.monotonic() >= deadline:
                raise ValueError("browser_children_not_joined")
            time.sleep(0.005)
        if self.libc.prctl(36, self.previous, 0, 0, 0) != 0:
            raise ValueError("browser_ownership_restore_failed")
        self.closed = True
        if self.saturated:
            raise ValueError("browser_child_limit")
        return {"children_observed": self.observed, "children_joined": self.joined}


def _owner_descriptor():
    parent = os.getppid()
    descriptor = os.pidfd_open(parent)
    if os.getppid() != parent or select.select([descriptor], [], [], 0)[0]:
        os.close(descriptor)
        raise ValueError("browser_owner_exited")
    return descriptor


def _run_child(work, validate, parent, start, output, deadline, controller_work):
    """The separate-session child outlives a killed CLI long enough to clean up."""
    cancelled = False
    stopped = threading.Event()
    ready = threading.Event()
    watcher = None

    def cancel(_number, _frame):
        nonlocal cancelled
        if not cancelled:
            cancelled = True
            raise InterruptedError("browser_owner_exited")

    def watch():
        ready.set()
        while not stopped.is_set():
            if select.select([parent], [], [], 0.02)[0]:
                os.kill(os.getpid(), signal.SIGTERM)
                return

    status = 1
    try:
        os.setsid()
        signal.signal(signal.SIGTERM, cancel)
        signal.signal(signal.SIGINT, cancel)
        if os.read(start, 1) != b"1":
            raise ValueError("browser_start_abandoned")
        if not controller_work:
            watcher = threading.Thread(target=watch, daemon=True)
            watcher.start()
            if not ready.wait(1):
                raise ValueError("browser_watch_not_ready")
        if select.select([parent], [], [], 0)[0]:
            raise ValueError("browser_owner_exited")
        # The dedicated controller watches this inherited pidfd directly in its selector.
        # It creates its run child before starting any thread.
        result = validate(work(parent) if controller_work else work())
        if cancelled or time.monotonic() >= deadline or select.select([parent], [], [], 0)[0]:
            raise ValueError("browser_owner_exited")
        data = json.dumps(result, sort_keys=True, allow_nan=False).encode("utf-8")
        if len(data) > 8192:
            raise ValueError("browser_result_limit")
        position = 0
        while position < len(data):
            position += os.write(output, data[position:])
        status = 0
    except BaseException:
        # Work and validation exceptions can contain page or certificate data.
        # Only the exit status crosses this process boundary.
        pass
    finally:
        signal.signal(signal.SIGTERM, signal.SIG_IGN)
        signal.signal(signal.SIGINT, signal.SIG_IGN)
        stopped.set()
        if watcher is not None:
            watcher.join(timeout=1)
            if watcher.is_alive():
                status = 1
        os.close(parent)
        os.close(start)
        os.close(output)
    os._exit(status)


def _controller(work, validate, seconds, graceful_child=False,
                controller_work=False, parent_descriptor=None):
    """Join a real run child and every adopted descendant before returning.

    The CLI controller stays in the collector's process group. Its run child
    enters a separate session and watches a pidfd opened before the fork. A
    collector's SIGKILL therefore leaves that child able to cancel its browser
    and join descendants. While the controller lives, its own subreaper also
    covers an abruptly killed or stopped run child. All receipt data is bounded
    and validated in both processes; publication occurs after actual cleanup.
    """
    if type(seconds) not in (int, float) or not 0 < seconds <= 50:
        raise ValueError("browser_deadline_limit")
    deadline = time.monotonic() + seconds
    descriptors = []
    owner = None
    old_handlers = {}
    data = bytearray()
    summary = None
    status = None
    child = None
    child_descriptor = None
    interrupted = False
    cleaning = False

    def cancelled(_number, _frame):
        nonlocal interrupted
        interrupted = True
        if not cleaning:
            raise InterruptedError("browser_execution_cancelled")

    try:
        external_owner = _owner_descriptor() if parent_descriptor is None else os.dup(parent_descriptor)
        descriptors.append(external_owner)
        parent = os.pidfd_open(os.getpid())
        descriptors.append(parent)
        start_read, start_write = os.pipe2(os.O_CLOEXEC)
        descriptors.extend((start_read, start_write))
        result_read, result_write = os.pipe2(os.O_CLOEXEC)
        descriptors.extend((result_read, result_write))
        owner = OwnedChildren()
        for number in (signal.SIGTERM, signal.SIGINT):
            old_handlers[number] = signal.signal(number, cancelled)
        if time.monotonic() >= deadline or select.select([external_owner], [], [], 0)[0]:
            raise InterruptedError("browser_start_abandoned")
        child = os.fork()
        if child == 0:
            os.close(external_owner)
            os.close(start_write)
            os.close(result_read)
            _run_child(work, validate, parent, start_read, result_write, deadline, controller_work)
        owner._capture()
        descriptor = owner.identities.get(child)
        if descriptor is None:
            raise ValueError("browser_child_not_owned")
        child_descriptor = descriptor
        os.write(start_write, b"1")
        os.set_blocking(result_read, False)
        while True:
            if time.monotonic() >= deadline:
                raise TimeoutError("browser_deadline")
            events, _, _ = select.select([external_owner, descriptor, result_read], [], [],
                                         max(0, min(0.05, deadline - time.monotonic())))
            if external_owner in events:
                raise InterruptedError("browser_owner_exited")
            if result_read in events:
                data.extend(os.read(result_read, 8193 - len(data)))
                if len(data) > 8192:
                    raise ValueError("browser_result_limit")
            if descriptor in events:
                _, status = os.waitpid(child, 0)
                break
        try:
            data.extend(os.read(result_read, 8193 - len(data)))
        except BlockingIOError:
            pass
    finally:
        cleaning = True
        try:
            if graceful_child and child_descriptor is not None and status is None:
                # This is the dedicated cleanup controller, never application work.
                # Let it reap its stopped/killed work child before the outer CLI falls back to its own subreaper after five seconds.
                try:
                    signal.pidfd_send_signal(child_descriptor, signal.SIGTERM)
                except ProcessLookupError:
                    pass
                select.select([child_descriptor], [], [], 5)
            if owner is not None:
                summary = owner.close()
        finally:
            for descriptor in descriptors:
                os.close(descriptor)
            for number, handler in old_handlers.items():
                signal.signal(number, handler)
    if interrupted or status != 0 or time.monotonic() >= deadline or len(data) > 8192:
        raise ValueError("browser_owned_work_failed")
    return validate(json.loads(data)), summary


def supervise(work, validate, seconds=50):
    """Keep cleanup runnable when both the CLI dies and application work stops.

    A separate-session controller does no application work: it owns one run
    child, observes the CLI's pidfd, and reaps all adopted descendants. The CLI
    owns the controller and also joins it before publishing. The same absolute
    deadline bounds result eligibility at both levels. Controller cleanup and
    the CLI's fallback join each have five seconds, at most ten additional
    seconds on failure. No process or descriptor escapes a success.
    """
    if type(seconds) not in (int, float) or not 0 < seconds <= 50:
        raise ValueError("browser_deadline_limit")
    deadline = time.monotonic() + seconds

    def run_owned(parent):
        value, ownership = _controller(work, validate, deadline - time.monotonic(),
                                      parent_descriptor=parent)
        return {"result": value, "ownership": ownership}

    def valid_owned(value):
        if type(value) is not dict or set(value) != {"result", "ownership"}:
            raise ValueError("browser_owned_result_invalid")
        ownership = value["ownership"]
        if type(ownership) is not dict or set(ownership) != {"children_observed", "children_joined"}:
            raise ValueError("browser_owned_result_invalid")
        if any(type(count) is not int or not 1 <= count <= 256 for count in ownership.values()) \
                or ownership["children_observed"] != ownership["children_joined"]:
            raise ValueError("browser_owned_result_invalid")
        validate(value["result"])
        return value

    value, outer = _controller(run_owned, valid_owned, seconds, graceful_child=True,
                              controller_work=True)
    for key, count in outer.items():
        value["ownership"][key] += count
    valid_owned(value)
    return value["result"], value["ownership"]

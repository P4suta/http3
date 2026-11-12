#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 the http contributors
# SPDX-License-Identifier: MIT OR Apache-2.0
"""One finite Chromium session, with verified TLS and owned descendants."""
import sys
sys.dont_write_bytecode = True
from contextlib import contextmanager
import json
import os
from pathlib import Path
import re
import resource
import signal
import socket
import subprocess
import tempfile
import time
import urllib.error
import urllib.request
sys.path.insert(0, str(Path(__file__).resolve().parents[3] / "scripts"))
from process_supervisor import owned_run
from netlog import certificate_rejected
from oracle import validate_observation, validate_rejection
from owned import OwnedChildren, supervise
from receipt import browser as validate_receipt

ROOT = Path(__file__).resolve().parents[3]
BROWSER = "/opt/browser/chrome-linux64/chrome"
DRIVER = "/opt/browser/chromedriver-linux64/chromedriver"
VERSION = "153.0.8010.36"
MAX_LOG = 8_388_608


def require(condition):
    if not condition:
        raise ValueError("browser_contract_failed")


def unique_json(data):
    def unique(pairs):
        value = {}
        for key, item in pairs:
            require(key not in value)
            value[key] = item
        return value
    require(len(data) <= MAX_LOG)
    return json.loads(data, object_pairs_hook=unique)


class Driver:
    def __init__(self, port, deadline):
        self.port, self.deadline = port, deadline

    def command(self, method, path, value=None):
        remaining = self.deadline - time.monotonic()
        require(remaining > 0)
        request = urllib.request.Request("http://127.0.0.1:" + str(self.port) + path,
            data=None if value is None else json.dumps(value).encode(), method=method,
            headers={"Content-Type": "application/json"})
        try:
            response = urllib.request.urlopen(request, timeout=min(12, remaining))
        except urllib.error.HTTPError as response:
            with response:
                data = response.read(1_048_577)
        else:
            with response:
                data = response.read(1_048_577)
        require(len(data) <= 1_048_576)
        value = unique_json(data)["value"]
        require(not (type(value) is dict and "error" in value))
        return value


SCRIPT = """const done=arguments[0];
fetch('/body').then(async response=>{
 const bytes=new Uint8Array(await response.arrayBuffer());
 const pattern=new TextEncoder().encode('browser-protocol-');
 const timing=performance.getEntriesByName(new URL('/body',location.href).href).at(-1);
 const cancellation=new AbortController();
 const interrupted=await fetch('/abort',{signal:cancellation.signal});
 const reader=interrupted.body.getReader();
 const first=await reader.read();
 const barrier=await fetch('/abort-ready');
 let name='';cancellation.abort();
 try{await reader.read();}catch(error){name=error.name;}
 done({status:response.status,bytes:bytes.length,
  payload_valid:bytes.length===72250&&bytes.every((v,i)=>v===pattern[i%pattern.length]),
  next_hop:timing.nextHopProtocol,secure_context:isSecureContext,
  aborted:interrupted.status===200&&!first.done&&first.value.length===64&&barrier.status===204,
  abort_name:name});
}).catch(()=>done({failed:true}));"""


def environment(home):
    return {"PATH": "/usr/local/bin:/usr/bin:/bin", "HOME": str(home),
            "XDG_DATA_HOME": str(home / ".local/share"), "LANG": "C.UTF-8",
            "LC_ALL": "C.UTF-8", "TZ": "UTC"}


def isolation():
    require(sys.platform == "linux" and os.geteuid() != 0)
    status = Path("/proc/self/status").read_text()
    require(len(status) <= 65536)
    fields = dict(line.split(":", 1) for line in status.splitlines() if ":" in line)
    require(fields["Seccomp"].strip() == "2" and fields["NoNewPrivs"].strip() == "1")
    require(int(fields["CapEff"].strip(), 16) == 0)
    require({name for _, name in socket.if_nameindex()} == {"lo"})
    require(0 < int(Path("/sys/fs/cgroup/pids.max").read_text()) <= 256)
    # A browser cannot grow its memory-only NetLog or any profile file past this finite limit.
    # This restriction is inherited only by owned children.
    resource.setrlimit(resource.RLIMIT_FSIZE, (MAX_LOG, MAX_LOG))


@contextmanager
def profile(owner):
    with tempfile.TemporaryDirectory(prefix="http-browser-") as directory:
        try:
            yield directory
        finally:
            # Reap writers before touching the files they can still mutate.
            owner.close()


def run(protocol, trusted, port):
    isolation()
    deadline = time.monotonic() + 45
    owner = OwnedChildren()
    netlog = os.memfd_create("http-browser-netlog", os.MFD_CLOEXEC)
    session = None
    observed = None
    network_response = False
    driver = None
    try:
        with profile(owner) as directory:
            home = Path(directory)
            database = home / ".local/share/pki/nssdb"
            database.mkdir(parents=True)
            env = environment(home)
            owned_run(["/usr/bin/certutil", "-N", "--empty-password", "-d", "sql:" + str(database)],
                check=True, timeout=3, max_output_bytes=0, env=env,
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            if trusted:
                owned_run(["/usr/bin/certutil", "-A", "-d", "sql:" + str(database),
                    "-n", "http-fixture-root", "-t", "C,,", "-i",
                    str(ROOT / "packages/quic_core/test/fixtures/ecdsa-p256-server.pem")],
                    check=True, timeout=3, max_output_bytes=0, env=env,
                    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            with socket.socket() as reservation:
                reservation.bind(("127.0.0.1", 0))
                driver_port = reservation.getsockname()[1]
            child = owner.start([DRIVER, "--port=" + str(driver_port),
                "--allowed-ips=127.0.0.1", "--log-level=OFF"], env=env)
            driver = Driver(driver_port, deadline)
            started = time.monotonic() + 5
            while True:
                try:
                    driver.command("GET", "/status")
                    break
                except Exception:
                    require(child.poll() is None and time.monotonic() < started)
                    time.sleep(0.02)
            origin = "https://localhost:" + str(port)
            flags = ["--headless", "--no-sandbox", "--no-first-run", "--no-proxy-server",
                "--disable-background-networking", "--disable-breakpad", "--disable-crash-reporter",
                "--disable-dev-shm-usage", "--user-data-dir=" + str(home / "profile"),
                "--host-resolver-rules=MAP localhost 127.0.0.1",
                "--log-net-log=/proc/" + str(os.getpid()) + "/fd/" + str(netlog)]
            if protocol == 3:
                flags += ["--enable-quic", "--origin-to-force-quic-on=localhost:" + str(port)]
            response = driver.command("POST", "/session", {"capabilities": {"alwaysMatch": {
                "browserName": "chrome", "acceptInsecureCerts": False, "pageLoadStrategy": "eager",
                "goog:loggingPrefs": {"performance": "ALL"},
                "goog:chromeOptions": {"binary": BROWSER, "args": flags}}}})
            session = response["sessionId"]
            require(type(session) is str and re.fullmatch(r"[a-f0-9]{32}", session) is not None)
            capabilities = response["capabilities"]
            require(capabilities["acceptInsecureCerts"] is False and capabilities["browserVersion"] == VERSION)
            require(capabilities["chrome"]["chromedriverVersion"].split(" ", 1)[0] == VERSION)
            base = "/session/" + session
            driver.command("POST", base + "/timeouts", {"script": 10000, "pageLoad": 10000, "implicit": 0})
            if trusted:
                driver.command("POST", base + "/url", {"url": origin + "/"})
                observed = validate_observation(driver.command("POST", base + "/execute/async",
                    {"script": SCRIPT, "args": []}), protocol)
            else:
                try:
                    driver.command("POST", base + "/url", {"url": origin + "/"})
                except Exception:
                    pass
                logs = driver.command("POST", base + "/log", {"type": "performance"})
                require(type(logs) is list and len(logs) <= 4096)
                for entry in logs:
                    message = unique_json(entry["message"].encode())["message"]
                    if message.get("method") == "Network.responseReceived":
                        network_response |= message["params"]["response"].get("url", "").startswith(origin + "/")
            driver.command("DELETE", base)
            session = None
            joined = owner.close()
            require(os.fstat(netlog).st_size <= MAX_LOG)
            os.lseek(netlog, 0, os.SEEK_SET)
            data = os.read(netlog, MAX_LOG + 1)
            rejected = certificate_rejected(data)
            del data
            if trusted:
                require(not rejected)
            else:
                observed = validate_rejection({"certificate_rejected": rejected, "net_error": -202 if rejected else 0,
                    "http_response_observed": network_response})
            require(joined["children_observed"] > 0 and joined["children_observed"] == joined["children_joined"])
            return {"observation": observed, "ownership": joined,
                    "browser_sandbox": False, "container_seccomp": True,
                    "non_root": True, "network_loopback_only": True, "tls_verification": True}
    finally:
        if session is not None and driver is not None and not owner.closed:
            try:
                driver.command("DELETE", "/session/" + session)
            except Exception:
                pass
        try:
            owner.close()
        finally:
            os.close(netlog)


def main(arguments):
    require(len(arguments) == 5)
    protocol, trust, port, destination, nonce = arguments
    require(protocol in ("1", "2", "3") and trust in ("trusted", "untrusted"))
    require(port.isascii() and port.isdecimal() and 0 < int(port) <= 65535)
    require(re.fullmatch(r"[a-f0-9]{32}", nonce) is not None)
    def work():
        result = run(int(protocol), trust == "trusted", int(port))
        result.update(schema=1, nonce=nonce, protocol=int(protocol), trusted=trust == "trusted")
        return result

    def validate(result):
        return validate_receipt(result, nonce, int(protocol), trust == "trusted")

    result, ownership = supervise(work, validate)
    for key, count in ownership.items():
        result["ownership"][key] += count
    validate(result)
    with open(destination, "x", encoding="utf-8") as target:
        json.dump(result, target, sort_keys=True)
        target.write("\n")


if __name__ == "__main__":
    try:
        main(sys.argv[1:])
    except BaseException:
        # The parent receives exit and fixed receipt facts only; page text,
        # certificate data, driver output, arguments and exceptions stay private.
        sys.exit(1)

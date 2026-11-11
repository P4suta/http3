#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 the http contributors
# SPDX-License-Identifier: MIT OR Apache-2.0
"""One real Firefox session with explicit CA trust and joined descendants."""
import sys
sys.dont_write_bytecode = True
import base64
import io
import json
import os
from pathlib import Path
import re
import resource
import socket
import subprocess
import time
import urllib.error
import urllib.request
import zipfile
sys.path.insert(0, str(Path(__file__).resolve().parents[3] / "scripts"))
from process_supervisor import owned_run
from browser_worker import ROOT, SCRIPT, MAX_LOG, environment, profile, unique_json, require
from firefox_receipt import browser as validate_receipt
from oracle import validate_observation
from owned import OwnedChildren, supervise

BROWSER = "/opt/firefox/firefox/firefox"
DRIVER = "/opt/firefox/geckodriver"
VERSION = "155.0.1"
DRIVER_VERSION = "0.37.1"


class DriverError(Exception):
    def __init__(self, certificate):
        self.certificate = certificate


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
        if type(value) is dict and "error" in value:
            raise DriverError(value["error"] == "insecure certificate")
        return value


def counter(path, name):
    data = Path(path).read_bytes()
    require(len(data) <= 4096)
    fields = [line.split() for line in data.splitlines()]
    selected = [value for key, value in fields if key == name.encode()]
    require(len(selected) == 1 and selected[0].isdigit())
    return int(selected[0])


def isolation():
    require(sys.platform == "linux" and os.geteuid() != 0)
    status = Path("/proc/self/status").read_bytes()
    require(len(status) <= 65536)
    fields = dict(line.split(b":", 1) for line in status.splitlines() if b":" in line)
    require(fields[b"Seccomp"].strip() == b"2" and fields[b"NoNewPrivs"].strip() == b"1"
            and int(fields[b"CapEff"].strip(), 16) == 0)
    require({name for _, name in socket.if_nameindex()} == {"lo"})
    require(Path("/sys/fs/cgroup/pids.max").read_bytes().strip() == b"512")
    require(counter("/sys/fs/cgroup/pids.events", "max") == 0
            and counter("/sys/fs/cgroup/memory.events", "oom_kill") == 0)
    resource.setrlimit(resource.RLIMIT_FSIZE, (MAX_LOG, MAX_LOG))


def preferences(protocol, port):
    require(type(protocol) is int and protocol in (1, 2, 3)
            and type(port) is int and 0 < port <= 65535)
    values = {"network.proxy.type": 0, "network.dns.disableIPv6": True,
        "network.dns.localDomains": "localhost", "security.enterprise_roots.enabled": False,
        "browser.cache.disk.enable": False, "network.http.http3.enable": protocol == 3,
        "network.http.spdy.enabled.http2": protocol != 1}
    if protocol == 3:
        values.update({"network.http.http3.alt-svc-mapping-for-testing": 'localhost;h3=":' + str(port) + '"',
            "network.http.http3.force-use-alt-svc-mapping-for-testing": True,
            # Firefox otherwise stops H3 after successfully authenticating an explicitly trusted private root.
            # Certificate verification remains on.
            "network.http.http3.disable_when_third_party_roots_found": False})
    return values


def encoded_profile(database):
    certificate_database = Path(database) / "cert9.db"
    require(certificate_database.is_file() and not certificate_database.is_symlink()
            and 0 < certificate_database.stat().st_size <= 1_048_576)
    encoded = io.BytesIO()
    with zipfile.ZipFile(encoded, "w", zipfile.ZIP_DEFLATED) as archive:
        archive.write(certificate_database, "cert9.db")
    require(len(encoded.getvalue()) <= 1_048_576)
    return base64.b64encode(encoded.getvalue()).decode("ascii")


def run(protocol, trusted, port):
    isolation()
    deadline = time.monotonic() + 45
    owner, driver, session = OwnedChildren(), None, None
    try:
        with profile(owner) as directory:
            home = Path(directory)
            database = home / "profile"
            database.mkdir()
            env = dict(environment(home), MOZ_CRASHREPORTER_DISABLE="1", MOZ_HEADLESS="1")
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
            child = owner.start([DRIVER, "--host", "127.0.0.1", "--port", str(driver_port), "--log", "fatal"], env=env)
            driver = Driver(driver_port, deadline)
            started = time.monotonic() + 5
            while True:
                try:
                    driver.command("GET", "/status")
                    break
                except Exception:
                    require(child.poll() is None and time.monotonic() < started)
                    time.sleep(0.02)
            response = driver.command("POST", "/session", {"capabilities": {"alwaysMatch": {
                "browserName": "firefox", "acceptInsecureCerts": False, "pageLoadStrategy": "eager",
                "moz:firefoxOptions": {"binary": BROWSER, "args": ["-headless"],
                    "profile": encoded_profile(database), "prefs": preferences(protocol, port)}}}})
            session = response["sessionId"]
            require(type(session) is str and re.fullmatch(r"[a-f0-9-]{36}", session) is not None)
            capabilities = response["capabilities"]
            require(capabilities["acceptInsecureCerts"] is False and capabilities["browserVersion"] == VERSION
                    and capabilities["moz:geckodriverVersion"] == DRIVER_VERSION)
            base = "/session/" + session
            driver.command("POST", base + "/timeouts", {"script": 10000, "pageLoad": 10000, "implicit": 0})
            if trusted:
                driver.command("POST", base + "/url", {"url": "https://localhost:" + str(port) + "/"})
                observed = validate_observation(driver.command("POST", base + "/execute/async",
                    {"script": SCRIPT, "args": []}), protocol)
            else:
                rejected = False
                try:
                    driver.command("POST", base + "/url", {"url": "https://localhost:" + str(port) + "/"})
                except DriverError as error:
                    rejected = error.certificate
                require(rejected)
                observed = {"certificate_rejected": True, "webdriver_error": "insecure certificate"}
            driver.command("DELETE", base)
            session = None
            joined = owner.close()
            require(joined["children_observed"] > 0 and joined["children_observed"] == joined["children_joined"])
            peak = Path("/sys/fs/cgroup/pids.peak").read_bytes().strip()
            require(peak.isdigit() and 1 <= int(peak) <= 512)
            return {"observation": observed, "ownership": joined,
                "browser_sandbox": "default", "container_seccomp": True, "non_root": True,
                "network_loopback_only": True, "tls_verification": True, "maximum_threads": 512,
                "thread_peak": int(peak), "thread_limit_hits": counter("/sys/fs/cgroup/pids.events", "max"),
                "oom_kills": counter("/sys/fs/cgroup/memory.events", "oom_kill"),
                "h3_forced_mapping": protocol == 3, "h3_private_root_policy": protocol == 3}
    finally:
        if session is not None and driver is not None and not owner.closed:
            try:
                driver.command("DELETE", "/session/" + session)
            except Exception:
                pass
        owner.close()


def main(arguments):
    require(len(arguments) == 5)
    protocol, trust, port, destination, nonce = arguments
    require(protocol in ("1", "2", "3") and trust in ("trusted", "untrusted"))
    require(port.isascii() and port.isdecimal() and 0 < int(port) <= 65535
            and re.fullmatch(r"[a-f0-9]{32}", nonce) is not None)
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
        sys.exit(1)

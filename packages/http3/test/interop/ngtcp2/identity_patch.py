#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 the http contributors
# SPDX-License-Identifier: MIT OR Apache-2.0
"""Add only a pre-network provenance query to the two upstream entrypoints."""
import hashlib
import json
from pathlib import Path
import shutil
import struct
import subprocess
import sys
import tempfile
import time
from process_supervisor import owned_popen

INPUTS = Path("/inputs")
SOURCES = Path("/sources")
NAMES = ["gcc", "g++", "cc1", "cc1plus", "as", "ld", "ar", "ranlib", "cmake", "make", "pkg-config", "patchelf"]


def require(condition):
    if not condition:
        raise ValueError("native_build_identity_mismatch")


def digest(path):
    path = Path(path)
    size = path.stat().st_size
    require(0 <= size <= 256 * 1024 * 1024)
    result = hashlib.sha256()
    seen = 0
    with path.open("rb") as source:
        while True:
            chunk = source.read(min(65536, size - seen + 1))
            if not chunk:
                break
            seen += len(chunk)
            require(seen <= size)
            result.update(chunk)
    require(seen == size == path.stat().st_size)
    return result.hexdigest()


def run(*command):
    with tempfile.TemporaryFile() as output:
        child = owned_popen(command, stdout=output, stderr=subprocess.DEVNULL)
        deadline = time.monotonic() + 20
        try:
            while child.poll() is None:
                require(time.monotonic() < deadline and output.tell() <= 1048576)
                time.sleep(0.01)
            require(child.returncode == 0)
        finally:
            if child.poll() is None:
                child.kill()
            child.wait(timeout=5)
        output.seek(0)
        data = output.read(1048577)
        require(len(data) <= 1048576)
        return data.decode().strip()


def inventory(directory, names=None):
    if names is None:
        names = sorted(str(path.relative_to(directory)) for path in directory.rglob("*") if path.is_file())
    require(0 < len(names) <= 20000)
    result = hashlib.sha256(b"http-interop-files-v1\x00")
    result.update(struct.pack(">Q", len(names)))
    for name in names:
        path = directory / name
        require(path.resolve().is_relative_to(directory.resolve()) and not path.is_symlink())
        encoded = name.encode()
        result.update(struct.pack(">Q", len(encoded)))
        result.update(encoded)
        result.update(bytes.fromhex(digest(path)))
    return {"sha256": result.hexdigest(), "files": len(names)}, names


def tools():
    result = []
    for name in NAMES:
        path = run("gcc", "-print-prog-name=" + name) if name in ("cc1", "cc1plus") else shutil.which(name)
        require(path is not None)
        result.append({"name": name, "sha256": digest(Path(path).resolve())})
    return result


def metadata(lock, inventories):
    require(run("gcc", "-dumpfullversion") == run("g++", "-dumpfullversion") == lock["compiler_version"])
    for name, version in lock["packages"].items():
        require(run("dpkg-query", "-W", "-f=${Version}", name) == version)
    sources = []
    for source in lock["sources"]:
        require(digest(Path("/archives") / (source["name"] + "-" + source["version"] + ".tar.xz")) == source["sha256"])
        directory = SOURCES / (source["name"] + "-" + source["version"])
        observed, names = inventory(directory, inventories.get(source["name"]))
        inventories[source["name"]] = names
        sources.append({"name": source["name"], "version": source["version"],
                        "archive_sha256": source["sha256"], **observed})
    return {"schema": 1, "compiler_version": lock["compiler_version"],
            "lock_sha256": digest(INPUTS / "sources.lock.json"),
            "patch_sha256": digest(INPUTS / "identity_patch.py"),
            "recipe_sha256": digest(INPUTS / "Dockerfile"),
            "sources": sources, "native_tools": tools()}


def header(role, observed):
    encoded = json.dumps(json.dumps({**observed, "role": role}, sort_keys=True, separators=(",", ":")) + "\n")
    return """#include <stdio.h>
#include <string.h>
#include <ngtcp2/ngtcp2.h>
#include <nghttp3/nghttp3.h>
static int http_interop_identity(int argc, char **argv) {
  if(argc != 2 || strcmp(argv[1], "--http-interop-identity")) return 0;
  printf("%s %s\\n", ngtcp2_version(0)->version_str, nghttp3_version(0)->version_str);
  fputs(""" + encoded + """, stdout);
  return 1;
}
"""


def apply():
    lock = json.loads((INPUTS / "sources.lock.json").read_text())
    entrypoints = [
        (SOURCES / "ngtcp2-1.25.0/examples/server.cc", "int main(int argc, char **argv) {", "server"),
        (SOURCES / "curl-8.22.0/src/tool_main.c", "int main(int argc, char *argv[])\n#endif\n{", "client"),
    ]
    for path, needle, role in entrypoints:
        original = path.read_text()
        require(original.count(needle) == 1)
        # Include before main's platform selection, never inside a function.
        original = '#include "/inputs/identity-' + role + '.h"\n' + original
        path.write_text(original.replace(needle, needle + "\n  if(http_interop_identity(argc, argv)) return 0;"))
    inventories = {}
    observed = metadata(lock, inventories)
    for role in ("client", "server"):
        (INPUTS / ("identity-" + role + ".h")).write_text(header(role, observed))
    (INPUTS / "build-before.json").write_text(json.dumps({"metadata": observed, "inventories": inventories}, sort_keys=True))


def verify():
    before = json.loads((INPUTS / "build-before.json").read_text())
    lock = json.loads((INPUTS / "sources.lock.json").read_text())
    require(before["metadata"] == metadata(lock, before["inventories"]))
    for role in ("client", "server"):
        require((INPUTS / ("identity-" + role + ".h")).read_text() == header(role, before["metadata"]))
    (INPUTS / "build-identity.json").write_text(json.dumps(before["metadata"], sort_keys=True))


if __name__ == "__main__":
    require(len(sys.argv) == 2 and sys.argv[1] in ("apply", "verify"))
    apply() if sys.argv[1] == "apply" else verify()

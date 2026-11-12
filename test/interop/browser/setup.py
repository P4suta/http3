#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 the http contributors
# SPDX-License-Identifier: MIT OR Apache-2.0
"""Install the two pinned official archives into a new, owned directory."""
import sys
sys.dont_write_bytecode = True
import argparse
import json
import os
from pathlib import Path
import shutil
import signal
import stat
import tempfile
import urllib.request
import zipfile
from archive import MAX_ARCHIVE, archive_members, digest, tree_identity, require


def install_archives(archives, destination, pins):
    archives = Path(archives).resolve(strict=True)
    destination = Path(destination).absolute()
    require(not destination.exists() and not destination.is_symlink())
    require(destination.parent.is_dir())
    staging = Path(tempfile.mkdtemp(prefix=".http-browser-", dir=destination.parent))
    try:
        for role, prefix in (("browser", "chrome-linux64"), ("driver", "chromedriver-linux64")):
            pin = pins[role]
            archive_path = archives / (prefix + ".zip")
            require(digest(archive_path, MAX_ARCHIVE) == {"sha256": pin["sha256"], "bytes": pin["archive_bytes"]})
            with zipfile.ZipFile(archive_path) as archive:
                for member in archive_members(archive, prefix):
                    target = staging / member.filename
                    require(target.resolve().is_relative_to(staging))
                    if member.is_dir():
                        target.mkdir(parents=True, exist_ok=True)
                        target.chmod(0o755)
                        continue
                    target.parent.mkdir(parents=True, exist_ok=True)
                    seen = 0
                    with archive.open(member) as source, target.open("xb") as output:
                        while chunk := source.read(min(65536, member.file_size - seen + 1)):
                            seen += len(chunk)
                            require(seen <= member.file_size)
                            output.write(chunk)
                    require(seen == member.file_size)
                    # Archive metadata can never install setuid or writable shared executables.
                    # All identity inputs remain readable.
                    target.chmod(0o755 if (member.external_attr >> 16) & 0o111 else 0o644)
            tree_identity(archive_path, staging, pin)
        require(not destination.exists() and not destination.is_symlink())
        staging.chmod(0o755)
        staging.rename(destination)
    finally:
        if staging.exists():
            shutil.rmtree(staging)


def download(archives, pins):
    archives = Path(archives)
    archives.mkdir(parents=True, exist_ok=True)
    for role, prefix in (("browser", "chrome-linux64"), ("driver", "chromedriver-linux64")):
        pin = pins[role]
        path = archives / (prefix + ".zip")
        if path.exists():
            require(digest(path, MAX_ARCHIVE) == {"sha256": pin["sha256"], "bytes": pin["archive_bytes"]})
            path.chmod(0o644)
            continue
        expected = "https://storage.googleapis.com/chrome-for-testing-public/" + pins["version"] + "/linux64/" + prefix + ".zip"
        require(pin["url"] == expected)
        descriptor, temporary = tempfile.mkstemp(prefix=".download-", dir=archives)
        try:
            with os.fdopen(descriptor, "wb") as target, urllib.request.urlopen(expected, timeout=15) as response:
                require(response.geturl() == expected and response.status == 200)
                seen = 0
                while chunk := response.read(min(65536, MAX_ARCHIVE - seen + 1)):
                    seen += len(chunk)
                    require(seen <= MAX_ARCHIVE and seen <= pin["archive_bytes"])
                    target.write(chunk)
            require(digest(temporary, MAX_ARCHIVE) == {"sha256": pin["sha256"], "bytes": pin["archive_bytes"]})
            require(not path.exists())
            Path(temporary).chmod(0o644)
            os.rename(temporary, path)
        finally:
            Path(temporary).unlink(missing_ok=True)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--archives", required=True)
    parser.add_argument("--destination", required=True)
    parser.add_argument("--download", action="store_true")
    args = parser.parse_args()
    def unique(pairs):
        value = {}
        for key, item in pairs:
            require(key not in value)
            value[key] = item
        return value
    data = Path(__file__).with_name("pins.json").read_bytes()
    require(len(data) <= 16384)
    document = json.loads(data, object_pairs_hook=unique)
    require(set(document) == {"schema", "chromium"} and document["schema"] == 1)
    pins = document["chromium"]
    def expired(_number, _frame):
        raise TimeoutError("browser_setup_deadline")
    signal.signal(signal.SIGALRM, expired)
    signal.setitimer(signal.ITIMER_REAL, 300)
    try:
        if args.download:
            download(args.archives, pins)
        install_archives(args.archives, args.destination, pins)
    finally:
        signal.setitimer(signal.ITIMER_REAL, 0)


if __name__ == "__main__":
    try:
        main()
    except BaseException:
        print("browser setup failed", file=sys.stderr)
        sys.exit(1)

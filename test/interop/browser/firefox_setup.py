#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 the http contributors
# SPDX-License-Identifier: MIT OR Apache-2.0
"""Install immutable official Firefox and geckodriver archives under one owner."""
import sys
sys.dont_write_bytecode = True
import argparse
import json
import os
from pathlib import Path
import shutil
import signal
import tempfile
import urllib.parse
import urllib.request
from archive import MAX_ARCHIVE, digest, require
from firefox_archive import extract

ARCHIVES = {"browser": "firefox.tar.xz", "driver": "geckodriver.tar.gz"}
URLS = {
    "browser": "https://archive.mozilla.org/pub/firefox/releases/155.0.1/linux-x86_64/en-US/firefox-155.0.1.tar.xz",
    "driver": "https://github.com/mozilla/geckodriver/releases/download/v0.37.1/geckodriver-v0.37.1-linux64.tar.gz",
}


def install_archives(archives, destination, pins):
    archives = Path(archives).resolve(strict=True)
    destination = Path(destination).absolute()
    require(not destination.exists() and not destination.is_symlink() and destination.parent.is_dir())
    staging = Path(tempfile.mkdtemp(prefix=".http-firefox-", dir=destination.parent))
    try:
        for role, name in ARCHIVES.items():
            extract(archives / name, staging, pins[role])
        require(not destination.exists() and not destination.is_symlink())
        staging.chmod(0o755)
        staging.rename(destination)
    finally:
        if staging.exists():
            shutil.rmtree(staging)


def download(archives, pins):
    archives = Path(archives)
    archives.mkdir(parents=True, exist_ok=True)
    for role, name in ARCHIVES.items():
        pin, expected = pins[role], URLS[role]
        require(pin["url"] == expected)
        path = archives / name
        identity = {"sha256": pin["sha256"], "bytes": pin["archive_bytes"]}
        if path.exists():
            require(digest(path, MAX_ARCHIVE) == identity)
            path.chmod(0o644)
            continue
        descriptor, temporary = tempfile.mkstemp(prefix=".firefox-download-", dir=archives)
        try:
            with os.fdopen(descriptor, "wb") as target, urllib.request.urlopen(expected, timeout=15) as response:
                final = urllib.parse.urlsplit(response.geturl())
                allowed = {"archive.mozilla.org"} if role == "browser" else {"github.com", "release-assets.githubusercontent.com"}
                require(final.scheme == "https" and final.hostname in allowed and final.port in (None, 443)
                        and final.username is None and final.password is None and not final.fragment
                        and response.status == 200)
                seen = 0
                while chunk := response.read(min(65536, MAX_ARCHIVE - seen + 1)):
                    seen += len(chunk)
                    require(seen <= MAX_ARCHIVE and seen <= pin["archive_bytes"])
                    target.write(chunk)
            require(digest(temporary, MAX_ARCHIVE) == identity)
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
    data = Path(__file__).with_name("firefox-pins.json").read_bytes()
    require(len(data) <= 16384)
    document = json.loads(data, object_pairs_hook=unique)
    require(set(document) == {"schema", "firefox"} and document["schema"] == 1)
    pins = document["firefox"]
    def expired(_number, _frame):
        raise TimeoutError("firefox_setup_deadline")
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
        print("Firefox setup failed", file=sys.stderr)
        sys.exit(1)

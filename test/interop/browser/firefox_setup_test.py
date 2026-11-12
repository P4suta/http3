# SPDX-FileCopyrightText: 2026 the http contributors
# SPDX-License-Identifier: MIT OR Apache-2.0
import hashlib
import io
import os
from pathlib import Path
import struct
import tarfile
import tempfile
import unittest
from unittest.mock import patch
import firefox_setup as setup


def fixtures():
    pins, archives = {}, {}
    for role, name in (("browser", "firefox/firefox"), ("driver", "geckodriver")):
        content = (role + " fixture").encode()
        raw = io.BytesIO()
        with tarfile.open(fileobj=raw, mode="w") as archive:
            member = tarfile.TarInfo(name)
            member.size, member.mode = len(content), 0o4755
            archive.addfile(member, io.BytesIO(content))
        encoded = name.encode()
        resource = hashlib.sha256(b"http-browser-tar-tree-v1\0" + struct.pack(">Q", 1)
            + struct.pack(">Q", len(encoded)) + encoded + hashlib.sha256(content).digest()).hexdigest()
        archives[setup.ARCHIVES[role]] = raw.getvalue()
        pins[role] = {"url": setup.URLS[role], "executable": name,
            "archive_bytes": len(raw.getvalue()), "sha256": hashlib.sha256(raw.getvalue()).hexdigest(),
            "executable_bytes": len(content), "executable_sha256": hashlib.sha256(content).hexdigest(),
            "resource_files": 1, "resource_sha256": resource}
    return pins, archives


class Response(io.BytesIO):
    status = 200

    def __init__(self, data, url):
        super().__init__(data)
        self.url = url

    def geturl(self):
        return self.url


class Installation(unittest.TestCase):
    def test_exact_install_is_atomic_and_removes_privileged_modes(self):
        pins, archives = fixtures()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            cache, destination = root / "archives", root / "installed"
            cache.mkdir()
            for name, data in archives.items():
                (cache / name).write_bytes(data)
            setup.install_archives(cache, destination, pins)
            self.assertTrue((destination / "firefox/firefox").is_file())
            self.assertTrue((destination / "geckodriver").is_file())
            if os.name == "posix":
                self.assertEqual(destination.stat().st_mode & 0o7777, 0o755)
                self.assertEqual((destination / "firefox/firefox").stat().st_mode & 0o7777, 0o755)
            with self.assertRaises(ValueError):
                setup.install_archives(cache, destination, pins)

    def test_corrupt_archive_leaves_no_partial_installation(self):
        pins, archives = fixtures()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            cache, destination = root / "archives", root / "installed"
            cache.mkdir()
            for name, data in archives.items():
                (cache / name).write_bytes(data)
            (cache / "geckodriver.tar.gz").write_bytes(b"corrupted")
            with self.assertRaises(ValueError):
                setup.install_archives(cache, destination, pins)
            self.assertFalse(destination.exists())
            self.assertEqual(len(list(root.glob(".http-firefox-*"))), 0)

    def test_unexpected_redirect_and_overflow_are_rejected_without_retention(self):
        pins, _ = fixtures()
        for url, data in (("http://archive.mozilla.org/", b"x"),
                          ("https://unrelated.invalid/", b"x"),
                          (setup.URLS["browser"], b"x" * (pins["browser"]["archive_bytes"] + 1))):
            with tempfile.TemporaryDirectory() as directory:
                with patch.object(setup.urllib.request, "urlopen", return_value=Response(data, url)):
                    with self.assertRaises(ValueError):
                        setup.download(directory, pins)
                self.assertEqual(len(list(Path(directory).iterdir())), 0)

    def test_downloaded_bytes_and_reused_cache_remain_exact(self):
        pins, archives = fixtures()
        def reply(url, **_kwargs):
            role = next(role for role, expected in setup.URLS.items() if expected == url)
            return Response(archives[setup.ARCHIVES[role]], url)
        with tempfile.TemporaryDirectory() as directory:
            with patch.object(setup.urllib.request, "urlopen", side_effect=reply) as request:
                setup.download(directory, pins)
                self.assertEqual(request.call_count, 2)
            with patch.object(setup.urllib.request, "urlopen", side_effect=AssertionError("unexpected network")):
                setup.download(directory, pins)
            (Path(directory) / "firefox.tar.xz").write_bytes(b"changed")
            with self.assertRaises(ValueError):
                setup.download(directory, pins)


if __name__ == "__main__":
    unittest.main()

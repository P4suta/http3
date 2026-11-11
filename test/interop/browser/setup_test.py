# SPDX-FileCopyrightText: 2026 the http contributors
# SPDX-License-Identifier: MIT OR Apache-2.0
import sys
sys.dont_write_bytecode = True
import hashlib
import io
import os
from pathlib import Path
import stat
import struct
import tempfile
import unittest
from unittest import mock
import zipfile
from archive import tree_identity
from setup import install_archives, download


def fixture(directory):
    pins = {}
    for role, prefix, filename in [("browser", "chrome-linux64", "chrome"),
            ("driver", "chromedriver-linux64", "chromedriver")]:
        data = b"fixed-public-executable"
        relative = prefix + "/" + filename
        path = directory / (prefix + ".zip")
        info = zipfile.ZipInfo(relative)
        info.create_system = 3
        info.external_attr = (stat.S_IFREG | 0o4755) << 16
        with zipfile.ZipFile(path, "w") as archive:
            archive.writestr(info, data)
        combined = hashlib.sha256(b"http-browser-archive-tree-v1\0")
        combined.update(struct.pack(">Q", 1))
        combined.update(struct.pack(">Q", len(relative.encode())))
        combined.update(relative.encode())
        combined.update(hashlib.sha256(data).digest())
        pins[role] = {"sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
            "archive_bytes": path.stat().st_size, "executable": relative,
            "executable_sha256": hashlib.sha256(data).hexdigest(), "executable_bytes": len(data),
            "resource_files": 1, "resource_sha256": combined.hexdigest()}
    return pins


class Installation(unittest.TestCase):
    @unittest.skipUnless(os.name == "posix", "POSIX runtime permissions")
    def test_root_and_downloaded_archives_are_runtime_readable(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); pins = fixture(root); destination = root / "installed"
            install_archives(root, destination, pins)
            self.assertEqual(0o755, stat.S_IMODE(destination.stat().st_mode))
            pins["version"] = "153.0.8010.36"
            payloads = {}
            for role, prefix in [("browser", "chrome-linux64"), ("driver", "chromedriver-linux64")]:
                url = "https://storage.googleapis.com/chrome-for-testing-public/153.0.8010.36/linux64/" + prefix + ".zip"
                pins[role]["url"] = url
                payloads[url] = (root / (prefix + ".zip")).read_bytes()
            def response(url, timeout):
                value = io.BytesIO(payloads[url]); value.status = 200; value.geturl = lambda: url
                return value
            with mock.patch("setup.urllib.request.urlopen", side_effect=response):
                download(root / "downloads", pins)
            for path in (root / "downloads").iterdir():
                self.assertEqual(0o644, stat.S_IMODE(path.stat().st_mode))

    def test_installed_files_match_archive_and_are_not_setuid(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); pins = fixture(root); destination = root / "installed"
            install_archives(root, destination, pins)
            for role, pin in pins.items():
                archive = root / ("chrome-linux64.zip" if role == "browser" else "chromedriver-linux64.zip")
                self.assertEqual(pin["resource_files"], tree_identity(archive, destination, pin)["files"])
                if os.name == "posix":
                    self.assertEqual(0o755, stat.S_IMODE((destination / pin["executable"]).stat().st_mode))

    def test_existing_directory_is_never_replaced(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); pins = fixture(root); destination = root / "installed"
            destination.mkdir(); marker = destination / "marker"; marker.write_bytes(b"owned")
            with self.assertRaises(ValueError): install_archives(root, destination, pins)
            self.assertEqual(b"owned", marker.read_bytes())

    def test_changed_archive_or_resource_pin_never_publishes(self):
        for field in ("sha256", "executable_sha256", "resource_sha256"):
            with self.subTest(field=field), tempfile.TemporaryDirectory() as directory:
                root = Path(directory); pins = fixture(root); destination = root / "installed"
                pins["browser"][field] = "0" * 64
                with self.assertRaises(ValueError): install_archives(root, destination, pins)
                self.assertFalse(destination.exists())
                self.assertEqual(2, len(list(root.iterdir())))

    def test_extra_missing_and_modified_installed_resources_are_rejected(self):
        for change in ("extra", "missing", "changed"):
            with self.subTest(change=change), tempfile.TemporaryDirectory() as directory:
                root = Path(directory); pins = fixture(root); destination = root / "installed"
                install_archives(root, destination, pins)
                executable = destination / pins["browser"]["executable"]
                if change == "extra": (executable.parent / "extra").write_bytes(b"extra")
                elif change == "missing": executable.unlink()
                else: executable.write_bytes(b"changed")
                with self.assertRaises((ValueError, OSError)):
                    tree_identity(root / "chrome-linux64.zip", destination, pins["browser"])


if __name__ == "__main__":
    unittest.main()

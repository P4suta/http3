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
import firefox_archive as subject


def archive(entries):
    data = io.BytesIO()
    with tarfile.open(fileobj=data, mode="w") as target:
        for name, content, kind in entries:
            item = tarfile.TarInfo(name)
            item.type, item.size, item.mode = kind, len(content), 0o4755
            item.linkname = "firefox/firefox" if kind in (tarfile.SYMTYPE, tarfile.LNKTYPE) else ""
            target.addfile(item, io.BytesIO(content))
    data.seek(0)
    return data


class ArchiveTests(unittest.TestCase):
    def rejects(self, entries):
        with archive(entries) as data, tarfile.open(fileobj=data) as source:
            with self.assertRaises(ValueError):
                subject.members(source, "firefox/firefox")

    def test_duplicate_members_are_rejected(self):
        self.rejects([("firefox/firefox", b"x", tarfile.REGTYPE)] * 2)

    def test_links_and_special_files_are_rejected(self):
        for kind in (tarfile.SYMTYPE, tarfile.LNKTYPE, tarfile.CHRTYPE, tarfile.DIRTYPE):
            with self.subTest(kind=kind):
                self.rejects([("firefox/firefox", b"x", kind)])

    def test_noncanonical_and_escaping_names_are_rejected(self):
        for name in ("/firefox/firefox", "firefox/../firefox", "firefox//firefox",
                     "firefox/./firefox", "firefox\\firefox", "elsewhere/firefox"):
            with self.subTest(name=name):
                self.rejects([(name, b"x", tarfile.REGTYPE)])

    def test_expansion_limit_is_checked_before_extracting(self):
        with patch.object(subject, "MAX_EXPANDED", 1):
            self.rejects([("firefox/firefox", b"xx", tarfile.REGTYPE)])

    def test_member_count_is_bounded(self):
        self.rejects([("firefox/firefox", b"x", tarfile.REGTYPE)]
                     + [("firefox/f" + str(i), b"x", tarfile.REGTYPE) for i in range(4096)])

    def test_empty_regular_resources_have_an_exact_identity(self):
        with archive([("firefox/firefox", b"x", tarfile.REGTYPE),
                      ("firefox/empty", b"", tarfile.REGTYPE)]) as data:
            with tarfile.open(fileobj=data) as source:
                self.assertEqual(len(subject.members(source, "firefox/firefox")), 2)
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "empty"
            path.write_bytes(b"")
            self.assertEqual(subject.resource_digest(path),
                             {"bytes": 0, "sha256": hashlib.sha256(b"").hexdigest()})

    def test_exact_installation_and_executable_identity(self):
        content, name = b"fixture executable", "firefox/firefox"
        combined = hashlib.sha256(b"http-browser-tar-tree-v1\0")
        combined.update(struct.pack(">Q", 1))
        combined.update(struct.pack(">Q", len(name)))
        combined.update(name.encode())
        combined.update(hashlib.sha256(content).digest())
        raw = archive([(name, content, tarfile.REGTYPE)]).getvalue()
        pin = {"executable": name, "sha256": hashlib.sha256(raw).hexdigest(),
               "archive_bytes": len(raw), "executable_sha256": hashlib.sha256(content).hexdigest(),
               "executable_bytes": len(content), "resource_files": 1,
               "resource_sha256": combined.hexdigest()}
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source, installation = root / "source.tar", root / "installed"
            source.write_bytes(raw)
            installation.mkdir()
            self.assertEqual(subject.extract(source, installation, pin)["files"], 1)
            if os.name == "posix":
                self.assertEqual((installation / name).stat().st_mode & 0o7777, 0o755)
            (installation / "firefox/extra").write_bytes(b"extra")
            with self.assertRaises(ValueError):
                subject.tree_identity(source, installation, pin)
            (installation / "firefox/extra").unlink()
            (installation / name).write_bytes(b"changed")
            with self.assertRaises(ValueError):
                subject.tree_identity(source, installation, pin)


if __name__ == "__main__":
    unittest.main()

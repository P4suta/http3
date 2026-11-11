# SPDX-FileCopyrightText: 2026 the http contributors
# SPDX-License-Identifier: MIT OR Apache-2.0
import sys
sys.dont_write_bytecode = True
import io
import stat
import unittest
import warnings
import zipfile
from archive import archive_members


def members(names):
    data = io.BytesIO()
    with zipfile.ZipFile(data, "w") as archive:
        for name in names:
            info = name if isinstance(name, zipfile.ZipInfo) else zipfile.ZipInfo(name)
            if isinstance(name, str):
                # Preserve deliberately malformed wire names even on Windows,
                # where ZipInfo's constructor otherwise normalizes backslashes.
                info.filename = name
            with warnings.catch_warnings():
                # This one duplicate is deliberate input to the rejection test.
                warnings.filterwarnings("ignore", message="Duplicate name: 'browser/a'", category=UserWarning)
                archive.writestr(info, b"fixed")
    data.seek(0)
    return zipfile.ZipFile(data)


class ArchiveBoundary(unittest.TestCase):
    def test_one_canonical_tree_is_accepted(self):
        with members(["browser/a", "browser/sub/b"]) as archive:
            self.assertEqual(2, len(archive_members(archive, "browser")))

    def test_escape_duplicates_and_foreign_trees_are_refused(self):
        for names in [["../escape"], ["/browser/file"], ["browser/../escape"],
                      ["browser/a", "browser/a"], ["other/a"], ["browser\\escape"],
                      ["browser//a"], ["browser/./a"]]:
            with self.subTest(case=names), members(names) as archive:
                with self.assertRaisesRegex(ValueError, "invalid_browser_archive"):
                    archive_members(archive, "browser")

    def test_symbolic_links_and_special_files_are_refused(self):
        for mode in [stat.S_IFLNK | 0o777, stat.S_IFIFO | 0o600]:
            info = zipfile.ZipInfo("browser/entry")
            info.create_system = 3
            info.external_attr = mode << 16
            with members([info]) as archive:
                with self.assertRaisesRegex(ValueError, "invalid_browser_archive"):
                    archive_members(archive, "browser")


if __name__ == "__main__":
    unittest.main()

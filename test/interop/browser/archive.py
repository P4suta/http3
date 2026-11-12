# SPDX-FileCopyrightText: 2026 the http contributors
# SPDX-License-Identifier: MIT OR Apache-2.0
"""Finite, canonical identities for the pinned official browser archives."""
import hashlib
from pathlib import Path, PurePosixPath
import stat
import struct
import zipfile

MAX_ARCHIVE = 268_435_456
MAX_EXPANDED = 536_870_912
MAX_MEMBER = 402_653_184


def require(condition):
    if not condition:
        raise ValueError("invalid_browser_archive")


def hash_stream(source, maximum):
    digest = hashlib.sha256()
    size = 0
    while True:
        chunk = source.read(min(65536, maximum - size + 1))
        if not chunk:
            return {"sha256": digest.hexdigest(), "bytes": size}
        size += len(chunk)
        require(size <= maximum)
        digest.update(chunk)


def digest(path, maximum=MAX_MEMBER):
    path = Path(path)
    require(path.is_file() and not path.is_symlink())
    size = path.stat().st_size
    require(0 < size <= maximum)
    with path.open("rb") as source:
        result = hash_stream(source, maximum)
    require(result["bytes"] == size == path.stat().st_size)
    return result


def archive_members(archive, directory):
    members = archive.infolist()
    require(0 < len(members) <= 4096)
    names = set()
    expanded = 0
    for member in members:
        name = member.orig_filename
        require(name == member.filename)
        path = PurePosixPath(name)
        require(type(name) is str and len(name.encode()) <= 1024 and "\\" not in name
                and not path.is_absolute() and path.parts and path.parts[0] == directory
                and all(part not in ("", ".", "..") for part in path.parts))
        require(name == path.as_posix() + ("/" if member.is_dir() else ""))
        require(path.as_posix() not in names)
        names.add(path.as_posix())
        mode = stat.S_IFMT(member.external_attr >> 16)
        require(mode in ((0, stat.S_IFDIR) if member.is_dir() else (0, stat.S_IFREG)))
        require(not member.flag_bits & 1 and member.compress_type in (zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED))
        require(0 <= member.file_size <= MAX_MEMBER)
        expanded += member.file_size
        require(expanded <= MAX_EXPANDED)
    return members


def tree_identity(archive_path, installation, pin):
    archive_digest = digest(archive_path, MAX_ARCHIVE)
    require(archive_digest == {"sha256": pin["sha256"], "bytes": pin["archive_bytes"]})
    root = Path(installation).resolve(strict=True)
    prefix = PurePosixPath(pin["executable"]).parts[0]
    combined = hashlib.sha256(b"http-browser-archive-tree-v1\0")
    with zipfile.ZipFile(archive_path) as archive:
        members = archive_members(archive, prefix)
        files = [member for member in members if not member.is_dir()]
        combined.update(struct.pack(">Q", len(files)))
        expected = set()
        for member in sorted(files, key=lambda item: item.filename):
            relative = PurePosixPath(member.filename)
            current = root.joinpath(*relative.parts)
            require(current.resolve(strict=True).is_relative_to(root) and not current.is_symlink())
            with archive.open(member) as source:
                expected_digest = hash_stream(source, MAX_MEMBER)
            require(expected_digest["bytes"] == member.file_size)
            require(digest(current) == expected_digest)
            encoded = member.filename.encode()
            combined.update(struct.pack(">Q", len(encoded)))
            combined.update(encoded)
            combined.update(bytes.fromhex(expected_digest["sha256"]))
            expected.add(relative.as_posix())
        actual = set()
        seen = 0
        for path in (root / prefix).rglob("*"):
            seen += 1
            require(seen <= 4096 and not path.is_symlink())
            if path.is_file():
                actual.add(path.relative_to(root).as_posix())
        require(actual == expected)
    executable = digest(root / pin["executable"])
    require(executable == {"sha256": pin["executable_sha256"], "bytes": pin["executable_bytes"]}
            and combined.hexdigest() == pin["resource_sha256"] and len(expected) == pin["resource_files"])
    return {"sha256": combined.hexdigest(), "files": len(expected),
            "archive": archive_digest, "executable": executable}

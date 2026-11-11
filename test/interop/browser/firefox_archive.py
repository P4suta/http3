# SPDX-FileCopyrightText: 2026 the http contributors
# SPDX-License-Identifier: MIT OR Apache-2.0
"""Bounded identities and extraction for the pinned Mozilla tar distributions."""
import hashlib
from pathlib import Path, PurePosixPath
import struct
import tarfile
from archive import MAX_ARCHIVE, MAX_EXPANDED, MAX_MEMBER, digest, hash_stream, require


def iter_members(archive, executable):
    prefix = PurePosixPath(executable).parts[0]
    entries, names, expanded = [], set(), 0
    for item in archive:
        require(len(entries) < 4096)
        path = PurePosixPath(item.name)
        require(type(item.name) is str and len(item.name.encode()) <= 1024
                and item.name == path.as_posix() and not path.is_absolute()
                and "\\" not in item.name and path.parts and path.parts[0] == prefix
                and all(part not in ("", ".", "..") for part in path.parts))
        require(item.name not in names and item.isfile() and not item.sparse)
        require(0 <= item.size <= MAX_MEMBER)
        expanded += item.size
        require(expanded <= MAX_EXPANDED)
        names.add(item.name)
        entries.append(item)
        yield item
    require(entries and executable in names)


def members(archive, executable):
    return list(iter_members(archive, executable))


def resource_digest(path):
    path = Path(path)
    require(path.is_file() and not path.is_symlink())
    size = path.stat().st_size
    require(0 <= size <= MAX_MEMBER)
    with path.open("rb") as source:
        observed = hash_stream(source, MAX_MEMBER)
    require(observed["bytes"] == size == path.stat().st_size)
    return observed


def tree_identity(archive_path, installation, pin):
    archive_digest = digest(archive_path, MAX_ARCHIVE)
    require(archive_digest == {"sha256": pin["sha256"], "bytes": pin["archive_bytes"]})
    root = Path(installation).resolve(strict=True)
    combined = hashlib.sha256(b"http-browser-tar-tree-v1\0")
    expected, records = set(), []
    # Compressed tar has no random-access index.
    # Read each member once and sort only its bounded name/digest metadata after streaming the archive.
    with tarfile.open(archive_path, "r|*") as archive:
        for item in iter_members(archive, pin["executable"]):
            current = root.joinpath(*PurePosixPath(item.name).parts)
            require(current.resolve(strict=True).is_relative_to(root) and not current.is_symlink())
            with archive.extractfile(item) as source:
                observed = hash_stream(source, MAX_MEMBER)
            require(observed["bytes"] == item.size and resource_digest(current) == observed)
            records.append((item.name, observed["sha256"]))
            expected.add(item.name)
    combined.update(struct.pack(">Q", len(records)))
    for name, sha256 in sorted(records):
        encoded = name.encode()
        combined.update(struct.pack(">Q", len(encoded)))
        combined.update(encoded)
        combined.update(bytes.fromhex(sha256))
    base = root / PurePosixPath(pin["executable"]).parts[0]
    actual = set()
    if base.is_file():
        actual.add(base.relative_to(root).as_posix())
    else:
        seen = 0
        for current in base.rglob("*"):
            seen += 1
            require(seen <= 4096 and not current.is_symlink())
            if current.is_file():
                actual.add(current.relative_to(root).as_posix())
    require(actual == expected)
    executable = digest(root / pin["executable"])
    require(executable == {"sha256": pin["executable_sha256"], "bytes": pin["executable_bytes"]}
            and combined.hexdigest() == pin["resource_sha256"] and len(expected) == pin["resource_files"])
    return {"sha256": combined.hexdigest(), "files": len(expected),
            "archive": archive_digest, "executable": executable}


def extract(archive_path, staging, pin):
    staging = Path(staging).resolve(strict=True)
    require(digest(archive_path, MAX_ARCHIVE) == {"sha256": pin["sha256"], "bytes": pin["archive_bytes"]})
    with tarfile.open(archive_path, "r|*") as archive:
        for item in iter_members(archive, pin["executable"]):
            destination = staging.joinpath(*PurePosixPath(item.name).parts)
            require(destination.resolve().is_relative_to(staging))
            destination.parent.mkdir(parents=True, exist_ok=True)
            seen = 0
            with archive.extractfile(item) as source, destination.open("xb") as output:
                while chunk := source.read(min(65536, item.size - seen + 1)):
                    seen += len(chunk)
                    require(seen <= item.size)
                    output.write(chunk)
            require(seen == item.size)
            destination.chmod(0o755 if item.mode & 0o111 else 0o644)
    return tree_identity(archive_path, staging, pin)

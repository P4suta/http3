#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 the http contributors
# SPDX-License-Identifier: MIT OR Apache-2.0
"""Add a non-network identity mode to the two pinned upstream entrypoints."""
import hashlib
import json
import os
from pathlib import Path
import shutil
import struct
import subprocess
import sys
from process_supervisor import owned_check_output

COMMIT = "55886df3be579579207104c8e645825b6347a209"
RUST = "1.98.1"
ENTRYPOINTS = ["apps/src/bin/quiche-client.rs", "apps/src/bin/quiche-server.rs"]
VERSION_SOURCE = "quiche/src/lib.rs"
IDENTITY_FUNCTION = r'''
// Test-only identity observation; all network behavior remains upstream code.
fn http_interop_identity() -> bool {
    if std::env::args().nth(1).as_deref() != Some("--http-interop-identity") {
        return false;
    }
    println!("{}", quiche::http_interop_version());
    let mut output = std::io::stdout().lock();
    std::io::Write::write_all(&mut output,
        include_bytes!("../../../http-interop-identity.json")).unwrap();
    std::io::Write::write_all(&mut output,
        include_bytes!("../../../Cargo.lock")).unwrap();
    true
}
'''


def checked(command):
    return owned_check_output(
        command, timeout=60, max_output_bytes=4096
    ).decode().strip()


def digest_file(path):
    digest = hashlib.sha256()
    with Path(path).open("rb") as source:
        for chunk in iter(lambda: source.read(65536), b""):
            digest.update(chunk)
    return digest.hexdigest()


def source_digest():
    rows = owned_check_output(
        ["git", "ls-files", "--stage", "-z"],
        timeout=60,
        max_output_bytes=8_388_608,
    ).split(b"\x00")[:-1]
    if not 0 < len(rows) <= 20000:
        raise ValueError("invalid_source_inventory")
    digest = hashlib.sha256(b"http-interop-quiche-source-v1\x00")
    digest.update(struct.pack(">Q", len(rows)))
    for row in sorted(rows):
        metadata, name = row.split(b"\t", 1)
        mode, object_id, stage = metadata.split()
        if stage != b"0":
            raise ValueError("unmerged_source_input")
        path = Path(os.fsdecode(name))
        digest.update(struct.pack(">Q", len(name)))
        digest.update(name)
        digest.update(mode)
        if mode == b"160000":
            # Unused upstream fuzz corpora are gitlinks, not compiled files.
            content = hashlib.sha256(object_id).digest()
        elif mode == b"120000":
            content = hashlib.sha256(os.fsencode(os.readlink(path))).digest()
        elif mode in (b"100644", b"100755") and not path.is_symlink():
            content = bytes.fromhex(digest_file(path))
        else:
            raise ValueError("unsupported_source_mode")
        digest.update(content)
    return digest.hexdigest(), len(rows)


def identity():
    if checked(["git", "rev-parse", "HEAD"]) != COMMIT:
        raise ValueError("wrong_quiche_commit")
    if sorted(checked(["git", "diff", "--name-only"]).splitlines()) != ENTRYPOINTS + [VERSION_SOURCE]:
        raise ValueError("unexpected_quiche_source_change")
    rustc = checked(["rustc", "--version"]).split()
    cargo = checked(["cargo", "--version"]).split()
    if rustc[:2] != ["rustc", RUST] or cargo[:2] != ["cargo", RUST]:
        raise ValueError("wrong_rust_toolchain")
    compiler = Path(checked(["rustup", "which", "rustc"])).resolve(strict=True)
    cargo_binary = Path(checked(["rustup", "which", "cargo"])).resolve(strict=True)
    drivers = list((compiler.parent.parent / "lib").glob("librustc_driver-*.so"))
    if len(drivers) != 1:
        raise ValueError("missing_rust_compiler_driver")
    source, count = source_digest()
    return {"schema": 1, "source_commit": COMMIT,
        "source_sha256": source, "source_files": count,
        "lock_sha256": digest_file("Cargo.lock"),
        "patch_sha256": digest_file(__file__),
        "rust_version": RUST, "rustc_sha256": digest_file(compiler),
        "rustc_driver_sha256": digest_file(drivers[0]),
        "cargo_sha256": digest_file(cargo_binary),
        "native_tools": [{"name": name, "sha256": digest_file(shutil.which(name))}
            for name in ["cc", "c++", "clang", "cmake", "make", "ar", "ld"]]}


def main():
    if sys.argv[1:] == ["apply"]:
        for name in ENTRYPOINTS:
            path = Path(name)
            source = path.read_text()
            if source.count("fn main() {") != 1 or "http_interop_identity" in source:
                raise ValueError("unexpected_upstream_entrypoint")
            path.write_text(source.replace("fn main() {",
                "fn main() {\n    if http_interop_identity() { return; }", 1)
                + IDENTITY_FUNCTION)
        version_source = Path(VERSION_SOURCE)
        source = version_source.read_text()
        if "http_interop_version" in source:
            raise ValueError("unexpected_version_source")
        version_source.write_text(source + '\n#[doc(hidden)]\n'
            'pub fn http_interop_version() -> &' + "'static str { env!(\"CARGO_PKG_VERSION\") }\n")
        Path("http-interop-identity.json").write_text(json.dumps(identity(), sort_keys=True) + "\n")
    elif sys.argv[1:] == ["verify"]:
        recorded = json.loads(Path("http-interop-identity.json").read_text())
        if recorded != identity():
            raise ValueError("quiche_build_input_changed")
    else:
        raise ValueError("invalid_identity_patch_command")


if __name__ == "__main__":
    main()

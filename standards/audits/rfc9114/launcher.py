#!/usr/bin/env python3

# SPDX-FileCopyrightText: 2026 the http contributors
# SPDX-License-Identifier: MIT OR Apache-2.0

"""Execute the exact reviewed RFC 9114 applicator byte snapshot."""

from __future__ import annotations

import hashlib
import os
from pathlib import Path
import re
import sys


ROOT = Path(__file__).resolve().parents[3]
AUDIT_DIRECTORY = Path(__file__).resolve().parent
TOOL = AUDIT_DIRECTORY / "apply_review.py"
ARTIFACT_MANIFEST = AUDIT_DIRECTORY / "artifact-manifest.json"
EVIDENCE_GATE = AUDIT_DIRECTORY / "evidence_gate.py"
MISE_CONFIG = ROOT / ".mise.toml"
MAX_BYTES = 32 * 1024 * 1024
EXPECTED_TOOL_SHA256 = "6ce19c30a5cb42bd786e06d9110532cadcf83976900dd4f37fc93b0826124c74"
MISE_PYTHON_VERSION = "3.12.13"
LOCAL_FROZEN_PYTHON = {
    "implementation": "cpython",
    "version": "3.12.14",
    "sha256": "dd5f8d19f6755d6491ee7c4bef2fe35ddd521334cc3ca3ed8fc93ebcadf135d0",
}


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def read_bounded(path: Path) -> bytes:
    with path.open("rb") as handle:
        data = handle.read(MAX_BYTES + 1)
        if len(data) > MAX_BYTES or handle.read(1):
            raise RuntimeError("bounded_read_rejected")
    return data


def verify_python(mise_snapshot: bytes) -> str:
    configured = os.environ.get("HTTP_AUDIT_PYTHON")
    running = Path(sys.executable).resolve(strict=True)
    if configured and Path(configured).resolve(strict=True) != running:
        raise RuntimeError("python_executable_mismatch")
    if sys.flags.isolated != 1 or sys.flags.dont_write_bytecode != 1:
        raise RuntimeError("python_flags_mismatch")
    text = mise_snapshot.decode("utf-8")
    versions = re.findall(
        r'^python\s*=\s*"([0-9]+\.[0-9]+\.[0-9]+)"\s*$', text, re.M
    )
    if versions != [MISE_PYTHON_VERSION]:
        raise RuntimeError("mise_python_configuration_mismatch")
    version = ".".join(str(value) for value in sys.version_info[:3])
    executable_sha256 = digest(read_bounded(running))
    if sys.implementation.name != "cpython":
        raise RuntimeError("python_implementation_mismatch")
    if version == MISE_PYTHON_VERSION:
        return executable_sha256
    if {
        "implementation": sys.implementation.name,
        "version": version,
        "sha256": executable_sha256,
    } != LOCAL_FROZEN_PYTHON:
        raise RuntimeError("python_identity_mismatch")
    return executable_sha256


def execute_snapshot() -> int:
    launcher_snapshot = read_bounded(Path(__file__).resolve(strict=True))
    tool_snapshot = read_bounded(TOOL)
    if digest(tool_snapshot) != EXPECTED_TOOL_SHA256:
        raise RuntimeError("tool_snapshot_mismatch")
    manifest_snapshot = read_bounded(ARTIFACT_MANIFEST)
    gate_snapshot = read_bounded(EVIDENCE_GATE)
    mise_snapshot = read_bounded(MISE_CONFIG)
    python_sha256 = verify_python(mise_snapshot)
    binding = {
        "schema": 1,
        "tool_relative_path": "standards/audits/rfc9114/apply_review.py",
        "tool_snapshot": tool_snapshot,
        "tool_sha256": digest(tool_snapshot),
        "launcher_relative_path": "standards/audits/rfc9114/launcher.py",
        "launcher_snapshot": launcher_snapshot,
        "launcher_sha256": digest(launcher_snapshot),
        "gate_snapshot": gate_snapshot,
        "gate_sha256": digest(gate_snapshot),
        "artifact_manifest_snapshot": manifest_snapshot,
        "mise_config_snapshot": mise_snapshot,
        "python_implementation": sys.implementation.name,
        "python_version": ".".join(str(value) for value in sys.version_info[:3]),
        "python_executable_sha256": python_sha256,
    }
    namespace = {
        "__name__": "__main__",
        "__file__": str(TOOL),
        "__package__": None,
        "__builtins__": __builtins__,
        "__audit_launch__": binding,
    }
    try:
        code = compile(tool_snapshot, "<rfc9114-reviewed-applicator>", "exec")
        exec(code, namespace, namespace)
    except SystemExit as exit_signal:
        return exit_signal.code if isinstance(exit_signal.code, int) else 1
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(execute_snapshot())
    except SystemExit:
        raise
    except Exception:
        print(
            "rfc9114_strict_inventory status=Rejected "
            "category=outer_launcher_rejected",
            file=sys.stderr,
        )
        raise SystemExit(1)

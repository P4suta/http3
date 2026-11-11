#!/usr/bin/env python3

# SPDX-FileCopyrightText: 2026 the http contributors
# SPDX-License-Identifier: MIT OR Apache-2.0

"""Launch the exact RFC 9114 v4 applicator snapshot supplied by the trust root."""

from __future__ import annotations

import hashlib
import os
from typing import Any


TOOL_PATH = "standards/audits/rfc9114/v4/apply_review.py"
LAUNCHER_PATH = "standards/audits/rfc9114/v4/launcher.py"


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def checked_binding() -> dict[str, Any]:
    binding = globals().get("__rfc9114_v4_binding__")
    if not isinstance(binding, dict) or set(binding) != {
        "schema",
        "root",
        "anchor",
        "anchor_relative",
        "anchor_snapshot",
        "anchor_sha256",
        "snapshots",
        "python_identity",
        "launcher_snapshot",
        "launcher_sha256",
    }:
        raise RuntimeError("launch_binding_invalid")
    anchor = binding.get("anchor")
    snapshots = binding.get("snapshots")
    launcher_snapshot = binding.get("launcher_snapshot")
    anchor_snapshot = binding.get("anchor_snapshot")
    if (
        binding.get("schema") != 4
        or not isinstance(anchor, dict)
        or not isinstance(anchor.get("members"), dict)
        or not isinstance(snapshots, dict)
        or not 0 < len(snapshots) <= 1024
        or not all(isinstance(relative, str) for relative in snapshots)
        or len(
            {
                os.path.normcase(
                    os.path.normpath(relative.replace("/", os.sep))
                )
                for relative in snapshots
            }
        )
        != len(snapshots)
        or not isinstance(binding.get("anchor_relative"), str)
        or not isinstance(anchor_snapshot, bytes)
        or digest(anchor_snapshot) != binding.get("anchor_sha256")
        or binding.get("anchor_sha256") != anchor.get("anchor_sha256")
        or not isinstance(launcher_snapshot, bytes)
        or snapshots.get(LAUNCHER_PATH) is not launcher_snapshot
        or digest(launcher_snapshot) != binding.get("launcher_sha256")
        or binding.get("launcher_sha256") != anchor["members"].get(LAUNCHER_PATH)
        or not isinstance(snapshots.get(TOOL_PATH), bytes)
        or digest(snapshots[TOOL_PATH]) != anchor["members"].get(TOOL_PATH)
    ):
        raise RuntimeError("launch_binding_identity_mismatch")
    return binding


def launch(mode: str, run_id: str) -> int:
    binding = checked_binding()
    tool_snapshot = binding["snapshots"][TOOL_PATH]
    namespace = {
        "__name__": "rfc9114_v4_application",
        "__file__": "<rfc9114-v4-application-snapshot>",
        "__package__": None,
        "__builtins__": __builtins__,
        "__rfc9114_v4_binding__": binding,
    }
    code = compile(tool_snapshot, "<rfc9114-v4-application-snapshot>", "exec")
    exec(code, namespace, namespace)
    entry = namespace.get("run")
    if not callable(entry):
        raise RuntimeError("application_entry_missing")
    result = entry(mode, run_id)
    if not isinstance(result, int) or isinstance(result, bool):
        raise RuntimeError("application_result_invalid")
    return result

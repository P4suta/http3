#!/usr/bin/env python3

# SPDX-FileCopyrightText: 2026 the http contributors
# SPDX-License-Identifier: MIT OR Apache-2.0

"""Build the static RFC 9114 launcher evidence lock after inputs stabilize.

This builder never invokes PowerShell, Erlang, Gleam, or a mutation runner. It
can publish only ``StaticReady`` with an explicitly pending independent audit.
The read-only consumer revalidates the complete lock before the write returns.
"""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path, PurePosixPath
import time
from typing import Any


def load_gate(root: Path) -> Any:
    path = root / "scripts/rfc9114_launcher_evidence_gate.py"
    specification = importlib.util.spec_from_file_location(
        "rfc9114_launcher_evidence_gate_snapshot", path
    )
    if specification is None or specification.loader is None:
        raise RuntimeError("gate_module_load_rejected")
    module = importlib.util.module_from_spec(specification)
    specification.loader.exec_module(module)
    return module


def build(root: Path, gate: Any) -> tuple[dict[str, Any], str]:
    gate.ACTIVE_DEADLINE = time.monotonic() + gate.ABSOLUTE_GATE_SECONDS
    store = gate.DiskStore(root)
    integration = gate.parse_json(
        store.read(gate.INTEGRATION_PATH, gate.MAX_ARTIFACT_BYTES), "integration"
    )
    gate.validate_integration(integration, store)
    if (
        integration["status"] != "Wired"
        or integration["mise"]["wired"] is not True
        or integration["ci"]["wired"] is not True
    ):
        gate.reject("consumer_gate_not_wired")

    artifacts = {
        role: gate.sha256(store.read(path, gate.MAX_ARTIFACT_BYTES))
        for role, path in gate.REQUIRED_ARTIFACTS.items()
    }
    summary = gate.parse_json(
        store.read(gate.SUMMARY_PATH, gate.MAX_ARTIFACT_BYTES), "summary"
    )
    gate.validate_summary(summary, store, artifacts)
    policy = {
        "production_controls": 55,
        "mutation_count": len(gate.MUTATION_IDS),
        "absolute_deadline_ms": 1_200_000,
        "maximum_artifact_bytes": gate.MAX_ARTIFACT_BYTES,
        "maximum_evidence_bytes": gate.MAX_EVIDENCE_BYTES,
    }
    evidence = []
    for label, path in gate.EVIDENCE_PATHS.items():
        canonical_bytes = store.read(path, gate.MAX_EVIDENCE_BYTES)
        canonical = gate.parse_json(canonical_bytes, "canonical_evidence")
        evidence.append(
            {
                "label": label,
                "canonical_path": path,
                "canonical_sha256": gate.sha256(canonical_bytes),
                "run_id": canonical.get("run_id"),
                "engine_sha256": canonical.get("engine", {}).get(
                    "executable_sha256"
                ),
            }
        )
    lock: dict[str, Any] = {
        "schema": 1,
        "lock_kind": "rfc9114_launcher_evidence_lock",
        "generation": 4,
        "status": "StaticReady",
        "shareable": True,
        "implementer_id": "http3_launcher_independent_audit",
        "source_epoch": gate.source_identity(store),
        "policy": policy,
        "artifacts": [
            {"role": role, "path": path, "sha256": artifacts[role]}
            for role, path in gate.REQUIRED_ARTIFACTS.items()
        ],
        "mutation_set": {
            "summary_path": gate.SUMMARY_PATH,
            "summary_sha256": artifacts["mutant_summary"],
            "count": len(gate.MUTATION_IDS),
            "ids_sha256": gate.mutation_ids_sha256(),
        },
        "evidence": evidence,
        "integration": {
            "candidate_path": gate.INTEGRATION_PATH,
            "candidate_sha256": artifacts["integration_candidate"],
            "mise_wired": True,
            "ci_wired": True,
        },
        "independent_audit": {
            "status": "Pending",
            "reviewer_kind": "different_agent",
            "reviewer_id": None,
            "report_path": None,
            "report_sha256": None,
        },
        "subject_sha256": "0" * 64,
    }
    lock["subject_sha256"] = gate.sha256(
        gate.canonical_json(gate.subject_object(lock))
    )
    status = gate.validate_lock(store, lock, False)
    if status != "StaticReady":
        gate.reject("generated_lock_not_static_ready")
    return lock, lock["subject_sha256"]


def main() -> int:
    gate: Any = None
    try:
        sys.dont_write_bytecode = True
        if len(sys.argv) != 1:
            raise RuntimeError("argument_rejected")
        root = Path(__file__).resolve(strict=True).parent.parent
        gate = load_gate(root)
        lock_path = root.joinpath(*PurePosixPath(gate.LOCK_PATH).parts)
        if lock_path.exists():
            existing = gate.parse_json(
                gate.DiskStore(root).read(gate.LOCK_PATH, gate.MAX_LOCK_BYTES),
                "existing_lock",
            )
            if existing.get("status") == "Ready":
                gate.reject("ready_lock_downgrade_rejected")
        lock, subject = build(root, gate)
        digest = gate.atomic_write(
            lock_path, gate.pretty_json(lock), gate.MAX_LOCK_BYTES
        )
        if gate.consume(root, gate.LOCK_PATH, False) != "StaticReady":
            gate.reject("published_lock_readback_rejected")
        print(
            "rfc9114_launcher_evidence_lock=StaticReady "
            f"subject_sha256={subject} lock_sha256={digest} native_started=false"
        )
        return 0
    except Exception as error:
        code = str(error)
        if gate is None or not gate.CONTROL_RE.fullmatch(code):
            code = "unexpected_lock_builder_failure"
        print(
            "rfc9114_launcher_evidence_lock=Rejected "
            f"failure={code} native_started=false"
        )
        return 1


if __name__ == "__main__":
    raise SystemExit(main())

#!/usr/bin/env python3

# SPDX-FileCopyrightText: 2026 the http contributors
# SPDX-License-Identifier: MIT OR Apache-2.0

"""Apply the reviewed RFC 9114 inventory through the v4 trust boundary."""

from __future__ import annotations

import copy
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import stat
import subprocess
import sys
import tempfile
import time
from typing import Any, Callable


TOOL_PATH = "standards/audits/rfc9114/v4/apply_review.py"
IO_PATH = "standards/audits/rfc9114/v4/io_state.py"
SCHEMA_PATH = "standards/audits/rfc9114/v4/report_schema.py"
DOMAIN_PATH = "standards/audits/rfc9114/v4/review_domain.py"
CONTROL_PATH = "standards/audits/rfc9114/v4/reviewed-controls.json"
CANDIDATE_PATH = "standards/audits/rfc9114/candidate-inventory.json"
REVIEW_PATH = "standards/audits/rfc9114/independent-review.json"
SOURCE_MANIFEST_PATH = "standards/audits/rfc9114/reviewed-source-manifest.json"
INVALIDATION_PATH = "standards/audits/rfc9114/v4/invalidation-chain.json"
REQUIREMENTS_PATH = "standards/requirements.json"
EXPECTED_BEFORE = "6d9c34e9311c73cc9540b5b51a133c755d6225d88015068169a44369842bf533"
EXPECTED_AFTER = "76bdca016340f90dc8a75157b5fc4b04951e151eae3ed1cd000000ba0cd7115a"
REVIEWED_COUNTS = {"Implemented": 31, "NotApplicable": 36, "Open": 148}
SAFE_FIXTURE_ARTIFACT_NAMES = {
    "original.bin",
    "intended.bin",
    "claimed.bin",
    "published.bin",
    "concurrent.bin",
    "transaction.json",
    "report.json",
    "report-red.json",
    "report-self-test.json",
    "report-apply.json",
    "pending.json",
    "done.json",
    "abandoned.json",
    "journal.json",
    "preparation-rejected.json",
    "publication-failure.json",
}


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def checked_binding() -> dict[str, Any]:
    value = globals().get("__rfc9114_v4_binding__")
    if not isinstance(value, dict) or set(value) != {
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
    anchor = value.get("anchor")
    snapshots = value.get("snapshots")
    if (
        value.get("schema") != 4
        or not isinstance(value.get("root"), str)
        or not isinstance(anchor, dict)
        or not isinstance(anchor.get("members"), dict)
        or not isinstance(anchor.get("anchor_sha256"), str)
        or not isinstance(value.get("anchor_relative"), str)
        or not isinstance(value.get("anchor_snapshot"), bytes)
        or digest(value["anchor_snapshot"]) != value.get("anchor_sha256")
        or value.get("anchor_sha256") != anchor.get("anchor_sha256")
        or not isinstance(snapshots, dict)
        or set(snapshots) != set(anchor["members"])
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
    ):
        raise RuntimeError("launch_binding_invalid")
    for relative, expected in anchor["members"].items():
        snapshot = snapshots.get(relative)
        if (
            not isinstance(relative, str)
            or not isinstance(expected, str)
            or not re.fullmatch(r"[0-9a-f]{64}", expected)
            or not isinstance(snapshot, bytes)
            or digest(snapshot) != expected
        ):
            raise RuntimeError("anchor_member_identity_mismatch")
    return value


BINDING = checked_binding()
ROOT = Path(BINDING["root"])
ANCHOR = BINDING["anchor"]
SNAPSHOTS = BINDING["snapshots"]
EVIDENCE = ROOT / "build/root-validation/rfc9114-v4"
TRANSACTIONS = EVIDENCE / "transactions"


def ensure_evidence_directory() -> None:
    IO["assert_plain_directory"](ROOT, "input_root_alias_rejected")
    current = ROOT
    for part in ("build", "root-validation", "rfc9114-v4"):
        current = current / part
        if not os.path.lexists(current):
            try:
                os.mkdir(current)
                IO["fsync_parent"](current)
            except FileExistsError:
                pass
        IO["assert_plain_directory"](current, "report_directory_alias_rejected")


def load_snapshot(relative: str, name: str, extra: dict[str, Any] | None = None) -> dict[str, Any]:
    namespace: dict[str, Any] = {
        "__name__": name,
        "__file__": f"<{name}-snapshot>",
        "__package__": None,
        "__builtins__": __builtins__,
    }
    if extra:
        namespace.update(extra)
    code = compile(SNAPSHOTS[relative], f"<{name}-snapshot>", "exec")
    exec(code, namespace, namespace)
    return namespace


IO = load_snapshot(IO_PATH, "rfc9114_v4_io")
SCHEMA = load_snapshot(SCHEMA_PATH, "rfc9114_v4_schema")
Rejected = IO["Rejected"]
SimulatedCrash = IO["SimulatedCrash"]


DOMAIN = load_snapshot(DOMAIN_PATH, "rfc9114_v4_domain")


def stable_cited_source(relative: str) -> tuple[bytes, os.stat_result]:
    path = IO["checked_relative_path"](ROOT, relative)
    result = IO["strict_read_path"](path, with_metadata=True)
    if not isinstance(result, tuple) or len(result) != 2:
        raise Rejected("evidence_source_read_failed")
    return result


DOMAIN.update(
    {
        "ROOT": ROOT,
        "REQUIREMENTS": ROOT / REQUIREMENTS_PATH,
        "AUDIT_DIRECTORY": ROOT / "standards/audits/rfc9114",
        "CANDIDATE": ROOT / CANDIDATE_PATH,
        "REVIEW": ROOT / REVIEW_PATH,
        "SOURCE_MANIFEST": ROOT / SOURCE_MANIFEST_PATH,
        "INVALIDATION_CHAIN": ROOT / INVALIDATION_PATH,
        "Rejected": Rejected,
        "read_bounded": IO["strict_read_path"],
        "stable_regular_bytes": lambda path, _category: IO["strict_read_path"](path),
        "stable_source_bytes": stable_cited_source,
    }
)


def manifest_object(relative: str) -> dict[str, Any]:
    try:
        value = SCHEMA["object_from"](SNAPSHOTS[relative], "reviewed_manifest")
    except (KeyError, SCHEMA["SchemaRejected"]) as error:
        raise Rejected("reviewed_manifest_invalid") from error
    return value


CONTROL_MANIFEST = manifest_object(CONTROL_PATH)


def checked_invalidation_chain(data: bytes) -> None:
    expected = manifest_object(INVALIDATION_PATH)
    try:
        chain = SCHEMA["object_from"](data, "invalidation_chain")
    except SCHEMA["SchemaRejected"] as error:
        raise Rejected("invalidation_chain_invalid") from error
    entries = chain.get("entries")
    if (
        chain != expected
        or set(chain) != {
            "schema",
            "chain_kind",
            "standard",
            "current_generation",
            "entries",
            "replacement_required",
        }
        or chain.get("schema") != 1
        or chain.get("chain_kind")
        != "rfc9114_review_application_invalidation_chain"
        or chain.get("standard") != "RFC9114"
        or chain.get("current_generation") != 4
        or not isinstance(entries, list)
        or [item.get("generation") for item in entries if isinstance(item, dict)]
        != [1, 2, 3]
        or any(item.get("status") != "Rejected" for item in entries)
        or entries[-1].get("audit_report_sha256")
        != "2e113c08bb912ac0876cead37fb8f64de34c87a37a118e2fe7a48e02632385d8"
        or entries[-1].get("audit_manifest_sha256")
        != "a962f0c28423df6edd4dd02eea869f3ecac850efff3a7678cd85d6b41343ca48"
        or entries[-1].get("audit_script_sha256")
        != "e794b2622466ecdd3f0e753c6bcff3240374c4460ec23b4847a1c66796749e21"
        or len(entries[-1].get("failure_classifications", [])) != 14
    ):
        raise Rejected("invalidation_chain_contract_mismatch")


def expected_controls(source_state: str) -> list[dict[str, str]]:
    try:
        return SCHEMA["reviewed_controls"](CONTROL_MANIFEST, source_state)
    except SCHEMA["SchemaRejected"] as error:
        raise Rejected(str(error)) from error


def validate_inventory(controls: Any, exact_pre_state: bool) -> None:
    state = "pre_review" if exact_pre_state else "reviewed"
    expected = expected_controls(state)
    try:
        SCHEMA["validate_control_prefix"](controls, len(controls) if isinstance(controls, list) else -1, expected)
    except SCHEMA["SchemaRejected"] as error:
        raise Rejected(str(error)) from error
    if controls != expected:
        raise Rejected("control_inventory_entry_mismatch")


DOMAIN["validate_control_inventory"] = validate_inventory


def strict_read(relative: str, *, hook: Callable[[str, Path], None] | None = None) -> bytes:
    return IO["strict_read"](ROOT, relative, hook=hook)


def validate_member_snapshot(relative: str, data: bytes) -> None:
    expected = ANCHOR["members"].get(relative)
    if not isinstance(expected, str) or digest(data) != expected:
        raise Rejected("anchor_member_identity_mismatch")


def validate_python_identity(identity: dict[str, Any]) -> None:
    try:
        SCHEMA["validate_python_identity"](
            identity,
            ANCHOR["python_policy"]["allowed"],
            ANCHOR["members"][".mise.toml"],
        )
    except (KeyError, TypeError, SCHEMA["SchemaRejected"]) as error:
        category = str(error) if isinstance(error, SCHEMA["SchemaRejected"]) else "python_identity_not_allowed"
        raise Rejected(category) from error


def post_validate_members(expected_requirements: bytes) -> None:
    requirements_policy = ANCHOR.get("requirements_policy")
    if requirements_policy != {
        "before_sha256": EXPECTED_BEFORE,
        "after_sha256": EXPECTED_AFTER,
    }:
        raise Rejected("anchor_requirements_policy_mismatch")
    anchor_current = strict_read(BINDING["anchor_relative"])
    if (
        anchor_current != BINDING["anchor_snapshot"]
        or digest(anchor_current) != BINDING["anchor_sha256"]
    ):
        raise Rejected("external_anchor_disk_drift")
    for relative, snapshot in SNAPSHOTS.items():
        current = strict_read(relative)
        if current != snapshot:
            raise Rejected("anchor_member_disk_drift")
    if strict_read(REQUIREMENTS_PATH) != expected_requirements:
        raise Rejected("requirements_disk_drift")
    validate_python_identity(BINDING["python_identity"])
    running_python = BINDING["python_identity"]
    executable = Path(os.path.realpath(os.path.abspath(sys.executable)))
    executable_before = os.stat(executable, follow_symlinks=False)
    executable_bytes = IO["strict_read_path"](
        executable, require_single_link=False
    )
    executable_after = os.stat(executable, follow_symlinks=False)
    if (
        executable_before.st_dev,
        executable_before.st_ino,
        executable_before.st_nlink,
    ) != (
        executable_after.st_dev,
        executable_after.st_ino,
        executable_after.st_nlink,
    ):
        raise Rejected("execution_identity_drift")
    observed_execution_identity = {
        "implementation": sys.implementation.name,
        "version": ".".join(str(value) for value in sys.version_info[:3]),
        "executable_sha256": digest(executable_bytes),
        "executable_path_sha256": digest(
            os.fsencode(os.path.normcase(os.path.normpath(os.fspath(executable))))
        ),
        "executable_link_count": executable_after.st_nlink,
        "os": platform.system().lower(),
        "architecture": platform.machine().lower(),
        "mise_config_sha256": ANCHOR["members"][".mise.toml"],
        "identity_kind": "mise_resolved_cpython",
    }
    if (
        observed_execution_identity != running_python
        or sys.flags.isolated != 1
        or sys.flags.dont_write_bytecode != 1
        or sys.flags.optimize != 0
    ):
        raise Rejected("execution_identity_drift")
    actual = {
        "implementation": sys.implementation.name,
        "version": ".".join(str(value) for value in sys.version_info[:3]),
        "executable_sha256": digest(executable_bytes),
        "executable_path_sha256": digest(
            os.fsencode(os.path.normcase(os.path.normpath(os.fspath(executable))))
        ),
        "executable_link_count": executable_after.st_nlink,
        "os": platform.system().lower(),
        "architecture": platform.machine().lower(),
        "mise_config_sha256": ANCHOR["members"][".mise.toml"],
        "identity_kind": "mise_resolved_cpython",
    }
    if actual != running_python:
        raise Rejected("execution_identity_drift")


def safe_failure(value: BaseException) -> str:
    if not isinstance(value, (Rejected, SCHEMA["SchemaRejected"])):
        return "typed_rejection"
    if len(value.args) != 1 or not isinstance(value.args[0], str):
        return "typed_rejection"
    return IO["safe_category"](value.args[0])


def nullable_counts(value: dict[str, int] | None) -> dict[str, int | None]:
    if value is None:
        return {"Implemented": None, "NotApplicable": None, "Open": None}
    return {
        name: value.get(name, 0)
        for name in ("Implemented", "NotApplicable", "Open")
    }


def audit_approved() -> bool:
    review = ANCHOR.get("independent_audit")
    return (
        isinstance(review, dict)
        and set(review) == {"status", "report_sha256"}
        and review.get("status") == "Approved"
        and isinstance(review.get("report_sha256"), str)
        and bool(re.fullmatch(r"[0-9a-f]{64}", review["report_sha256"]))
    )


def make_report(
    *,
    mode: str,
    run_id: str,
    status: str,
    failure: str | None,
    phase: str,
    controls: list[dict[str, str]],
    source_before: str,
    source_after: str,
    applied_now: bool,
    before_counts: dict[str, int] | None,
    after_counts: dict[str, int] | None,
    result_hash: str,
    transaction: dict[str, Any],
    diagnostic_evidence_override: dict[str, Any] | None = None,
) -> bytes:
    diagnostic_evidence = (
        checked_safe_fixture_summary(run_id)
        if diagnostic_evidence_override is None
        else diagnostic_evidence_override
    )
    report = {
        "schema": 4,
        "report_kind": "rfc9114_v4_review_application",
        "status": status,
        "shareable": True,
        "mode": mode,
        "run_id": run_id,
        "failure_category": failure,
        "identity": {
            "anchor_sha256": ANCHOR["anchor_sha256"],
            "member_sha256": ANCHOR["members"],
            "python": BINDING["python_identity"],
        },
        "source_state_before": source_before,
        "source_state_after": source_after,
        "applied_now": applied_now,
        "before_counts": nullable_counts(before_counts),
        "after_counts": nullable_counts(after_counts),
        "reviewed_counts": REVIEWED_COUNTS,
        "scope": {
            "standard": "RFC9114",
            "canonical_rows": 215,
            "independently_assessed_rows": 161,
        },
        "completion": {
            "phase": phase,
            "controls_expected": 45,
            "controls_completed": len(controls),
        },
        "self_test_controls": controls,
        "expected_output_sha256": EXPECTED_AFTER,
        "result_requirements_sha256": result_hash,
        "target_transaction": transaction,
        "diagnostic_evidence": diagnostic_evidence,
        "rerun": {
            "command": f"python -I -B standards/audits/rfc9114_v4_bootstrap.py cycle {mode}",
            "expected_run_id_required": True,
        },
    }
    return (json.dumps(report, indent=2, sort_keys=True) + "\n").encode("utf-8")


def checked_safe_fixture_summary(run_id: str) -> dict[str, Any]:
    path = EVIDENCE / "safe-fixtures" / f"run-{run_id}" / "fixture-summary.json"
    if not os.path.lexists(path):
        return {
            "safe_fixture_run_id": None,
            "manifest_sha256": None,
            "artifact_count": None,
        }
    data = IO["strict_read_path"](path)
    try:
        summary = SCHEMA["object_from"](data, "fixture_summary")
    except SCHEMA["SchemaRejected"] as error:
        raise Rejected("fixture_summary_invalid") from error
    artifacts = summary.get("artifacts")
    if (
        set(summary)
        != {
            "schema",
            "manifest_kind",
            "run_id",
            "application_controls",
            "infrastructure_controls",
            "artifact_count",
            "artifacts",
        }
        or summary.get("schema") != 4
        or summary.get("manifest_kind") != "rfc9114_v4_safe_fixture_manifest"
        or summary.get("run_id") != run_id
        or summary.get("application_controls") != 45
        or summary.get("infrastructure_controls") != 31
        or not isinstance(artifacts, list)
        or summary.get("artifact_count") != len(artifacts)
        or not artifacts
        or len(artifacts) > 4096
    ):
        raise Rejected("fixture_summary_invalid")
    safe_root = path.parent
    observed_relatives: list[str] = []
    for item in artifacts:
        if not isinstance(item, dict) or set(item) != {"relative", "bytes", "sha256"}:
            raise Rejected("fixture_summary_invalid")
        relative = item.get("relative")
        if (
            not isinstance(relative, str)
            or "\\" in relative
            or relative.startswith("/")
            or len(relative) > 512
            or any(part in {"", ".", ".."} for part in relative.split("/"))
            or any(
                not re.fullmatch(r"[a-z0-9][a-z0-9._-]{0,119}", part)
                for part in relative.split("/")
            )
            or not isinstance(item.get("bytes"), int)
            or isinstance(item["bytes"], bool)
            or item["bytes"] < 0
            or not isinstance(item.get("sha256"), str)
            or not re.fullmatch(r"[0-9a-f]{64}", item["sha256"])
            or relative in observed_relatives
        ):
            raise Rejected("fixture_summary_invalid")
        relative_parts = relative.split("/")
        artifact_name = relative_parts[-1]
        if artifact_name not in SAFE_FIXTURE_ARTIFACT_NAMES and not (
            len(relative_parts) >= 2
            and relative_parts[-2] == "reports"
            and re.fullmatch(r"[0-9a-f]{64}\.json", artifact_name)
        ):
            raise Rejected("fixture_summary_invalid")
        observed_relatives.append(relative)
        artifact = safe_root.joinpath(*relative_parts)
        artifact_data = IO["strict_read_path"](artifact)
        if len(artifact_data) != item["bytes"] or digest(artifact_data) != item["sha256"]:
            raise Rejected("fixture_summary_identity_mismatch")
    if observed_relatives != sorted(observed_relatives):
        raise Rejected("fixture_summary_invalid")
    if safe_fixture_artifact_entries(safe_root) != artifacts:
        raise Rejected("fixture_summary_completeness_mismatch")
    return {
        "safe_fixture_run_id": run_id,
        "manifest_sha256": digest(data),
        "artifact_count": len(artifacts),
    }


def safe_fixture_artifact_entries(safe_root: Path) -> list[dict[str, Any]]:
    artifacts: list[dict[str, Any]] = []
    pending_directories = [safe_root]
    observed_entries = 0
    while pending_directories:
        directory = pending_directories.pop()
        children = IO["bounded_directory_entries"](
            directory, "fixture_summary_invalid"
        )
        for child in children:
            observed_entries += 1
            if observed_entries > 8192:
                raise Rejected("fixture_summary_inventory_exceeded")
            metadata = os.stat(child, follow_symlinks=False)
            if stat.S_ISDIR(metadata.st_mode):
                if stat.S_ISLNK(metadata.st_mode) or IO["is_reparse"](metadata):
                    raise Rejected("fixture_summary_invalid")
                if len(pending_directories) >= 1024:
                    raise Rejected("fixture_summary_inventory_exceeded")
                pending_directories.append(child)
                continue
            report_artifact = child.parent.name == "reports" and child.suffix == ".json"
            selected = child.name in SAFE_FIXTURE_ARTIFACT_NAMES or report_artifact
            if not selected:
                continue
            if (
                not stat.S_ISREG(metadata.st_mode)
                or stat.S_ISLNK(metadata.st_mode)
                or IO["is_reparse"](metadata)
                or metadata.st_nlink != 1
                or (
                    report_artifact
                    and not re.fullmatch(r"[0-9a-f]{64}\.json", child.name)
                )
            ):
                raise Rejected("fixture_summary_invalid")
            data = IO["strict_read_path"](child)
            artifacts.append(
                {
                    "relative": child.relative_to(safe_root).as_posix(),
                    "bytes": len(data),
                    "sha256": digest(data),
                }
            )
    artifacts.sort(key=lambda item: item["relative"])
    if not artifacts or len(artifacts) > 4096:
        raise Rejected("safe_fixture_artifacts_missing")
    return artifacts


def validate_report(data: bytes, mode: str, run_id: str) -> None:
    try:
        SCHEMA["validate_report"](
            data,
            mode,
            run_id,
            anchor=ANCHOR,
            controls_manifest=CONTROL_MANIFEST,
        )
    except SCHEMA["SchemaRejected"] as error:
        raise Rejected(str(error)) from error


def no_transaction(reconciled: list[dict[str, str]] | None = None) -> dict[str, Any]:
    return {
        "required": False,
        "run_id": None,
        "journal_sha256": None,
        "reconciled": reconciled or [],
    }


def expect_rejected(expected: str, operation: Callable[[], Any]) -> None:
    try:
        operation()
    except (Rejected, SCHEMA["SchemaRejected"]) as error:
        if str(error) != expected:
            raise Rejected("self_test_wrong_rejection") from error
    else:
        raise Rejected("self_test_mutant_accepted")


def external_replace(path: Path, data: bytes) -> None:
    descriptor, name = tempfile.mkstemp(prefix=".external-", dir=path.parent)
    temporary = Path(name)
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
        IO["fsync_parent"](path)
    finally:
        temporary.unlink(missing_ok=True)


def transaction_case(base: Path, name: str) -> tuple[Path, bytes, bytes, Any]:
    case = base / name
    case.mkdir(parents=True)
    target = case / "target.json"
    original = b'{"state":"original"}\n'
    intended = b'{"state":"intended"}\n'
    IO["durable_new_file"](target, original)
    transaction = IO["TargetTransaction"](
        target,
        original,
        intended,
        case / "recovery",
        digest(name.encode("ascii"))[:32],
    )
    return target, original, intended, transaction


def os_released_lock_self_test(base: Path) -> None:
    case = base / "os-released-lock"
    case.mkdir()
    lock_path = case / "target.lock"
    ready_path = case / "ready.bin"
    release_path = case / "release.bin"
    snapshot_path = case / "io-snapshot.py"
    io_snapshot = SNAPSHOTS[IO_PATH]
    IO["durable_new_file"](snapshot_path, io_snapshot)
    child_code = (
        "import hashlib,os,stat,sys,time\n"
        "p=sys.argv[1]\n"
        "before=os.lstat(p)\n"
        "fd=os.open(p,os.O_RDONLY|getattr(os,'O_BINARY',0))\n"
        "try:\n"
        " opened=os.fstat(fd)\n"
        " data=b''\n"
        " while len(data)<=1048576:\n"
        "  chunk=os.read(fd,min(65536,1048577-len(data)))\n"
        "  if not chunk: break\n"
        "  data+=chunk\n"
        " after=os.fstat(fd)\n"
        "finally:\n"
        " os.close(fd)\n"
        "identity=lambda s:(s.st_dev,s.st_ino,s.st_mode,s.st_nlink,s.st_size,s.st_mtime_ns,s.st_ctime_ns)\n"
        "if (identity(before)!=identity(opened) or identity(opened)!=identity(after) or "
        "not stat.S_ISREG(opened.st_mode) or opened.st_nlink!=1 or "
        "getattr(before,'st_file_attributes',0)&0x400 or len(data)>1048576 or "
        "hashlib.sha256(data).hexdigest()!=sys.argv[2]): os._exit(4)\n"
        "m={'__name__':'rfc9114_v4_child_io','__file__':'<io-snapshot>',"
        "'__package__':None,'__builtins__':__builtins__}\n"
        "exec(compile(data,'<io-snapshot>','exec'),m,m)\n"
        "lock=m['ProcessFileLock'](m['Path'](sys.argv[3]))\n"
        "lock.acquire()\n"
        "m['durable_new_file'](m['Path'](sys.argv[4]),b'ready\\n')\n"
        "deadline=time.monotonic()+5.0\n"
        "while not os.path.exists(sys.argv[5]) and time.monotonic()<deadline:\n"
        " time.sleep(0.01)\n"
        "os._exit(0 if os.path.exists(sys.argv[5]) else 3)\n"
    )
    arguments = [
        sys.executable,
        "-I",
        "-B",
        "-c",
        child_code,
        os.fspath(snapshot_path),
        digest(io_snapshot),
        os.fspath(lock_path),
        os.fspath(ready_path),
        os.fspath(release_path),
    ]
    options: dict[str, Any] = {
        "stdin": subprocess.DEVNULL,
        "stdout": subprocess.DEVNULL,
        "stderr": subprocess.DEVNULL,
        "close_fds": True,
    }
    if os.name == "nt":
        options["creationflags"] = getattr(subprocess, "CREATE_NO_WINDOW", 0x08000000)
    else:
        options["start_new_session"] = True
    child = subprocess.Popen(arguments, **options)

    def stop_owned_child() -> None:
        if child.poll() is not None:
            return
        child.terminate()
        try:
            child.wait(timeout=2.0)
        except subprocess.TimeoutExpired:
            child.kill()
            child.wait(timeout=2.0)

    try:
        deadline = time.monotonic() + 5.0
        while not os.path.lexists(ready_path):
            if child.poll() is not None or time.monotonic() >= deadline:
                raise Rejected("os_release_lock_ready_timeout")
            time.sleep(0.01)
        if IO["strict_read_path"](ready_path) != b"ready\n":
            raise Rejected("os_release_lock_ready_mismatch")
        contender = IO["ProcessFileLock"](lock_path)
        expect_rejected("exclusive_lock_busy", contender.acquire)
        contender.release()
        IO["durable_new_file"](release_path, b"release\n")
        try:
            return_code = child.wait(timeout=5.0)
        except subprocess.TimeoutExpired as error:
            raise Rejected("os_release_lock_exit_timeout") from error
        if return_code != 0:
            raise Rejected("os_release_lock_child_failed")
        successor = IO["ProcessFileLock"](lock_path)
        successor.acquire()
        successor.release()
    finally:
        stop_owned_child()
    for path in (ready_path, release_path, lock_path, snapshot_path):
        path.unlink(missing_ok=True)
    case.rmdir()


def finish_rejected_transaction(transaction: Any, error: BaseException) -> None:
    transaction.reject(safe_failure(error))


def assert_recovery_values(transaction: Any, original: bytes, intended: bytes) -> None:
    if (
        IO["generated_read"](transaction.original) != original
        or IO["generated_read"](transaction.intended_copy) != intended
    ):
        raise Rejected("transaction_recovery_value_lost")


def assert_independent_existing(paths: list[Path]) -> None:
    existing = [path for path in paths if path.exists()]
    metadata = [os.stat(path, follow_symlinks=False) for path in existing]
    if any(item.st_nlink != 1 for item in metadata):
        raise Rejected("transaction_recovery_alias_detected")
    identities = {(item.st_dev, item.st_ino) for item in metadata}
    if len(identities) != len(metadata):
        raise Rejected("transaction_recovery_alias_detected")


def valid_rejected_report(mode: str, run_id: str) -> bytes:
    return make_report(
        mode=mode,
        run_id=run_id,
        status="Rejected",
        failure="fixture_rejection",
        phase="fixture_rejection",
        controls=[],
        source_before="unknown",
        source_after="unknown",
        applied_now=False,
        before_counts=None,
        after_counts=None,
        result_hash=EXPECTED_BEFORE,
        transaction=no_transaction(),
    )


def report_case(base: Path, name: str, run_id: str, hook: Any = None) -> Any:
    case = base / name
    case.mkdir(parents=True)
    return IO["ReportStore"](
        case, "self-test", run_id, validate_report, hook=hook
    )


def report_consume(directory: Path, run_id: str | None) -> bytes:
    return IO["consume_pointer_pair"](
        directory, "self-test", run_id, validate_report
    )


def reconcile_report_case(directory: Path, suffix: str) -> str:
    run_id = digest(("successor:" + suffix).encode("ascii"))[:32]
    successor = IO["ReportStore"](
        directory, "self-test", run_id, validate_report
    )
    successor.begin()
    successor.publish(valid_rejected_report("self-test", run_id), validate_report)
    successor.close()
    report_consume(directory, run_id)
    return run_id


def report_crash_control(base: Path, boundary: str, *, ready_expected: bool) -> None:
    run_id = digest(("report-crash:" + boundary).encode("ascii"))[:32]

    def crash(observed: str, _path: Path) -> None:
        if observed == boundary:
            raise SimulatedCrash()

    store = report_case(base, boundary, run_id, crash)
    try:
        store.begin()
        store.publish(valid_rejected_report("self-test", run_id), validate_report)
    except SimulatedCrash:
        store.abandon_for_test()
    else:
        raise Rejected("report_crash_control_did_not_crash")
    if ready_expected:
        report_consume(store.directory, run_id)
    else:
        try:
            report_consume(store.directory, run_id)
        except Rejected:
            pass
        else:
            raise Rejected("incomplete_report_was_consumed")
        reconcile_report_case(store.directory, boundary)


def infrastructure_self_test(
    _output: bytes, run_id: str | None = None
) -> list[dict[str, str]]:
    controls: list[dict[str, str]] = []

    def add(name: str, observed: str = "accepted") -> None:
        controls.append({"name": name, "observed": observed})

    if not isinstance(run_id, str) or not re.fullmatch(r"[0-9a-f]{32}", run_id):
        raise Rejected("safe_fixture_run_id_invalid")
    ensure_evidence_directory()
    safe_parent = EVIDENCE / "safe-fixtures"
    if not os.path.lexists(safe_parent):
        try:
            os.mkdir(safe_parent)
            IO["fsync_parent"](safe_parent)
        except FileExistsError:
            pass
    IO["assert_plain_directory"](safe_parent, "report_directory_alias_rejected")
    existing_safe_runs = IO["bounded_directory_entries"](
        safe_parent, "safe_fixture_inventory_exceeded", limit=1024
    )
    if len(existing_safe_runs) >= 1024:
        raise Rejected("safe_fixture_inventory_exceeded")
    for existing_safe_run in existing_safe_runs:
        if not re.fullmatch(r"run-[0-9a-f]{32}", existing_safe_run.name):
            raise Rejected("safe_fixture_inventory_invalid")
        IO["assert_plain_directory"](
            existing_safe_run, "safe_fixture_inventory_invalid"
        )
    safe_root = safe_parent / f"run-{run_id}"
    os.mkdir(safe_root)
    IO["assert_plain_directory"](safe_root, "report_directory_alias_rejected")

    alias_case = safe_root / "aliases"
    alias_case.mkdir()
    source = alias_case / "source.bin"
    IO["durable_new_file"](source, b"safe-alias-fixture\n")
    symlink = alias_case / "symlink.bin"
    try:
        os.symlink(source, symlink)
    except OSError as error:
        raise Rejected("symlink_fixture_unavailable") from error
    expect_rejected("input_alias_rejected", lambda: IO["strict_read_path"](symlink))
    add("input_symlink_rejected", "input_alias_rejected")

    hardlink = alias_case / "hardlink.bin"
    os.link(source, hardlink)
    expect_rejected("input_alias_rejected", lambda: IO["strict_read_path"](hardlink))
    add("input_hardlink_rejected", "input_alias_rejected")

    swap_source = alias_case / "swap.bin"
    IO["durable_new_file"](swap_source, b"before\n")

    def swap_after_open(boundary: str, path: Path) -> None:
        if boundary == "after_open":
            with path.open("r+b") as handle:
                handle.seek(0)
                handle.write(b"after-longer\n")
                handle.truncate()
                handle.flush()
                os.fsync(handle.fileno())

    expect_rejected(
        "input_changed_during_read",
        lambda: IO["strict_read_path"](swap_source, hook=swap_after_open),
    )
    add("input_swap_during_read_rejected", "input_changed_during_read")

    saved_python_identity = BINDING["python_identity"]
    unknown_python = dict(saved_python_identity)
    unknown_python["executable_sha256"] = "0" * 64
    expect_rejected("python_identity_not_allowed", lambda: validate_python_identity(unknown_python))
    saved_allowed_identities = ANCHOR["python_policy"]["allowed"]
    for allowed_mutant in (
        [saved_python_identity, dict(saved_python_identity)],
        [saved_python_identity, {"version": saved_python_identity["version"]}],
        [dict(saved_python_identity) for _index in range(17)],
    ):
        ANCHOR["python_policy"]["allowed"] = allowed_mutant
        try:
            expect_rejected(
                "python_identity_not_allowed",
                lambda: validate_python_identity(saved_python_identity),
            )
        finally:
            ANCHOR["python_policy"]["allowed"] = saved_allowed_identities

    # The publication-boundary check must independently observe the running executable.
    # A coordinated in-memory substitution of the recorded identity and its allowlist cannot make that observation pass.
    saved_python_allowlist = ANCHOR["python_policy"]["allowed"]
    BINDING["python_identity"] = unknown_python
    ANCHOR["python_policy"]["allowed"] = [unknown_python]
    try:
        expect_rejected(
            "execution_identity_drift",
            lambda: post_validate_members(strict_read(REQUIREMENTS_PATH)),
        )
    finally:
        BINDING["python_identity"] = saved_python_identity
        ANCHOR["python_policy"]["allowed"] = saved_python_allowlist
    add("python_unknown_hash_rejected", "python_identity_not_allowed")

    expect_rejected(
        "anchor_member_identity_mismatch",
        lambda: validate_member_snapshot(TOOL_PATH, SNAPSHOTS[TOOL_PATH] + b"\n"),
    )
    add("anchor_coordinated_substitution_rejected", "anchor_member_identity_mismatch")

    transaction_root = safe_root / "transactions"
    target, original, intended, transaction = transaction_case(
        transaction_root, "independent-inodes"
    )
    transaction.begin()
    transaction.commit()
    if not isinstance(transaction.journal_sha256, str):
        raise Rejected("transaction_journal_identity_missing")
    transaction.assert_independent_recovery()
    assert_recovery_values(transaction, original, intended)

    release_target, release_original, release_intended, release_case = (
        transaction_case(transaction_root, "committed-release-error")
    )
    release_case.begin()
    release_lock = release_case.lock.release

    def release_then_report_error() -> None:
        release_lock()
        raise Rejected("exclusive_lock_release_failed")

    release_case.lock.release = release_then_report_error
    release_case.commit()
    if (
        release_case.state != "Committed"
        or IO["strict_read_path"](release_target) != release_intended
        or not isinstance(release_case.journal_sha256, str)
    ):
        raise Rejected("transaction_committed_release_regressed")
    assert_recovery_values(release_case, release_original, release_intended)
    release_case.assert_independent_recovery()
    add("transaction_recovery_independent_inodes")

    before_recovery = {
        path.name: IO["generated_read"](path)
        for path in (
            transaction.original,
            transaction.intended_copy,
            transaction.claimed,
            transaction.published,
        )
    }
    with target.open("wb") as handle:
        handle.write(b'{"state":"mutated-after-commit"}\n')
        handle.flush()
        os.fsync(handle.fileno())
    after_recovery = {
        path.name: IO["generated_read"](path)
        for path in (
            transaction.original,
            transaction.intended_copy,
            transaction.claimed,
            transaction.published,
        )
    }
    if before_recovery != after_recovery:
        raise Rejected("post_commit_recovery_mutated")
    add("transaction_post_commit_inplace_preserves_recovery")

    race_specs = (
        ("before_claim", "transaction_concurrent_before_claim_preserved"),
        ("after_claim", "transaction_concurrent_after_claim_preserved"),
        ("before_publish", "transaction_concurrent_before_publish_preserved"),
        ("after_publish", "transaction_concurrent_after_publish_preserved"),
    )
    for boundary, control_name in race_specs:
        race_target, race_original, race_intended, race = transaction_case(
            transaction_root, "race-" + boundary
        )
        concurrent = (f'{{"state":"concurrent-{boundary}"}}\n').encode("ascii")

        def inject(observed: str, path: Path, *, selected: str = boundary) -> None:
            if observed == selected:
                external_replace(path, concurrent)

        race.hook = inject
        try:
            race.begin()
        except Rejected as error:
            finish_rejected_transaction(race, error)
        else:
            raise Rejected("transaction_race_accepted")
        assert_recovery_values(race, race_original, race_intended)
        if (
            not race.concurrent.is_file()
            or IO["generated_read"](race.concurrent) != concurrent
            or IO["generated_read"](race_target) != concurrent
            or race.stage.exists()
        ):
            raise Rejected("transaction_concurrent_value_lost")
        claimed_expected = concurrent if boundary == "before_claim" else race_original
        if IO["generated_read"](race.claimed) != claimed_expected:
            raise Rejected("transaction_claimed_value_lost")
        assert_independent_existing(
            [
                race.original,
                race.intended_copy,
                race.claimed,
                race.published,
                race.concurrent,
                race_target,
            ]
        )
        add(control_name)

    inplace_target, inplace_original, inplace_intended, inplace = transaction_case(
        transaction_root, "race-after-publish-inplace"
    )
    inplace_concurrent = b'{"state":"concurrent-inplace"}\n'

    def inject_inplace(observed: str, path: Path) -> None:
        if observed == "after_publish":
            with path.open("r+b") as handle:
                handle.seek(0)
                handle.write(inplace_concurrent)
                handle.truncate()
                handle.flush()
                os.fsync(handle.fileno())

    inplace.hook = inject_inplace
    try:
        inplace.begin()
    except Rejected as error:
        finish_rejected_transaction(inplace, error)
    else:
        raise Rejected("transaction_inplace_race_accepted")
    assert_recovery_values(inplace, inplace_original, inplace_intended)
    if (
        IO["strict_read_path"](inplace_target) != inplace_concurrent
        or IO["strict_read_path"](inplace.concurrent) != inplace_concurrent
        or inplace.stage.exists()
    ):
        raise Rejected("transaction_inplace_concurrent_value_lost")
    assert_independent_existing(
        [
            inplace.original,
            inplace.intended_copy,
            inplace.claimed,
            inplace.concurrent,
            inplace_target,
        ]
    )

    late_target, late_original, late_intended, late = transaction_case(
        transaction_root, "late-same-bytes-replacement"
    )
    late.begin()
    external_replace(late_target, late_intended)
    try:
        late.commit()
    except Rejected as error:
        if str(error) != "transaction_target_ownership_mismatch":
            raise Rejected("transaction_late_race_wrong_rejection") from error
        finish_rejected_transaction(late, error)
    else:
        raise Rejected("transaction_late_race_accepted")
    if (
        IO["strict_read_path"](late_target) != late_intended
        or IO["strict_read_path"](late.concurrent) != late_intended
    ):
        raise Rejected("transaction_late_concurrent_value_lost")
    assert_recovery_values(late, late_original, late_intended)
    assert_independent_existing(
        [
            late.original,
            late.intended_copy,
            late.claimed,
            late.published,
            late.concurrent,
            late_target,
        ]
    )

    crash_groups = (
        (
            (
                "after_lock_acquired",
                "after_attempt_directory",
                "after_original_copy",
                "after_intended_copy",
                "before_pending_journal",
                "after_pending_journal",
                "after_lock",
            ),
            "transaction_crash_after_lock_reconciled",
        ),
        (
            ("before_claim", "after_claim_move_before_journal"),
            "transaction_crash_before_claim_reconciled",
        ),
        (
            ("after_claim", "after_stage_create_before_journal"),
            "transaction_crash_after_claim_reconciled",
        ),
        (
            ("before_publish", "after_target_link_before_journal"),
            "transaction_crash_before_publish_reconciled",
        ),
        (
            (
                "after_publish",
                "after_published_copy_before_stage_release",
                "after_stage_release_before_journal",
                "after_published_journal",
            ),
            "transaction_crash_after_publish_reconciled",
        ),
    )
    last_crash: Any = None
    committed_boundaries = {
        "after_target_link_before_journal",
        "after_publish",
        "after_published_copy_before_stage_release",
        "after_stage_release_before_journal",
        "after_published_journal",
    }
    for boundaries, control_name in crash_groups:
        for boundary in boundaries:
            crash_target, crash_original, crash_intended, crashed = transaction_case(
                transaction_root, "crash-" + boundary
            )
            contender: Any = None

            def crash_hook(observed: str, _path: Path, *, selected: str = boundary) -> None:
                nonlocal contender
                if observed == selected:
                    if selected == "after_lock_acquired":
                        # A live contender must fail before it publishes any attempt artifacts.
                        # This is the deterministic guard against reconciliation mistaking a lock waiter for a crashed transaction.
                        contender = IO["TargetTransaction"](
                            crash_target,
                            crash_original,
                            crash_intended,
                            crashed.root,
                            digest(b"active-lock-contender")[:32],
                        )
                        expect_rejected("exclusive_lock_busy", contender.begin)
                        contender.reject("exclusive_lock_busy")
                        if os.path.lexists(contender.directory):
                            raise Rejected("transaction_waiter_published_attempt")
                    raise SimulatedCrash()

            crashed.hook = crash_hook
            try:
                crashed.begin()
            except SimulatedCrash:
                crashed.abandon_for_test()
            else:
                raise Rejected("transaction_crash_control_did_not_crash")
            recovery_lock = IO["ProcessFileLock"](crashed.root / "target.lock")
            recovery_lock.acquire()
            try:
                outcomes = IO["TargetTransaction"].reconcile_all(
                    crash_target, crashed.root, recovery_lock
                )
            finally:
                recovery_lock.release()
            if boundary == "after_lock_acquired":
                if outcomes or os.path.lexists(crashed.directory):
                    raise Rejected("transaction_lock_boundary_not_clean")
            elif len(outcomes) != 1 or outcomes[0]["state"] not in {
                "RecoveredCommitted",
                "RecoveredOriginal",
                "Rejected",
            }:
                raise Rejected("transaction_crash_not_reconciled")
            preparation_boundaries = {
                "after_attempt_directory",
                "after_original_copy",
                "after_intended_copy",
                "before_pending_journal",
            }
            if boundary in preparation_boundaries:
                abandoned = crashed.abandoned_preparation
                if (
                    not abandoned.is_dir()
                    or not (abandoned / "preparation-rejected.json").is_file()
                    or os.path.lexists(crashed.directory)
                ):
                    raise Rejected("transaction_preparation_not_preserved")
                if boundary != "after_attempt_directory" and IO["generated_read"](
                    abandoned / "original.bin"
                ) != crash_original:
                    raise Rejected("transaction_preparation_original_lost")
                if boundary in {"after_intended_copy", "before_pending_journal"} and IO[
                    "generated_read"
                ](abandoned / "intended.bin") != crash_intended:
                    raise Rejected("transaction_preparation_intended_lost")
            elif boundary != "after_lock_acquired":
                assert_recovery_values(crashed, crash_original, crash_intended)
            expected_target = (
                crash_intended if boundary in committed_boundaries else crash_original
            )
            if (
                IO["generated_read"](crash_target) != expected_target
                or crashed.stage.exists()
            ):
                raise Rejected("transaction_crash_value_not_reconciled")
            assert_independent_existing(
                [
                    crashed.original,
                    crashed.intended_copy,
                    crashed.claimed,
                    crashed.published,
                    crashed.concurrent,
                    crash_target,
                ]
            )
            last_crash = crashed
        add(control_name)

    os_released_lock_self_test(transaction_root)

    for restore_linked in (False, True):
        restore_name = "restore-link" if restore_linked else "restore-stage"
        restore_target, restore_original, restore_intended, restore_case = transaction_case(
            transaction_root, "crash-" + restore_name
        )

        def crash_after_claim_for_restore(observed: str, _path: Path) -> None:
            if observed == "after_claim":
                raise SimulatedCrash()

        restore_case.hook = crash_after_claim_for_restore
        try:
            restore_case.begin()
        except SimulatedCrash:
            restore_case.abandon_for_test()
        else:
            raise Rejected("transaction_restore_crash_setup_failed")
        restore_stage = (
            restore_target.parent / f".rfc9114-v4-{restore_case.run_id}.restore"
        )
        IO["durable_new_file"](restore_stage, restore_original)
        if restore_linked:
            os.link(restore_stage, restore_target)
            IO["fsync_parent"](restore_target)
        restore_lock = IO["ProcessFileLock"](restore_case.root / "target.lock")
        restore_lock.acquire()
        try:
            restore_outcomes = IO["TargetTransaction"].reconcile_all(
                restore_target, restore_case.root, restore_lock
            )
        finally:
            restore_lock.release()
        if (
            len(restore_outcomes) != 1
            or IO["strict_read_path"](restore_target) != restore_original
            or restore_stage.exists()
        ):
            raise Rejected("transaction_restore_crash_not_reconciled")
        assert_recovery_values(restore_case, restore_original, restore_intended)
        assert_independent_existing(
            [
                restore_case.original,
                restore_case.intended_copy,
                restore_case.claimed,
                restore_case.concurrent,
                restore_target,
            ]
        )

    if last_crash is None:
        raise Rejected("transaction_crash_inventory_empty")
    expect_rejected(
        "exclusive_lock_not_owned",
        lambda: IO["TargetTransaction"].reconcile_all(
            last_crash.target,
            last_crash.root,
            IO["ProcessFileLock"](last_crash.root / "target.lock"),
        ),
    )
    idempotent_lock = IO["ProcessFileLock"](last_crash.root / "target.lock")
    idempotent_lock.acquire()
    try:
        if IO["TargetTransaction"].reconcile_all(
            last_crash.target, last_crash.root, idempotent_lock
        ):
            raise Rejected("transaction_recovery_not_idempotent")
    finally:
        idempotent_lock.release()

    poison_target, _poison_original, _poison_intended, poison = transaction_case(
        transaction_root, "poisoned-concurrent-evidence"
    )

    def crash_poison_after_claim(observed: str, _path: Path) -> None:
        if observed == "after_claim":
            raise SimulatedCrash()

    poison.hook = crash_poison_after_claim
    try:
        poison.begin()
    except SimulatedCrash:
        poison.abandon_for_test()
    else:
        raise Rejected("transaction_poison_fixture_did_not_crash")
    actual_concurrent = b'{"state":"actual-concurrent"}\n'
    IO["durable_new_file"](poison_target, actual_concurrent)
    IO["durable_new_file"](
        poison.concurrent, b'{"state":"forged-concurrent-evidence"}\n'
    )
    poison_lock = IO["ProcessFileLock"](poison.root / "target.lock")
    poison_lock.acquire()
    try:
        expect_rejected(
            "transaction_recovery_identity_mismatch",
            lambda: IO["TargetTransaction"].reconcile_all(
                poison_target, poison.root, poison_lock
            ),
        )
    finally:
        poison_lock.release()
    if IO["strict_read_path"](poison_target) != actual_concurrent:
        raise Rejected("transaction_poison_target_value_lost")

    missing_target, _missing_original, missing_intended, missing = transaction_case(
        transaction_root, "terminal-missing-recovery-artifact"
    )
    missing.begin()
    missing.commit()
    missing.published.unlink()
    IO["fsync_parent"](missing.published)
    missing_journal = IO["json_object"](
        IO["strict_read_path"](missing.journal_path), "transaction_journal"
    )
    missing_journal["artifacts"]["published"] = None
    IO["atomic_write"](
        missing.journal_path,
        IO["json_bytes"](missing_journal),
        prefix="terminal_missing_artifact_mutant",
    )
    missing_lock = IO["ProcessFileLock"](missing.root / "target.lock")
    missing_lock.acquire()
    try:
        expect_rejected(
            "transaction_recovery_identity_mismatch",
            lambda: IO["TargetTransaction"].reconcile_all(
                missing_target, missing.root, missing_lock
            ),
        )
    finally:
        missing_lock.release()
    if IO["strict_read_path"](missing_target) != missing_intended:
        raise Rejected("transaction_terminal_target_value_lost")
    add("transaction_idempotent_recovery")

    commit_target, commit_original, commit_intended, commit_crash = transaction_case(
        transaction_root, "crash-after-committed-journal"
    )

    def crash_after_commit(observed: str, _path: Path) -> None:
        if observed == "after_committed_journal":
            raise SimulatedCrash()

    commit_crash.hook = crash_after_commit
    commit_crash.begin()
    try:
        commit_crash.commit()
    except SimulatedCrash:
        commit_crash.abandon_for_test()
    else:
        raise Rejected("transaction_commit_crash_control_did_not_crash")
    if IO["strict_read_path"](commit_target) != commit_intended:
        raise Rejected("transaction_commit_crash_value_lost")
    assert_recovery_values(commit_crash, commit_original, commit_intended)
    commit_lock = IO["ProcessFileLock"](commit_crash.root / "target.lock")
    commit_lock.acquire()
    try:
        if IO["TargetTransaction"].reconcile_all(
            commit_target, commit_crash.root, commit_lock
        ):
            raise Rejected("transaction_committed_journal_not_terminal")
    finally:
        commit_lock.release()

    report_root = safe_root / "reports"
    bare_ready_run = "8" * 32
    bare_ready = report_case(report_root, "bare-attempt", bare_ready_run)
    bare_ready.begin()
    bare_ready.publish(
        valid_rejected_report("self-test", bare_ready_run), validate_report
    )
    bare_ready.close()
    consumer_guard = IO["ProcessFileLock"](
        bare_ready.directory / "report-intent.lock"
    )
    consumer_guard.acquire()
    guarded_contender = IO["ReportStore"](
        bare_ready.directory, "self-test", "3" * 32, validate_report
    )
    try:
        expect_rejected("exclusive_lock_busy", guarded_contender.begin)
        if os.path.lexists(guarded_contender.attempt):
            raise Rejected("report_attempt_created_outside_intent_lock")
    finally:
        guarded_contender.close()
        consumer_guard.release()
    report_consume(bare_ready.directory, bare_ready_run)
    os.mkdir(bare_ready.directory / "attempts" / ("run-" + "9" * 32))
    expect_rejected(
        "report_attempt_incomplete",
        lambda: report_consume(bare_ready.directory, bare_ready_run),
    )
    forged_attempt = bare_ready.directory / "attempts" / ("run-" + "9" * 32)
    IO["durable_new_file"](forged_attempt / "abandoned.json", b"{}\n")
    expect_rejected(
        "report_attempt_contract_mismatch",
        lambda: report_consume(bare_ready.directory, bare_ready_run),
    )
    (forged_attempt / "abandoned.json").unlink()
    IO["fsync_parent"](forged_attempt / "abandoned.json")
    reconcile_report_case(bare_ready.directory, "bare-attempt")

    # A syntactically correct Done marker is not a terminal attempt on its own.
    # Only the single crash state with a durable ModePointer journal is repairable; a forged/early Done paired with any earlier state must keep the old canonical Ready unusable.
    forged_ready_run = "6" * 32
    forged_ready = report_case(report_root, "forged-done", forged_ready_run)
    forged_ready.begin()
    forged_ready.publish(
        valid_rejected_report("self-test", forged_ready_run), validate_report
    )
    forged_ready.close()
    forged_done_run = "7" * 32
    forged_done_attempt = (
        forged_ready.directory / "attempts" / ("run-" + forged_done_run)
    )
    os.mkdir(forged_done_attempt)
    forged_done_report = valid_rejected_report("self-test", forged_done_run)
    forged_done_sha256 = digest(forged_done_report)
    IO["durable_new_file"](
        forged_done_attempt
        / "reports"
        / f"{forged_done_sha256}.json",
        forged_done_report,
    )
    IO["durable_new_file"](
        forged_done_attempt / "pending.json",
        IO["json_bytes"](
            {
                "schema": 4,
                "marker_kind": "Pending",
                "mode": "self-test",
                "run_id": forged_done_run,
            }
        ),
    )
    IO["durable_new_file"](
        forged_done_attempt / "done.json",
        IO["json_bytes"](
            {
                "schema": 4,
                "marker_kind": "Done",
                "mode": "self-test",
                "run_id": forged_done_run,
                "report_sha256": forged_done_sha256,
            }
        ),
    )
    IO["durable_new_file"](
        forged_done_attempt / "journal.json",
        IO["json_bytes"](
            {
                "schema": 4,
                "journal_kind": "rfc9114_v4_report_attempt",
                "mode": "self-test",
                "run_id": forged_done_run,
                "state": "Pending",
                "report_sha256": None,
            }
        ),
    )
    expect_rejected(
        "report_attempt_contract_mismatch",
        lambda: report_consume(forged_ready.directory, forged_ready_run),
    )

    missing_report_ready_run = "4" * 32
    missing_report_ready = report_case(
        report_root, "forged-done-missing-report", missing_report_ready_run
    )
    missing_report_ready.begin()
    missing_report_ready.publish(
        valid_rejected_report("self-test", missing_report_ready_run),
        validate_report,
    )
    missing_report_ready.close()
    missing_report_run = "5" * 32
    missing_report_attempt = (
        missing_report_ready.directory
        / "attempts"
        / ("run-" + missing_report_run)
    )
    os.mkdir(missing_report_attempt)
    missing_report_sha256 = digest(
        valid_rejected_report("self-test", missing_report_run)
    )
    IO["durable_new_file"](
        missing_report_attempt / "pending.json",
        IO["json_bytes"](
            {
                "schema": 4,
                "marker_kind": "Pending",
                "mode": "self-test",
                "run_id": missing_report_run,
            }
        ),
    )
    IO["durable_new_file"](
        missing_report_attempt / "done.json",
        IO["json_bytes"](
            {
                "schema": 4,
                "marker_kind": "Done",
                "mode": "self-test",
                "run_id": missing_report_run,
                "report_sha256": missing_report_sha256,
            }
        ),
    )
    IO["durable_new_file"](
        missing_report_attempt / "journal.json",
        IO["json_bytes"](
            {
                "schema": 4,
                "journal_kind": "rfc9114_v4_report_attempt",
                "mode": "self-test",
                "run_id": missing_report_run,
                "state": "ReadyPrepared",
                "report_sha256": missing_report_sha256,
            }
        ),
    )
    expect_rejected(
        "report_attempt_contract_mismatch",
        lambda: report_consume(
            missing_report_ready.directory, missing_report_ready_run
        ),
    )

    old_run = "a" * 32
    stale = report_case(report_root, "stale-ready", old_run)
    stale.begin()
    stale.publish(valid_rejected_report("self-test", old_run), validate_report)
    stale.close()
    pending_run = "b" * 32

    def after_lock_crash(boundary: str, _path: Path) -> None:
        if boundary == "report_after_lock":
            raise SimulatedCrash()

    pending = IO["ReportStore"](
        stale.directory,
        "self-test",
        pending_run,
        validate_report,
        hook=after_lock_crash,
    )
    try:
        pending.begin()
    except SimulatedCrash:
        pending.abandon_for_test()
    else:
        raise Rejected("stale_ready_control_did_not_crash")
    expect_rejected("report_attempt_incomplete", lambda: report_consume(stale.directory, old_run))
    reconcile_report_case(stale.directory, "stale-ready")
    add("report_stale_ready_pending_rejected")

    for boundary in (
        "report_after_attempt_directory",
        "report_pending_before_journal",
        "report_after_pending",
        "report_after_lock",
    ):
        report_crash_control(report_root, boundary, ready_expected=False)
    add("report_crash_after_lock_reconciled")
    for boundary in (
        "report_before_running",
        "running_pointer_after_stage",
        "running_pointer_before_replace",
    ):
        report_crash_control(report_root, boundary, ready_expected=False)
    add("report_crash_before_running_reconciled")
    for boundary in (
        "running_pointer_after_replace",
        "report_running_pointer_before_journal",
        "report_after_running",
    ):
        report_crash_control(report_root, boundary, ready_expected=False)
    add("report_crash_after_running_rejected")
    report_crash_control(report_root, "report_before_immutable", ready_expected=False)
    add("report_crash_before_immutable_rejected")
    for boundary in (
        "report_immutable_before_journal",
        "report_after_immutable",
        "mode_pointer_after_stage",
        "mode_pointer_before_replace",
        "mode_pointer_after_replace",
        "report_mode_pointer_before_journal",
    ):
        report_crash_control(report_root, boundary, ready_expected=False)
    add("report_crash_after_immutable_rejected")
    for boundary in (
        "report_before_ready",
        "report_done_before_journal",
        "report_before_canonical_final",
        "canonical_pointer_after_stage",
        "canonical_pointer_before_replace",
    ):
        report_crash_control(report_root, boundary, ready_expected=False)

    # Every injectable boundary before the final atomic replace must be followed by the identity callback.
    # A drift leaves canonical Running;
    # the completed immutable/per-mode pieces can never be consumed as a pair.
    publication_drift_boundaries = (
        "report_before_immutable",
        "report_immutable_before_journal",
        "report_after_immutable",
        "mode_pointer_after_stage",
        "mode_pointer_before_replace",
        "mode_pointer_after_replace",
        "report_mode_pointer_before_journal",
        "report_before_ready",
        "report_done_before_journal",
        "report_before_canonical_final",
        "canonical_pointer_after_stage",
        "canonical_pointer_before_replace",
    )
    for boundary in publication_drift_boundaries:
        drift_run = digest(("publication-drift:" + boundary).encode("ascii"))[:32]
        identity_before = b"anchored-identity-before\n"
        identity_after = b"anchored-identity-after\n"
        drift_store = report_case(
            report_root, "publication-drift-" + boundary, drift_run
        )
        identity_path = drift_store.directory / "identity.bin"
        IO["durable_new_file"](identity_path, identity_before)

        def inject_drift(
            observed: str,
            _path: Path,
            *,
            selected: str = boundary,
            selected_identity: Path = identity_path,
        ) -> None:
            if observed == selected:
                external_replace(selected_identity, identity_after)

        def validate_publication_identity(
            *, selected_identity: Path = identity_path
        ) -> None:
            if IO["strict_read_path"](selected_identity) != identity_before:
                raise Rejected("publication_identity_drift")

        drift_store.hook = inject_drift
        drift_store.begin()
        expect_rejected(
            "publication_identity_drift",
            lambda store=drift_store: store.publish(
                valid_rejected_report("self-test", drift_run),
                validate_report,
                pre_final=validate_publication_identity,
            ),
        )
        if os.path.lexists(drift_store.done):
            failure_sha256 = drift_store.record_publication_failure(
                "publication_identity_drift"
            )
            if (
                digest(IO["strict_read_path"](drift_store.publication_failure))
                != failure_sha256
            ):
                raise Rejected("publication_failure_marker_identity_mismatch")
        drift_store.close()
        drift_pointer = IO["json_object"](
            IO["strict_read_path"](drift_store.directory / "report.json"),
            "drift_pointer",
        )
        if drift_pointer.get("state") != "Running" or drift_pointer.get("run_id") != drift_run:
            raise Rejected("publication_drift_exposed_final")
        # Even a byte-for-byte forged canonical/per-mode pair must not revive an attempt that carries a durable publication-failure marker.
        failed_final_pointer = IO["strict_read_path"](
            drift_store.directory / "report-self-test.json"
        )
        IO["atomic_write"](
            drift_store.directory / "report.json",
            failed_final_pointer,
            prefix="failed_publication_pair_mutant",
        )
        expect_rejected(
            "report_attempt_contract_mismatch",
            lambda store=drift_store: report_consume(store.directory, drift_run),
        )
        IO["atomic_write"](
            drift_store.directory / "report.json",
            IO["pointer_bytes"]("self-test", drift_run, "Running", None),
            prefix="failed_publication_running_restore",
        )
        reconcile_report_case(drift_store.directory, "publication-drift-" + boundary)
    add("report_crash_before_ready_rejected")
    ready_run = digest(b"report-crash-after-ready")[:32]
    def crash_after_ready(observed: str, _path: Path) -> None:
        if observed == "canonical_pointer_after_commit":
            raise SimulatedCrash()

    ready_store = report_case(
        report_root, "crash-after-ready", ready_run, hook=crash_after_ready
    )
    ready_store.begin()
    try:
        ready_store.publish(
            valid_rejected_report("self-test", ready_run), validate_report
        )
    except SimulatedCrash:
        pass
    else:
        raise Rejected("report_after_ready_control_did_not_crash")
    # The only action after the final replace is this injected abrupt stop.
    # No post-Ready validation can turn the durable exact pair into Rejected.
    ready_store.abandon_for_test()
    report_consume(ready_store.directory, ready_run)
    add("report_crash_after_ready_accepted_exact_run")

    reject_run = "c" * 32
    reject_store = report_case(report_root, "failed-rejection", reject_run)
    reject_store.begin()
    (reject_store.directory / "report-self-test.json").mkdir()
    expect_rejected(
        "generated_write_failed",
        lambda: reject_store.publish(valid_rejected_report("self-test", reject_run), validate_report),
    )
    running = IO["json_object"](
        IO["generated_read"](reject_store.directory / "report.json"), "running_pointer"
    )
    reject_store.close()
    if running.get("state") != "Running" or running.get("run_id") != reject_run:
        raise Rejected("failed_rejection_did_not_leave_running")
    add("report_rejection_failure_keeps_running")

    mixed_run = "d" * 32
    mixed_store = report_case(report_root, "mixed-pointer", mixed_run)
    mixed_store.begin()
    mixed_store.publish(valid_rejected_report("self-test", mixed_run), validate_report)
    mixed_store.close()
    IO["atomic_write"](
        mixed_store.directory / "report-self-test.json",
        IO["pointer_bytes"]("self-test", "e" * 32, "Final", "0" * 64),
        prefix="mixed_fixture",
    )
    expect_rejected("report_pointer_pair_mismatch", lambda: report_consume(mixed_store.directory, mixed_run))
    add("report_mixed_pointer_rejected")

    stale_run = "f" * 32
    stale_store = report_case(report_root, "stale-run", stale_run)
    stale_store.begin()
    stale_store.publish(valid_rejected_report("self-test", stale_run), validate_report)
    stale_store.close()
    expect_rejected("report_run_id_mismatch", lambda: report_consume(stale_store.directory, "0" * 32))
    add("report_stale_run_rejected")

    strict_run = "1" * 32
    strict_report = valid_rejected_report("self-test", strict_run)
    extra = json.loads(strict_report)
    extra["secret"] = "sensitive"
    expect_rejected(
        "report_schema_mismatch",
        lambda: validate_report((json.dumps(extra) + "\n").encode("utf-8"), "self-test", strict_run),
    )
    if (
        safe_failure(ValueError("secrettoken")) != "typed_rejection"
        or safe_failure(Rejected("input_missing")) != "input_missing"
    ):
        raise Rejected("failure_category_sanitization_regressed")
    add("report_strict_schema_secret_extra_rejected")

    incomplete = json.loads(strict_report)
    del incomplete["identity"]
    expect_rejected(
        "report_schema_mismatch",
        lambda: validate_report((json.dumps(incomplete) + "\n").encode("utf-8"), "self-test", strict_run),
    )
    partial_counts = json.loads(strict_report)
    partial_counts["before_counts"] = {
        "Implemented": 8,
        "NotApplicable": None,
        "Open": 207,
    }
    expect_rejected(
        "report_completeness_mismatch",
        lambda: validate_report(
            (json.dumps(partial_counts) + "\n").encode("utf-8"),
            "self-test",
            strict_run,
        ),
    )
    unknown_result = json.loads(strict_report)
    unknown_result["result_requirements_sha256"] = "f" * 64
    expect_rejected(
        "report_completeness_mismatch",
        lambda: validate_report(
            (json.dumps(unknown_result) + "\n").encode("utf-8"),
            "self-test",
            strict_run,
        ),
    )
    add("rejected_report_incomplete_rejected")

    add("exact_inventory_manifest_accepted")
    expected = expected_controls("pre_review")[14:]
    if controls != expected:
        raise Rejected("infrastructure_control_inventory_mismatch")
    artifacts = safe_fixture_artifact_entries(safe_root)
    summary = {
        "schema": 4,
        "manifest_kind": "rfc9114_v4_safe_fixture_manifest",
        "run_id": run_id,
        "application_controls": 45,
        "infrastructure_controls": len(controls),
        "artifact_count": len(artifacts),
        "artifacts": artifacts,
    }
    IO["atomic_write"](
        safe_root / "fixture-summary.json",
        IO["json_bytes"](summary),
        prefix="safe_fixture_manifest",
    )
    checked_safe_fixture_summary(run_id)
    return controls


def missing_infrastructure_binding(_output: bytes) -> list[dict[str, str]]:
    raise Rejected("safe_fixture_run_id_missing")


DOMAIN["infrastructure_self_test"] = missing_infrastructure_binding


def recover_target_transactions() -> list[dict[str, str]]:
    lock = IO["ProcessFileLock"](TRANSACTIONS / "target.lock")
    lock.acquire()
    try:
        return IO["TargetTransaction"].reconcile_all(
            ROOT / REQUIREMENTS_PATH, TRANSACTIONS, lock
        )
    finally:
        lock.release()


def source_state(requirements: bytes) -> str:
    observed = digest(requirements)
    if observed == EXPECTED_BEFORE:
        return "pre_review"
    if observed == EXPECTED_AFTER:
        return "reviewed"
    raise Rejected("requirements_identity_mismatch")


def prepare(mode: str, run_id: str) -> dict[str, Any]:
    if mode not in {"red", "self-test", "apply"}:
        raise Rejected("invalid_mode")
    ensure_evidence_directory()
    reconciled: list[dict[str, str]] = []
    if mode == "apply":
        reconciled = recover_target_transactions()
    requirements = strict_read(REQUIREMENTS_PATH)
    candidate = strict_read(CANDIDATE_PATH)
    review = strict_read(REVIEW_PATH)
    source_manifest = strict_read(SOURCE_MANIFEST_PATH)
    invalidation_chain = strict_read(INVALIDATION_PATH)
    controls_snapshot = strict_read(CONTROL_PATH)
    if controls_snapshot != SNAPSHOTS[CONTROL_PATH]:
        raise Rejected("control_manifest_disk_drift")
    checked_invalidation_chain(invalidation_chain)
    before_state = source_state(requirements)
    exact_pre = before_state == "pre_review"
    if exact_pre:
        DOMAIN["checked_inputs"](requirements, candidate, review)
        output = DOMAIN["build_output"](requirements, candidate, review)
    else:
        DOMAIN["validate_post_state"](requirements, candidate, review)
        output = requirements
    if digest(output) != EXPECTED_AFTER:
        raise Rejected("rendered_identity_mismatch")
    before_counts = DOMAIN["disposition_counts"](
        DOMAIN["decode_object"](requirements, "requirements")
    )
    DOMAIN["infrastructure_self_test"] = lambda completed_output: infrastructure_self_test(
        completed_output, run_id
    )
    controls_completed, controls = DOMAIN["semantic_self_test"](
        requirements,
        candidate,
        review,
        source_manifest,
        exact_pre_state=exact_pre,
    )
    if controls_completed != 45 or controls != expected_controls(before_state):
        raise Rejected("control_inventory_entry_mismatch")
    DOMAIN["checked_source_manifest"](output, candidate, review, source_manifest)

    applied_now = False
    transaction_object: Any = None
    transaction_report = no_transaction(reconciled)
    after_state = before_state
    expected_current = requirements
    if mode == "apply" and exact_pre:
        transaction_object = IO["TargetTransaction"](
            ROOT / REQUIREMENTS_PATH,
            requirements,
            output,
            TRANSACTIONS,
            run_id,
        )
        try:
            recovered_during_begin = transaction_object.begin()
            reconciled.extend(recovered_during_begin)
            reconciled.sort(key=lambda item: item["run_id"])
            post_validate_members(output)
            DOMAIN["validate_post_state"](strict_read(REQUIREMENTS_PATH), candidate, review)
            transaction_object.commit()
        except Exception as error:
            transaction_object.reject(safe_failure(error))
            raise
        journal_sha = transaction_object.journal_sha256
        if not isinstance(journal_sha, str) or not re.fullmatch(
            r"[0-9a-f]{64}", journal_sha
        ):
            raise Rejected("transaction_journal_identity_missing")
        transaction_report = {
            "required": True,
            "run_id": run_id,
            "journal_sha256": journal_sha,
            "reconciled": reconciled,
        }
        applied_now = True
        after_state = "reviewed"
        expected_current = output
    elif mode == "apply":
        reconciled.sort(key=lambda item: item["run_id"])
        transaction_report = no_transaction(reconciled)

    after_counts = REVIEWED_COUNTS if after_state == "reviewed" else before_counts
    if mode == "red":
        status = "ObservedRed" if exact_pre else "UnexpectedGreen"
        failure = "expected_red_observed" if exact_pre else "red_control_unexpected_green"
    elif mode == "self-test" and exact_pre:
        status = "StaticReady"
        failure = "application_pending"
    else:
        status = "Ready" if audit_approved() else "AuditPending"
        failure = None if status == "Ready" else "independent_audit_pending"

    # The apply path already performs this check while the target transaction owns the canonical file and before commit.
    # All non-mutating paths still need the same complete validation here.
    # Report publication performs one more check at the final canonical-pointer boundary.
    if not applied_now:
        post_validate_members(expected_current)
    return {
        "status": status,
        "failure": failure,
        "controls": controls,
        "before_state": before_state,
        "after_state": after_state,
        "applied_now": applied_now,
        "before_counts": before_counts,
        "after_counts": after_counts,
        "result_hash": digest(expected_current),
        "expected_current": expected_current,
        "transaction": transaction_report,
        "transaction_object": transaction_object,
    }


def rejected_report(
    mode: str,
    run_id: str,
    category: str,
    *,
    phase: str,
    controls: list[dict[str, str]],
    source_before: str,
    source_after: str,
    before_counts: dict[str, int] | None,
    after_counts: dict[str, int] | None,
    result_hash: str,
    transaction: dict[str, Any],
    applied_now: bool = False,
) -> bytes:
    return make_report(
        mode=mode,
        run_id=run_id,
        status="Rejected",
        failure=IO["safe_category"](category),
        phase=IO["safe_category"](phase),
        controls=controls,
        source_before=source_before,
        source_after=source_after,
        applied_now=applied_now,
        before_counts=before_counts,
        after_counts=after_counts,
        result_hash=result_hash,
        transaction=transaction,
    )


def run(mode: str, run_id: str) -> int:
    if mode not in {"red", "self-test", "apply"} or not re.fullmatch(r"[0-9a-f]{32}", run_id):
        raise RuntimeError("invocation_invalid")
    ensure_evidence_directory()
    publisher = IO["ReportStore"](
        EVIDENCE, mode, run_id, validate_report
    )
    result: dict[str, Any] | None = None
    phase = "attempt_created"
    try:
        publisher.begin()
        phase = "validating"
        result = prepare(mode, run_id)
        phase = "publishing"
        report = make_report(
            mode=mode,
            run_id=run_id,
            status=result["status"],
            failure=result["failure"],
            phase="complete",
            controls=result["controls"],
            source_before=result["before_state"],
            source_after=result["after_state"],
            applied_now=result["applied_now"],
            before_counts=result["before_counts"],
            after_counts=result["after_counts"],
            result_hash=result["result_hash"],
            transaction=result["transaction"],
        )
        publisher.publish(
            report,
            validate_report,
            pre_final=lambda: post_validate_members(result["expected_current"]),
        )
        return 0 if result["status"] in {"ObservedRed", "StaticReady", "AuditPending", "Ready"} else 1
    except Exception as error:
        category = safe_failure(error)
        transaction = result.get("transaction_object") if result else None
        if transaction is not None and transaction.state not in transaction.TERMINAL:
            try:
                transaction.reject(category)
            except Exception:
                category = "transaction_recovery_failed"
        if publisher.locked:
            source_before = result["before_state"] if result else "unknown"
            source_after = result["after_state"] if result else "unknown"
            controls = result["controls"] if result else []
            result_hash = result["result_hash"] if result else EXPECTED_BEFORE
            transaction_report = result["transaction"] if result else no_transaction()
            # Once Done exists it already binds a validated immutable report and the durable per-mode pointer.
            # Reusing the attempt for a Rejected report would regress its journal and could mismatch the old Done hash.
            # Keep canonical Running and let the next lock owner reconcile the sole ModePointer -> ReadyPrepared crash state instead.
            if os.path.lexists(publisher.done):
                try:
                    publisher.record_publication_failure(category)
                except Exception:
                    category = "publication_failure_record_failed"
            else:
                try:
                    if result is None:
                        expected_for_rejection = strict_read(REQUIREMENTS_PATH)
                        observed_state = source_state(expected_for_rejection)
                        observed_counts = DOMAIN["disposition_counts"](
                            DOMAIN["decode_object"](
                                expected_for_rejection, "requirements"
                            )
                        )
                        source_before = "unknown"
                        source_after = observed_state
                        result_hash = digest(expected_for_rejection)
                        before_counts = None
                        after_counts = observed_counts
                    else:
                        expected_for_rejection = result["expected_current"]
                        before_counts = result["before_counts"]
                        after_counts = result["after_counts"]
                    report = rejected_report(
                        mode,
                        run_id,
                        category,
                        phase=phase,
                        controls=controls,
                        source_before=source_before,
                        source_after=source_after,
                        before_counts=before_counts,
                        after_counts=after_counts,
                        result_hash=result_hash,
                        transaction=transaction_report,
                        applied_now=result["applied_now"] if result else False,
                    )
                    publisher.publish(
                        report,
                        validate_report,
                        pre_final=lambda: post_validate_members(
                            expected_for_rejection
                        ),
                    )
                except Exception:
                    category = "rejection_publication_failed"
        return 1
    finally:
        try:
            publisher.close()
        except Exception:
            # The canonical Final replace is authoritative.
            # Both lock descriptors are closed in ProcessFileLock.release() even when the explicit unlock API reports an error, and process exit is a second OS-enforced release boundary.
            # Do not reinterpret an already committed immutable pair as Rejected.
            if not publisher.committed:
                raise

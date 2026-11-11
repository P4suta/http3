#!/usr/bin/env python3
# Copyright (c) 2026 the http contributors
# SPDX-FileCopyrightText: 2026 the http contributors
# SPDX-License-Identifier: MIT OR Apache-2.0
# The standalone unittest runner needs no pytest installation.
# Keep assertions active under Python optimization.
# ruff: noqa: PT009, PT027
"""Adversarial file and schema contracts for the QPACK Python oracle."""

from __future__ import annotations

import importlib.util
import io
import json
import os
import subprocess
import sys
import tempfile
import threading
import time
import types
import unittest
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from typing import Never

sys.dont_write_bytecode = True


ROOT = Path(__file__).resolve().parents[4]
ORACLE_PATH = ROOT / "packages/http3/test/interop/qpack_oracle.py"
sys.path.insert(0, str(ROOT / "scripts"))
from process_supervisor import owned_run  # noqa: E402

__all__ = ()

_PRIVATE_CANARY = "private-header-value"
_FORCED_FAILURE = "forced"
_MISSING_BLOCKED_STREAM = "header must precede encoder control"
_SECOND_METADATA_INSPECTION = 2
_IMPORT_FAILURE = "oracle import failed"


class _Encoder:
    __module__ = "qpack_contract_fake_binding"


class _Decoder:
    __module__ = "qpack_contract_fake_binding"


class _StreamBlockedError(Exception):
    pass


def load_oracle(fake_root: Path) -> types.ModuleType:
    package_file = fake_root / "pylsqpack.py"
    binding_file = fake_root / "pylsqpack-binding.pyd"
    package_file.write_bytes(b"qpack-contract-package-v1\n")
    binding_file.write_bytes(b"qpack-contract-binding-v1\n")
    package = types.ModuleType("pylsqpack")
    package.__file__ = str(package_file)
    package.__version__ = "1.0.0"
    package.Encoder = _Encoder
    package.Decoder = _Decoder
    package.StreamBlocked = _StreamBlockedError
    binding = types.ModuleType("qpack_contract_fake_binding")
    binding.__file__ = str(binding_file)
    sys.modules["pylsqpack"] = package
    sys.modules["qpack_contract_fake_binding"] = binding
    spec = importlib.util.spec_from_file_location(
        "qpack_oracle_under_test",
        ORACLE_PATH,
    )
    if spec is None or spec.loader is None:
        raise RuntimeError(_IMPORT_FAILURE)
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


# Private hooks inject filesystem races that public calls cannot schedule.
class QpackOracleContractTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls._module_root = tempfile.TemporaryDirectory(prefix="qpack-fake-module-")
        cls.oracle = load_oracle(Path(cls._module_root.name))

    @classmethod
    def tearDownClass(cls) -> None:
        cls._module_root.cleanup()

    def setUp(self) -> None:
        self._temporary = tempfile.TemporaryDirectory(prefix="qpack-contract-")
        self.directory = Path(self._temporary.name)

    def tearDown(self) -> None:
        self._temporary.cleanup()

    def minimal_transcript(self) -> dict[str, object]:
        identity = self.oracle.current_oracle_identity()
        return {
            "schema": self.oracle.SCHEMA,
            "direction": "http3-to-pylsqpack",
            "oracle": identity,
            "oracle_run_id": "01" * self.oracle.RUN_ID_HEX_BYTES,
            "configuration": {
                "maximum_table_capacity": self.oracle.CAPACITY,
                "maximum_blocked_streams": self.oracle.BLOCKED_STREAMS,
            },
            "steps": [
                {
                    "id": "one",
                    "stream_id": 0,
                    "delivery": "encoder_first",
                    "encoder_stream": "",
                    "field_section": "00",
                    "headers": [{"name": "61", "value": "62"}],
                },
            ],
        }

    def test_exact_exception_types_do_not_run_hostile_accessors(self) -> None:
        class HostileSystemExit(SystemExit):
            def __getattribute__(self, _name: str) -> Never:
                raise RuntimeError(_PRIVATE_CANARY)

        class HostileKeyboardInterrupt(KeyboardInterrupt):
            def __getattribute__(self, _name: str) -> Never:
                raise RuntimeError(_PRIVATE_CANARY)

        self.assertEqual(self.oracle.failure_exit_status(HostileSystemExit()), 1)
        self.assertEqual(self.oracle.failure_exit_status(HostileKeyboardInterrupt()), 1)
        self.assertEqual(self.oracle.failure_exit_status(SystemExit(17)), 17)
        self.assertEqual(self.oracle.failure_exit_status(KeyboardInterrupt()), 130)

    def test_failure_output_is_fixed_and_broken_sink_is_contained(self) -> None:
        captured = io.StringIO()
        previous = sys.stderr
        try:
            sys.stderr = captured
            self.assertEqual(self.oracle.run_cli(["private-path-and-header"]), 1)
        finally:
            sys.stderr = previous
        self.assertEqual(captured.getvalue(), "qpack oracle failed\n")

        class BrokenSink:
            def write(self, _value: str) -> int:
                raise OSError(_PRIVATE_CANARY)

            def flush(self) -> None:
                raise OSError(_PRIVATE_CANARY)

        try:
            sys.stderr = BrokenSink()
            self.assertEqual(self.oracle.run_cli(["private-path-and-header"]), 1)
        finally:
            sys.stderr = previous

        release = threading.Event()

        class StoppedSink:
            def write(self, _value: str) -> int:
                release.wait(10)
                return 0

            def flush(self) -> None:
                release.wait(10)

        started = time.monotonic()
        try:
            sys.stderr = StoppedSink()
            self.assertEqual(self.oracle.run_cli(["private-path-and-header"]), 1)
        finally:
            sys.stderr = previous
            release.set()
        self.assertLess(time.monotonic() - started, 0.75)

    def test_json_depth_nodes_duplicates_and_container_limits(self) -> None:
        duplicate = self.directory / "duplicate.json"
        duplicate.write_bytes(b'{"token":"secret","token":"second"}')
        with self.assertRaisesRegex(RuntimeError, "duplicate JSON key"):
            self.oracle.load_json(duplicate)
        nested = None
        for _ in range(self.oracle.MAX_JSON_DEPTH + 1):
            nested = [nested]
        with self.assertRaisesRegex(RuntimeError, "JSON depth limit exceeded"):
            self.oracle.validate_json_shape(nested)
        nodes = [[None] * 1000 for _ in range(101)]
        with self.assertRaisesRegex(RuntimeError, "JSON node limit exceeded"):
            self.oracle.validate_json_shape(nodes)
        with self.assertRaisesRegex(RuntimeError, "JSON array limit exceeded"):
            self.oracle.validate_json_shape(
                [None] * (self.oracle.MAX_CONTAINER_ITEMS + 1),
            )
        deep_text = self.directory / "deep.json"
        deep_text.write_bytes(
            b"[" * (self.oracle.MAX_JSON_DEPTH + 2)
            + b"0"
            + b"]" * (self.oracle.MAX_JSON_DEPTH + 2),
        )
        with self.assertRaisesRegex(RuntimeError, "JSON depth limit exceeded"):
            self.oracle.load_json(deep_text)
        node_text = self.directory / "nodes.json"
        node_text.write_bytes(
            b"[" + b",".join([b"0"] * (self.oracle.MAX_JSON_NODES + 1)) + b"]",
        )
        with self.assertRaisesRegex(RuntimeError, "JSON node limit exceeded"):
            self.oracle.load_json(node_text)
        integer_text = self.directory / "integer.json"
        integer_text.write_bytes(
            b"9" * (self.oracle.MAX_JSON_INTEGER_TOKEN_BYTES + 1),
        )
        with self.assertRaisesRegex(RuntimeError, "JSON integer token limit exceeded"):
            self.oracle.load_json(integer_text)

    def test_schema_counts_hex_and_stale_identity_are_rejected(self) -> None:
        document = self.minimal_transcript()
        self.assertEqual(
            self.oracle.validate_transcript(document, "http3-to-pylsqpack")["cases"],
            1,
        )
        extra = dict(document)
        extra["unaccounted"] = True
        with self.assertRaisesRegex(RuntimeError, "invalid transcript fields"):
            self.oracle.validate_transcript(extra, "http3-to-pylsqpack")
        bad_hex = json.loads(json.dumps(document))
        bad_hex["steps"][0]["field_section"] = "AA"
        with self.assertRaisesRegex(RuntimeError, "invalid field section"):
            self.oracle.validate_transcript(bad_hex, "http3-to-pylsqpack")
        too_many = json.loads(json.dumps(document))
        too_many["steps"][0]["headers"] *= self.oracle.MAX_HEADERS_PER_STEP + 1
        with self.assertRaisesRegex(RuntimeError, "invalid headers"):
            self.oracle.validate_transcript(too_many, "http3-to-pylsqpack")
        stale = json.loads(json.dumps(document["oracle"]))
        stale["driver_sha256"] = "00" * 32
        with self.assertRaisesRegex(RuntimeError, "stale oracle identity"):
            self.oracle.validate_oracle_identity(stale, require_current=True)
        invalid_runtime = json.loads(json.dumps(document["oracle"]))
        invalid_runtime["python_runtime"]["version"] = "unverified"
        with self.assertRaisesRegex(RuntimeError, "invalid python version"):
            self.oracle.validate_oracle_identity(invalid_runtime, require_current=False)
        four_part_runtime = json.loads(json.dumps(document["oracle"]))
        four_part_runtime["python_runtime"]["version"] = "3.12.0.1"
        with self.assertRaisesRegex(RuntimeError, "invalid python version"):
            self.oracle.validate_oracle_identity(
                four_part_runtime,
                require_current=False,
            )
        unicode_runtime = json.loads(json.dumps(document["oracle"]))
        unicode_runtime["python_runtime"]["version"] = "3.12.\u0660"
        with self.assertRaisesRegex(RuntimeError, "invalid python version"):
            self.oracle.validate_oracle_identity(unicode_runtime, require_current=False)

    def test_hardlinks_special_files_and_active_locks_are_rejected(self) -> None:
        source = self.directory / "source.json"
        source.write_bytes(b"{}\n")
        linked = self.directory / "linked.json"
        os.link(source, linked)
        with self.assertRaisesRegex(RuntimeError, "hard-linked file rejected"):
            self.oracle.read_verified(source)
        linked.unlink()
        with self.assertRaisesRegex(RuntimeError, "unsafe file"):
            self.oracle.read_verified(self.directory)
        lock = source.with_name(source.name + self.oracle.LOCK_SUFFIX)
        lock.mkdir()
        with self.assertRaisesRegex(RuntimeError, "active or abandoned publication"):
            self.oracle.read_verified(source)
        lock.rmdir()

    def test_leaf_symlink_or_directory_junction_is_rejected(self) -> None:
        target = self.directory / "target"
        target.mkdir()
        (target / "value.json").write_bytes(b"{}\n")
        linked = self.directory / "linked"
        if os.name == "nt":
            completed = owned_run(
                ["cmd.exe", "/d", "/c", "mklink", "/J", str(linked), str(target)],
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                timeout=10,
                max_output_bytes=0,
                check=False,
            )
            self.assertEqual(completed.returncode, 0, "junction fixture unavailable")
        else:
            linked.symlink_to(target, target_is_directory=True)
        try:
            with self.assertRaisesRegex(RuntimeError, "unsafe directory"):
                self.oracle.read_verified(linked / "value.json")
        finally:
            if os.name == "nt":
                linked.rmdir()
            else:
                linked.unlink()

    def test_path_replacement_during_read_is_detected(self) -> None:
        source = self.directory / "racing.json"
        replacement = self.directory / "replacement.json"
        source.write_bytes(b"a" * 70_000)
        replacement.write_bytes(b"b" * 70_000)
        original_metadata = self.oracle._plain_file_metadata  # noqa: SLF001
        calls = 0

        def racing_metadata(
            path: Path,
            *,
            missing: str = "input missing",
        ) -> os.stat_result:
            nonlocal calls
            calls += 1
            # Replace the path after the verified handle closes.
            # Windows permits replacement at the same boundary.
            if calls == _SECOND_METADATA_INSPECTION:
                replacement.replace(source)
            return original_metadata(path, missing=missing)

        self.oracle._plain_file_metadata = racing_metadata  # noqa: SLF001
        try:
            with self.assertRaisesRegex(RuntimeError, "input changed while reading"):
                self.oracle.read_verified(source)
        finally:
            self.oracle._plain_file_metadata = original_metadata  # noqa: SLF001

    def test_verified_digest_is_bound_to_the_exact_bytes(self) -> None:
        source = self.directory / "verified.json"
        source.write_bytes(b'{"schema":1}')
        _value, verified = self.oracle.load_json(source)
        source.write_bytes(b'{"schema":2}')
        self.assertNotEqual(verified.sha256, self.oracle.read_verified(source).sha256)

    def test_competing_publication_fails_without_partial_output(self) -> None:
        destination = self.directory / "report.json"
        competitor = b"competitor\n"
        original_link = self.oracle.os.link

        def racing_link(
            source: Path,
            target: Path,
            *,
            follow_symlinks: bool = True,
        ) -> None:
            Path(target).write_bytes(competitor)
            original_link(source, target, follow_symlinks=follow_symlinks)

        with self.oracle.publication_lock(destination) as locked:
            self.oracle._invalidate_output_locked(locked)  # noqa: SLF001
            self.oracle.os.link = racing_link
            try:
                with self.assertRaisesRegex(
                    RuntimeError,
                    "concurrent output publication",
                ):
                    self.oracle._write_json_locked(locked, {"schema": 1})  # noqa: SLF001
            finally:
                self.oracle.os.link = original_link
            self.assertEqual(destination.read_bytes(), competitor)
            destination.unlink()
        self.assertFalse(list(self.directory.glob("*.pending")))
        self.assertFalse(
            destination.with_name(destination.name + self.oracle.LOCK_SUFFIX).exists(),
        )

    def test_failed_replacement_invalidates_prior_ready_output(self) -> None:
        destination = self.directory / "report.json"
        self.oracle.write_json(destination, {"status": "Ready"})
        original_link = self.oracle.os.link

        def failed_link(_source: Path, _target: Path, **_kwargs: object) -> Never:
            raise OSError(_FORCED_FAILURE)

        self.oracle.os.link = failed_link
        try:
            with self.assertRaisesRegex(RuntimeError, "concurrent output publication"):
                self.oracle.write_json(destination, {"status": "Ready", "new": True})
        finally:
            self.oracle.os.link = original_link
        self.assertFalse(destination.exists())
        self.assertFalse(list(self.directory.glob("*.pending")))

    def test_unsafe_failed_publication_retains_lock_and_output_limit_is_atomic(
        self,
    ) -> None:
        unsafe_destination = self.directory / "unsafe-report.json"
        unsafe_destination.mkdir()
        unsafe_lock = unsafe_destination.with_name(
            unsafe_destination.name + self.oracle.LOCK_SUFFIX,
        )
        with (
            self.assertRaisesRegex(RuntimeError, "publication lock release failed"),
            self.oracle.publication_lock(unsafe_destination),
        ):
            raise RuntimeError(_PRIVATE_CANARY)
        self.assertTrue(unsafe_destination.is_dir())
        self.assertTrue(unsafe_lock.is_dir())
        self.assertEqual(
            [entry.name for entry in unsafe_lock.iterdir()],
            [self.oracle.OWNER_FILE],
        )
        (unsafe_lock / self.oracle.OWNER_FILE).unlink()
        unsafe_lock.rmdir()
        unsafe_destination.rmdir()

        hardlink_destination = self.directory / "hardlink-report.json"
        hardlink_alias = self.directory / "hardlink-report-alias.json"
        hardlink_destination.write_bytes(b'{"status":"Ready"}\n')
        os.link(hardlink_destination, hardlink_alias)
        hardlink_lock = hardlink_destination.with_name(
            hardlink_destination.name + self.oracle.LOCK_SUFFIX,
        )
        with self.assertRaisesRegex(RuntimeError, "publication lock release failed"):
            self.oracle.write_json(hardlink_destination, {"status": "Ready"})
        self.assertTrue(hardlink_destination.exists())
        self.assertTrue(hardlink_alias.exists())
        self.assertTrue(hardlink_lock.is_dir())
        (hardlink_lock / self.oracle.OWNER_FILE).unlink()
        hardlink_lock.rmdir()
        hardlink_alias.unlink()
        hardlink_destination.unlink()

        oversized_destination = self.directory / "oversized-report.json"
        oversized_value = {"value": "x" * self.oracle.MAX_OUTPUT_BYTES}
        with self.assertRaisesRegex(RuntimeError, "output byte limit exceeded"):
            self.oracle.write_json(oversized_destination, oversized_value)
        self.assertFalse(oversized_destination.exists())
        self.assertFalse(
            oversized_destination.with_name(
                oversized_destination.name + self.oracle.LOCK_SUFFIX,
            ).exists(),
        )
        self.assertFalse(list(self.directory.glob("*.pending")))

        deep_destination = self.directory / "deep-report.json"
        deep_value = None
        for _ in range(self.oracle.MAX_JSON_DEPTH + 1):
            deep_value = [deep_value]
        with self.assertRaisesRegex(RuntimeError, "JSON depth limit exceeded"):
            self.oracle.write_json(deep_destination, {"value": deep_value})
        self.assertFalse(deep_destination.exists())
        self.assertFalse(
            deep_destination.with_name(
                deep_destination.name + self.oracle.LOCK_SUFFIX,
            ).exists(),
        )

    def test_post_commit_replacement_is_removed_before_unlock(self) -> None:
        destination = self.directory / "report.json"
        competitor = b'{"status":"Ready","unbound":true}\n'
        original_link = self.oracle.os.link

        def replace_after_commit(
            source: Path,
            target: Path,
            *,
            follow_symlinks: bool = True,
        ) -> None:
            original_link(source, target, follow_symlinks=follow_symlinks)
            target.unlink()
            Path(target).write_bytes(competitor)

        self.oracle.os.link = replace_after_commit
        try:
            with self.assertRaisesRegex(RuntimeError, "published output changed"):
                self.oracle.write_json(destination, {"status": "Ready"})
        finally:
            self.oracle.os.link = original_link
        self.assertFalse(destination.exists())
        self.assertFalse(list(self.directory.glob("*.pending")))
        self.assertFalse(
            destination.with_name(destination.name + self.oracle.LOCK_SUFFIX).exists(),
        )

    def test_publication_stays_bound_through_unlock(self) -> None:
        destination = self.directory / "report.json"
        lock = destination.with_name(destination.name + self.oracle.LOCK_SUFFIX)
        competitor = b'{"status":"Ready","unbound":true}\n'

        with (
            self.assertRaisesRegex(RuntimeError, "published output changed"),
            self.oracle.publication_lock(destination) as locked,
        ):
            self.oracle._invalidate_output_locked(locked)  # noqa: SLF001
            self.oracle._write_json_locked(locked, {"status": "Ready"})  # noqa: SLF001
            destination.unlink()
            destination.write_bytes(competitor)
        self.assertFalse(destination.exists())
        self.assertFalse(lock.exists())
        self.assertFalse(list(self.directory.glob("*.pending")))

        original_rmdir = self.oracle.os.rmdir

        def replace_while_unlocking(
            path: str | Path,
            *,
            dir_fd: int | None = None,
        ) -> None:
            original_rmdir(path, dir_fd=dir_fd)
            if Path(path) == lock:
                destination.unlink()
                destination.write_bytes(competitor)

        self.oracle.os.rmdir = replace_while_unlocking
        try:
            with self.assertRaisesRegex(
                RuntimeError,
                "publication lock release failed",
            ):
                self.oracle.write_json(destination, {"status": "Ready"})
        finally:
            self.oracle.os.rmdir = original_rmdir
        self.assertFalse(destination.exists())
        self.assertTrue(lock.is_dir())
        self.assertEqual(list(lock.iterdir()), [])
        lock.rmdir()
        self.assertFalse(list(self.directory.glob("*.pending")))

    def test_report_is_removed_when_input_changes_after_publication(self) -> None:
        source = self.directory / "implementation.json"
        report = self.directory / "report.json"
        document = self.minimal_transcript()
        first = document["steps"][0]
        document["steps"] = [
            {**first, "id": "blocked-one", "stream_id": 0, "delivery": "header_first"},
            {**first, "id": "blocked-two", "stream_id": 4, "delivery": "header_first"},
        ]
        self.oracle.write_json(source, document)

        class VerificationDecoder:
            def __init__(self, _capacity: int, _blocked_streams: int) -> None:
                self.blocked_stream: int | None = None

            def feed_header(self, stream_id: int, _field_section: bytes) -> Never:
                self.blocked_stream = stream_id
                raise _StreamBlockedError

            def feed_encoder(self, _encoder_stream: bytes) -> list[int]:
                if self.blocked_stream is None:
                    raise RuntimeError(_MISSING_BLOCKED_STREAM)
                return [self.blocked_stream]

            def resume_header(
                self,
                _stream_id: int,
            ) -> tuple[bytes, list[tuple[bytes, bytes]]]:
                return b"", [(b"a", b"b")]

        original_decoder = self.oracle.pylsqpack.Decoder
        original_write = self.oracle._write_json_locked  # noqa: SLF001

        def mutate_after_report(path: Path, value: dict[str, object]) -> object:
            published = original_write(path, value)
            source.write_bytes(b"{}\n")
            return published

        self.oracle.pylsqpack.Decoder = VerificationDecoder
        self.oracle._write_json_locked = mutate_after_report  # noqa: SLF001
        try:
            with self.assertRaisesRegex(
                RuntimeError,
                "implementation changed during verification",
            ):
                self.oracle.verify(source, report)
        finally:
            self.oracle.pylsqpack.Decoder = original_decoder
            self.oracle._write_json_locked = original_write  # noqa: SLF001
        self.assertFalse(report.exists())
        self.assertFalse(
            report.with_name(report.name + self.oracle.LOCK_SUFFIX).exists(),
        )

    def test_abandoned_lock_makes_prior_ready_output_ineligible(self) -> None:
        destination = self.directory / "report.json"
        self.oracle.write_json(destination, {"status": "Ready"})
        lock = destination.with_name(destination.name + self.oracle.LOCK_SUFFIX)
        lock.mkdir()
        try:
            with (
                self.assertRaisesRegex(
                    RuntimeError,
                    "active or abandoned publication",
                ),
                self.oracle.publication_lock(destination),
            ):
                self.fail("abandoned lock was acquired")
            self.assertFalse(destination.exists())
        finally:
            lock.rmdir()


if __name__ == "__main__":
    unittest.main(verbosity=2)

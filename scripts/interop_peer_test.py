#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 the http contributors
# SPDX-License-Identifier: MIT OR Apache-2.0
import argparse
import base64
import contextlib
import gzip
import hashlib
import io
import json
import os
from pathlib import Path
import signal
import shutil
import subprocess
import sys
import tarfile
import tempfile
import time
import unittest
from unittest import mock

import interop_peer
from process_supervisor import owned_popen, owned_run


class PeerIdentityTest(unittest.TestCase):
    def test_identity_probe_entrypoint_loads_companions_in_isolated_mode(self) -> None:
        script = Path(interop_peer.__file__).resolve()
        with tempfile.TemporaryDirectory() as directory:
            result = owned_run(
                [sys.executable, "-I", "-B", str(script), "--help"],
                cwd=directory, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                timeout=10, max_output_bytes=65536,
            )
        self.assertEqual(result.returncode, 0)
        self.assertIn(b"--root", result.stdout)
        self.assertEqual(result.stderr, b"")

    def test_python_dependency_identity_is_bounded_and_rejects_duplicate_locks(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            first = root / "first.py"
            second = root / "second.py"
            first.write_bytes(b"first")
            second.write_bytes(b"second")
            lock = root / "requirements.lock"
            lock.write_text("example-package==1.2.3\n")

            class Distribution:
                version = "1.2.3"
                files = ["first.py", "second.py"]

                def locate_file(self, item):
                    return root / item

            with mock.patch.object(interop_peer.importlib.metadata, "distribution",
                                   return_value=Distribution()):
                identity = interop_peer.python_dependencies(lock)
                self.assertEqual(identity[0]["files"], 2)
                lock.write_text("example-package==1.2.3\nexample_package==1.2.3\n")
                with self.assertRaisesRegex(ValueError, "duplicate_python_dependency"):
                    interop_peer.python_dependencies(lock)
                lock.write_text("example-package==1.2.3\n")
                Distribution.files = ["first.py", "first.py"]
                with self.assertRaisesRegex(ValueError, "duplicate_python_package_file"):
                    interop_peer.python_dependencies(lock)
                Distribution.files = ["entry-" + str(index)
                                      for index in range(interop_peer.MAX_NODE_ENTRIES + 1)]
                with self.assertRaisesRegex(ValueError, "python_package_file_limit"):
                    interop_peer.python_dependencies(lock)

    def test_failure_status_is_finite_exact_and_preserves_cancellation(self):
        self.assertEqual(interop_peer.failure_exit_status(SystemExit(130)), 130)
        self.assertEqual(interop_peer.failure_exit_status(SystemExit(143)), 143)
        self.assertEqual(interop_peer.failure_exit_status(KeyboardInterrupt()), 130)
        for error in [SystemExit(0), SystemExit(256), SystemExit("private-canary"),
                      RuntimeError("private-canary")]:
            with self.subTest(error=type(error).__name__):
                self.assertEqual(interop_peer.failure_exit_status(error), 1)

        class HostileExit(SystemExit):
            def __getattribute__(self, _name):
                raise RuntimeError("private-canary")

        self.assertEqual(interop_peer.failure_exit_status(HostileExit(143)), 1)
        self.assertEqual(interop_peer.failure_result(SystemExit(143)),
                         {"kind": "cancelled", "exit_status": 143})
        self.assertEqual(interop_peer.failure_result(SystemExit(7)),
                         {"kind": "failed", "exit_status": 7})
        self.assertEqual(interop_peer.failure_result(HostileExit(143)),
                         {"kind": "failed", "exit_status": 1})
        self.assertEqual(interop_peer.command_exit_status(SystemExit(0)), 0)
        self.assertEqual(interop_peer.command_exit_status(SystemExit(143)), 143)
        self.assertEqual(interop_peer.command_exit_status(KeyboardInterrupt()), 130)
        self.assertEqual(interop_peer.command_exit_status(HostileExit(0)), 1)

    def test_shareable_failure_report_has_a_closed_bounded_schema(self):
        completion = {
            "outcome": "completed", "exit_status": 1,
            "exit_observed": True, "controlled_shutdown": False,
            "elapsed_milliseconds": 7, "stdout_bytes": 2,
            "stderr_bytes": 3,
        }
        report = interop_peer.peer_failure_report(
            "curl-h1-h2", "1" * 64, "A" * 64, "client", "request",
            "exit_validation", completion, SystemExit(7))
        self.assertEqual(report["result"], {"kind": "failed", "exit_status": 7})
        self.assertNotIn("private-canary", json.dumps(report))
        interop_peer.validate_peer_failure_report(report)

        cancelled = interop_peer.peer_failure_report(
            "curl-h1-h2", "1" * 64, "A" * 64, "client", "request",
            "identity_before", None, SystemExit(143))
        self.assertEqual(cancelled["result"],
                         {"kind": "cancelled", "exit_status": 143})
        interop_peer.validate_peer_failure_report(cancelled)

        mutants = []
        mutants.append(dict(report, private="private-canary"))
        mutants.append(dict(report, schema=True))
        mutants.append(dict(report, status="Ready"))
        mutants.append(dict(report, peer="../private-canary"))
        mutants.append(dict(report, run_id="g" * 64))
        mutants.append(dict(report, source_sha256="old"))
        mutants.append(dict(report, role=[]))
        mutants.append(dict(report, phase="private"))
        mutants.append(dict(report, result={"kind": [], "exit_status": 1}))
        mutants.append(dict(report, result={"kind": "failed", "exit_status": True}))
        mutants.append(dict(report, result={"kind": "failed", "exit_status": 143}))
        mutants.append(dict(report, result={"kind": "cancelled", "exit_status": 1}))
        mutants.append(dict(report, completion=None))
        mutants.append(dict(report, completion=dict(completion, private="private-canary")))
        mutants.append(dict(report, completion=dict(completion, outcome="unknown")))
        mutants.append(dict(report, completion=dict(completion, outcome=[])))
        mutants.append(dict(report, completion=dict(completion, exit_status=True)))
        mutants.append(dict(report, completion=dict(completion, exit_observed=False)))
        mutants.append(dict(report, completion=dict(completion, controlled_shutdown=0)))
        mutants.append(dict(report, completion=dict(completion, elapsed_milliseconds=125001)))
        mutants.append(dict(report, completion=dict(
            completion, stdout_bytes=interop_peer.MAX_OUTPUT,
            stderr_bytes=1)))
        for index, mutant in enumerate(mutants):
            with self.subTest(case=index):
                with self.assertRaises(ValueError):
                    interop_peer.validate_peer_failure_report(mutant)

        with self.assertRaises(ValueError):
            interop_peer.peer_failure_report(
                "curl-h1-h2", "1" * 64, "A" * 64, "client", "request",
                "execution", dict(completion, private="private-canary"),
                RuntimeError("private-canary"))

    def test_signal_handler_uses_the_canonical_shell_status(self):
        with self.assertRaises(SystemExit) as stopped:
            interop_peer.interrupted(signal.SIGTERM, None)
        self.assertEqual(stopped.exception.code, 143)

    def test_cli_redacts_base_exceptions_and_survives_a_broken_stderr(self):
        stderr = io.StringIO()
        with mock.patch.object(interop_peer, "install_signal_handlers"), \
                mock.patch.object(interop_peer, "main", side_effect=SystemExit(143)), \
                mock.patch.object(interop_peer.sys, "stderr", stderr):
            self.assertEqual(interop_peer.cli(), 143)
        self.assertEqual(stderr.getvalue(),
                         "independent peer execution or identity verification failed\n")

        class BrokenSink:
            def write(self, _value):
                raise RuntimeError("private-canary")

            def flush(self):
                raise RuntimeError("private-canary")

        with mock.patch.object(interop_peer, "install_signal_handlers"), \
                mock.patch.object(interop_peer, "main", side_effect=KeyboardInterrupt()), \
                mock.patch.object(interop_peer.sys, "stderr", BrokenSink()):
            self.assertEqual(interop_peer.cli(), 130)
        with mock.patch.object(interop_peer, "install_signal_handlers"), \
                mock.patch.object(interop_peer, "main", side_effect=SystemExit(0)), \
                mock.patch.object(interop_peer.sys, "stderr", BrokenSink()):
            self.assertEqual(interop_peer.cli(), 0)

    def test_interruption_after_run_binding_keeps_a_typed_safe_failure(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "standards").mkdir()
            peer = {"id": "curl-h1-h2", "identity_kind": "curl", "pin": "fixture",
                    "scenarios": [{"role": "client", "scenario": "cancelled"}]}
            (root / "standards/interop-profile.json").write_text(json.dumps({"peers": [peer]}))
            reports = root / "build/interop/peers"
            reports.mkdir(parents=True)
            interop_peer.write_json_atomic(reports / "curl-h1-h2.json", {
                "schema": 2, "status": "Running", "run_id": "1" * 64,
                "source_sha256": "2" * 64,
            })
            arguments = argparse.Namespace(
                root=str(root), peer="curl-h1-h2", role="client", run_id="1" * 64,
                scenario="cancelled", timeout=2,
                command=["--", sys.executable, "-c", "pass"],
            )
            with mock.patch.object(interop_peer, "identify", side_effect=KeyboardInterrupt()):
                with self.assertRaises(KeyboardInterrupt):
                    interop_peer.run(arguments)
            name = interop_peer.invocation_name("client", "cancelled")
            failure = interop_peer.read_json(
                root / "build/interop/failures/curl-h1-h2" / name)
            self.assertEqual(failure["phase"], "identity_before")
            self.assertEqual(failure["result"], {"kind": "cancelled", "exit_status": 130})
            self.assertNotIn("private-canary", json.dumps(failure))

            with mock.patch.object(interop_peer, "identify", side_effect=KeyboardInterrupt()), \
                    mock.patch.object(interop_peer, "write_json_atomic",
                                      side_effect=RuntimeError("private-canary")):
                with self.assertRaises(KeyboardInterrupt):
                    interop_peer.run(arguments)

    def test_json_evidence_io_rejects_links_and_oversized_inputs(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            original = root / "report.json"
            interop_peer.write_json_atomic(original, {"status": "Running", "run_id": "1" * 64})
            self.assertEqual(interop_peer.read_json(original)["status"], "Running")

            hardlink = root / "hardlink.json"
            os.link(original, hardlink)
            try:
                with self.assertRaisesRegex(ValueError, "peer_json_hardlink"):
                    interop_peer.read_json(original)
                with self.assertRaisesRegex(ValueError, "unsafe_peer_json_destination"):
                    interop_peer.write_json_atomic(original, {"status": "Ready"})
            finally:
                hardlink.unlink()

            symlink = root / "symlink.json"
            try:
                symlink.symlink_to(original)
            except OSError:
                pass
            else:
                with self.assertRaisesRegex(ValueError, "unsafe_peer_json"):
                    interop_peer.read_json(symlink)

            linked_parent = root / "linked-parent"
            actual_parent = root / "actual-parent"
            actual_parent.mkdir()
            try:
                linked_parent.symlink_to(actual_parent, target_is_directory=True)
            except OSError:
                pass
            else:
                with self.assertRaisesRegex(ValueError, "unsafe_evidence_directory"):
                    interop_peer.write_json_atomic(linked_parent / "escaped.json", {"status": "Ready"})

            oversized = root / "oversized.json"
            oversized.write_bytes(b" " * (interop_peer.MAX_JSON + 1))
            with self.assertRaisesRegex(ValueError, "oversized_peer_json"):
                interop_peer.read_json(oversized)

    def test_json_evidence_publication_is_complete_and_leaves_no_pending_file(self):
        with tempfile.TemporaryDirectory() as directory:
            destination = Path(directory) / "nested" / "report.json"
            value = {"schema": 2, "status": "Running", "run_id": "a" * 64}
            interop_peer.write_json_atomic(destination, value)
            self.assertEqual(interop_peer.read_json(destination), value)
            self.assertEqual(list(destination.parent.glob("*.pending")), [])

    def test_tool_entrypoints_do_not_change_source_inventory_with_bytecode(self):
        repository = Path(__file__).resolve().parents[1]
        files = ["scripts/interop_peer.py", "scripts/process_supervisor.py",
                 "scripts/interop_go_build.py",
                 "test/interop/masquego/native_runner.py"]
        for entry in ["scripts/interop_go_build.py", "test/interop/masquego/native_runner.py"]:
            with self.subTest(entry=entry), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                for relative in files:
                    destination = root / relative
                    destination.parent.mkdir(parents=True, exist_ok=True)
                    destination.write_bytes((repository / relative).read_bytes())
                environment = os.environ.copy()
                environment.pop("PYTHONDONTWRITEBYTECODE", None)
                environment.pop("PYTHONPYCACHEPREFIX", None)
                result = owned_run([sys.executable, str(root / entry), "--help"],
                    cwd=root, env=environment, stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL, timeout=10,
                    max_output_bytes=0, check=False)
                self.assertTrue(result.returncode == 0)
                self.assertTrue(not any(root.rglob("*.pyc")))

    def test_go_identity_requires_actual_current_build_receipt(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "go.sum").write_text("example.org/peer v1.0.0 h1:locked\n")
            peer = {"id": "quic-go-h3", "identity_kind": "go", "pin": "example.org/peer@v1.0.0",
                "go_version": "go1.27.0", "lock": "go.sum",
                "lock_sha256": interop_peer.digest_file(root / "go.sum")["sha256"]}
            info = "peer: go1.27.0\n\tdep\texample.org/peer\tv1.0.0\th1:locked\n"
            with mock.patch.object(interop_peer, "probe", return_value=info), \
                 mock.patch.object(interop_peer, "shared_libraries", return_value=[]):
                with self.assertRaisesRegex(ValueError, "missing_go_build_receipt"):
                    interop_peer.identify(root, peer, [sys.executable])

    def test_node_archives_reject_tampering_links_traversal_duplicates_and_expansion(self):
        with tempfile.TemporaryDirectory() as directory:
            archive = Path(directory) / "package.tgz"
            def verify(data):
                archive.write_bytes(data)
                expected = {"integrity": "sha512-" + base64.b64encode(hashlib.sha512(data).digest()).decode()}
                return interop_peer.node_archive_files(archive, expected)
            def packed(entries):
                result = io.BytesIO()
                with tarfile.open(fileobj=result, mode="w:gz") as writer:
                    for name, kind in entries:
                        info = tarfile.TarInfo(name)
                        info.type = kind
                        if kind == tarfile.REGTYPE:
                            info.size = 2
                            writer.addfile(info, io.BytesIO(b"ok"))
                        else:
                            info.linkname = "private-marker"
                            writer.addfile(info)
                return result.getvalue()
            accepted = packed([("package/index.js", tarfile.REGTYPE)])
            self.assertEqual(set(verify(accepted)), {"index.js"})
            with self.assertRaisesRegex(ValueError, "node_archive_integrity"):
                interop_peer.node_archive_files(archive, {"integrity": "sha512-" + "a" * 86 + "=="})
            for entries, code in [
                ([("package/../outside", tarfile.REGTYPE)], "unsafe_node_archive_path"),
                ([("/absolute", tarfile.REGTYPE)], "unsafe_node_archive_path"),
                ([("package/link", tarfile.SYMTYPE)], "node_archive_special_entry"),
                ([("package/index.js", tarfile.REGTYPE)] * 2, "invalid_node_archive_file")]:
                with self.assertRaisesRegex(ValueError, code):
                    verify(packed(entries))
            with self.assertRaisesRegex(ValueError, "node_archive_expansion_limit"):
                verify(gzip.compress(b"x" * (64 * 1024 * 1024 + 1)))

    def test_node_identity_binds_isolated_interpreter_fixture_lock_and_installed_files(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "test/peer.mjs"
            source.parent.mkdir()
            source.write_text("export const public_fixture = true;\n")
            installation = root / "build/node"
            package = installation / "node_modules/ohttp-ts"
            package.mkdir(parents=True)
            (installation / "peer.mjs").write_bytes(source.read_bytes())
            (package / "package.json").write_text(json.dumps({"name": "ohttp-ts", "version": "0.5.1"}))
            (package / "index.js").write_text("export const independent = true;\n")
            archive = io.BytesIO()
            with tarfile.open(fileobj=archive, mode="w:gz") as writer:
                for file in package.iterdir():
                    writer.add(file, arcname="package/" + file.name)
            archives = installation / "archives"
            archives.mkdir()
            archive_bytes = archive.getvalue()
            (archives / "ohttp-ts-0.5.1.tgz").write_bytes(archive_bytes)
            lock = {"lockfileVersion": 3, "packages": {"": {}, "node_modules/ohttp-ts": {
                "version": "0.5.1", "integrity": "sha512-" + base64.b64encode(hashlib.sha512(archive_bytes).digest()).decode(),
                "resolved": "https://registry.npmjs.org/ohttp-ts/-/ohttp-ts-0.5.1.tgz"}}}
            (root / "lock.json").write_text(json.dumps(lock))
            (installation / "package-lock.json").write_bytes((root / "lock.json").read_bytes())
            peer = {"identity_kind": "node", "pin": "ohttp-ts@0.5.1", "node_version": "v26.8.2",
                "lock": "lock.json", "lock_sha256": interop_peer.digest_file(root / "lock.json")["sha256"],
                "fixture": "test/peer.mjs", "installation": "build/node"}
            command = [sys.executable, "--disable-proto=throw", "--no-addons", "--no-global-search-paths", str(installation / "peer.mjs")]
            with mock.patch.object(interop_peer, "probe", return_value="v26.8.2\n"), \
                 mock.patch.object(interop_peer, "shared_libraries", return_value=[]), \
                 mock.patch.dict(os.environ, {}, clear=True):
                identity = interop_peer.identify(root, peer, command)
                self.assertEqual(identity["version"], "v26.8.2")
                self.assertEqual(identity["fixture_sha256"], interop_peer.digest_file(source)["sha256"])
                self.assertEqual(identity["dependencies"][0]["files"], 2)
                (package / "index.js").write_text("export const independent = false;\n")
                with self.assertRaisesRegex(ValueError, "node_package_content_drift"):
                    interop_peer.identify(root, peer, command)
                (package / "index.js").write_text("export const independent = true;\n")
                with mock.patch.dict(os.environ, {"NODE_OPTIONS": "--import=private-marker"}):
                    with self.assertRaisesRegex(ValueError, "node_environment_override"):
                        interop_peer.identify(root, peer, command)
                with self.assertRaisesRegex(ValueError, "node_not_isolated"):
                    interop_peer.identify(root, peer, [sys.executable, str(installation / "peer.mjs")])
                (package / "package.json").write_text(json.dumps({"name": "ohttp-ts", "version": "0.5.2"}))
                with self.assertRaisesRegex(ValueError, "installed_package_version_drift"):
                    interop_peer.identify(root, peer, command)
                (package / "package.json").write_text(json.dumps({"name": "ohttp-ts", "version": "0.5.1"}))
                extra = installation / "node_modules/unlocked"
                extra.mkdir()
                with self.assertRaisesRegex(ValueError, "unlocked_installed_node_package"):
                    interop_peer.identify(root, peer, command)
                extra.rmdir()
                (installation / "peer.mjs").write_text("private-marker\n")
                with self.assertRaisesRegex(ValueError, "stale_node_fixture"):
                    interop_peer.identify(root, peer, command)
                (installation / "peer.mjs").write_bytes(source.read_bytes())
                (installation / "package-lock.json").write_text("{}")
                with self.assertRaisesRegex(ValueError, "stale_node_lock"):
                    interop_peer.identify(root, peer, command)
                (installation / "package-lock.json").write_bytes((root / "lock.json").read_bytes())
                unexpected = package / "unexpected-empty-directory"
                unexpected.mkdir()
                with self.assertRaisesRegex(ValueError, "node_package_content_drift"):
                    interop_peer.identify(root, peer, command)
                unexpected.rmdir()
                deep = package
                for index in range(65):
                    deep = deep / ("d" + str(index))
                    deep.mkdir()
                with self.assertRaisesRegex(ValueError, "node_dependency_path_limit"):
                    interop_peer.identify(root, peer, command)
                shutil.rmtree(package / "d0")
                index = package / "index.js"
                index_bytes = index.read_bytes()
                outside = root / "outside-node-file"
                outside.write_bytes(index_bytes)
                index.unlink()
                os.link(outside, index)
                with self.assertRaisesRegex(ValueError, "node_dependency_hardlink"):
                    interop_peer.identify(root, peer, command)
                index.unlink()
                outside.unlink()
                index.write_bytes(index_bytes)
                if os.name == "posix":
                    link = package / "injected.js"
                    link.symlink_to(source)
                    with self.assertRaisesRegex(ValueError, "node_dependency_symlink"):
                        interop_peer.identify(root, peer, command)

    def test_node_dependency_inventory_has_one_global_entry_ceiling(self):
        self.assertEqual(interop_peer.MAX_NODE_ENTRIES, 20_000)
        with tempfile.TemporaryDirectory() as directory:
            package = Path(directory).resolve()
            directory_metadata = os.lstat(package)
            actual_lstat = os.lstat

            class Entry:
                def __init__(self, name):
                    self.name = name

            class Scan:
                def __enter__(self):
                    return (Entry("entry-" + str(index))
                            for index in range(5))

                def __exit__(self, *_arguments):
                    return False

            def metadata(path):
                return actual_lstat(path) if Path(path).exists() else directory_metadata

            with mock.patch.object(interop_peer, "MAX_NODE_ENTRIES", 4), \
                    mock.patch.object(interop_peer.os, "scandir", return_value=Scan()), \
                    mock.patch.object(interop_peer.os, "lstat", side_effect=metadata):
                with self.assertRaisesRegex(ValueError, "node_dependency_inventory_limit"):
                    interop_peer.node_dependency_inventory(package, maximum_entries=4)

    def test_native_identity_requires_locked_source_toolchain_and_role(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            lock = {"schema": 1, "compiler_version": "15.2.0", "sources": [
                {"name": name, "version": version, "sha256": "a" * 64}
                for name, version in [("ngtcp2", "1.25.0"), ("nghttp3", "1.18.0"), ("curl", "8.22.0")]]}
            (root / "sources.lock").write_text(json.dumps(lock))
            (root / "identity_patch.py").write_text("identity-only fixture\n")
            (root / "Dockerfile").write_text("fixed build recipe\n")
            peer = {"pin": "ngtcp2@1.25.0", "compiler_version": "15.2.0",
                "identity_patch": "identity_patch.py", "build_recipe": "Dockerfile", "lock": "sources.lock",
                "lock_sha256": interop_peer.digest_file(root / "sources.lock")["sha256"]}
            metadata = {"schema": 1, "role": "client", "compiler_version": "15.2.0",
                "lock_sha256": peer["lock_sha256"],
                "patch_sha256": interop_peer.digest_file(root / "identity_patch.py")["sha256"],
                "recipe_sha256": interop_peer.digest_file(root / "Dockerfile")["sha256"],
                "sources": [{"name": item["name"], "version": item["version"],
                    "archive_sha256": item["sha256"], "sha256": "b" * 64, "files": 100}
                    for item in lock["sources"]],
                "native_tools": [{"name": name, "sha256": "c" * 64} for name in
                    ["gcc", "g++", "cc1", "cc1plus", "as", "ld", "ar", "ranlib", "cmake", "make", "pkg-config", "patchelf"]]}
            def output(current, versions="1.25.0 1.18.0"):
                return versions + "\n" + json.dumps(current) + "\n"
            accepted = interop_peer.native_identity(root, peer, output(metadata))
            self.assertEqual(accepted["version"], "gcc 15.2.0")
            self.assertIn({"name": "peer-role", "version": "client", "files": 0,
                "sha256": hashlib.sha256(b"client").hexdigest()}, accepted["dependencies"])
            for field in ["lock_sha256", "patch_sha256", "recipe_sha256"]:
                with self.assertRaises(ValueError, msg=field):
                    interop_peer.native_identity(root, peer, output(dict(metadata, **{field: "0" * 64})))
            for current in [dict(metadata, role="private-marker"), dict(metadata, compiler_version="15.1.0"),
                            dict(metadata, sources=metadata["sources"][:-1]),
                            dict(metadata, native_tools=metadata["native_tools"][:-1]),
                            dict(metadata, argv="private-marker")]:
                with self.assertRaises(ValueError):
                    interop_peer.native_identity(root, peer, output(current))
            with self.assertRaises(ValueError):
                interop_peer.native_identity(root, peer, output(metadata, versions="1.24.0 1.18.0"))
            with self.assertRaisesRegex(ValueError, "duplicate_json_key"):
                interop_peer.native_identity(root, peer,
                    output(metadata).replace('"schema": 1', '"schema": "private-marker", "schema": 1'))

    def test_go_identity_rejects_a_different_actual_compiler(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "go.sum").write_text("example.org/peer v1.0.0 h1:locked\n")
            peer = {"identity_kind": "go", "pin": "example.org/peer@v1.0.0",
                "go_version": "go1.27.0", "lock": "go.sum",
                "lock_sha256": interop_peer.digest_file(root / "go.sum")["sha256"]}
            info = "peer: go1.26.0\n\tdep\texample.org/peer\tv1.0.0\th1:locked\n"
            with mock.patch.object(interop_peer, "probe", return_value=info), \
                 mock.patch.object(interop_peer, "shared_libraries", return_value=[]):
                with self.assertRaisesRegex(ValueError, "go_compiler_version_drift"):
                    interop_peer.identify(root, peer, [sys.executable])

    def test_rust_identity_accepts_only_embedded_current_source_and_lock(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            lock = b'version = 4\n\n[[package]]\nname = "quiche"\nversion = "0.29.3"\n'
            (root / "Cargo.lock").write_bytes(lock)
            (root / "identity_patch.py").write_bytes(b"fixture identity patch\n")
            peer = {"pin": "quiche@0.29.3", "lock": "Cargo.lock",
                "lock_sha256": hashlib.sha256(lock).hexdigest(),
                "identity_patch": "identity_patch.py", "source_commit": "a" * 40,
                "rust_version": "1.98.1"}
            metadata = {"schema": 1, "source_commit": "a" * 40,
                "source_sha256": "b" * 64, "source_files": 100,
                "lock_sha256": peer["lock_sha256"],
                "patch_sha256": interop_peer.digest_file(root / "identity_patch.py")["sha256"],
                "rust_version": "1.98.1", "rustc_sha256": "c" * 64,
                "rustc_driver_sha256": "d" * 64, "cargo_sha256": "e" * 64,
                "native_tools": [{"name": name, "sha256": "f" * 64}
                    for name in ["cc", "c++", "clang", "cmake", "make", "ar", "ld"]]}
            def output(current):
                return "0.29.3\n" + json.dumps(current) + "\n" + lock.decode()
            accepted = interop_peer.rust_identity(root, peer, output(metadata))
            self.assertEqual(accepted["lock_sha256"], peer["lock_sha256"])
            self.assertIn("rustc-driver", [item["name"] for item in accepted["dependencies"]])
            for field in ["source_commit", "lock_sha256", "patch_sha256"]:
                altered = dict(metadata, **{field: "0" * len(metadata[field])})
                with self.assertRaises(ValueError, msg=field):
                    interop_peer.rust_identity(root, peer, output(altered))
            with self.assertRaises(ValueError):
                interop_peer.rust_identity(root, peer, output(metadata) + "# stale embedded lock\n")
            with self.assertRaises(ValueError):
                interop_peer.rust_identity(root, peer, output(dict(metadata, argv="private-marker")))
            duplicated = output(metadata).replace('"schema": 1', '"schema": "private-marker", "schema": 1')
            with self.assertRaisesRegex(ValueError, "duplicate_json_key"):
                interop_peer.rust_identity(root, peer, duplicated)

    def test_file_contents_distinguish_equal_length_executables(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "peer"
            path.write_bytes(b"version-one")
            before = interop_peer.digest_file(path)
            path.write_bytes(b"version-two")
            self.assertNotEqual(before, interop_peer.digest_file(path))

    def test_identity_hash_rejects_growth_even_when_final_size_was_restored(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "peer"
            path.write_bytes(b"one")
            # A concurrently replaced file can grow while read and return to its original stat size before the final metadata check.
            with mock.patch.object(interop_peer.os, "read", side_effect=[b"onetwo", b""]):
                with self.assertRaisesRegex(ValueError, "identity_file_changed"):
                    interop_peer.digest_file(path)

    def test_dependency_identity_cannot_redistribute_path_boundaries(self):
        with tempfile.TemporaryDirectory() as directory:
            first = Path(directory) / "first"
            second = Path(directory) / "second"
            first.write_bytes(b"x")
            second.write_bytes(b"yz")
            before = interop_peer.digest_files([("a", first), ("b", second)])
            first.write_bytes(b"xy")
            second.write_bytes(b"z")
            self.assertNotEqual(before, interop_peer.digest_files([("a", first), ("b", second)]))
            with self.assertRaisesRegex(ValueError, "duplicate_dependency_file"):
                interop_peer.digest_files([("a", first), ("a", second)])
            with self.assertRaisesRegex(ValueError, "invalid_dependency_file_name"):
                interop_peer.digest_rows([([], {"sha256": "a" * 64, "bytes": 1})])

    def test_invocation_names_separate_roles_and_scenarios(self):
        self.assertNotEqual(interop_peer.invocation_name("client", "a"),
                            interop_peer.invocation_name("server", "a"))

    def test_stale_run_id_is_rejected_before_peer_identity_or_execution(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "standards").mkdir()
            peer = {"id": "curl-h1-h2", "identity_kind": "curl", "pin": "curl fixture",
                    "scenarios": [{"role": "client", "scenario": "stale-run"}]}
            (root / "standards/interop-profile.json").write_text(json.dumps({"peers": [peer]}))
            reports = root / "build/interop/peers"
            reports.mkdir(parents=True)
            interop_peer.write_json_atomic(reports / "curl-h1-h2.json", {
                "schema": 2, "status": "Running", "run_id": "1" * 64,
                "source_sha256": "2" * 64,
            })
            arguments = argparse.Namespace(
                root=str(root), peer="curl-h1-h2", role="client", run_id="3" * 64,
                scenario="stale-run", timeout=2,
                command=["--", sys.executable, "-c", "raise SystemExit('must not run')"],
            )
            with mock.patch.object(interop_peer, "identify") as identify, \
                    mock.patch.object(interop_peer, "collect") as collect:
                with self.assertRaisesRegex(ValueError, "peer_run_changed"):
                    interop_peer.run(arguments)
                identify.assert_not_called()
                collect.assert_not_called()
            self.assertFalse((root / "build/interop/invocations").exists())
            self.assertFalse((root / "build/interop/failures").exists())


@unittest.skipUnless(os.name == "posix", "POSIX interoperability harness")
class PeerProcessTest(unittest.TestCase):
    def test_an_exited_daemon_does_not_lose_its_exit_facts_during_discovery(self):
        child = owned_popen([sys.executable, "-c", "raise SystemExit(7)"])
        self.assertEqual(child.wait(timeout=3), 7)
        self.assertFalse(interop_peer.publish_owned_listener(child.pid, "udp"))

    def test_owned_udp_listener_is_discovered_without_a_reservation_socket(self):
        with tempfile.TemporaryDirectory() as directory:
            observed = io.StringIO()
            port_file = Path(directory) / "bound-port"
            command = [sys.executable, "-c",
                "import socket,time;from pathlib import Path;"
                "peer=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);peer.bind(('127.0.0.1',0));"
                f"Path({str(port_file)!r}).write_text(str(peer.getsockname()[1]));time.sleep(60)"]
            with contextlib.redirect_stdout(observed):
                facts, _ = interop_peer.collect(command, 5,
                    ready=lambda pid: interop_peer.publish_owned_listener(pid, "udp"),
                    stop_requested=lambda: observed.getvalue().startswith("PORT="))
            self.assertEqual(observed.getvalue(), "PORT=" + port_file.read_text() + "\n")
            self.assertEqual(facts["exit_status"], -15)
            self.assertTrue(facts["controlled_shutdown"])

    def test_supervisor_owner_exit_stops_and_reaps_the_independent_peer(self):
        with tempfile.TemporaryDirectory() as directory:
            group_file = Path(directory) / "peer-group"
            supervisor_file = Path(directory) / "supervisor"
            finished_file = Path(directory) / "finished"
            peer_code = (
                "import os,time; from pathlib import Path; "
                f"Path({str(group_file)!r}).write_text(str(os.getpid())); time.sleep(60)"
            )
            supervisor_code = (
                "import sys; from pathlib import Path; "
                f"sys.path.insert(0,{str(Path(__file__).resolve().parent)!r}); "
                "import interop_peer\n"
                "try:\n"
                f" interop_peer.collect([sys.executable,'-c',{peer_code!r}],60)\n"
                "except ValueError:\n"
                f" Path({str(finished_file)!r}).write_text('reaped')\n"
            )
            owner_code = (
                "import subprocess,sys,time; from pathlib import Path; "
                f"child=subprocess.Popen([sys.executable,'-c',{supervisor_code!r}],"
                "stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL); "
                f"Path({str(supervisor_file)!r}).write_text(str(child.pid))\n"
                f"while not Path({str(group_file)!r}).exists(): time.sleep(0.005)\n"
            )
            owner = owned_popen([sys.executable, "-c", owner_code])
            try:
                owner.wait(timeout=3)
                deadline = time.monotonic() + 3
                while not finished_file.exists() and time.monotonic() < deadline:
                    time.sleep(0.005)
                self.assertTrue(finished_file.exists(), "owner exit must join the peer before cleanup returns")
                with self.assertRaises(ProcessLookupError):
                    os.killpg(int(group_file.read_text()), 0)
            finally:
                for path, kill in ((group_file, os.killpg), (supervisor_file, os.kill)):
                    if path.exists():
                        try:
                            kill(int(path.read_text()), signal.SIGKILL)
                        except ProcessLookupError:
                            pass
                if owner.poll() is None:
                    owner.kill()
                    owner.wait(timeout=3)

    def test_failed_peer_preserves_safe_completion_without_minting_invocation(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "standards").mkdir()
            version = " ".join(interop_peer.probe(["curl", "--version"]).splitlines()[0].split()[:2])
            peer = {"id": "curl-h1-h2", "identity_kind": "curl", "pin": version,
                    "scenarios": [{"role": "client", "scenario": "probe-failure"}]}
            (root / "standards/interop-profile.json").write_text(json.dumps({"peers": [peer]}))
            reports = root / "build/interop/peers"
            reports.mkdir(parents=True)
            (reports / "curl-h1-h2.json").write_text(json.dumps({"schema": 2, "status": "Running",
                "run_id": "1" * 64, "source_sha256": "2" * 64}))
            arguments = argparse.Namespace(root=str(root), peer="curl-h1-h2", role="client",
                run_id="1" * 64, scenario="probe-failure", timeout=2,
                command=["--", "curl", "--silent", "--show-error", "private-peer-marker://localhost"])
            with self.assertRaises(ValueError):
                interop_peer.run(arguments)
            name = interop_peer.invocation_name("client", "probe-failure")
            failure = (root / "build/interop/failures/curl-h1-h2" / name).read_text()
            facts = json.loads(failure)
            self.assertEqual(facts["phase"], "exit_validation")
            self.assertEqual(facts["completion"]["exit_status"], 1)
            self.assertTrue(facts["completion"]["exit_observed"])
            self.assertNotIn("private-peer-marker", failure)
            self.assertNotIn("output_sha256", failure)
            self.assertFalse((root / "build/interop/invocations/curl-h1-h2" / name).exists())

    def test_daemon_shutdown_requires_an_explicit_completed_oracle(self):
        started = time.monotonic()
        facts, _ = interop_peer.collect([sys.executable, "-c", "import time; time.sleep(60)"], 5,
            stop_requested=lambda: time.monotonic() - started > 0.1)
        self.assertEqual(facts["outcome"], "completed")
        self.assertEqual(facts["exit_status"], -15)
        self.assertTrue(facts["controlled_shutdown"])
        self.assertTrue(facts["exit_observed"])

    def test_early_daemon_exit_is_not_an_oracle_requested_shutdown(self):
        facts, _ = interop_peer.collect([sys.executable, "-c", "pass"], 5,
            stop_requested=lambda: False)
        self.assertEqual(facts["exit_status"], 0)
        self.assertFalse(facts["controlled_shutdown"])

    def test_actual_exit_failure_is_retained_without_output_in_public_facts(self):
        facts, output = interop_peer.collect([sys.executable, "-c",
            "import sys; print('private-peer-marker'); sys.exit(60)"], 5)
        self.assertEqual(facts["exit_status"], 60)
        self.assertEqual(facts["outcome"], "completed")
        self.assertTrue(facts["exit_observed"])
        self.assertIn(b"private-peer-marker", output)
        self.assertNotIn("private-peer-marker", str(facts))
        self.assertNotIn("sha256", str(facts))

    def test_absolute_deadline_stops_a_silent_peer(self):
        started = time.monotonic()
        facts, _ = interop_peer.collect([sys.executable, "-c", "import time; time.sleep(60)"], 0.1)
        self.assertEqual(facts["outcome"], "timeout")
        self.assertTrue(facts["exit_observed"])
        self.assertLess(time.monotonic() - started, 5)

    def test_output_limit_stops_peer_independently_of_deadline(self):
        facts, output = interop_peer.collect([sys.executable, "-c",
            "import os,time; os.write(1,b'x'*65536); time.sleep(60)"], 30, limit=4096)
        self.assertEqual(facts["outcome"], "output_limit")
        self.assertTrue(facts["exit_observed"])
        self.assertLess(facts["elapsed_milliseconds"], 5000)
        self.assertLessEqual(len(output), 4096)

    def test_descendant_holding_output_pipe_cannot_escape_deadline(self):
        facts, output = interop_peer.collect([sys.executable, "-c",
            "import os,time; print(os.getpid(),flush=True); child=os.fork(); time.sleep(60) if child==0 else None"], 0.1)
        self.assertEqual(facts["outcome"], "timeout")
        self.assertTrue(facts["exit_observed"])
        with self.assertRaises(ProcessLookupError):
            os.killpg(int(output.strip()), 0)


if __name__ == "__main__":
    from interop_go_build_test import GoBuildReceiptTests
    unittest.main()

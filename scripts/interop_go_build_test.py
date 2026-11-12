#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 the http contributors
# SPDX-License-Identifier: MIT OR Apache-2.0
import copy
import argparse
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest import mock

import interop_go_build as build
import interop_peer


class GoBuildReceiptTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name).resolve()
        self.identifier = "masque-independent"
        directory, _, binary = build.PEERS[self.identifier]
        self.directory = self.root / directory
        self.directory.mkdir(parents=True)
        self.source = self.directory / "main.go"
        self.source.write_text("package main\nfunc main() {}\n")
        (self.directory / "go.mod").write_text("module example.org/main\n")
        self.checksum = "h1:" + "A" * 43 + "="
        self.lock = self.directory / "go.sum"
        self.lock.write_text("example.org/peer v1.0.0 " + self.checksum + "\n")
        self.compiler = self.root / "go"
        self.compiler.write_bytes(b"actual-compiler-fixture")
        self.binary = self.root / "build/interop/bin" / binary
        self.binary.parent.mkdir(parents=True)
        self.binary.write_bytes(b"actual-compiled-binary-fixture")
        for path in build.COMMON_RECIPES + [directory + "/setup.sh", directory + "/run.sh"]:
            file = self.root / path
            file.parent.mkdir(parents=True, exist_ok=True)
            file.write_text("bounded recipe\n")
        self.peer = {"id": self.identifier, "identity_kind": "go", "pin": "example.org/peer@v1.0.0",
                     "go_version": "go1.27.0", "lock": directory + "/go.sum",
                     "lock_sha256": interop_peer.digest_file(self.lock)["sha256"]}
        self.profile = self.root / "standards/interop-profile.json"
        self.profile.write_text(json.dumps({"peers": [self.peer]}))
        self.info = ("peer: go1.27.0\n\tpath\texample.org/main\n"
                     "\tmod\texample.org/main\t(devel)\n\tdep\texample.org/peer\tv1.0.0\t" + self.checksum + "\n" +
                     "\tbuild\t-buildmode=exe\n\tbuild\t-compiler=gc\n\tbuild\t-trimpath=true\n"
                     "\tbuild\tCGO_ENABLED=0\n\tbuild\tGOARCH=amd64\n\tbuild\tGOOS=linux\n")
        self.runtime = {"sha256": "a" * 64, "files": 10}
        self.completion = {"outcome": "completed", "exit_status": 0, "exit_observed": True,
                           "controlled_shutdown": False, "elapsed_milliseconds": 1,
                           "stdout_bytes": 0, "stderr_bytes": 0}
        self.receipt = dict(schema=1, status="Passed", peer=self.identifier, nonce="ab" * 16,
                            **build.inputs(self.root, self.peer),
                            compiler=interop_peer.digest_file(self.compiler), toolchain=self.runtime,
                            binary=interop_peer.digest_file(self.binary),
                            module_info=build.module_info(self.info, "go1.27.0"),
                            steps=[dict(step=name, **self.completion) for name in build.STEP_NAMES])
        self.write(self.receipt)
        interop_peer.write_json_atomic(build.attempt_path(self.root, self.identifier),
            {"schema": 1, "peer": self.identifier, "nonce": self.receipt["nonce"]})
        self.addCleanup(mock.patch.stopall)
        mock.patch.object(interop_peer, "executable", return_value=self.compiler).start()
        mock.patch.object(build, "toolchain", return_value=self.runtime).start()

    def write(self, value):
        interop_peer.write_json_atomic(build.receipt_path(self.root, self.identifier), value)

    def verify(self, info=None, binary=None):
        return build.verify(self.root, self.peer, binary or self.binary, self.info if info is None else info)

    def test_complete_source_compiler_runtime_and_binary_binding(self):
        self.assertTrue(self.verify() == self.receipt)

    def test_current_source_inventory_cannot_omit_added_changed_or_deleted_go(self):
        for change in ("added", "changed", "deleted"):
            with self.subTest(change=change):
                extra = self.directory / "extra.go"
                original = self.source.read_bytes()
                if change == "added":
                    extra.write_bytes(b"package main\n")
                elif change == "changed":
                    self.source.write_bytes(b"package main\n// changed\n")
                else:
                    self.source.unlink()
                with self.assertRaises(ValueError):
                    self.verify()
                self.source.write_bytes(original)
                extra.unlink(missing_ok=True)

    def test_native_assembler_object_cgo_and_embedded_inputs_are_explicitly_refused(self):
        for suffix in sorted(build.UNSUPPORTED_SUFFIXES | {".S", ".C", ".F"}):
            extra = self.directory / ("hidden" + suffix)
            extra.write_bytes(b"private-source-marker")
            with self.assertRaisesRegex(ValueError, "unbound_go_native_input"):
                self.verify()
            extra.unlink()
        self.source.write_bytes(b"package main\n//go:embed hidden.txt\n")
        with self.assertRaisesRegex(ValueError, "unbound_go_embedded_input"):
            self.verify()
        for imported in [b'import "C"', b'import ("fmt"; "C")', b'import /* fixed */ `C`',
                         b'import "\\x43"', b'import "\\u0043"', b'import "\\U00000043"',
                         b'import "\\103"', b'import `C\r`', b'import ("https://example.test"; "C")']:
            self.source.write_bytes(b"package main\n" + imported + b"\n")
            with self.assertRaisesRegex(ValueError, "unbound_go_cgo_import"):
                self.verify()
        for content in [b'// import "C"\n', b'/* import "C" */\n', b"var a = 'C'\n",
                        b'import "https://example.test"\n']:
            build.pure_go_source(content)

    def test_every_recipe_and_lock_is_bound(self):
        for entry in self.receipt["recipes"] + [{"path": self.peer["lock"]}]:
            file = self.root / entry["path"]
            original = file.read_bytes()
            file.write_bytes(original + b"changed")
            with self.assertRaises(ValueError):
                self.verify()
            file.write_bytes(original)

    def test_different_binary_compiler_and_runtime_are_refused(self):
        for file in (self.binary, self.compiler):
            original = file.read_bytes()
            file.write_bytes(b"different executable")
            with self.assertRaises(ValueError):
                self.verify()
            file.write_bytes(original)
        with mock.patch.object(build, "toolchain", return_value={"sha256": "b" * 64, "files": 10}):
            with self.assertRaisesRegex(ValueError, "go_build_runtime_changed"):
                self.verify()
        alias = self.root / "alias"
        alias.write_bytes(self.binary.read_bytes())
        with self.assertRaisesRegex(ValueError, "unbound_go_build_binary"):
            self.verify(binary=alias)

    def test_old_receipt_cannot_resurrect_after_a_new_build_attempt(self):
        interop_peer.write_json_atomic(build.attempt_path(self.root, self.identifier),
            {"schema": 1, "peer": self.identifier, "nonce": "cd" * 16})
        with self.assertRaisesRegex(ValueError, "stale_go_build_attempt"):
            self.verify()

    def test_missing_unexecuted_failed_steps_and_private_fields_are_rejected(self):
        path = build.receipt_path(self.root, self.identifier)
        path.unlink()
        with self.assertRaisesRegex(ValueError, "missing_go_build_receipt"):
            self.verify()
        for change in [dict(self.receipt, private="private-marker"), dict(self.receipt, schema=True),
                       dict(self.receipt, steps=[]), dict(self.receipt, status="Running")]:
            self.write(change)
            with self.assertRaises(ValueError):
                self.verify()
        for field, value in [("exit_status", 1), ("exit_status", False), ("exit_observed", False),
                             ("controlled_shutdown", True), ("stdout_bytes", True),
                             ("elapsed_milliseconds", 125001), ("private", "private-marker")]:
            changed = copy.deepcopy(self.receipt)
            changed["steps"][2][field] = value
            self.write(changed)
            with self.assertRaises(ValueError):
                self.verify()

    def test_actual_module_info_rejects_uncontrolled_settings_or_changed_dependency(self):
        for old, new in [("go1.27.0", "go1.26.0"), ("CGO_ENABLED=0", "CGO_ENABLED=1"),
                         ("-trimpath=true", "-trimpath=false"), ("v1.0.0", "v1.0.1")]:
            with self.assertRaises(ValueError):
                self.verify(info=self.info.replace(old, new))
        for extra in ["\tbuild\t-ldflags=private-marker\n", "\tbuild\tGOOS=linux\n",
                      "\t=>\tunlocked\tv1.0.0\n"]:
            with self.assertRaises(ValueError):
                self.verify(info=self.info + extra)

    def test_float_and_boolean_counts_cannot_masquerade_as_input_sizes(self):
        for key in ("sources", "recipes"):
            changed = copy.deepcopy(self.receipt)
            changed[key][0]["bytes"] = float(changed[key][0]["bytes"])
            self.write(changed)
            with self.assertRaisesRegex(ValueError, "invalid_go_input_rows"):
                self.verify()
        changed = copy.deepcopy(self.receipt)
        changed["toolchain"]["files"] = float(changed["toolchain"]["files"])
        self.write(changed)
        with self.assertRaisesRegex(ValueError, "invalid_go_runtime_identity"):
            self.verify()

    def test_compiler_generated_default_godebug_is_bounded_and_public(self):
        setting = "asynctimerchan=0,containermaxprocs=1,http2client=1"
        parsed = build.module_info(self.info + "\tbuild\tDefaultGODEBUG=" + setting + "\n", "go1.27.0")
        self.assertIn({"name": "DefaultGODEBUG", "value": setting}, parsed["settings"])
        for value in ["private-marker", "http2client=private-marker", "http2client=1,http2client=0",
                      "http2client=-1", "http2client=12345678901", "x" * 65 + "=0",
                      ",".join("setting" + str(index) + "=0" for index in range(129)),
                      ",".join("x" * 40 + str(index) + "=0" for index in range(128))]:
            with self.assertRaises(ValueError):
                build.module_info(self.info + "\tbuild\tDefaultGODEBUG=" + value + "\n", "go1.27.0")

    def build_with(self, change=None, writes_binary=True):
        calls = []
        def run(command, seconds, **kwargs):
            calls.append(command)
            self.assertEqual(seconds, 120)
            self.assertEqual(kwargs["limit"], 1048576)
            self.assertEqual(kwargs["env"]["CGO_ENABLED"], "0")
            if "build" in command:
                self.assertFalse(self.binary.exists())
                if writes_binary:
                    self.binary.write_bytes(b"fresh actual compiler output")
                if change:
                    change()
            return self.completion, b"private-compiler-output-marker"
        def probe(command, _env):
            return self.info if "-m" in command else "go version go1.27.0 linux/amd64\n"
        with mock.patch.object(interop_peer, "collect", side_effect=run), \
             mock.patch.object(build, "probe", side_effect=probe):
            build.build(self.root, self.identifier)
        return calls

    def test_actual_compiler_steps_precede_new_receipt_and_output_never_publishes(self):
        calls = self.build_with()
        self.assertEqual(len(calls), 4)
        current = self.verify()
        self.assertNotEqual(current["nonce"], self.receipt["nonce"])
        encoded = build.receipt_path(self.root, self.identifier).read_bytes()
        self.assertFalse(b"private-compiler-output-marker" in encoded)
        self.assertTrue("-a" in calls[2] and "-buildvcs=false" in calls[2])

    def test_cancellation_after_candidate_publication_invalidates_success(self):
        with mock.patch.object(build, "verify", side_effect=KeyboardInterrupt()):
            with self.assertRaises(KeyboardInterrupt):
                self.build_with()
        self.assertEqual(interop_peer.read_json(build.receipt_path(
            self.root, self.identifier)), {"schema": 1, "status": "Failed"})

    def test_cli_preserves_cancellation_and_ignores_diagnostic_sink_failure(self):
        arguments = ["--root", str(self.root), "--peer", self.identifier]

        class BrokenSink:
            def write(self, _value):
                raise RuntimeError("private-compiler-marker")

            def flush(self):
                raise RuntimeError("private-compiler-marker")

        with mock.patch.object(build.peer_tools, "install_signal_handlers"), \
                mock.patch.object(build, "build", side_effect=SystemExit(143)), \
                mock.patch.object(build.sys, "stderr", BrokenSink()):
            self.assertEqual(build.cli(arguments), 143)
        with mock.patch.object(build.peer_tools, "install_signal_handlers"), \
                mock.patch.object(build, "build"), \
                mock.patch.object(build.sys, "stdout", BrokenSink()):
            self.assertEqual(build.cli(arguments), 0)

    def test_drift_during_compile_leaves_prior_success_invalidated(self):
        with self.assertRaisesRegex(ValueError, "go_inputs_changed_during_build"):
            self.build_with(change=lambda: self.source.write_bytes(b"changed during actual compile"))
        self.assertTrue(interop_peer.read_json(build.receipt_path(self.root, self.identifier))["status"] == "Failed")

    def test_successful_noop_cannot_reuse_old_executable(self):
        with self.assertRaises(FileNotFoundError):
            self.build_with(writes_binary=False)
        self.assertTrue(interop_peer.read_json(build.receipt_path(self.root, self.identifier))["status"] == "Failed")

    def test_user_toolchain_and_cache_injection_are_removed(self):
        with mock.patch.dict(os.environ, {name: "private-marker" for name in
                ["GOENV", "GOROOT", "GOFLAGS", "GOTOOLCHAIN", "GOCACHEPROG", "GOEXPERIMENT", "CGO_CFLAGS", "GoRoot", "Cgo_Cflags"]}):
            observed = build.environment()
        self.assertTrue(all(value != "private-marker" for value in observed.values()))
        self.assertEqual(observed["GOENV"], "off")
        self.assertEqual(observed["CGO_ENABLED"], "0")

    def test_actual_peer_execution_cannot_inherit_private_go_runtime_overrides(self):
        peer = dict(self.peer, scenarios=[{"role": "client", "scenario": "runtime-control"}])
        self.profile.write_text(json.dumps({"peers": [peer]}))
        report = self.root / "build/interop/peers" / (self.identifier + ".json")
        interop_peer.write_json_atomic(report, {"schema": 2, "status": "Running",
            "run_id": "1" * 64, "source_sha256": "2" * 64})
        arguments = argparse.Namespace(root=str(self.root), peer=self.identifier, role="client",
            run_id="1" * 64, scenario="runtime-control", timeout=2,
            command=["--", str(self.binary)])
        def collect(_command, _timeout, **kwargs):
            effective = kwargs.get("env") or os.environ
            self.assertTrue("GODEBUG" not in effective)
            self.assertTrue("GOMAXPROCS" not in effective)
            self.assertTrue(effective.get("GOMEMLIMIT") == "1GiB")
            return self.completion, b""
        with mock.patch.dict(os.environ, {"GODEBUG": "private-marker", "GOMAXPROCS": "private-marker"}), \
             mock.patch.object(interop_peer, "identify", return_value={"fixed": "identity"}), \
             mock.patch.object(interop_peer, "collect", side_effect=collect):
            interop_peer.run(arguments)


if __name__ == "__main__":
    unittest.main()

# SPDX-FileCopyrightText: 2026 the http contributors
# SPDX-License-Identifier: MIT OR Apache-2.0
"""Verify actual browser, driver and resources against the official archives."""
import sys
sys.dont_write_bytecode = True
from pathlib import Path
from archive import tree_identity, digest


def identify(root, peer, selected_python, command):
    sys.path.insert(0, str(root / "scripts"))
    from interop_peer import read_json, probe, shared_libraries
    pins_path = root / "test/interop/browser/pins.json"
    pins = read_json(pins_path)["chromium"]
    version = pins["version"]
    if (peer["id"] != "chromium" or peer["pin"] != "chromium " + version
            or len(command) != 7 or Path(command[1]).resolve() != (root / peer["fixture"]).resolve()
            or peer["fixture"] != "test/interop/browser/browser_worker.py"
            or peer["lock_sha256"] != digest(pins_path)["sha256"]):
        raise ValueError("invalid_browser_identity")
    directory = Path("/opt/browser")
    archives = Path("/opt/browser-archives")
    dependencies = []
    for role in ("browser", "driver"):
        pin = pins[role]
        archive = archives / ("chrome-linux64.zip" if role == "browser" else "chromedriver-linux64.zip")
        tree = tree_identity(archive, directory, pin)
        executable = directory / pin["executable"]
        observed = probe([str(executable), "--version"]).strip()
        valid = (observed == "Google Chrome for Testing " + version if role == "browser"
                 else observed.startswith("ChromeDriver " + version + " "))
        if not valid:
            raise ValueError("browser_version_drift")
        for name, metadata in [(role, tree["executable"]), (role + "-archive", tree["archive"]),
                               (role + "-resources", tree)]:
            dependencies.append({"name": name, "version": version,
                                 "sha256": metadata["sha256"], "files": metadata.get("files", 1)})
        for library in shared_libraries(executable):
            dependencies.append(dict(library, name=role + "-" + library["name"]))
    for library in shared_libraries(Path(selected_python).resolve()):
        dependencies.append(dict(library, name="python-" + library["name"]))
    dependencies.append({"name": "python", "version": probe([selected_python, "--version"]).strip().removeprefix("Python "),
                         "sha256": digest(Path(selected_python).resolve())["sha256"], "files": 1})
    dependencies.append({"name": "nss-certutil", "version": "binary",
                         "sha256": digest(Path("/usr/bin/certutil"))["sha256"], "files": 1})
    return {"version": "chromium " + version, "lock_sha256": digest(pins_path)["sha256"],
            "fixture_sha256": digest(root / peer["fixture"])["sha256"],
            "dependencies": dependencies}

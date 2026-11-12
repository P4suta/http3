# SPDX-FileCopyrightText: 2026 the http contributors
# SPDX-License-Identifier: MIT OR Apache-2.0
"""Bind actual Firefox, Gecko driver, bundled resources and dynamic libraries."""
import sys
sys.dont_write_bytecode = True
from pathlib import Path
from archive import digest
from firefox_archive import tree_identity
from firefox_setup import ARCHIVES


def identify(root, peer, selected_python, command):
    sys.path.insert(0, str(root / "scripts"))
    from interop_peer import read_json, probe, shared_libraries, require
    pins_path = root / "test/interop/browser/firefox-pins.json"
    pins = read_json(pins_path)["firefox"]
    require(peer["id"] == "firefox" and peer["pin"] == "firefox " + pins["version"]
            and len(command) == 7 and Path(command[1]).resolve() == (root / peer["fixture"]).resolve()
            and peer["fixture"] == "test/interop/browser/firefox_worker.py"
            and peer["lock_sha256"] == digest(pins_path)["sha256"], "invalid_firefox_identity")
    policy = {"h3_route": "explicit-loopback-alt-svc", "private_roots_allow_h3": True,
        "tls_verification": True, "maximum_threads": 512, "sandbox": "default"}
    require(type(peer["browser_policy"]) is dict and set(peer["browser_policy"]) == set(policy)
            and all(type(peer["browser_policy"][key]) is type(value)
                    and peer["browser_policy"][key] == value for key, value in policy.items()), "invalid_firefox_policy")
    directory, archives = Path("/opt/firefox"), Path("/opt/firefox-archives")
    dependencies = []
    for role in ("browser", "driver"):
        pin = pins[role]
        tree = tree_identity(archives / ARCHIVES[role], directory, pin)
        executable = directory / pin["executable"]
        observed = probe([str(executable), "--version"]).strip()
        require([line for line in observed.splitlines() if line.startswith("Mozilla Firefox ")]
                == ["Mozilla Firefox " + pin["version"]] and len(observed.splitlines()) <= 16 if role == "browser"
                else observed.startswith("geckodriver " + pin["version"] + " "), "firefox_version_drift")
        for name, metadata in [(role, tree["executable"]), (role + "-archive", tree["archive"]),
                               (role + "-resources", tree)]:
            dependencies.append({"name": name, "version": pin["version"],
                "sha256": metadata["sha256"], "files": metadata.get("files", 1)})
        libraries = {}
        candidates = [executable]
        if role == "browser":
            # The small launcher loads libxul and other ELF files dynamically;
            # inspecting the launcher alone misses their system dependencies.
            candidates = sorted((directory / "firefox").rglob("*"))
        require(len(candidates) <= 4096, "firefox_distribution_limit")
        for candidate in candidates:
            if not candidate.is_file():
                continue
            with candidate.open("rb") as source:
                elf = source.read(4) == b"\x7fELF"
            if not elf:
                continue
            for library in shared_libraries(candidate, allow_static=role == "driver", env={"PATH": "/usr/local/bin:/usr/bin:/bin",
                    "LANG": "C", "LD_LIBRARY_PATH": str(directory / "firefox")}):
                name = library["name"]
                require(name not in libraries or libraries[name] == library, "firefox_library_drift")
                libraries[name] = library
        dependencies += [dict(value, name=role + "-" + name) for name, value in sorted(libraries.items())]
    dependencies += [dict(value, name="python-" + value["name"])
                     for value in shared_libraries(Path(selected_python).resolve())]
    dependencies.append({"name": "python", "version": probe([selected_python, "--version"]).strip().removeprefix("Python "),
        "sha256": digest(Path(selected_python).resolve())["sha256"], "files": 1})
    dependencies.append({"name": "nss-certutil", "version": "binary",
        "sha256": digest(Path("/usr/bin/certutil"))["sha256"], "files": 1})
    require(len(dependencies) <= 128, "firefox_dependency_limit")
    return {"version": "firefox " + pins["version"], "lock_sha256": digest(pins_path)["sha256"],
        "fixture_sha256": digest(root / peer["fixture"])["sha256"], "dependencies": dependencies}

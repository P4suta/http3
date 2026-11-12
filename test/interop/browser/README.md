# Chromium and Firefox interoperability

This fixture runs the official Chrome for Testing 153.0.8010.36 browser and matching ChromeDriver on Linux x86-64.
`pins.json` fixes both download archives,
the executable bytes and every installed resource.
The setup verifies archive members before extraction, rejects escaping paths and special files, and never replaces an existing installation.
Each invocation verifies those actual files and resolved shared-library dependencies before and after execution.

The six scenarios cover HTTP/1.1, HTTP/2 and HTTP/3.
Each trusted connection must observe status 201, all 72,250 body bytes, a secure browser context and the actual `nextHopProtocol`.
A second response stops while its public Body callback is blocked; the browser must report `AbortError` and the native server must observe source cancellation, callback exit and complete listener shutdown.
The three untrusted cases require an actual certificate-verifier failure (-202), no HTTP response observed by Chrome and zero native application requests.

HTTP/3 is selected explicitly with `--origin-to-force-quic-on`; these scenarios qualify direct HTTP/3 interoperability, not browser Alt-Svc discovery.
Certificate verification remains enabled.
The trusted profile has only the explicit fixture CA in a new NSS database; the untrusted profile receives no fixture CA.

Chrome's own sandbox is disabled in this test container and that fact is a required receipt field.
Execution requires a non-root user, Docker's default seccomp filter, no added capabilities, `no-new-privileges`, a finite PID limit,
and a network namespace containing only loopback.
Browser, driver and escaped child processes must all terminate before a successful receipt can be published.

Build the dependency image from this directory:

```sh
docker build -t http-browser:otp29 test/interop/browser
docker build --build-arg BASE_IMAGE=hexpm/erlang@sha256:2f4fe0bea2303f2020d5ab8642c23e1d346bef3e39dca8259745ff11bf5d2223 -t http-browser:otp28 test/interop/browser
```

The default OTP 29 base is `hexpm/erlang@sha256:a6b64e4e3849f5a009c1839fc0ca016207b6926d7800f481e60942cc64fd50a0`.
Gleam 1.18.1 and rebar3 3.27.0 downloads are independently SHA-256 checked.
Dependency retrieval and a fresh native build happen before the isolated test container is started.
Run against an owned workspace snapshot whose package source caches are present, using the image's non-root user:

```sh
docker run --rm --init --network none --cap-drop ALL --security-opt no-new-privileges \
  --pids-limit 256 --memory 2g --mount type=bind,source=/absolute/snapshot,target=/work \
  http-browser:otp29 bash test/interop/browser/run.sh
```

`run.sh` normally rebuilds the native `http` package and verifies its fresh manifest.
`HTTP_BROWSER_SKIP_FRESH_BUILD=1` only skips compilation; the begin/end audits still require a valid current-source native manifest.
A changed source,
replaced browser, missing receipt, private extra field, failed VM or incomplete cleanup prevents `Ready`.

`container.sh` is the Linux host entry point.
It first exercises three actual Docker lifecycle controls, then runs the build and isolated browser phases.
A separate controller survives caller termination, joins the attaching CLI,
checks the container's unique ownership label, removes that container, and confirms its absence before returning success.
Execution budgets are 300 and 600 seconds; daemon cleanup has a separate 20-second budget.
Docker's socket is never passed to the browser container or the three temporary control containers.
The host must already have an accessible Docker daemon.

Share only validated `build/interop/browser/chromium/*.json`,
`build/interop/native/chromium/*.json`, peer/invocation reports and retained fresh-build manifests.
The `*.controls` directories are private execution controls, including ephemeral ports, and are never evidence artifacts.

Run `oracle_test.py`, `netlog_test.py`, `archive_test.py`, `setup_test.py` and `receipt_test.py` with `python3 -B`.
Linux ownership controls are in `owned_test.py` and `browser_worker_test.py`; `native_runner_test.py` uses real Erlang VMs to exercise no-work, private-output, timeout and source-drift failures.
`container_owner_test.py` exercises real owner, CLI and detached helper processes through a deterministic daemon fixture.
The separate `container_daemon_test.py IMAGE` exercises the actual Docker daemon on a Linux host; a fixture result cannot substitute for those three controls.
`escript scripts/interop_browser_test.escript` independently rejects malformed and incomplete completion records.
These synthetic controls validate the verifier; they do not substitute for real browser execution.

## Firefox

`firefox_container.sh` applies the same ownership and native-work contracts to official Firefox 155.0.1 and geckodriver 0.37.1 on Linux x86-64.
The dedicated `firefox-pins.json` binds Mozilla's archive, the GitHub release asset, both executables and every installed resource.
Tar members are streamed once;
only bounded names and digests are retained for the canonical tree identity.
Empty regular resources are hashed, and links, special files, duplicate names,
escaping paths and excess expansion are rejected.
All bundled ELF files are included when resolving the dependency closure, including libraries loaded by the small Firefox launcher.

Firefox retains its default browser sandbox policy.
Its separate test container has the same non-root, seccomp, capability and loopback restrictions, a finite 512-thread limit, 2 GiB memory and 256 MiB shared memory.
The 256-entry process ownership ledger is unchanged.
The larger thread limit is explicit: a real browser plus native server exceeded 256 threads, while completed controls observed 302–322 threads and zero limit hits.
Receipts require the actual container thread peak, zero thread-limit hits and zero OOM kills.

The temporary Firefox profile contains only its explicit NSS trust database.
`acceptInsecureCerts` remains false.
For HTTP/3 only, the fixture configures a loopback Alt-Svc mapping and permits verified private roots to use HTTP/3.
Firefox otherwise [disables HTTP/3 after authenticating a private root](https://github.com/mozilla-firefox/firefox/blob/main/netwerk/protocol/http/Http3Session.cpp).
The precise preferences are `network.http.http3.force-use-alt-svc-mapping-for-testing=true` and `network.http.http3.disable_when_third_party_roots_found=false`, alongside the explicit mapping.
They control protocol selection; each untrusted-root scenario must still return WebDriver's `insecure certificate` error and the native endpoint must observe zero application requests.
This qualifies the declared direct HTTP/3 test policy, not Firefox's default connection-selection behavior.

`firefox_run.sh` performs the six actual scenarios.
The runner records Firefox's policy separately from Chromium's policy and uses the same retained native manifest and completion checks.
Share only the top-level JSON receipts under the `firefox` peer/browser/native/invocation directories.
Run `firefox_archive_test.py`, `firefox_setup_test.py`, `firefox_worker_test.py` and `escript scripts/interop_firefox_test.escript` for the bounded synthetic controls;
Linux-only process controls report a platform skip on other hosts.

# Independent interoperability evidence

Run `mise run interop-setup` and `mise run interop` on Linux with the tools pinned in `standards/interop-profile.json`.
The shell runners use the selected `erl`, `erlc`, `gleam`, `python3`, `curl`, `nghttp`, `nghttpd`, and `go` from `PATH`.

Each peer report has a fresh run nonce and the complete authored source identity.
Before and after execution, the native package's fresh-build manifest must match its source and compiled artifacts.
Both manifests are retained in `build/interop/manifests`; imported reports validate their original runtime and artifacts without comparing them to another platform's BEAM files.
Setting the runner's `SKIP_FRESH_BUILD` flag skips recompilation only; it does not skip verification.

Every driver first uses `--prepare` to remove an older completed report, then captures the 64-digit run ID returned by `--begin`.
Scenario recording, daemon completion, failure cleanup and finalization all require that exact ID.
State changes share one exclusive publication lock.
A second live driver is rejected,
and a delayed operation from an older run cannot remove, extend or mark the new run ready.
The unscoped `--fail` command is reserved for explicit operator recovery and is not used by normal drivers.
Shell and browser drivers reject any begin receipt other than one lowercase 64-digit hexadecimal ID.
Interrupt and termination cleanup preserve status 130 and 143 respectively in the run-scoped typed failure receipt.

`scripts/interop_peer.py` owns each independent process, enforces an absolute deadline of at most 120 seconds and an 8 MiB combined output ceiling, and reaps its process group before publishing completion.
Cancellation or loss of the invoking owner also kills and joins the independent peer.
The scenario oracle in the shell runner must pass before `interop_audit.escript --record` can attach that completed invocation.
A missing invocation, another run's nonce, changed source, changed binary, failed exit, or missing role cannot qualify.

Executable SHA256 and size identify the actual peer binary or interpreter.
Curl and nghttp2 report the resolved shared libraries.
Python additionally records the version and a framed digest of each installed distribution's actual files,
alongside the hash-locked requirements file and the executed fixture.
Its selected virtual environment is preserved, and isolated Python execution excludes the working directory and `PYTHONPATH` from import lookup.

Go peers retain the actual executable and a receipt from the bounded build runner.
The receipt binds every fixture Go source, `go.mod`, `go.sum`, the recipes, profile, compiler and toolchain bytes to the executable built with `-a -mod=readonly -trimpath -buildvcs=false` and `CGO_ENABLED=0`.
A new attempt invalidates the preceding receipt before compilation; restoring an old success after a failed build cannot qualify.
Sources and tools are checked before and after compilation and again around execution.
Source additions, local module replacements, embedded files, native fixture inputs and dynamic linking are rejected by this deliberately narrow pure-Go fixture contract.

The independent Erlang reader inspects the retained ELF's Go build information and verifies its compiler version, module versions/checksums and build settings against the receipt, profile and `go.sum`.
Dependency SHA256 values identify Go checksum strings, with `files: 0`; the executable digest binds the compiled code.
The embedded compiler version must match the exact `go1.27.0` pin.
CI preserves `build/interop/go-build/` (receipts and attempt nonces) and the three fixed Go binaries under `build/interop/bin/`; the audit bundle requires those same paths.
Compiler/toolchain digests record the producing host's observations.
Imported evidence does not claim an independent attestation of that host, and independent audit and signatures remain external conditions.

Quiche 0.29.3 is built from its exact source commit with Rust 1.98.1 in a digest-pinned Docker build image.
Run `bash packages/http3/test/interop/quiche/setup.sh` on Linux, then `bash test/interop/quiche/run.sh`.
The host requires Docker and Python 3.11 or later; it does not need a Rust toolchain.
The locked workspace dependencies,
framed source inventory, actual compiler, Cargo, compiler driver and native build tools are embedded in both executables and verified before and after their build.
The identity-only upstream patch is hashed independently and does not change the peer's network implementation.
The executed binaries and their runtime libraries are hashed again before and after each scenario.
The bidirectional fixture verifies certificate authentication, connection reuse, status, bodies exceeding the initial flow-control window and response trailers.
A daemon must complete the native client's oracle before controlled shutdown can qualify; client payloads are compared to a separate expected file.

The ngtcp2/nghttp3 peer builds ngtcp2 1.25.0, nghttp3 1.18.0 and curl 8.22.0 from SHA256-locked official source archives with GCC 15.2.0.
Run `bash packages/http3/test/interop/ngtcp2/setup.sh`, then `bash test/interop/ngtcp2/run.sh`.
Curl provides the authenticated client frontend for the pinned QUIC/HTTP/3 stack; upstream `gtlsserver` provides the server.
The example `gtlsclient` is excluded because it does not validate the server certificate.
The build image, required development packages, source archives and recipe are pinned.
Each executable reports its actual linked ngtcp2/nghttp3 versions and its role, alongside the source inventories and compiler/tool digests captured before and after compilation.
Runtime libraries are bundled with relative lookup paths and hashed at execution.
A report from the other role, another recipe or a different library version cannot qualify.
This peer deliberately shares quiche's bounded public-API native oracle;
invocations, identities and completion records remain separate.
Its client requires HTTP/3 without TCP fallback and checks status, 72,000-byte bodies,
response trailers and the exact certificate-rejection exit code.

The OHTTP Go peer pins `github.com/chris-wood/ohttp-go` at `v0.0.0-20260205154755-776f22a178b8`, compiled with Go 1.27.0 and the checked-in `go.sum`.
Run `bash test/interop/ohttpgo/setup.sh`, then `bash test/interop/ohttpgo/run.sh`.
Six scenarios cover independent client,
relay and gateway roles with AES-128-GCM and ChaCha20-Poly1305.
Both outer connections validate the fixture CA over TLS.
The opaque relay forwards only the fixed gateway destination, OHTTP media type and encrypted bytes; the native gateway rejects leaked cookie and tracking-header fixtures.
Status,
66,000-byte content, headers, trailers, padding, ciphertext tampering and incorrect media types have explicit oracles.
Each finite peer server exits successfully only after all three expected requests finish, and the native oracle must also pass before the completed invocation is recorded.
The AES client deliberately omits the ALPN extension, and the ChaCha20 client advertises HTTP/1.1.
The Go gateway and relay also exercise HTTP/2, including an immediate response to an unfinished empty request followed by a normal stream reset.
Completed responses and later pooled exchanges must survive that reset sequence as required by RFC 9113 section 8.1.

This peer covers known-length Binary HTTP.
Its pinned request decoder fails on nonempty trailers, so its gateway compares decrypted request bytes against the independent implementation's encoder output, including 128 padding bytes.
No upstream behavior is patched.
Its response decoder and both HPKE/OHTTP directions run normally.
The relay is a small Go HTTP fixture around the opaque encrypted message; it does not claim a separate relay library implementation.
`go test -mod=readonly -count=1 -timeout=30s ./...` in `test/interop/ohttpgo` checks both AEADs and deliberately mutated plaintext and size boundaries.

The TypeScript peer executes the published `ohttp-ts` 0.5.1 package.
npm's integrity lock pins `bhttp-ts` 0.5.3, `hpke` 1.1.8 and `quicvarint` 0.2.1.
An override also selects `hpke` 1.1.8 for `ohttp-ts`.
Setup requires Node.js 26.13.0 and npm 11.20.0.
Setup checks both versions, disables lifecycle scripts, and copies the bounded JavaScript fixture into an isolated build directory.
Run `mise x node@26.13.0 -- bash test/interop/ohttpts/setup.sh`, then `mise x node@26.13.0 -- bash test/interop/ohttpts/run.sh`.
No upstream code is patched.
Three roles and both AEADs cover the same native public-API OHTTP contract as the Go peer, with the independent TypeScript streaming Binary HTTP encoder/decoder checking indeterminate-length and known-length messages, 66,000-byte bodies, headers, trailers and padding.
Both directions use verified TLS 1.3 over HTTP/1.1.
The relay fixture forwards opaque ciphertext to a fixed gateway and does not claim to be a third-party relay library.
Its 128 KiB wire/plaintext ceilings are fixture limits; they are not attributed to the ordinary upstream OHTTP API.

The TypeScript executable identity includes the actual Node binary and loaded runtime libraries, the source fixture digest, the exact lock, and every file in all four installed packages.
Cached upstream tarballs must match the lock's SHA-512 integrity values; each installed file must also match its locked tarball before and after execution.
The verifier never extracts paths and rejects special entries, duplicate files and oversized expansion.
Node loader environment overrides, native addons, global module lookup, unpinned packages, symlinked dependencies,
version drift and changed fixture copies cannot qualify.
The report contains only framed digests and fixed identity fields.
Each server has a 45-second absolute lifetime and observes completed handlers and socket close events before exiting normally.
Run the crypto, tamper, plaintext-oracle and byte limit controls with `node --disable-proto=throw --no-addons --no-global-search-paths --test --test-timeout=30000 build/interop/ohttpts/peer_test.mjs` after setup.
Node's experimental ChaCha20 WebCrypto notice is local diagnostic output; reports retain its byte count only.

The installed Node inventory also matches the archive-derived directory set.
One closure-wide file/directory count, byte ceiling, path-byte ceiling and depth ceiling bound traversal; hard links, links, reparse points, special files, duplicate names and changes during the scan are rejected.

The public reports contain only bounded identity and completion facts.
Arguments, environment values, host paths, endpoints, stdout/stderr contents,
and output hashes are omitted.
Raw protocol traces and failure logs remain local diagnostics; they are not the peer report artifact.
Failed executions retain only the fixed failure phase and bounded completion facts under `build/interop/failures`; they cannot mint a successful invocation.
Cancellation is retained as a finite `cancelled` result with the canonical process exit status.
Failure-report publication and diagnostic-sink failures cannot replace that original exit status or expose exception values.
The independent Erlang cleanup audit rejects unknown fields, stale source or run identities, undeclared scenarios, malformed exit facts, oversized files,
links, hard links, and noncanonical file names before writing `build/interop/failure-audits/PEER.json`.
That receipt records the declared peer pin, execution environment, verified scope, failure classifications, and a fixed rerun command.
CI publishes failed-run files only together with this current-source receipt.

CI also passes the completed peer step's exact outcome to `interop_audit.escript --verify-published-failures-for PEER OUTCOME`.
`success` requires an empty failure set; `failure` requires the named peer's current audited receipt.
Cancelled, skipped, missing, or mixed evidence cannot satisfy that gate.

The independent MASQUE peer uses `masque-go` 0.4.0 as both CONNECT-UDP client and proxy.
Two concurrent flows on one authenticated HTTP/3 connection each exchange eight tagged datagrams; a disallowed target must return 502 without creating another relay.
The native fixture retains actual flow, datagram,
rejection and joined-worker counts with a fresh nonce.
Its supervisor requires the VM to exit, the source and compiled fixture to remain unchanged, and zero stdout/stderr before attaching the result to the independent invocation.
The standalone receipts under `build/interop/native/masque-independent/` and the peer report's embedded copies are preserved in CI and the audit bundle.
Run `mise run interop-masque`; see [the fixture contract](masquego/README.md) for its explicit scope.
CONNECT-IP requires separate evidence.

The native supervisor's controls start actual Erlang child processes with no result, a stale nonce, private output, an output flood, a valid result followed by a stall, a controlled exception, and source replacement during execution.
Loader environment overrides are removed only from the child.
These synthetic programs verify the supervisor; they cannot qualify as interoperability.
Run `python3 -B test/interop/masquego/native_runner_test.py` on Linux with the pinned Erlang tools.

The curl certificate-negative scenario requires exit 60 specifically.
Connection refusal and timeout cannot stand in for successful certificate verification rejection.
Its HTTP/2 multiplexing scenario requires two simultaneous handlers on the same TCP connection before either can respond.

The nghttp2 runner exercises both roles, with bodies larger than the initial HTTP/2 flow-control window and request/response trailers.
It compares actual client stdout to a separate expected body file.
The daemon owns an ephemeral loopback port from startup; its supervisor discovers that owned socket without closing a reservation first.
Server completion requires a current-run oracle signal followed by an observed, controlled SIGTERM exit.
An early daemon exit does not satisfy the scenario.

Run the harness regressions with `python3 -B scripts/interop_peer_test.py`,
`python3 -B scripts/interop_cleanup_test.py`,
`python3 -B test/interop/browser/run_contract_test.py`, and `escript scripts/interop_audit.escript --self-test`.
Run `python3 -B test/interop/ngtcp2/verify_response.py --self-test` and `python3 -B test/interop/quiche/verify_response.py --self-test` for the bounded independent-response oracles.
Run `escript scripts/interop_fixture_audit.escript` for the native endpoint limits and truthful drain contract.
Native HTTP/3 response collection has a 128 KiB byte ceiling and 4,096-event budget, including empty DATA events; a forced drain cannot qualify as completed interoperability.
The process tests require POSIX, like the interoperability runners.
The overall peer matrix remains `Blocked` while any configured independent implementation lacks an actual completed, current-source report.

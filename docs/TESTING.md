# Testing

HTTP/3 combines untrusted binary protocols, cryptographic state, asynchronous
messages, processes, timers, and UDP sockets. Tests must make failures
reproducible and leave the runtime in a known state. This guide applies to
every change while the v1 gate remains reopened.

## Development loop

Use Red-Green-Refactor for every behavior change:

1. **Red:** write the smallest test for the intended observable behavior and
   confirm that it fails for the expected reason.
2. **Green:** make the smallest implementation change that passes the new test
   and the existing applicable suites.
3. **Refactor:** improve code and test structure while keeping all suites
   green.

A bug fix must begin with a regression that reproduces the defect. Preserve
the regression after the fix. A test that already passed on the defective code
does not establish the failure and must be made more precise.

Documentation-only and configuration-only changes do not need invented
protocol tests, but they still run the complete local quality check.

## Verification layers

Run every layer affected by a change. Record why a genuinely unrelated layer
was not run instead of adding an assertion with no value.

### Pure and state-model tests

- Test every codec with published examples, boundaries, truncation, invalid
  semantics, non-byte-aligned input, and peer-controlled allocation limits.
- Test TLS transcripts, key transitions, transport state, recovery, congestion,
  stream lifecycle, HTTP/3 ordering, and QPACK references deterministically.
- Test error and event normalization without exposing raw native handles.
- Keep retained regression inputs for every parser or state-machine defect.

The native package suite is run by `mise run core-check`; it is also the
first stage of the root `mise run check`.

### Real UDP and public behavior

An in-memory model does not replace a real UDP loopback test. The public suite
must exercise:

- default certificate-chain and hostname or IP verification;
- IPv4 and IPv6 where the host supports them;
- bounded and streaming clients and servers;
- concurrent streams and connections, flow-control pressure, and slow
  consumers;
- cancellation races, timeout, peer termination, graceful drain, immediate
  stop, and owner termination;
- QUIC v1/v2, loss, reordering, Retry, resumption, 0-RTT, migration, ECN, and
  MTU behavior where applicable; and
- informational responses, trailers, push, Capsules, Extended CONNECT, HTTP
  Datagrams, priority, and qlog through the public API.

Every request fixture asserts status, headers, and body rather than accepting a
successful function return as sufficient.

### Generated properties and parser fuzzing

Each package owns the corpus for the decoders it implements, so both tasks run
two runners: `test/native/gleam_quic_fuzz.gleam` and
`test/native/gleam_quic_property.gleam` here, and
`packages/gleam_quic/test/gleam_quic_fuzz.gleam` and
`packages/gleam_quic/test/gleam_quic_property.gleam` in the core package.

`mise run property` executes 10,000 deterministic generated round-trip and
wire-codec properties per runner. `mise run fuzz` executes 10,000 deterministic
parser inputs plus 16 retained seeds per runner, together covering QUIC,
transport parameters, TLS, HTTP/3, QPACK, and Capsule decoders.

These tasks are reproducible test generators, not a replacement for
coverage-guided fuzzing under a native sanitizer. A crashing or divergent case
must be minimized and added to the retained corpus before it is fixed.

### Fault injection

`mise run fault` uses the public client and server over real UDP through a
deterministic userspace proxy. The fixed gate covers:

- duplicate datagrams and idempotent processing;
- corruption followed by authenticated discard and recovery;
- delayed datagrams and retransmission; and
- deterministic packet loss and recovery;
- datagram reordering without stream corruption; and
- a constrained path MTU that still completes application requests.

The normal public suite additionally covers Initial-loss and streaming-loss
variants. Pure models cover exhaustion, clock edges, replay,
amplification, ECN failure, migration, reset, and key lifecycle without making
wall-clock races part of the assertion.

### Independent interoperability

`mise run interop` exercises both native endpoint roles against two
independently implemented stacks:

| Peer | Version | Native client | Native server |
| --- | --- | --- | --- |
| aioquic | 1.3.0, hash-locked | Starts with v1 against a v2-only peer, authenticates RFC 9368 negotiation, verifies the CA and hostname, exchanges an Extended CONNECT Datagram, migrates, resumes, sends observed 0-RTT, and writes qlog | Accepts a TLS-verified bounded POST from the peer and writes qlog |
| quic-go | 0.61.0, Go module checksums | Streams a POST over explicitly selected QUIC v1 and v2 and writes qlog | Accepts TLS-verified POST requests from explicit v1 and v2 peer clients and writes qlog |

The aioquic peer records explicit markers for QUIC v2, Datagram receipt, the
post-migration request, and receipt before handshake completion. Its flushed
qlog must contain an actual 0-RTT packet. Every native and peer endpoint must
produce a non-empty qlog.

Install the hash-locked Python environment, then run the gate:

```sh
mise run interop-setup
mise run interop
```

The runner pins its Python dependency graph and Go module graph, places all
temporary binaries and qlogs in a unique temporary directory, applies GNU
`timeout` to every peer operation, terminates remaining children in a trap,
and refuses to recursively clean an unexpected path. See
[`test/interop`](../test/interop/README.md).

### Conformance evidence

Conformance must be established by the native source, not by an external
production backend:

- RFC and published cryptographic/QPACK known-answer vectors;
- strict codec and semantic negative tests;
- deterministic TLS, QUIC, HTTP/3, and QPACK state models;
- generated properties and retained parser fuzz cases;
- real-UDP protocol-error, loss, reordering, fault, and lifecycle cases; and
- two independent client/server peer implementations.

This repository does not label an unrelated peer's unit-test count as native
conformance and does not claim the existence of an official monolithic HTTP/3
certification runner. When a maintained relevant runner becomes available, it
is added as another gate rather than replacing the corpus above.

### Performance and lifetime

The public harness defines three fixed workloads:

| Task | Warm-up | Measured trials | Connections | Requests per connection | Payload |
| --- | ---: | ---: | ---: | ---: | ---: |
| `mise run benchmark` | 1 | 5 | 4 | 100 | 1 KiB |
| `mise run load` | 1 | 3 | 32 | 100 | 16 KiB |
| `mise run soak` | 1 | 1 | 8 | 10,000 | 1 KiB |

Each worker owns one TLS-verified reusable connection and verifies every echoed
body. The interval includes connect, all streams, close, listener stop, and
cleanup convergence. The soak task runs 80,000 warm-up streams plus 80,000
measured streams. Each row records process count, total mailbox messages, and
BEAM memory before and after cleanup. See [Performance](../benchmarks/README.md)
for the methodology, uncertainty, environment, and raw results.

### Optional BeamTrace diagnostics

`mise run diagnose -- <scenario>` records one explicitly requested local
diagnostic root with an externally installed BeamTrace v0.2.x executable.
BeamTrace is not added to either package dependency graph, the runner does not
download or upload anything, and this task is excluded from normal CI,
release gates, and performance evidence.

The harness warms code and crypto paths before the trace root, uses metadata
mode and the `gleam-actor` preset, writes only strict-metadata qlog, and retains
a finite artifact set when a workload or clock check fails. A clock self-check
must confirm one node-local monotonic domain before timing or compare is
enabled. See the [diagnostic runner](../test/diagnostics/README.md) for
scenarios, artifact handling, redaction, and issue-sharing guidance.

## Current 2026-08-25 worktree evidence

The following gates pass on the current uncommitted OTP 29 worktree:

- `mise run check`: 208 native-core tests, 226 public-package tests (102
  HTTP/3/QPACK/driver tests moved with source ownership; none were dropped),
  warnings-as-errors builds, documentation, canonical compiler API snapshots,
  glinter, Markdown/TOML/workflow/shell/spelling lint, REUSE, Dialyzer, xref,
  repository Semgrep rules, gitleaks, and a twice-exported, content-audited,
  byte-reproducible `gleam_quic` Hex archive;
- `mise run security`: the same FFI and licence checks plus OSV dependency
  lookup and CycloneDX generation;
- `mise run property` and `mise run fuzz`: 10,000 generated cases each plus
  retained fuzz seeds;
- `mise run fault`: all six fixed real-UDP duplicate, corruption, delay, MTU,
  loss, and reordering scenarios; and
- `mise run interop`: bidirectional aioquic 1.3.0 and quic-go 0.61.0, including
  QUIC v1/v2 and a peer-observed wire 0-RTT request.

Raw consecutive Gleam 1.18.1 exports can emit the two core dependencies in a
different metadata order even though `contents.tar.gz` is identical. The
`core-package` stage validates the original Hex checksum, canonicalizes that
unordered metadata and all outer tar attributes, recomputes the Hex checksum,
audits the actual and declared file sets, and compares two outputs byte for
byte. Its current canonical SHA-256 is
`5672B5C1D0650496413796D20A9B8DB69D3AC4278276B4488858DAD31C91A74D`.
The root export still correctly refuses its development-only path dependency;
the required temporary-registry, exact-semver, empty-consumer, OTP 28/29
release simulation is therefore open. The current performance diagnostic also
fails the fixed thresholds and recorded one long-load peer-close failure.
These passing gates are strong incremental evidence, not a release-candidate
qualification.

## Superseded 2026-08-24 qualification record

The former completion record reported:

- `mise run check`: 278 native-core tests and 108 public-package tests, both
  warnings-as-errors builds, generated documentation, compiler public-interface
  audit, glinter, Markdown, TOML, GitHub Actions, shell, spelling, and REUSE
  checks;
- `mise run property`: 10,000 generated cases;
- `mise run fuzz`: 10,000 generated cases plus 16 retained seeds;
- `mise run fault`: all four fixed real-UDP fault scenarios;
- `mise run interop`: bidirectional aioquic 1.3.0 and quic-go 0.61.0 gates,
  including quic-go v1/v2 and aioquic's authenticated v1-to-v2 negotiation and
  advanced observations; and
- benchmark, load, and 160,000-stream soak tasks with every raw row retained.

The full local gate used Linux with Erlang/OTP 29. The intended lower bound
was also built and tested in the official `erlang:28-alpine` image at digest
`sha256:17385598fb0470d8f63511f1e69eed2338bf0fad0ae1972570cd100767d01859`:
all 108 root and 278 native tests passed after a clean dependency resolution.
CI separately defines OTP 28–29 build/test jobs and Linux, macOS, and Windows
smoke jobs. The workflow uses pinned actions and is checked by `actionlint`;
hosted operating-system outcomes were not observed in this repository.

This record predates the reopened findings and does not qualify the current
worktree. It lacks the required coverage thresholds, million-case nightly
model run, expanded deterministic faults, ngtcp2/nghttp3 and quiche peers,
TLS/mTLS matrix, qlog schema/qvis gate, CUBIC reference differential,
two-package release simulation, fixed performance thresholds, and
clean-archive rerun. Dialyzer/xref, secret/static/dependency/licence scanners,
and CycloneDX generation have since been added, but do not qualify the old
record. See the [conformance matrix](CONFORMANCE.md).

## Timeouts

Every wait for a process, message, stream, connection, listener, timer, socket,
or peer has a fixed upper bound. Do not use an unbounded receive or an
arbitrary sleep as synchronization. Wait for an observable readiness,
protocol, or shutdown event.

A timeout is a test failure, not successful cancellation. Include enough
operation and connection or stream context to diagnose the blocked state
without logging secrets.

## Process and socket cleanup

Each fixture has one clear owner for every process, connection, stream,
listener, peer process, file, temporary directory, and UDP socket. Register
cleanup immediately after acquiring a resource and run it when setup, an
assertion, or the body fails.

Cleanup must:

1. stop accepting new work;
2. cancel or close owned streams and connections;
3. close listeners, files, and sockets;
4. terminate independent peer children;
5. wait with a fixed timeout for owned processes to terminate; and
6. fail if a resource remains alive or cleanup reports an unexpected error.

Shutdown and cancellation paths are idempotent. Tests use OS-assigned loopback
ports, do not depend on execution order, and do not leave mailbox messages,
qlogs, Python bytecode, or temporary peer artifacts in the working tree.

The Erlang qlog fixtures in `test/http3_test_ffi.erl` and
`packages/gleam_quic/test/qlog_test_ffi.erl` create their scratch directories
under the first non-empty of the `TMPDIR`, `TEMP`, and `TMP` environment
variables, falling back to `/tmp`, so they still run where `/tmp` is read-only
or absent, and each fixture deletes the uniquely named subdirectory it created.
The shell runners `test/interop/run.sh` and `test/diagnostics/run.sh` honour
only `${TMPDIR:-/tmp}`.

## Local completion commands

Run the reproducible local gate from the repository root:

```sh
mise install
mise run check
mise run security
mise run fault
mise run property
mise run fuzz
mise run interop-setup
mise run interop
mise run benchmark
mise run load
mise run soak
```

`mise run check` includes both package builds/tests/docs/lints, canonical API
snapshots, the three-layer package-private import boundary gate, FFI
Dialyzer/xref, repository Semgrep rules, REUSE, gitleaks, and the
deterministic core-package archive gate. The Semgrep task keeps its
settings file and log under the gitignored `build/semgrep/` rather than `/tmp`,
so the gate also runs where `/tmp` is read-only or absent.
`mise run security` adds the online OSV lookup and generates
`build/security/http3.cdx.json` as CycloneDX evidence. Expensive fault,
interop, and performance tasks remain separate. Passing a normal gate means an
edit is internally consistent; it does not close the release findings. A
phase is complete only when its applicable separate gates pass, their evidence
is retained, and the conformance matrix is updated honestly.

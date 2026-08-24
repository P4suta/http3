# Testing

HTTP/3 combines untrusted binary protocols, cryptographic state, asynchronous
messages, processes, timers, and UDP sockets. Tests must make failures
reproducible and leave the runtime in a known state. This guide applies to
every future change, including changes made after the v1 source-tree gate.

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

`mise run property` executes 10,000 deterministic generated round-trip and
wire-codec properties. `mise run fuzz` executes 10,000 deterministic parser
inputs plus 16 retained seeds across QUIC, transport parameters, TLS,
HTTP/3, QPACK, and Capsule decoders.

These tasks are reproducible test generators, not a replacement for
coverage-guided fuzzing under a native sanitizer. A crashing or divergent case
must be minimized and added to the retained corpus before it is fixed.

### Fault injection

`mise run fault` uses the public client and server over real UDP through a
deterministic userspace proxy. The fixed gate covers:

- duplicate datagrams and idempotent processing;
- corruption followed by authenticated discard and recovery;
- delayed datagrams and retransmission; and
- a constrained path MTU that still completes application requests.

The normal public suite additionally covers deterministic Initial loss and
datagram reordering. Pure models cover exhaustion, clock edges, replay,
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

Conformance is established by the native source, not by an external production
backend:

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

## 2026-08-24 qualification record

The completed local record is:

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

The full local gate uses Linux with Erlang/OTP 29. The supported lower bound
was also built and tested in the official `erlang:28-alpine` image at digest
`sha256:17385598fb0470d8f63511f1e69eed2338bf0fad0ae1972570cd100767d01859`:
all 108 root and 278 native tests passed after a clean dependency resolution.
CI separately defines OTP 28–29 build/test jobs and Linux, macOS, and Windows
smoke jobs. The workflow uses pinned actions and is checked by `actionlint`;
hosted operating-system outcomes are a publication preflight once a hosted
repository exists.

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

## Local completion commands

Run the reproducible local gate from the repository root:

```sh
mise install
mise run check
mise run fault
mise run property
mise run fuzz
mise run interop-setup
mise run interop
mise run benchmark
mise run load
mise run soak
```

The expensive network and performance tasks are intentionally separate from
`mise run check` so a fast edit loop remains possible. A phase is complete
only when its applicable separate gates also pass and their evidence is
retained.

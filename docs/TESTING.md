# Testing

HTTP/3 combines protocol state machines, asynchronous messages, processes,
and UDP sockets. Tests must make failures reproducible and must leave the
runtime in a known state. This guide applies throughout implementation, not
only after a client or server API is complete.

## Development loop

Use Red-Green-Refactor for every behavior change:

1. **Red:** write the smallest test that describes the intended observable
   behavior and confirm that it fails for the expected reason.
2. **Green:** make the smallest implementation change that passes the new
   test and the existing suite.
3. **Refactor:** improve the implementation and test structure while keeping
   the suite green.

A bug fix must start with a regression test that reproduces the bug. Preserve
that test after the fix so the same failure cannot silently return. A test
that passes before the fix does not demonstrate the regression and must be
made more precise.

Documentation-only and configuration-only changes do not require invented
behavior tests, but they must still pass the complete local check.

## Verification layers

Every implementation change must exercise each applicable layer below. When
a layer is genuinely unaffected, record that fact in the change description
rather than adding a test with no useful assertion.

### For every implementation change

- Add pure unit tests for parsing, validation, limits, state transitions, and
  other deterministic logic.
- Test translation of backend events and failures into internal or public
  HTTP/3 events and errors. Raw backend atoms, maps, PIDs, references, and
  mailbox messages are test inputs below the adapter boundary, never public
  assertions.
- Exercise affected network behavior with a local loopback test over real UDP.
  An in-memory mock is useful for unit tests but does not replace this test.
- Run `mise run check` before considering the change complete.
- Audit the compiler-exported package interface so internal adapter modules,
  backend handle types, and construction bridges never enter the public API.

A loopback request-response test must perform actual HTTP/3 work, use bounded
request and response bodies, and assert the response status, headers, and
body. Test-only certificate configuration may be used for a local fixture;
any verification bypass must remain in an explicitly named, test-only surface
and must not enter normal client configuration.

### At the end of each implementation phase

- Run interoperability tests against at least one independently implemented
  HTTP/3 peer. Pin or record the peer version so failures can be reproduced.
- Run the applicable conformance suite and retain the exact suite version and
  invocation.
- Run fault-injection scenarios relevant to the phase, including packet loss,
  reordering, malformed or unexpected events, peer termination, and resource
  exhaustion where applicable.

Using the same backend on both sides is valuable loopback coverage, but it is
not independent interoperability evidence.

## Phase verification records

### Bounded buffered client — 2026-08-23

- The repository suite exercises the public API over real loopback UDP,
  including POST request bodies, response frames, untrusted-chain and hostname
  TLS rejection, fixed timeouts, request and response limits, peer termination,
  and deterministic loss and reordering of client datagrams through a
  userspace UDP proxy.
- Independent interoperability used aioquic 1.3.0 as the server. A request
  through the public `http3/client` API used the local CA without disabling
  hostname verification, sent `POST /interop` with a buffered body, and
  verified the returned status, peer header, and body.
- Applicable backend conformance used the resolved quic 1.8.1 source at
  commit `149301743b3607b5f6075dd5d58871ebadc57a2a`. Running
  `rebar3 eunit --module=quic_h3_compliance_tests` completed 185 RFC 9114 and
  RFC 9204 tests with no failures. This records the wire backend's suite; it
  does not claim that wrapper-level tests replace protocol conformance.
- The completion command is `mise run check`. The recorded run completed all
  project checks and 37 repository tests with no failures.

### Streaming, backpressure, and cancellation — 2026-08-23

- The repository suite exercises reusable connections and concurrent request
  streams over real UDP, multi-chunk request and response bodies, early
  responses, declared content lengths, fixed total stream timeouts, slow
  consumer limits, finish-state errors, peer termination, and owner cleanup.
- Race fixtures start two receivers or cancellers together without arbitrary
  sleeps. They verify one blocked receiver is released by cancellation,
  concurrent receive is rejected, and simultaneous cancellation returns one
  `Cancelled` plus one `AlreadyCancelled` result.
- Send-side pressure uses sixteen 16 KiB chunks with synchronous backend
  acceptance and a 256 KiB echoed response. Fault coverage repeats the
  streaming path through deterministic initial UDP packet loss.
- Independent interoperability used aioquic 1.3.0 as the server. The public
  streaming API connected with the local CA and hostname verification,
  transmitted two request chunks, observed response headers and two response
  data writes, and verified the complete body before idempotent shutdown.
- Applicable wire conformance remains the resolved quic 1.8.1 HTTP/3
  compliance module: 185 RFC 9114 and RFC 9204 tests completed without
  failures. Wrapper tests cover the lifecycle and event semantics added in
  this phase.
- The completion command is `mise run check`. The recorded run completed all
  project checks and 57 repository tests with no failures.

### Server — 2026-08-23

- The repository suite exercises the public server over real UDP, including
  bounded and multi-chunk request and response bodies, request metadata,
  declared content lengths, same-connection multiplexing, concurrent clients,
  concurrent accept rejection, fixed timeouts, and idempotent shutdown.
- Limit and lifecycle fixtures cover request and response body limits, bounded
  unconsumed request data, abrupt peer termination, blocked accept release,
  listener-owner termination, invalid credentials, and removal of completed
  request state. Pure tests cover response header validation and backend error
  normalization, including HTTP/3 stream-reset code 270.
- Independent interoperability used aioquic 1.3.0 as the client. It verified
  the local certificate and hostname, sent a two-chunk `POST` body, and
  consumed the public Gleam server's two-chunk response with status 202 and a
  declared content length.
- Applicable wire conformance remains the resolved quic 1.8.1 HTTP/3
  compliance module at commit
  `149301743b3607b5f6075dd5d58871ebadc57a2a`: 185 RFC 9114 and RFC 9204 tests
  completed without failures. The backend suite covers malformed wire input;
  wrapper tests separately cover normalization and resource ownership.
- The completion command is `mise run check`. The recorded repository test
  count before that command is 74 tests with no failures.

### Advanced transport capabilities — 2026-08-23

- The repository suite exercises HTTP Datagram negotiation, bidirectional
  payloads, maximum size, invalid alignment, bounded orphan data, and a
  deterministic concurrent-receive race over real UDP. It also covers client
  and server priority, qlog creation, congestion control, ping, MTU and
  statistics, migration followed by another request, ticket origin binding,
  unsafe-method rejection, and accepted 0-RTT on both peers.
- Independent interoperability used aioquic 1.3.0 as the server. The public
  API verified its certificate and hostname, exchanged an HTTP Datagram,
  changed priority and congestion control, generated qlog, migrated the client
  path and completed another request, acquired an origin-bound ticket, and
  sent an actual early request before the delayed handshake completed. The
  peer observed all three wire events rather than inferring them from local
  state. Reproduction files and exact commands are in
  [`test/interop`](../test/interop/README.md).
- Fault coverage rejects disabled Datagram negotiation, oversized and
  unaligned payloads, concurrent pulls, buffer exhaustion, cross-origin ticket
  use, and replay-unsafe POST before network request work. Existing
  deterministic loss and reordering fixtures continue to cover the shared
  transport path; the pinned compliance suite covers malformed HTTP/3 and
  QPACK wire input and wrapper tests cover typed normalization.
- Applicable wire conformance was rerun from the resolved quic 1.8.1 source at
  commit `149301743b3607b5f6075dd5d58871ebadc57a2a`. The upstream source
  checkout command `rebar3 eunit --module=quic_h3_compliance_tests` completed
  185 RFC 9114 and RFC 9204 tests with no failures. The Hex dependency omits
  upstream test sources, so conformance must run from that exact checkout.
- The repository suite completed 81 tests with no failures before the final
  completion check.
- `mise run api` exports the compiler package interface and rejects internal
  module names, backend handle types, or construction bridges while requiring
  the supported advanced accessors. A separate package compile confirmed the
  public opaque types remain usable and the removed bridge is not addressable.

### During performance work

- Use load tests to measure behavior under controlled concurrency and
  flow-control pressure.
- Use soak tests long enough to expose leaks, mailbox growth, and cleanup
  failures.
- Keep benchmarks reproducible: pin the toolchain and peer, record hardware
  and runtime settings, define payloads and concurrency, include warm-up and
  repeated trials, and retain raw results alongside summaries.

Performance claims must identify the benchmark procedure and uncertainty;
isolated best-case numbers are not sufficient.

### Performance verification — 2026-08-23

- `mise run benchmark` completed one warm-up and five measured trials using
  four reusable connections, 100 requests per connection, and 1 KiB request
  and response bodies. Measured throughput ranged from 1,133 through 1,181
  requests/second, with a median of 1,173.
- `mise run load` completed one warm-up and three measured trials using 32
  reusable connections, 100 requests per connection, and 16 KiB bodies.
  Measured throughput ranged from 1,239 through 1,311 requests/second, with a
  median of 1,291.
- `mise run soak` completed an 80,000-stream warm-up and an 80,000-stream
  measured trial on eight reusable connections. The measured trial took
  76.018408 seconds. Process counts returned below their starting values and
  total mailbox messages returned to zero after both iterations.
- The harness uses only public client and server APIs over real loopback UDP,
  verifies every echoed body, and applies fixed operation, worker, and cleanup
  timeouts. The exact methodology, uncertainty, environment, and all raw rows
  are retained in [Performance](../benchmarks/README.md).

### Native wire core — 2026-08-23

- The separate `gleam_quic` package starts with published RFC vectors for QUIC
  variable-length integers and packet-number reconstruction.
- Pure tests cover QUIC v1 and v2 long-header type mappings, Version
  Negotiation, unknown-version invariants, coalesced length-bearing packets,
  Retry separation, short headers, connection-ID limits, truncation, and
  non-byte-aligned input.
- The frame suite round-trips every RFC 9000 transport frame shape plus RFC
  9221 DATAGRAM, accepts permitted non-minimal integers and lengthless terminal
  frames, and rejects invalid ACK arithmetic, UTF-8, connection IDs, reset
  tokens, truncation, unknown frame types, and resource-limit violations.
- The transport parameter suite round-trips the complete RFC 9000 registry and
  the RFC 9221, RFC 9287, and RFC 9368 extensions. It covers unknown parameter
  preservation, duplicate rejection, sender roles, semantic ranges, required
  handshake parameters, downgrade-information structure, and count/value
  limits.
- RFC 5869, RFC 9001, and RFC 9369 vectors cover multi-block HKDF-SHA256,
  Initial secrets and directional keys, AES-128-GCM payload protection, header
  protection sampling and masking, packet-number encoding, authenticated
  decryption failure, and v1/v2 Retry Integrity Tags. Negative cases cover
  alignment, lengths, unsupported versions, ambiguity, and tampering without
  leaking runtime exceptions.
- Published RFC 5869, RFC 7748, RFC 8448, RFC 9001, and RFC 9369 vectors now
  cover SHA-256/SHA-384, X25519, the TLS 1.3 key schedule, AES-128-GCM,
  AES-256-GCM, ChaCha20-Poly1305, header protection, traffic-key update labels,
  Initial packets, and Retry authentication.
- Typed TLS tests cover handshake and extension bounds, duplicate extensions,
  SNI, ALPN, supported versions, groups and signature schemes, certificate and
  ticket messages, transcript rewriting, trust-anchor/path validation,
  localhost service identity, signature tampering, and constant-time tag
  comparison. A pure client/server state-model test completes ClientHello
  through authenticated Finished and installs matching Handshake and 1-RTT
  traffic keys; ALPN mismatch and Finished corruption are fatal.
- `mise run core-check` runs package format, warnings-as-errors build, 77 tests,
  documentation, and glinter. The root `mise run check` includes this gate so
  native-core regressions cannot pass the existing wrapper checks.

## Timeouts

Every wait for a process, message, stream, connection, listener, or peer must
have a fixed upper bound. Do not use an unbounded receive or an arbitrary
sleep as synchronization. Prefer waiting for an observable readiness or
shutdown event, with a timeout that is long enough for supported CI systems
but short enough to make a stuck test fail promptly.

Timeouts are test failures, not successful cancellation. Include the
operation and relevant connection or stream identifier in the failure so the
blocked state can be diagnosed without rerunning the test interactively.

## Process and socket cleanup

Each fixture must have one clear owner for every process, connection, stream,
listener, and UDP socket that it creates. Register cleanup immediately after
acquiring a resource and run it even when setup, an assertion, or the test
body fails.

Cleanup must:

1. stop accepting new work;
2. cancel or close owned streams and connections;
3. close listeners and sockets;
4. wait, with a fixed timeout, for owned processes to terminate; and
5. fail the test if resources remain alive or cleanup reports an unexpected
   error.

Shutdown and cancellation paths must be idempotent. Tests should use
OS-assigned loopback ports rather than fixed shared ports, must not depend on
execution order, and must not leave messages that can affect a later test.

## Local completion check

Run the complete reproducible check from the repository root:

```sh
mise install
mise run check
```

This checks formatting, builds with warnings as errors, runs tests, builds all
configured documentation pages, audits the compiler-exported public API, and
runs the source, Markdown, TOML, workflow, spelling, and REUSE licence checks.
The CI matrix additionally covers Erlang/OTP 26 through 29 and smoke tests on
Linux, macOS, and Windows.

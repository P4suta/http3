# Changelog

All notable changes to this project will be documented in this file. The
format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).
The version in `gleam.toml` is tool metadata; a changelog heading does not
imply a tag, a hosted release, or publication to Hex.

## Unreleased

### Added

- A repository-owned live UDP QUIC v1/v2 core with authenticated compatible
  version negotiation, frames, transport parameters, flow control, recovery,
  NewReno, CUBIC, pacing, ECN, anti-amplification, tokens, connection IDs,
  stateless reset, IPv4/IPv6, PMTU discovery, rebinding, and active migration.
- A native TLS 1.3 coordinator with certificate/path/identity authentication,
  AES-GCM and ChaCha20-Poly1305 packet protection, Retry, key updates,
  encrypted origin-bound tickets, resumption, replay-constrained 0-RTT, and
  rejection fallback.
- Native RFC 9114 HTTP/3 and RFC 9204 QPACK client/server sessions, including
  informational responses, trailers, server push, GOAWAY, graceful drain,
  dynamic-table feedback, blocked-stream limits, and Huffman coding.
- Typed RFC 9218 priority, Extended CONNECT, bounded Capsules, associated HTTP
  Datagrams, qlog, keepalive, congestion selection, and connection/path
  statistics.
- Bounded one-shot and reusable streaming public clients and servers with
  opaque handles, synchronous backpressure, pull events, cancellation,
  independent body/queue limits, total deadlines, SNI certificate selection,
  and deterministic cleanup.
- Reproducible 10,000-case property and parser-fuzz runners, retained fuzz
  seeds, deterministic real-UDP fault injection, and RFC/vector/negative
  conformance tests.
- A hermetic bidirectional interoperability runner for hash-locked aioquic
  1.3.0 and module-pinned quic-go 0.61.0, including explicit QUIC v1/v2,
  RFC 9368, Datagram, migration, qlog, resumption, and observed 0-RTT.
- Fixed benchmark, 32-connection load, and 160,000-stream soak workloads with
  body verification, bounded cleanup, process/mailbox convergence,
  environment metadata, and retained native-core raw results.
- A pre-release conformance matrix with explicit open findings, API,
  deployment/key-rotation, migration, and support guides.
- Compiler-derived semantic API snapshots for both packages and an audit that
  rejects raw codec, HTTP/3 adapter, BBR, backend-string, and native-handle
  leakage.
- A deterministic `gleam_quic` Hex-archive gate that validates the Hex
  checksum and declared file set, rejects tests, build output, interop peers,
  private keys, and HTTP/3/QPACK modules, and canonicalizes nondeterministic
  dependency ordering and tar attributes before proving byte identity.
- A finite external 0-RTT replay guard with opaque fingerprint/retention input,
  atomic caller-store decisions, and fail-closed 1-RTT fallback on rejection,
  callback error, exit, or timeout.
- End-to-end `Telemetry` limit wiring for client/server qlog writers, with one
  bounded active write, configurable waiting capacity, and drop/error/queue
  counters.
- End-to-end stream, frame, Datagram, QPACK, and accept-waiter limit wiring,
  including finite FIFO accept capacity and live transport/SETTINGS values.
- A generic `gleam_quic` public client/server API with opaque connections and
  streams, finite configuration, typed failures, redacted negotiated
  diagnostics, encrypted restart-safe tickets, and direct real-UDP coverage.
- P-256 key exchange with direct and HelloRetryRequest paths, plus public
  disabled/optional/required mTLS, one-call client credentials, redacted
  verified-client fingerprints, resumed reauthentication, and safe 0-RTT
  fallback.
- An optional external BeamTrace diagnostic runner with fixed non-secret actor
  labels, warm-up-before-root scenarios, strict qlog redaction, clock-domain
  validation, finite cleanup checks, and review-before-sharing artifacts.
- A three-layer boundary gate (a Semgrep rule, a `boundary` verb in the public
  API audit with the shrink-only `api/boundary.allow`, and an xref mode) that
  fails any root import of a package-private `gleam_quic` module; the root
  package now owns its RFC 9000 varint and stream-identifier helpers.
- `CLAUDE.md`, a dated evidence convention under `docs/evidence/`, stub tasks
  for the remaining qualification gates, and a nightly workflow skeleton.
- Runtime-only MixGleam 0.6.2 descriptors and a locked packaging gate that
  produces separate `http3` and `gleam_quic` OTP applications for
  Git-SHA-pinned Burrito consumers.

### Changed

- Replaced the external Erlang QUIC backend with the local `gleam_quic` path
  package and removed all external QUIC production dependencies and runtime
  calls.
- Restricted production Erlang FFI to opaque wrapping, UDP/time, runtime
  cryptography/X.509, and qlog file I/O; all wire protocols and state machines
  are Gleam code.
- Reopened the former v1-complete decision and made the open architecture,
  TLS, conformance, qlog, performance, security, interop, and packaging gates
  explicit.
- Hid raw QUIC wire modules and transitional HTTP/3 adapters from the
  `gleam_quic` package interface.
- Moved HTTP/3 sessions, QPACK, Capsules, workers, and their 102 direct tests
  into `http3`; the `gleam_quic` archive now contains transport-only source.
- Aligned the runtime matrix with Gleam 1.18's supported OTP 28/29 range and
  verified both root and native suites at the lower bound.
- Expanded `mise run check` with native-core checks, compiler-interface
  auditing, pinned workflow validation, shell formatting/linting, spelling,
  and REUSE compliance.
- Core-only driver, fuzz, and property tests moved into
  `packages/gleam_quic/test`; `mise run fuzz` and `mise run property` run both
  packages' generators with unchanged case counts.

### Fixed

- Authenticated QUIC Version Negotiation and rejected downgrade or inconsistent
  compatible-version information.
- Drained bursty handshake UDP input without command-path polling latency.
- Bounded terminal stream state and isolated qlog files per connection.
- Preserved valid coalesced HTTP/3 frames across QUIC read boundaries while
  retaining a finite parser buffer and enforcing each frame payload limit.
- Preserved resumption across Retry while correctly rejecting early data and
  waiting for 1-RTT before a request when no viable early key exists.
- Accepted peer zero-length source connection IDs and order-independent reset
  tokens required by independent QUIC implementations.
- Removed the non-functional public BBR option; only implemented NewReno and
  CUBIC remain.
- Replaced 10 ms UDP polling with active-once delivery and protocol-deadline
  timers, including finite relay batches and credit.
- Coalesced duplicate `PATH_CHALLENGE` values and bounded pending responses to
  prevent the reported response-amplification queue attack.
- Replaced backend-formatted failure strings with typed resolution, socket,
  TLS, QUIC, HTTP/3, timeout, close, limit, and overload failures.
- Bounded client and server request/response/Datagram event queues by count as
  well as bytes using amortized O(1) FIFO operations.
- Added atomic certificate and operational-key reload, current/previous key
  rings, and encrypted versioned ticket import/export across restarts.
- Preserved an actual wire-level 0-RTT send for single-address connections while
  retaining authenticated candidate selection for dual-stack racing.
- Replaced per-turn all-connection send polling with a finite dirty-connection
  set; protocol timer expiry still advances every live connection.
- Wired authenticated Retry and reusable `NEW_TOKEN` issuance into the generic
  listener, added an independently rotated address-token key ring, and made
  ticket snapshots include the token before returning so restart 0-RTT is
  deterministic.
- Replaced three interchangeable operational-ring arguments in the generic
  server API with one validated, named `OperationalKeys` bundle that rejects
  cross-purpose key reuse.
- Reissued `NEW_TOKEN` to established generic QUIC and HTTP/3 peers after an
  address-token key reload, allowing operators to retire the previous key
  generation without forcing a Retry on refreshed clients.
- Rejected mismatched certificate/private-key pairs during endpoint
  configuration instead of deferring the failure to a network handshake.
- Rejected client credentials whose leaf certificate is not valid for client
  authentication before opening a socket.
- Kept qlog device-writer failure isolated from transport work, retained
  bounded drop/error counters, and made teardown idempotent after failure.
- Removed raw Hex-archive checksum drift caused by unstable dependency order
  in consecutive Gleam exports; the checked release input now has a stable
  canonical checksum without changing package metadata semantics.
- Made repeated server-side connection close calls report `AlreadyClosed` as
  soon as the first call enters closing or draining, instead of depending on
  packet-flush timing.
- A pacing-limited QUIC connection now derives its wake-up from the congestion
  window and smoothed RTT current at each deadline computation and arms it only
  while output is pending, so queued data no longer stalls until an unrelated
  timer, PTO, or idle timeout.
- QUIC datagrams grow with the DPLPMTUD-validated path MTU: both roles
  advertise the RFC 9000 default `max_udp_payload_size` (65527), 1-RTT packets
  take their frame budget from the path after the coalesced ACK and the exact
  packet-protection overhead, DATAGRAM frames reserve room for the
  acknowledgement they share a packet with, the pacer burst and the
  NewReno/CUBIC `max_datagram_size` follow the path, and Initial, Handshake,
  0-RTT, and ACK-only packets are all measured against the path.
- QUIC UDP sockets request Don't-Fragment at open (Linux
  `IP(V6)_MTU_DISCOVER`, macOS/FreeBSD `IP(V6)_DONTFRAG`, Windows
  `IP_DONTFRAGMENT`); DPLPMTUD stays at the 1200-byte floor when a platform
  refuses it, an oversized send is classified as a path black hole on every
  send path instead of a socket failure, and peer-chosen Initial tokens are
  bounded so no Initial exceeds the floor.
- Test fixtures create qlog scratch directories under `TMPDIR`/`TEMP`/`TMP`
  instead of a hard-coded `/tmp`, and the Semgrep task writes its settings and
  log under `build/semgrep/`.

## 0.1.0 - 2026-08-23

### Added

- An Erlang-target Gleam package with `quic` 1.8.1 as the minimum backend.
- The `http3.is_supported()` backend capability probe.
- A private Gleam adapter and Erlang FFI boundary around `quic:is_available/0`.
- Architecture, roadmap, security, contribution, and licence documentation.
- Reproducible development tools, a complete local check task, and hardened CI
  definitions for OTP and operating-system compatibility.

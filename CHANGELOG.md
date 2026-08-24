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
- A completed public v1 contract, architecture, testing record, and
  pre-publication security review.

### Changed

- Replaced the external Erlang QUIC backend with the local `gleam_quic` path
  package and removed all external QUIC production dependencies and runtime
  calls.
- Restricted production Erlang FFI to opaque wrapping, UDP/time, runtime
  cryptography/X.509, and qlog file I/O; all wire protocols and state machines
  are Gleam code.
- Completed and requalified every roadmap phase on the native backend while
  keeping publication, tags, releases, and the metadata version separate.
- Aligned the runtime matrix with Gleam 1.18's supported OTP 28/29 range and
  verified both root and native suites at the lower bound.
- Expanded `mise run check` with native-core checks, compiler-interface
  auditing, pinned workflow validation, shell formatting/linting, spelling,
  and REUSE compliance.

### Fixed

- Authenticated QUIC Version Negotiation and rejected downgrade or inconsistent
  compatible-version information.
- Drained bursty handshake UDP input without command-path polling latency.
- Bounded terminal stream state and isolated qlog files per connection.
- Preserved resumption across Retry while correctly rejecting early data and
  waiting for 1-RTT before a request when no viable early key exists.
- Accepted peer zero-length source connection IDs and order-independent reset
  tokens required by independent QUIC implementations.

## 0.1.0 - 2026-08-23

### Added

- An Erlang-target Gleam package with `quic` 1.8.1 as the minimum backend.
- The `http3.is_supported()` backend capability probe.
- A private Gleam adapter and Erlang FFI boundary around `quic:is_available/0`.
- Architecture, roadmap, security, contribution, and licence documentation.
- Reproducible development tools, a complete local check task, and hardened CI
  definitions for OTP and operating-system compatibility.

# Changelog

All notable changes to this project will be documented in this file. The
format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).
The version in `gleam.toml` is tool metadata; a changelog heading does not
imply a tag, a hosted release, or publication to Hex.

## Unreleased

### Added

- A bounded one-shot HTTP/3 client using `gleam/http` request and response
  types, secure TLS defaults, explicit request and response limits, and a total
  timeout.
- Typed client configuration and normalized request, connection, stream,
  protocol, timeout, and body-limit errors without exposing backend values.
- Pure request validation for schemes, hosts, ports, methods, targets, HTTP/3
  header rules, content length, and byte-aligned bounded bodies before network
  work begins.
- Real-UDP loopback coverage for POST bodies, headers, multiple response DATA
  frames, headers-only responses, timeouts, TLS rejection, limits, peer
  termination, deterministic packet loss and reordering, and cleanup.
- Recorded public-client interoperability with aioquic 1.3.0 and the resolved
  backend's RFC 9114 and RFC 9204 compliance suite.
- A testing guide covering Red-Green-Refactor, regression tests, verification
  layers, fixed timeouts, resource cleanup, and reproducible performance work.
- Reusable streaming client connections with multiplexed request streams,
  pull-based bounded response events, synchronous producer pressure,
  cancellation, fixed deadlines, and deterministic cleanup.
- A bounded and streaming HTTP/3 server with opaque listener and request
  values, pull-based request bodies, synchronous response chunks, independent
  request and response limits, and idempotent shutdown.
- Recorded streaming-client and server interoperability with aioquic 1.3.0.
- Typed advanced transport controls for HTTP Datagrams, RFC 9218 priority,
  migration, replay-safe 0-RTT and origin-bound tickets, qlog, congestion
  control, ping, MTU, and connection and path statistics.
- Recorded independent aioquic 1.3.0 interoperability for Datagrams, migration,
  qlog, and an actual request sent before handshake completion.
- Reproducible public-API benchmark, controlled load, and sustained soak tasks
  with bounded cleanup, process and mailbox convergence, environment metadata,
  and retained raw results.

### Changed

- Clarified the HTTP/3-only scope, client-first implementation order, backend
  boundary, and capability-based rather than publication-based milestones.

## 0.1.0 - 2026-08-23

### Added

- An Erlang-target Gleam package with `quic` 1.8.1 as the minimum backend.
- The `http3.is_supported()` backend capability probe.
- A private Gleam adapter and Erlang FFI boundary around `quic:is_available/0`.
- Architecture, roadmap, security, contribution, and licence documentation.
- Reproducible development tools, a complete local check task, and hardened CI
  definitions for OTP and operating-system compatibility.

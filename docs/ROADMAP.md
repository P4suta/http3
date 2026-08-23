# Roadmap

The phases below are ordered. Later phases may be designed early, but they do
not displace the compatibility and safety work required by earlier phases.

## 1. Minimum client and server

Build `gleam/http`-compatible request and response types and implement real
HTTP/3 client and server request-response flows. Deliver both bounded buffered
bodies and backpressured streaming bodies. Introduce opaque `Connection` and
`Stream` values while keeping all backend handles and events internal.

This phase also establishes secure TLS defaults, deterministic shutdown, error
normalization, and integration tests against independent HTTP/3 peers.

## 2. Advanced capabilities and escape hatch

Add cancellation, HTTP Datagrams, stream priority, connection migration,
0-RTT, qlog, and other transport controls behind typed capabilities. Low-level
access must remain backend-neutral where possible and must not expose raw PIDs,
atoms, maps, or mailbox messages.

Any certificate-verification bypass remains confined to an explicit test or
development API.

## 3. Verification depth

Expand interoperability, conformance, load, soak, and fault-injection testing.
Cover flow-control pressure, packet loss and reordering, cancellation races,
peer protocol violations, resource limits, and graceful and abrupt shutdown.
Publish repeatable performance methodology rather than isolated benchmark
claims.

## 4. Pure Gleam QUIC backend

Develop a pure Gleam QUIC implementation as a separate package, then integrate
it behind the established backend boundary. Preserve the public `http3` API and
run the same compatibility suite against both backends before changing the
default.

This roadmap does not assign a name or public API to that future package.

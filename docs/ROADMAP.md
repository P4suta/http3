# Roadmap

The phases below are ordered. Later phases may be designed early, but they do
not displace the compatibility and safety work required by earlier phases.
The roadmap is exclusively for HTTP/3 on the Erlang target. HTTP/1.1, HTTP/2,
automatic protocol fallback, and the JavaScript target belong in other
projects.

Every phase uses Red-Green-Refactor and the verification layers in
[Testing](TESTING.md). A new behavior begins with a failing test. Completion
is based on observable behavior, cleanup, interoperability, and conformance;
publishing to GitHub or Hex, tagging, creating a release, and changing the
tooling version are optional operations and never phase gates.

## 1. Bounded buffered client

**Status:** complete as of 2026-08-23. Verification includes pure tests, event
and error normalization, real-UDP loopback, a TLS-verified public-client
round trip with the independent aioquic 1.3.0 peer, the quic 1.8.1 HTTP/3
compliance module, and deterministic packet-loss, reordering, peer-termination,
timeout, and resource-limit scenarios. Exact evidence is recorded in
[Testing](TESTING.md).

Implement a real HTTP/3 client request-response flow using `gleam/http`
request and response concepts. Buffer request and response bodies
only within explicit limits, reject limit violations with typed errors, and
make connection ownership and deterministic shutdown clear.

Establish certificate-chain and hostname verification by default, bounded
operation timeouts, backend event and error normalization, and real UDP
loopback coverage. Do not export an operation until it performs the documented
protocol work.

## 2. Streaming, backpressure, and cancellation

**Status:** complete as of 2026-08-23. The reusable client exposes opaque
connection and stream values, synchronous producer backpressure, bounded
pull-based response events, total stream deadlines, race-safe idempotent
cancellation, and deterministic owner/connection cleanup. Verification covers
independent aioquic 1.3.0 streaming interoperation, backend conformance, real
UDP multiplexing, flow-control pressure, cancellation races, slow consumers,
packet loss, early responses, peer failure, and resource limits.

Add streaming request and response bodies without changing the bounded helper
into an unbounded collector. Preserve flow-control backpressure, expose
end-of-stream and transport failures, and make cancellation observable,
idempotent, and race-safe.

Cover slow producers and consumers, early response termination, cancellation
at each connection and stream state, and cleanup after both local and peer
failure.

## 3. Server

**Status:** complete as of 2026-08-23. The server exposes opaque configuration,
listener, and request values; bounded and pull-based streaming request bodies;
synchronous streaming responses; typed limits and failures; and deterministic
ownership and shutdown. Verification covers an independent aioquic 1.3.0
client, backend conformance, real-UDP bounded and streaming round trips,
same-connection multiplexing, concurrent accepts, peer failure, malformed
event normalization, declared content lengths, and resource limits.

Implement the HTTP/3 server after the client has exercised the shared
connection, stream, body, error, cancellation, and shutdown model. Add bounded
buffered handling first, then streaming handlers with backpressure and
deterministic ownership.

Keep listener, connection, and request-process lifetimes explicit. Test clean
shutdown, abrupt peer termination, malformed input, concurrent streams, and
resource limits without exposing backend handles or mailbox formats.

## 4. Advanced capabilities and escape hatch

**Status:** complete as of 2026-08-23. Typed connection and stream controls
cover HTTP Datagrams, RFC 9218 priority, active migration, replay-safe 0-RTT,
qlog, congestion control, ping, MTU, and transport statistics. Verification
includes real-UDP client/server coverage, independent aioquic 1.3.0 Datagram,
migration, qlog, and actual early-request interoperability, backend
conformance, negotiation and resource limits, concurrent receive, origin
binding, and replay-safety failures.

Add HTTP Datagrams, stream priority, connection migration, 0-RTT, qlog, and
other transport controls behind typed capabilities. Low-level access must
remain backend-neutral where possible and must not expose raw PIDs, atoms,
maps, or mailbox messages.

Any certificate-verification bypass remains confined to an explicitly named,
test-only surface.

## Continuous verification

**Status:** active and implemented. The repository retains fixed benchmark,
32-connection load, and 160,000-stream soak tasks with warm-up, repeated trials
where applicable, bounded cleanup, process and mailbox convergence checks,
environment metadata, and raw CSV results. These localhost measurements are
verification evidence rather than production throughput claims.

Verification is not deferred to a late implementation phase. Every change
uses the applicable pure, adapter, and real-UDP loopback tests and passes
`mise run check`. Each phase completes with an independent HTTP/3 peer,
conformance coverage, and relevant fault injection.

When performance becomes the focus, add controlled load and soak tests and a
reproducible benchmark methodology. Cover flow-control pressure, packet loss
and reordering, cancellation races, peer protocol violations, resource limits,
and graceful and abrupt shutdown. Retain raw results rather than publishing
isolated benchmark claims.

## Future pure Gleam QUIC backend

Develop a pure Gleam QUIC implementation as a separate package, then integrate
it behind the established backend boundary. Preserve the public `http3` API and
run the same compatibility suite against both backends before changing the
default.

This roadmap does not assign a name or public API to that future package.

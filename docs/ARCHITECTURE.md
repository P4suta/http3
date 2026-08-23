# Architecture

## Goals

`http3` will provide an idiomatic, HTTP/3-only Gleam client and server on the
Erlang target. Applications should depend on stable HTTP concepts rather than
a specific QUIC implementation. HTTP/1.1, HTTP/2, automatic protocol fallback,
and the JavaScript target are non-goals and belong in separate projects.

The current bootstrap surface exposes capability discovery, bounded and
streaming clients, a bounded and streaming server, and typed advanced
transport capabilities. Public v1 additionally requires the native transport
and every gate in [Public v1 gate](V1.md); wrapper completion alone is not v1
completion.
The version in `gleam.toml` is required tool metadata, not an implementation,
publication, or quality milestone.

## Layers

```text
Application
    |
Public http3 modules and opaque configuration / connection / stream values
    |
http3/internal adapters and event normalization
    |
Small Erlang FFI modules
    |
QUIC backend
```

The public client uses `gleam/http` request and response concepts and owns its
configuration, event, and error types. `Client`, `Connection`, and `Stream`
are opaque, so callers cannot depend on the representation selected by a
backend.

The internal adapter is responsible for translating backend results and
events into those public types. Backend PIDs, references, atoms, maps, records,
and mailbox message formats must remain below this boundary. Small Erlang FFI
modules perform only operations that cannot be expressed directly or safely
in Gleam; they must not become an alternative public API or a second adapter
layer.

## Bootstrap backend

The temporary bootstrap backend is pure Erlang
[`quic`](https://github.com/benoitc/erlang_quic), starting at version 1.8.1.
It already supplies QUIC transport and HTTP/3 client and server machinery
without a native library dependency and supports the project's OTP 26–29
range. The upstream project has also discussed
[Gleam bindings](https://github.com/benoitc/erlang_quic/issues/21).

Because no maintained Gleam binding is provided, `http3` adds value by
normalizing backend behavior behind typed HTTP/3 concepts and by making
lifecycle, limits, backpressure, cancellation, and failures explicit.

This backend is development scaffolding, not the v1 runtime. It remains useful
as a behavior oracle and independent regression peer during native-core
development, but the final production dependency graph must not contain it.

The current call path is deliberately small:

```text
http3.is_supported()
    -> http3/internal/backend.is_supported()
    -> http3_internal_backend_ffi:is_supported()
    -> quic:is_available()
```

Calling `http3.is_supported()` therefore verifies that the resolved Hex
package compiled, loaded, and answered its own availability probe. It does not
probe network reachability or peer interoperability.

The bounded client call path keeps request normalization in Gleam and all
backend processes and messages in Erlang:

```text
http3/client.send()
    -> http3/internal/client_request.prepare()
    -> http3/internal/client_backend.send()
    -> http3_internal_client_ffi:send()
    -> monitored request worker
    -> quic_h3
```

The worker owns one connection, enforces one monotonic deadline, collects the
response within the configured byte limit, normalizes events into primitive
result data, and waits for connection shutdown before returning. Raw PIDs,
atoms, maps, references, and mailbox events do not cross the FFI boundary.

The streaming call path retains one monitored worker for a reusable
connection:

```text
http3/client.connect() / open_stream() / send_chunk() / next_event()
    -> http3/internal/client_stream_backend
    -> http3_internal_stream_ffi
    -> owner-monitored connection worker
    -> quic_h3
```

The worker multiplexes stream identifiers internally, retries only backend
send results that report flow-control or queue pressure, and applies one
monotonic deadline per stream. A pull waiter receives the next event directly;
otherwise response data enters a per-stream bounded queue. Filling that queue
cancels the stream with `ConsumerTooSlow`. Cancellation, connection close, and
owner termination have fixed cleanup bounds. Backend identities and messages
remain below the adapter boundary.

The server mirrors the same boundary and keeps listener names, connections,
stream identifiers, handlers, monitors, and backend events private:

```text
http3/server.start() / accept() / next_event() / send_chunk()
    -> http3/internal/server_backend
    -> http3_internal_server_ffi
    -> owner-monitored listener worker and request handlers
    -> quic_h3
```

The listener uses a fixed atom pool rather than constructing atoms from user
input. A monitored worker owns the backend listener and all accepted
connections. Request data is delivered through a bounded per-stream queue;
pull waiters receive an event directly when possible. Response chunk calls
synchronously retain backend pressure. Completed requests are removed from
worker state, and stop or owner termination releases blocked accept and event
calls within fixed cleanup bounds.

Advanced controls reuse those same opaque handles through another internal
adapter rather than opening a backend escape hatch:

```text
http3/transport typed connection and stream operations
    -> http3/internal/transport_backend
    -> existing client or server FFI worker call
    -> quic / quic_h3
```

HTTP Datagrams have explicit negotiation, payload and queue limits, and one
pull waiter per stream. Priority, migration, congestion control, ping, MTU,
and statistics are normalized into public Gleam values. qlog is disabled by
default and accepts only an explicit typed directory configuration. Session
tickets are opaque and origin-bound; the adapter retains the verified hostname
when a resumed connection uses the prior peer address to make genuine 0-RTT
possible. Early requests are locally restricted to replay-safe methods.
Client and server accessors create the public opaque transport values through
a private Gleam external backed by one small internal Erlang FFI module. No
constructor bridge or backend handle type appears in the compiler-exported
package interface.

## HTTP data model

The bounded client uses the request and response concepts from `gleam/http`.
Its concrete implementation introduced the `gleam_http` dependency; no
HTTP/1.1, HTTP/2, or OTP HTTP integration package is included.

Sharing request and response concepts does not imply HTTP/1.1 or HTTP/2
support and does not introduce automatic fallback. Multi-protocol selection
belongs in a separate integration project above this library.

Both buffered and streaming bodies are first-class requirements. Buffered
helpers may collect a stream within explicit limits; streaming APIs retain
backpressure and make end-of-stream, cancellation, and transport failure
observable.

## Implementation sequence

Bootstrap API work proceeded in dependency order:

1. the bounded buffered HTTP/3 client, whose independent interoperability,
   conformance, and fault-injection phase gate is complete;
2. streaming request and response bodies with backpressure and cancellation,
   whose independent interoperability and fault-injection gate is complete;
3. an HTTP/3 server built on the exercised connection and stream model, whose
   independent interoperability, lifecycle, and limit gate is complete; and
4. advanced capabilities exposed through typed, backend-neutral APIs where
   possible, whose independent Datagram, migration, qlog, and actual 0-RTT
   interoperability gate is complete.

Native protocol work then proceeds in the dependency order recorded in
[Roadmap](ROADMAP.md): wire codecs and invariants; TLS and packet protection;
transport, recovery and paths; HTTP/3 and QPACK; adapter cutover; and complete
interop, security and performance qualification.

Each behavior starts with a failing test and follows the gates in
[Testing](TESTING.md). No stage is gated on publishing the repository or
package, creating a tag or release, or changing the package version.

## Security boundary

Normal client configuration will always verify certificate chains and hostnames
by default. Disabling verification is never a convenience flag on the normal
configuration. A narrowly named, test-only surface may permit it for local
fixtures, with the unsafe choice visible at the call site.

Protocol data is untrusted. The current adapter validates request shape,
headers, body limits, response limits, status ordering, and backend event
shapes before constructing public values. Cancellation and shutdown must be
idempotent and must not leave unowned backend processes or streams.

HTTP Datagram buffers are bounded even when a Datagram arrives before its
request head. qlog output is an explicit security-sensitive choice. Resumption
tickets have no public field or serialization access, are rejected for another
host or port, and cannot enable a replay-unsafe early request.

## Native backend target

The repository-owned `gleam_quic` implementation lives in
`packages/gleam_quic`. `http3` will integrate it through the same internal
adapter and small-FFI boundary and preserve the public HTTP/3 API. Protocol
state machines and wire formats belong in Gleam; Erlang FFI is restricted to
UDP, time, randomness, cryptographic operations, and X.509 runtime primitives.

Backend selection is an implementation concern. Compatibility tests are
written against observable public behavior so the backend can be exchanged
without asking applications to migrate types or message handling. After
cutover the external backend can remain an out-of-process test peer, but it
cannot remain a runtime dependency.

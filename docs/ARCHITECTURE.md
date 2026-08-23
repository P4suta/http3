# Architecture

## Goals

`http3` will provide an idiomatic, HTTP/3-only Gleam client and server on the
Erlang target. Applications should depend on stable HTTP concepts rather than
a specific QUIC implementation. HTTP/1.1, HTTP/2, automatic protocol fallback,
and the JavaScript target are non-goals and belong in separate projects.

The current surface exposes capability discovery plus bounded and streaming
clients. It does not contain server placeholders.
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

## Initial backend

The initial backend is pure Erlang
[`quic`](https://github.com/benoitc/erlang_quic), starting at version 1.8.1.
It already supplies QUIC transport and HTTP/3 client and server machinery
without a native library dependency and supports the project's OTP 26–29
range. The upstream project has also discussed
[Gleam bindings](https://github.com/benoitc/erlang_quic/issues/21).

Because no maintained Gleam binding is provided, `http3` adds value by
normalizing backend behavior behind typed HTTP/3 concepts and by making
lifecycle, limits, backpressure, cancellation, and failures explicit.

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

Protocol work proceeds in dependency order:

1. the bounded buffered HTTP/3 client, whose independent interoperability,
   conformance, and fault-injection phase gate is complete;
2. streaming request and response bodies with backpressure and cancellation,
   whose independent interoperability and fault-injection gate is complete;
3. an HTTP/3 server built on the exercised connection and stream model; and
4. advanced capabilities exposed through typed, backend-neutral APIs where
   possible.

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

## Backend replacement

A future pure Gleam QUIC implementation will live in a separate package. Its
name and public API are intentionally undecided. `http3` will integrate it
through the same internal adapter and small-FFI boundary and preserve the
public HTTP/3 API.

Backend selection is an implementation concern. Compatibility tests will be
written against observable public behavior so the backend can be exchanged
without asking applications to migrate types or message handling.

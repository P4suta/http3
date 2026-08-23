# Architecture

## Goals

`http3` will provide an idiomatic Gleam HTTP/3 client and server on the Erlang
target. Applications should depend on stable HTTP concepts rather than a
specific QUIC implementation. The first usable release will include client and
server APIs, buffered and streaming bodies, and carefully scoped low-level
capabilities.

Version 0.1.0 establishes the boundary; it does not contain connection or
server placeholders.

## Layers

```text
Application
    |
Public http3 modules and opaque Connection / Stream values
    |
http3/internal adapters and event normalization
    |
Small Erlang FFI modules
    |
QUIC backend
```

The public layer will own request, response, body, connection, stream, and
error types. `Connection` and `Stream` will be opaque, so callers cannot depend
on the representation selected by a backend.

The internal adapter is responsible for translating backend results and
events into those public types. Backend PIDs, references, atoms, maps, records,
and mailbox message formats must remain below this boundary. The Erlang FFI is
limited to operations that cannot be expressed directly or safely in Gleam;
it must not become an alternative public API.

## Initial backend

The initial backend is pure Erlang
[`quic`](https://github.com/benoitc/erlang_quic), starting at version 1.8.1.
It supplies QUIC transport and HTTP/3 protocol machinery without a native
library dependency and supports the project's OTP 26–29 range. The upstream
project has also discussed
[Gleam bindings](https://github.com/benoitc/erlang_quic/issues/21).

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

## HTTP compatibility

The first protocol API will use the same request and response concepts as
`gleam/http`. The `gleam_http` dependency and any OTP integration packages are
intentionally deferred until concrete client and server modules use them. This
keeps the bootstrap runtime graph limited to `gleam_stdlib` and `quic`.

Both buffered and streaming bodies are first-class requirements. Buffered
helpers may collect a stream within explicit limits; streaming APIs retain
backpressure and make end-of-stream, cancellation, and transport failure
observable.

## Security boundary

Normal client configuration will always verify certificate chains and hostnames
by default. Disabling verification is never a convenience flag on the normal
configuration. A narrowly named test or development API may permit it for
local fixtures, with the unsafe choice visible at the call site.

Protocol data is untrusted. Future adapters must validate sizes, identifiers,
state transitions, and backend event shapes before constructing public values.
Cancellation and shutdown must be idempotent and must not leave unowned backend
processes or streams.

## Backend replacement

A future pure Gleam QUIC implementation will live in a separate package. Its
name and public API are intentionally undecided. `http3` will integrate it
through the same internal backend boundary and preserve the public HTTP/3 API.

Backend selection is an implementation concern. Compatibility tests will be
written against observable public behavior so the backend can be exchanged
without asking applications to migrate types or message handling.

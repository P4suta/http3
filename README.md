# http3

`http3` is an HTTP/3-only Gleam library for the Erlang target. Its public API
is designed to remain independent of the QUIC backend.

This is not a multi-protocol HTTP client. HTTP/1.1, HTTP/2, automatic protocol
fallback, and the JavaScript target are outside this package's scope. A
project that needs those capabilities should compose them outside `http3`.

> [!WARNING]
> This package is pre-alpha, is not published to Hex, and is not recommended
> for production use. The version in `gleam.toml` is tool metadata, not a
> publication or feature milestone. The bounded client, streaming client, and
> server are implemented; advanced transport capabilities remain planned.

## Current API

The package exposes a runtime capability probe, bounded and streaming clients,
and a bounded and streaming server. The probe does not make a network
connection:

```gleam
import http3

pub fn main() -> Nil {
  let supported = http3.is_supported()
  // Use `supported` to decide whether HTTP/3 may be enabled.
}
```

`is_supported()` delegates to the configured backend and does not make a
network connection. The initial backend is the pure Erlang
[`quic`](https://hex.pm/packages/quic) package, which already implements QUIC
and HTTP/3 client and server machinery. It is constrained to versions from
1.8.1 up to, but not including, 2.0.0. This package's value is a typed,
idiomatic Gleam API that keeps those backend details private.

The client accepts `gleam/http` requests and returns `gleam/http` responses
with `BitArray` bodies:

```gleam
import gleam/http/request
import http3/client

pub fn fetch() {
  let assert Ok(request) = request.to("https://example.com/")
  let request = request.set_body(request, <<>>)

  client.send(client.new(), request)
}
```

Each `send` call owns and closes one HTTP/3 connection. The default total
timeout is 30 seconds, and buffered request and response bodies are each
limited to 8 MiB. TLS certificate-chain and hostname verification are always
enabled. Typed configuration functions can change the limits, timeout, or
explicit CA trust set without exposing backend values.

For connection reuse and streaming bodies, establish a connection, open one
or more streams, send request chunks, and pull response events:

```gleam
let assert Ok(connection) = client.connect(configuration, "example.com", 443)
let request =
  request.new()
  |> request.set_host("example.com")
  |> request.set_body(Nil)
let assert Ok(stream) = client.open_stream(connection, request)
let assert Ok(Nil) = client.finish(stream)

case client.next_event(stream) {
  Ok(client.Response(_, _)) -> Nil
  Ok(client.Data(_)) -> Nil
  Ok(client.End) -> Nil
  // InformationalResponse and Trailers are also observable events.
  _ -> Nil
}
```

Request chunk calls synchronously preserve backend flow-control pressure.
Response events are pulled one at a time, and unconsumed data is bounded per
stream. Cancellation and connection close are observable and idempotent.

The server requires PEM certificate and private-key bytes, owns its listener
and connections, and pulls request heads and body events with fixed timeouts:

```gleam
let assert Ok(configuration) = server.new(certificate, private_key)
let assert Ok(listener) = server.start(configuration)
let assert Ok(incoming) = server.accept(listener)
let assert Ok(body) = server.read_body(incoming)
let assert Ok(Nil) = server.respond(incoming, 200, [], body)
let assert Ok(server.Stopped) = server.stop(listener)
```

Request and response bodies have independent limits. Streaming request events
and response writes preserve bounded buffering and flow-control pressure;
listener shutdown, owner termination, and repeated stop calls clean up
deterministically.

## Status

| Capability | Status |
| --- | --- |
| Backend availability probe | Implemented |
| Bounded buffered HTTP/3 client | Implemented; phase 1 verification complete |
| Streaming, backpressure, and cancellation | Implemented; phase 2 verification complete |
| HTTP/3 server | Implemented; phase 3 verification complete |
| Advanced typed capabilities | Planned |

APIs are added only when they perform real protocol work and have tests.

Implementation is client-first: the bounded client, streaming client, and
server are complete; advanced capabilities follow. Progress is gated by tested
behavior, not by a GitHub or Hex publication, tag, release, or version change;
those operations remain optional and outside this roadmap.

## Development

The supported runtime range is Erlang/OTP 26 through 29. The development
baseline is pinned to Gleam 1.18.1, Erlang/OTP 29.0.5, and rebar3 3.27.0 with
[`mise`](https://mise.jdx.dev/).

```sh
mise install
mise run check
```

`mise run check` verifies formatting, builds with warnings treated as errors,
runs the test suite, builds documentation, and runs the configured source,
Markdown, TOML, GitHub Actions, spelling, and licence checks.

See [Architecture](docs/ARCHITECTURE.md) for the backend boundary,
[Testing](docs/TESTING.md) for the required development and verification
workflow, and [Roadmap](docs/ROADMAP.md) for the implementation order.

## Security

TLS certificate-chain and hostname verification are enabled for the client.
The server requires valid certificate and private-key material. There is no
public option that disables client verification. See [SECURITY.md](SECURITY.md)
for reporting guidance.

## Licence

Copyright 2026 the `http3` contributors.

Licensed under either the MIT License or the Apache License, Version 2.0, at
your option. See [LICENSE](LICENSE) for details.

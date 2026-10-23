# http

`http` is a unified Gleam HTTP product for the Erlang target.
The repository contains three packages:

- `http` provides the common API and HTTP/1.1 and HTTP/2 runtimes.
- `http3` provides HTTP/3, QPACK, Capsules, Datagrams, and WebSocket over HTTP/3.
- `quic_core` provides application-protocol-independent QUIC v1/v2 and TLS 1.3.

The root API includes bounded `http/body` and `http/error` values, the reusable `http/client`, and protocol-neutral `http/server`, `http/context`, `http/middleware`, `http/resource`, and `http/diagnostics` contracts.
The [server guide](SERVER.md) describes the shared handler and lifecycle model.
The HTTP/1.1 and HTTP/2 runtimes, public HTTP/3 adapter, guarded CONNECT and Upgrade streams, verified protocol discovery, and finite policy stores are implemented.
Structured Fields and status, digest and signature, bHTTP and OHTTP, compression, WebSocket, and MASQUE modules are also present, with remaining qualification tracked in the [conformance status](CONFORMANCE.md).

## Quickstart

The client helper applies a one-megabyte response-body ceiling and closes its finite connection pool.

<!-- example: package=http id=quickstart_client -->
```gleam
import gleam/http/request
import http/body
import http/client

/// Fetch one resource and return its status and bounded body.
pub fn fetch(url: String) -> #(Int, BitArray) {
  let assert Ok(outgoing) = request.to(url)
  let assert Ok(running) = client.start(client.defaults())
  let assert Ok(incoming) =
    client.fetch(client: running, outgoing: request.set_body(outgoing, <<>>))
  let assert Ok(#(bytes, _trailers)) =
    body.read_all(incoming.body, 1024 * 1024)
  let assert Ok(Nil) = client.close(running)
  #(incoming.status, bytes)
}

pub fn main() -> Nil {
  let _example = fetch
  Nil
}
```

The handler uses the protocol-neutral API, and this example starts an HTTP/1.1 listener and completes a real loopback request before releasing both ends.

<!-- example: package=http id=quickstart_server -->
```gleam
import gleam/http/request
import gleam/http/response
import http/body
import http/client
import http/context
import http/server

pub fn main() -> Nil {
  let assert Ok(running) =
    server.start(server.defaults(), fn(_request, _context) {
      Ok(
        response.new(200)
        |> response.set_body(body.from_text("hello from http")),
      )
    })
  let assert Ok(listener) =
    server.listen_http1(
      running,
      <<127, 0, 0, 1>>,
      0,
      server.http1_defaults() |> server.allow_http1_cleartext,
    )
  let context.Endpoint(_, port) = server.listener_endpoint(listener)

  let assert Ok(outgoing) = request.to("http://127.0.0.1/")
  let outgoing =
    request.set_port(outgoing, port) |> request.set_body(<<>>)
  let assert Ok(fetching) =
    client.start(client.defaults() |> client.allow_plain_http)
  let assert Ok(incoming) = client.fetch(client: fetching, outgoing: outgoing)
  let assert Ok(#(bytes, _trailers)) = body.read_all(incoming.body, 65_536)
  assert incoming.status == 200
  assert bytes == <<"hello from http":utf8>>

  let assert Ok(Nil) = client.close(fetching)
  let assert Ok(Nil) = server.stop_listener(listener)
  let assert Ok(Nil) = server.stop(running)
  Nil
}
```

Cleartext requires explicit opt-in on both sides, as shown above.
A TLS listener takes a certificate, private key, and service identity, and the client always verifies that identity.

All three packages remain unpublished `0.1.0` development packages, and none is a supported production release.
Release readiness depends on completing the conformance, resource, interoperability, performance, documentation, and independent-audit gates.

Development is test-driven, and every behavior change starts with a failing test and continues through the affected regression suites.
See [Testing](TESTING.md) and the current [Roadmap](ROADMAP.md).

Repository tasks do not create tags, publish packages, push changes, or create hosted releases.

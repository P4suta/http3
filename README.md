# http

`http` is the unified Gleam HTTP product for the Erlang target. The repository
contains exactly three publishable packages:

- `http`: the common API and HTTP/1.1/HTTP/2 runtime;
- `http3`: HTTP/3, QPACK, Capsules, Datagrams, and WebSocket over HTTP/3; and
- `quic_core`: application-protocol-independent QUIC v1/v2 and TLS 1.3.

The root public surface includes bounded `http/body` and `http/error` values,
the reusable `http/client`, and the protocol-neutral `http/server`,
`http/context`, `http/middleware`, `http/resource`, and `http/diagnostics`
contracts. See the [server guide](docs/SERVER.md) for the common Handler and
lifecycle model. Bounded active-once HTTP/1.1 and HTTP/2 runtimes, the public
HTTP/3 adapter, guarded CONNECT/Upgrade streams, verified protocol discovery,
and finite policy stores are implemented. Structured Fields/status,
digest/signature, bHTTP/OHTTP, compression, WebSocket, and MASQUE modules are
also present; their remaining standards, live-adapter, peer, coverage, and
platform qualification is tracked in the generated
[conformance status](docs/CONFORMANCE.md).

## Quickstart

Send one request and read a bounded response body. Nothing here is unbounded:
the read has an explicit ceiling, and the client owns a finite pool which is
released when it is closed.

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

Serve one. A handler is a plain function from a request and its context to a
response, so the same handler runs behind HTTP/1.1, HTTP/2, and HTTP/3. This
example completes a real request over loopback and then releases both ends.

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

Cleartext is an explicit opt-in on both sides, as it is above. A TLS listener
takes a certificate, a private key, and the service identity it must present,
and the client verifies that identity with no way to turn verification off.

All three packages remain unpublished `0.1.0` development packages. They are
not release candidates or supported production releases until every
conformance, resource, interoperability, performance, documentation, and
independent-audit gate is complete.

Development is test-driven. Every behavior change starts with a failing test,
is implemented with the smallest bounded change, and is followed by the full
affected regression suites. See [Testing](docs/TESTING.md) and the current
[Roadmap](docs/ROADMAP.md).

No tag, publication, push, or hosted release is performed by repository tasks.

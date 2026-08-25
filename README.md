# http3

`http3` is an HTTP/3-only Gleam library for the Erlang target. It includes a
repository-owned QUIC v1/v2, TLS 1.3, HTTP/3, and QPACK implementation. The
public API exposes typed HTTP and transport concepts while keeping processes,
sockets, protocol state, cryptographic material, and Erlang message formats
private.

This is not a multi-protocol HTTP client. HTTP/1.1, HTTP/2, automatic protocol
fallback, and the JavaScript target are outside this package's scope. A
project that needs those capabilities should compose them above `http3`.

> [!WARNING]
> This source tree is unpublished and has not had an independent third-party
> security audit. The former v1-complete decision was reopened on 2026-08-25;
> known transport, TLS, conformance, performance, security-tooling, and package
> distribution gates remain open. It is not a release candidate or a supported
> production release. The version in `gleam.toml` is tool metadata, not a tag,
> release, or publication milestone.

## API overview

The capability probe checks whether the Erlang runtime supplies the mandatory
cryptographic primitives. It does not open a socket or contact a peer:

```gleam
import http3

pub fn main() -> Nil {
  let supported = http3.is_supported()
  // Use `supported` to decide whether HTTP/3 may be enabled.
}
```

The bounded client accepts `gleam/http` requests and returns `gleam/http`
responses with `BitArray` bodies:

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
limited to 8 MiB. Certificate-chain and service-identity verification are
always enabled. `http3/config` provides complete finite phase deadlines and
resource limits; there is no unlimited queue or deadline value.

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

Request writes synchronously preserve QUIC flow-control pressure. Response
events are pulled one at a time, and unconsumed data is bounded by both bytes
and event count per stream. Cancellation and connection close are observable
and idempotent.

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

Additional certificates can be selected by SNI. Request and response bodies
have independent limits. Streaming request events and response writes remain
bounded; graceful drain, immediate shutdown, owner termination, and repeated
stop calls clean up deterministically.

Advanced controls reuse opaque public connection and stream values:

```gleam
let connection_transport = client.connection_transport(connection)
let assert Ok(capabilities) = transport.capabilities(connection_transport)
let assert Ok(Nil) = transport.ping(connection_transport)

let stream_transport = client.stream_transport(stream)
let assert Ok(priority) = transport.priority(1, True)
let assert Ok(Nil) = transport.set_priority(stream_transport, priority)
```

The current source exercises QUIC v1/v2, compatible version negotiation, HTTP
Datagrams on Extended CONNECT, RFC 9218 priority, connection migration,
NewReno and CUBIC, ECN, PMTU discovery, statistics, ping, opt-in bounded qlog,
origin-bound resumption, and explicit 0-RTT. HTTP/3 informational responses,
trailers, server push, GOAWAY, graceful drain, Capsules, and QPACK have live
paths and tests. These are implementation facts, not a complete conformance or
release-readiness claim. A 0-RTT connection accepts only GET, HEAD, and OPTIONS
until its early-data outcome is known; replay-unsafe methods are rejected
locally.

## Status

| Capability | Status |
| --- | --- |
| Secure bounded/streaming HTTP/3 client and server paths | Implemented and tested |
| Event-driven UDP and finite per-stream event/Datagram queues | Implemented and tested |
| Typed deadlines, role-specific live limits, runtime failures, reload, and ticket persistence | Implemented and tested except aggregate `EndpointMemory`, tracked below |
| Physical HTTP/3/QPACK package ownership | Implemented; core archive contains transport only |
| Generic public `gleam_quic` transport API | Implemented and directly tested over real UDP; root HTTP/3 migration to it remains open |
| Per-connection actor isolation and complete global admission budgets | Open release blocker |
| Bounded external 0-RTT replay guard with safe 1-RTT fallback | Implemented and tested |
| P-256 key exchange and mTLS API | Implemented and directly tested; OTP/peer credential matrix remains open |
| Complete conformance, qlog, CUBIC, coverage, security, interop, and package gates | Open release blockers |
| Fixed performance thresholds | Not met by the retained baseline or 2026-08-25 diagnostic rerun |
| Public v1 source-tree gate | Reopened on 2026-08-25 |
| Tag, hosted release, and Hex publication | Deliberately not performed |

No external QUIC implementation is a production dependency. Independent
aioquic and quic-go programs are retained only as reproducible test peers.
HTTP/3 sessions, QPACK, Capsules, and workers are owned by `http3`. Raw
packet/frame/TLS codecs remain private to `gleam_quic`. Compiler-derived
semantic API snapshots for both packages are part of the local check.

## Development

The supported runtime range is Erlang/OTP 28 and 29, matching
[`Gleam 1.18`'s supported Erlang range][gleam-compatibility]. The development
baseline is pinned to Gleam 1.18.1, Erlang/OTP 29.0.5, and rebar3 3.27.0 with
[`mise`](https://mise.jdx.dev/).

```sh
mise install
mise run check
mise run fault
mise run fuzz
mise run property
mise run interop-setup
mise run interop
```

`mise run check` verifies formatting, warnings-as-errors builds, both test
suites, documentation, the compiler-exported public API, source and prose
linting, workflow syntax, spelling, shell scripts, REUSE compliance, and a
byte-reproducible, content-audited `gleam_quic` Hex archive. The separate
commands run expensive or environment-sensitive network, fuzz, property, and
independent-peer qualification gates. CI defines OTP 28–29 and Linux, macOS,
and Windows build/test matrices.

Start with the [API guide](docs/API.md). See also
[Architecture](docs/ARCHITECTURE.md), the [pre-release v1 gate](docs/V1.md),
the [conformance matrix](docs/CONFORMANCE.md),
[Deployment and key rotation](docs/DEPLOYMENT.md),
[Migration](docs/MIGRATION.md), [Testing](docs/TESTING.md), the
[security review](docs/SECURITY_REVIEW.md), [Support](SUPPORT.md),
[Performance](benchmarks/README.md), and the reopened
[Roadmap](docs/ROADMAP.md).

## Security

Client certificate-chain and hostname verification are enabled by default and
cannot be disabled through the public API. The server validates credential
material before startup. qlog is opt-in because traces can contain sensitive
metadata. See [SECURITY.md](SECURITY.md) for invariants and reporting guidance.

## Licence

Copyright 2026 the `http3` contributors.

Licensed under either the MIT License or the Apache License, Version 2.0, at
your option. See [LICENSE](LICENSE) for details.

[gleam-compatibility]: https://gleam.run/documentation/compatibility-reference/

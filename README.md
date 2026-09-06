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

All three packages remain unpublished `0.1.0` development packages. They are
not release candidates or supported production releases until every
conformance, resource, interoperability, performance, documentation, and
independent-audit gate is complete.

Development is test-driven. Every behavior change starts with a failing test,
is implemented with the smallest bounded change, and is followed by the full
affected regression suites. See [Testing](docs/TESTING.md) and the current
[Roadmap](docs/ROADMAP.md).

No tag, publication, push, or hosted release is performed by repository tasks.

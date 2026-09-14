# http3

`http3` is the HTTP/3 layer of the three-package Gleam HTTP product for the
Erlang target. It owns HTTP/3 framing and sessions, QPACK, Capsules, HTTP
Datagrams, priority, and WebSocket over HTTP/3. QUIC v1/v2 and TLS 1.3 belong
to the sibling `quic_core` package; the unified client, server, common body,
and HTTP/1.1 and HTTP/2 runtimes belong to `http`.

> [!WARNING]
> This package is unpublished, unaudited, and not a release candidate. The
> public-only QUIC boundary and aggregate resource admission are implemented;
> complete standards mapping, coverage, the full peer/platform matrix,
> performance, canonical-source qualification, and independent audit remain
> open. The narrower pinned live qlog profile is implemented and passing; that
> does not close the remaining standards-event inventory.

Public HTTP values use `gleam_http` requests, responses, methods, and headers.
Transport handles are opaque, waits and buffers are finite, and certificate
and service-identity verification cannot be disabled through the normal
public configuration.

The package has no Wisp runtime dependency. Applications and adapters can
connect through standard request/response values and the public streaming
contract owned by `http`.

## Development

From the repository root:

```sh
mise run http3-check
mise run api
mise run ffi-audit
```

Every behavior change follows Red-Green-Refactor: first demonstrate the
missing contract with a failing test, make the smallest bounded change, and
then run this package plus its upstream regression suites.

See the package [architecture](docs/ARCHITECTURE.md), [API guide](docs/API.md),
[conformance status](docs/CONFORMANCE.md), and [security review](docs/SECURITY_REVIEW.md).
Repository-wide qualification is tracked in the root
[conformance matrix](../../docs/CONFORMANCE.md) and [release gate](../../docs/V1.md).

No repository task tags, publishes, pushes, or creates a hosted release.

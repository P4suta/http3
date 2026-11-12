# http3

`http3` is the HTTP/3 layer of the three-package Gleam HTTP product for the
Erlang target. It owns HTTP/3 framing and sessions, QPACK, Capsules, HTTP
Datagrams, priority, and WebSocket over HTTP/3. QUIC v1/v2 and TLS 1.3 belong
to the sibling `quic_core` package; the unified client, server, common body,
and HTTP/1.1 and HTTP/2 runtimes belong to `http`.

> [!WARNING]
> This package is unpublished, unaudited, and not a release candidate. The
> public-only QUIC boundary, server aggregate admission, and per-connection
> diagnostic startup allowances are implemented. Client copies retain a bounded
> diagnostic byte and connection-slot reservation across attempts and origins.
> Unconfirmed cleanup remains charged; automatic capacity recovery and a shared
> client budget for all dynamic allocations remain open. Complete standards
> mapping, coverage, the full peer/platform matrix,
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

## Certificate service identity

DNS-ID and IP-ID are mandatory to implement for the HTTP/3 client.
SRV-ID and URI-ID are unsupported.
A DNS request origin supplies DNS-ID and TLS SNI; an IP-literal origin supplies IP-ID.
In either case the request origin supplies HTTP authority, pool identity, and ticket identity.
An exact address or alternate destination port changes only the UDP connect target.
Applications currently supply internationalized origins as canonical ASCII A-labels.
Presented DNS-ID wildcards must cover exactly one whole left-most label; the dual-provider adversarial qualification remains an open release gate.
The repository-wide [certificate identity profile](../../docs/CERTIFICATE_IDENTITY.md) defines the shared HTTP/1.1, HTTP/2, HTTP/3, and QUIC boundary.

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

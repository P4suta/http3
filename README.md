# http3

`http3` is the foundation of a Gleam-native HTTP/3 stack for the Erlang
target. Its public API is designed to remain independent of the QUIC backend.

> [!WARNING]
> This package is pre-alpha, is not published to Hex, and is not recommended
> for production use. Version 0.1.0 is a bootstrap release: it does not yet
> provide an HTTP/3 client or server.

## Current API

The only public operation is a runtime capability probe:

```gleam
import http3

pub fn main() -> Nil {
  let supported = http3.is_supported()
  // Use `supported` to decide whether HTTP/3 may be enabled.
}
```

`is_supported()` delegates to the configured backend and does not make a
network connection. The initial backend is the pure Erlang
[`quic`](https://hex.pm/packages/quic) package, constrained to versions from
1.8.1 up to, but not including, 2.0.0.

## Status

| Capability | Status |
| --- | --- |
| Backend availability probe | Implemented |
| HTTP/3 client | Planned |
| HTTP/3 server | Planned |
| Buffered bodies | Planned |
| Streaming bodies | Planned |
| Low-level escape hatch | Planned |

No placeholder client or server functions are exported. APIs are added only
when they perform real protocol work and have tests.

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

See [Architecture](docs/ARCHITECTURE.md) for the backend boundary and
[Roadmap](docs/ROADMAP.md) for the implementation order.

## Security

TLS certificate and hostname verification will be enabled by default for all
client APIs. Any option that disables verification will be isolated to an
explicit test or development API. See [SECURITY.md](SECURITY.md) for reporting
guidance.

## Licence

Copyright 2026 the `http3` contributors.

Licensed under either the MIT License or the Apache License, Version 2.0, at
your option. See [LICENSE](LICENSE) for details.

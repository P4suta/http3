# Migration guide

The unpublished package now exposes a generic transport boundary. Code that
temporarily imported packet, frame, TLS, driver, UDP, or former HTTP/3/QPACK
modules must move to supported public values before publication.

| Former coupling | Public replacement |
| --- | --- |
| Runtime socket/process handle | Opaque `client.Connection` or `server.Listener`/`Connection` |
| Raw stream identifier | Opaque role-specific `Stream` |
| Driver send/read calls | `send`, `finish`, `send_and_finish`, `receive`, `reset` |
| Raw DATAGRAM frame | `send_datagram`, `receive_datagram`, `maximum_datagram_size` |
| Transport/TLS state inspection | `connection_info`, `phase`, and statistics snapshots |
| Backend error text | Role error plus typed `quic_core/failure.Failure` |
| BBR selection | `NewReno` or `Cubic` |
| Unbounded timeout/queue sentinel | Validated opaque `Deadlines` and `Limits` |
| HTTP/3, QPACK, or Capsule import | Use the sibling `http3` package |

Higher-level protocol adapters should replace a relative wait followed by `client.close_with_code` with one absolute monotonic deadline passed to `client.close_with_code_until`.
Build the deadline from `diagnostics.monotonic_milliseconds`, the adapter drain allowance, the connection-specific `client.close_operation_allowance_milliseconds`, and `client.close_completion_allowance_milliseconds`.
The deadline must be future,
non-negative, and no greater than 9,223,372,036,854,775,807.
Expiry is reported as `client.Failure(failure.Timeout(failure.Operation))`; qlog I/O or cleanup-owner failure remains `client.Failure(failure.Socket(failure.WriteFile))`.
The qlog writer consumes that same absolute value in the diagnostics monotonic clock domain.
Its five-second native ceiling can shorten a larger boundary but cannot reconstruct one after a scheduling delay.

Server adapters apply the same rule with `server.stop_completion_allowance_milliseconds` and `server.stop_until`.
Every connection termination is fanned out before the listener waits; the shared deadline therefore remains independent of connection count.
Successful stop additionally proves every connection actor and the UDP relay are down and that the connection, diagnostic, and endpoint-memory ledgers are empty.

`client.new` now binds hostname, port, and initial ALPN together so an opaque
configuration cannot be connected to a different identity accidentally.
Resumption tickets are also origin-bound. Server certificate and private-key
bytes are validated by `server.new`, before the listener is started.

RSA server certificates below 2048 bits now return `server.InsufficientKeyStrength` from `server.new` and `server.with_certificate`.
Replace that credential; certificate syntax errors continue to return `server.InvalidCertificate`, while a mismatched key returns `server.IncompatiblePrivateKey`.

This is an unpublished breaking transition; no compatibility aliases are
provided. Compiler-derived API snapshots make any further public change an
explicit review event.

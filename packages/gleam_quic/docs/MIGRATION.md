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
| Backend error text | Role error plus typed `gleam_quic/failure.Failure` |
| BBR selection | `NewReno` or `Cubic` |
| Unbounded timeout/queue sentinel | Validated opaque `Deadlines` and `Limits` |
| HTTP/3, QPACK, or Capsule import | Use the sibling `http3` package |

`client.new` now binds hostname, port, and initial ALPN together so an opaque
configuration cannot be connected to a different identity accidentally.
Resumption tickets are also origin-bound. Server certificate and private-key
bytes are validated by `server.new`, before the listener is started.

This is an unpublished breaking transition; no compatibility aliases are
provided. Compiler-derived API snapshots make any further public change an
explicit review event.

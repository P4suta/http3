# API guide

The public API follows one ownership model: a configured endpoint creates an
opaque live value, live connections create opaque streams, and every blocking
operation has a finite deadline. Native sockets, processes, references,
mailbox messages, TLS state, certificates, tickets, and traffic secrets never
cross that boundary.

## Choose a role

Use `quic_core/client` when dialing a host and `quic_core/server` when
accepting connections. Both expose the same transport concepts:

| Task | Client | Server |
| --- | --- | --- |
| Start | `client.connect` | `server.start`, then `server.accept` |
| Local bidirectional stream | `client.open_bidirectional` | `server.open_bidirectional` |
| Local unidirectional stream | `client.open_unidirectional` | `server.open_unidirectional` |
| Peer stream | `client.accept_stream` | `server.accept_stream` |
| Stream I/O | `send`, `finish`, `send_and_finish`, `receive`, `reset` | Same |
| Datagram I/O | `send_datagram`, `receive_datagram` | Same |
| Datagram capacity | `maximum_datagram_size`, `guaranteed_datagram_size` | Same |
| Lifecycle | `client.close` | `server.close`, `server.stop` |

`receive(stream, maximum_bytes)` returns `Data(bytes, finished)`, `Finished`,
or `Reset(code)`. A locally opened unidirectional stream is send-only; a peer
unidirectional stream is receive-only. Using the wrong direction returns
`InvalidDirection` rather than crashing.

## Configure finite policy

<!-- example: package=quic_core id=finite_policy -->
```gleam
import gleam/result
import quic_core/client
import quic_core/config
import quic_core/failure

pub fn main() -> Nil {
  let assert Ok(deadlines) =
    config.with_deadline(config.default_deadlines(), failure.Handshake, 5_000)
  let assert Ok(deadlines) =
    config.with_deadline(deadlines, failure.Operation, 10_000)
  let assert Ok(limits) =
    config.with_limit(config.default_limits(), failure.Queue, 256)
  let assert Ok(limits) =
    config.with_limit(limits, failure.Buffer, 1_048_576)

  let _configured =
    client.new("example.com", 443, "sample")
    |> result.map(client.with_deadlines(_, deadlines))
    |> result.map(client.with_limits(_, limits))
  Nil
}
```

There is no `unlimited` sentinel. Invalid values are rejected while building a
policy, after which the complete opaque value is attached atomically.

Server operational secrets follow the same pattern: validate 256-bit keys,
rotate each `KeyRing`, then assemble one opaque `OperationalKeys` value using
the named `ticket:`, `address_token:`, and `stateless_reset:` arguments. Cross-
purpose key reuse is rejected before a listener starts.

## Authenticate clients explicitly

The client side needs one builder call; it never receives a decoded key or TLS
handle:

<!-- example: package=quic_core id=client_certificate -->
```gleam
import quic_core/client

pub fn configure(
  configuration: client.Client,
  client_certificate_pem: BitArray,
  client_private_key_pem: BitArray,
) {
  client.with_client_certificate(
    configuration,
    client_certificate_pem,
    client_private_key_pem,
  )
}

pub fn main() -> Nil {
  let _example = configure
  Nil
}
```

The certificate and private key are parsed and matched immediately. On the
server, decode the accepted client CA set once and choose a clear policy:

<!-- example: package=quic_core id=server_client_auth -->
```gleam
import quic_core/server

pub fn require_client_certificate(
  configuration: server.Server,
  client_ca_pem: BitArray,
) {
  let assert Ok(authorities) =
    server.client_certificate_authorities(client_ca_pem)
  server.with_client_authentication(
    configuration,
    server.Required(authorities),
  )
}

pub fn main() -> Nil {
  let _example = require_client_certificate
  Nil
}
```

`Optional(authorities)` permits a missing certificate; `Required(authorities)`
rejects it. After `server.accept`, `server.client_identity` returns `None` or
an opaque verified identity. Only its SHA-256 leaf fingerprint is accessible.
The certificate chain, public key record, TLS state, and private key remain
internal.

## Handle failures by intent

Public runtime errors wrap `failure.Failure` for resolution, socket, TLS,
QUIC, timeout, cancellation, close, limit, and overload outcomes. Local API
misuse remains role-specific, such as `InvalidDirection`, `StreamFinished`, or
`ConcurrentOperation`.

<!-- example: package=quic_core id=typed_failures -->
```gleam
import quic_core/client
import quic_core/failure

pub fn classify(stream: client.Stream) -> String {
  case client.receive(stream, 64 * 1024) {
    Error(client.Failure(failure.Timeout(failure.Operation))) -> "retry-later"
    Error(client.Failure(failure.Limit(failure.Queue, _maximum))) ->
      "backpressure"
    Error(client.Failure(failure.Tls(failure.Peer))) -> "reject-peer"
    _outcome -> "complete"
  }
}

pub fn main() -> Nil {
  let _example = classify
  Nil
}
```

Failures retain a trustworthy origin, phase, resource, maximum, or protocol
code when available. They do not contain backend-formatted strings or secret
material.

## Inspect a connection safely

`connection_info` reports only authenticated/configured metadata. `phase`,
`path_stats`, `connection_stats`, and `telemetry_stats` return immutable
snapshots. `maximum_datagram_size` reflects the live path, scheduled ACK debt,
and peer transport parameters. `guaranteed_datagram_size` instead reserves the
1200-byte path floor, the widest short-header protection, and the largest ACK
share admitted beside a Datagram. It never grows or shrinks during the
connection, which lets a long-lived downstream adapter fix its receive ceiling
before accepting payloads. These functions never return a native handle.

When qlog is enabled, `client.application_diagnostics` and
`server.application_diagnostics` return an opaque `ApplicationSink` borrowed
from the connection-owned writer. The sink can append typed HTTP/3 settings,
stream-role, frame-kind, payload-length, and validated numeric-code metadata.
It cannot emit arbitrary data or transport events, read writer state, or close
the trace; connection shutdown remains the diagnostic flush barrier. With qlog
disabled these calls return `None`. The writer serializes all producers through
one timestamp watermark. A late-arriving observation whose captured time is
older than the preceding accepted event is emitted at that preceding time;
dropped events do not advance the watermark.

## Resume explicitly

Call `client.resumption_ticket` after the server issues one. Persist it with
`ticket_storage_key` and `export_resumption_ticket`; restore it with
`import_resumption_ticket`, then attach it using `with_resumption_ticket`.
Tickets are origin-bound, so attaching one to a different host or port is
rejected before network I/O.

Attaching a ticket enables authenticated 1-RTT resumption only. Add
`client.with_zero_rtt` to make an explicit early-data attempt, and enable a
finite replay policy on the server. A failed external guard safely continues
at 1-RTT. Applications remain responsible for sending only replay-safe early
operations.

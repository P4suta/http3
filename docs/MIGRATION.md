# Migration from the former source API

The project is unpublished, so these changes intentionally break earlier
source-tree callers instead of preserving unsafe compatibility shims.

## Configuration

- Replace a single timeout with `http3/config.Deadlines`; DNS, connect,
  handshake, operation, idle, drain, and total phases are finite and distinct.
- Replace individual unbounded capacities with `http3/config.Limits`. There
  is no infinity sentinel. Existing 8 MiB body and 256 KiB stream-buffer
  defaults remain.
- Select `Ipv4`, `Ipv6`, or `DualStack` explicitly when the default is not
  suitable. Dual-stack clients stagger and race address families.
- Replace BBR selection with `transport.NewReno` or `transport.Cubic`. The
  former BBR value never performed BBR and has been removed.

## Failures

Replace backend strings with pattern matches on `http3/failure.Failure`.
Timeout phase, local/peer origin, limit resource, and trustworthy protocol
codes remain typed. No replacement exposes raw PIDs, sockets, atoms, mailbox
messages, certificate contents, or traffic secrets.

## Resumption and server operations

- 0-RTT is now disabled unless explicitly enabled with the finite single-node
  replay cache or a bounded caller-managed external replay guard. Rejection,
  guard failure, and timeout fall back to 1-RTT.
- Build purpose-specific current/previous key rings and install them as one
  `OperationalKeys` value. Listener key rotation no longer requires a stop.
- Persist client tickets only with caller-key encrypted
  `export_resumption_ticket`/`import_resumption_ticket`; raw ticket
  serialization is unavailable.
- Replace listener restarts for certificate changes with the atomic
  `server.reload_certificates` operation.

## Package boundary

Raw QUIC packet, frame, transport-parameter, stream-ID, packet-number, varint,
and HTTP/3 adapter modules are no longer exported by `gleam_quic`. Root users
should import only `http3`, `http3/client`, `http3/server`,
`http3/transport`, `http3/config`, `http3/failure`, or `http3/capsule`.

HTTP/3 session, QPACK, Capsule, and worker ownership now lives in `http3`; the
core archive contains none of those modules. The promised generic
`gleam_quic` endpoint surface remains pre-release work. Do not depend on
core-internal modules while the packages are path-linked in this repository.

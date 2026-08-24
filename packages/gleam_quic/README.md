# gleam_quic

`gleam_quic` is the repository-owned QUIC transport, TLS 1.3, HTTP/3, and
QPACK core used by the parent Erlang-target `http3` package. It is a local path
package and the only production backend. It is not published or supported as a
standalone low-level API.

The live UDP runtime implements:

- QUIC v1 and v2 packets, frames, transport parameters, compatible version
  negotiation, Retry, address tokens, stateless reset, and connection IDs;
- TLS 1.3 authentication, AES-GCM and ChaCha20-Poly1305 protection,
  resumption, replay-constrained 0-RTT, and key lifecycle;
- stream and connection flow control, reassembly, ACK/loss/PTO recovery,
  NewReno, CUBIC, pacing, ECN, anti-amplification, PMTU, IPv4/IPv6, rebinding,
  and migration;
- RFC 9114 HTTP/3 client/server sessions, push, GOAWAY, graceful drain, RFC
  9204 QPACK, priority, Extended CONNECT, Capsules, and HTTP Datagrams; and
- bounded workers, statistics, keepalive, and opt-in per-connection qlog.

Protocol parsing, transcript coordination, state machines, recovery,
congestion control, scheduling, and HTTP/3/QPACK behavior are Gleam code.
Small Erlang FFI modules expose only runtime UDP, monotonic time, secure
randomness, cryptographic operations, X.509 validation/signatures, and trace
file I/O.

The parent package owns the stable typed HTTP API and error normalization.
The implementation boundary and completed qualification contract are in
[Architecture](../../docs/ARCHITECTURE.md) and
[Public v1 gate](../../docs/V1.md).

Run this package's complete local check from the repository root:

```sh
mise run core-check
```

The root `mise run check` includes this gate. Generated property and parser
fuzz tasks are separate:

```sh
mise run property
mise run fuzz
```

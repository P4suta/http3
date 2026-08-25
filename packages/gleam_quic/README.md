# gleam_quic

`gleam_quic` is a generic QUIC v1/v2 transport for Gleam on the Erlang target.
It gives applications opaque clients, listeners, connections, streams,
Datagrams, resumption, migration, diagnostics, and typed failures. HTTP/3,
QPACK, and Capsules belong to the sibling `http3` package.

> [!WARNING]
> This package is unpublished, unaudited, and not yet a release candidate.
> The public transport API is implemented and exercised over real UDP, but the
> per-connection actor, credential-interoperability, conformance, performance,
> and distribution gates listed below remain open. Do not deploy it as a
> supported production release.

## Five-minute client

The common path is deliberately small: create a verified client, connect,
open a stream, exchange bytes, and close.

```gleam
import gleam_quic/client

pub fn exchange(ca_pem: BitArray) {
  let assert Ok(configuration) = client.new("example.com", 443, "sample")
  let assert Ok(configuration) =
    client.with_ca_certificates(configuration, ca_pem)
  let assert Ok(connection) = client.connect(configuration)
  let assert Ok(stream) = client.open_bidirectional(connection)
  let assert Ok(Nil) = client.send_and_finish(stream, <<"hello":utf8>>)
  let reply = client.receive(stream, 64 * 1024)
  let assert Ok(client.Closed) = client.close(connection)
  reply
}
```

System trust roots and hostname/IP identity verification are enabled by
default. There is no certificate-verification bypass. Supplying CA PEM bytes
replaces the system roots; it does not disable identity checks.

## Five-minute server

```gleam
import gleam_quic/server

pub fn serve(certificate_pem: BitArray, private_key_pem: BitArray) {
  let assert Ok(configuration) =
    server.new(certificate_pem, private_key_pem, "sample")
  let assert Ok(listener) = server.start(configuration)
  let assert Ok(connection) = server.accept(listener)
  let assert Ok(server.IncomingStream(stream, server.Bidirectional)) =
    server.accept_stream(connection)
  let assert Ok(server.Data(bytes, True)) = server.receive(stream, 64 * 1024)
  let assert Ok(Nil) = server.send_and_finish(stream, bytes)
  server.stop(listener)
}
```

Both sides support bidirectional and unidirectional streams. Reads are pull
based, writes apply synchronous transport backpressure, and unconsumed queues,
buffers, streams, connections, handshakes, Datagrams, and telemetry are
finite. `close` and `stop` are idempotent.

## Mutual TLS without handle plumbing

Client credentials and server policy are configured before any socket opens.
Certificate/key mismatches fail immediately, and the server exposes only a
SHA-256 fingerprint after path, purpose, and CertificateVerify validation:

```gleam
let assert Ok(client_cas) =
  server.client_certificate_authorities(client_ca_pem)
let server_configuration =
  server_configuration
  |> server.with_client_authentication(server.Required(client_cas))

let assert Ok(client_configuration) =
  client.with_client_certificate(
    client_configuration,
    client_certificate_pem,
    client_private_key_pem,
  )

let assert Ok(Some(identity)) = server.client_identity(connection)
let fingerprint = server.client_identity_fingerprint(identity)
```

Use `server.Optional(client_cas)` to accept either a verified identity or an
anonymous client, and `server.Disabled` to omit the certificate request.
Resumed mTLS connections authenticate the client again. Their 0-RTT attempt is
rejected safely while authenticated resumption continues at 1-RTT.

## Safe defaults, explicit power

- `gleam_quic/config` separates DNS, connect, handshake, operation, idle,
  drain, and total deadlines. Every value is finite.
- NewReno is the default; CUBIC is the only alternative. There is no inert BBR
  setting.
- QUIC v1 is the default and v2 is one builder call away.
- IPv4/IPv6 dual-stack clients race staggered candidates and cancel losers.
- TLS key agreement supports X25519 and P-256, including a P-256
  HelloRetryRequest path.
- 0-RTT is disabled unless both client and server opt in. A server must use a
  finite single-node replay cache or a finite external atomic replay guard.
- qlog is opt-in, privacy-strict, asynchronous, bounded, and reports
  drop/write/queue counters instead of blocking transport work.
- `connection_info` reports the authenticated wire version, actually selected
  ALPN and cipher, congestion controller, early-data outcome, and resumption
  outcome without exposing a TLS handle or secret.

Origin-bound tickets can be exported only after encryption with a caller-owned
256-bit storage key. The encoded value includes the address token and can be
imported after a process or listener restart. Operational ticket,
address-token, and stateless-reset keys use independent atomic
current/previous rings.

## Public boundary

Only these modules are public:

- `gleam_quic`
- `gleam_quic/client`
- `gleam_quic/config`
- `gleam_quic/diagnostics`
- `gleam_quic/failure`
- `gleam_quic/server`

Connections, streams, listeners, tickets, replay guards, and operational keys
are opaque. Compiler-interface auditing rejects PID, subject, reference,
native TLS values, traffic secrets, HTTP/3/QPACK types, and raw packet/frame
codecs at the package boundary.

See the [API guide](docs/API.md), [deployment guide](docs/DEPLOYMENT.md), and
[migration guide](docs/MIGRATION.md). Repository-wide conformance and release
status live in the [conformance matrix](../../docs/CONFORMANCE.md) and
[pre-release gate](../../docs/V1.md).

## Development

From the repository root:

```sh
mise run core-check
mise run core-package
mise run api
```

The core suite currently includes direct public real-UDP tests for negotiated
ALPN/cipher diagnostics, bidirectional and unidirectional streams, Datagrams,
typed direction errors, idempotent lifecycle operations, authenticated Retry
and `NEW_TOKEN`, atomic three-ring rotation, encrypted ticket persistence
across listener restart, authenticated resumption, mTLS required/optional
policy and redacted identity access, P-256/HelloRetryRequest, and accepted or
safely rejected 0-RTT. No tag, version change, Hex upload, hosted release, or
push has been performed or authorized.

`mise run core-package` exports twice, audits the declared and actual archive
contents, rejects private keys and non-transport modules, normalizes Hex
metadata ordering and tar attributes, and requires the two resulting archives
to be byte-identical. The canonical archive remains in
`build/gleam_quic-0.1.0.tar`; this is a local release input, not a publication.

## Remaining release blockers

- split the listener into a CID router/admission controller and one supervised
  actor per connection, then enforce the aggregate endpoint memory budget;
- qualify P-256 and mTLS across the OTP 28/29 credential and external-peer
  interoperability matrix;
- complete standards/errata, qlog/schema, CUBIC/HyStart++, coverage, fault,
  four-peer interop, platform, performance, and package-simulation gates; and
- qualify a signed release candidate from a clean source archive.

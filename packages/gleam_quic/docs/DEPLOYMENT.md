# Deployment and key rotation

This package is pre-release and unaudited. The notes below document intended
operations and do not override the open release blockers.

## Credentials

Decode and validate the full certificate set before calling
`server.reload_certificates`. The listener swaps one immutable set for new
handshakes; established connections keep their authenticated TLS state. Keep
private-key bytes out of logs, qlog, crash reports, and package archives.

## Client authentication

Build client trust anchors with `server.client_certificate_authorities`, then
attach `Disabled`, `Optional`, or `Required` policy before listener startup.
Clients attach their chain and matching key with one
`client.with_client_certificate` call. Mismatched pairs fail during
configuration; accepted identities have already passed path, clientAuth EKU,
digital-signature key-usage, and CertificateVerify checks.

Authorize a connection from the opaque identity fingerprint returned by
`server.client_identity`; do not treat certificate text or a caller-supplied
name as authenticated identity. Certificate reload affects new handshakes,
including resumed handshakes. mTLS always reauthenticates on resumption and
forces any early-data attempt to safe 1-RTT fallback.

## Operational keys

Use independent random 256-bit values for ticket, address-token, and
stateless-reset keys.
Construct a `KeyRing` with the current generation, then rotate with
`rotate_key_ring`; exactly one previous generation remains valid during the
transition. Assemble the three rings with named arguments so their purposes
cannot be confused:

```gleam
let assert Ok(keys) =
  server.operational_keys(
    ticket: server.key_ring(ticket_key),
    address_token: server.key_ring(address_token_key),
    stateless_reset: server.key_ring(stateless_reset_key),
  )

let configuration = server.with_operational_keys(configuration, keys)
```

The constructor rejects reuse of a key across purposes. Install the bundle
before startup or pass it to `reload_operational_keys` on a running listener.
Reloading automatically issues a token from the new current address-token key
to established peers. Keep the previous generation installed until clients
have had time to receive and persist that replacement.

Persist the current and previous generations in deployment secret storage so
resumption survives a restart. Never reuse the ticket key as the caller-owned
ticket storage key.

## 0-RTT replay policy

0-RTT is off by default. `with_single_node_zero_rtt` is appropriate only when
all uses of a ticket reach the same listener actor and restart replay is
acceptable to the application. A replicated deployment must use
`replay_guard(timeout, check)` and `with_external_zero_rtt`; `check` must make
an atomic insert-if-absent decision in shared storage for the requested
retention interval. Rejection, error, process exit, or timeout falls back to
authenticated 1-RTT.

0-RTT transport acceptance never makes an application operation replay-safe.
Authorize only idempotent/replay-tolerant application messages before
`connection_info` reports the final outcome.

## Diagnostics

qlog is disabled by default. Store enabled traces in a bounded, access-
controlled location and monitor `TelemetryStats` for drops and write errors.
The fixed qlog revisions are diagnostic drafts, not stable protocol claims.
Do not treat the library's finite defaults as a replacement for host memory,
file-system, firewall, and volumetric-DoS controls.

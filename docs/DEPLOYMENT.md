# Deployment and key rotation

This package is unpublished and not release-ready. This guide records the
intended safe operating model for testing and eventual deployment; it is not
a production-support statement.

## Before starting

- Run only on supported Erlang/OTP 28 or 29 with the pinned Gleam range.
- Supply a complete certificate chain and matching private key. Client
  certificate and hostname/IP verification cannot be disabled.
- Set finite connection, handshake, stream, body, buffer, queue, Datagram,
  QPACK, accept-waiter, and telemetry budgets for the host. The configured
  `EndpointMemory` value is not yet an enforced aggregate budget; use external
  BEAM/host memory controls until PRE-003 and PRE-004 close.
- Set separate DNS, connect, handshake, operation, idle, drain, and total
  deadlines. Do not treat timeouts as successful cancellation.
- Size UDP socket buffers and host firewall/rate limits for the deployment.
  The library's anti-amplification and admission controls do not stop
  volumetric traffic before it reaches the host.

Use `server.with_bind_address` with an `http3/address.Address` when a listener
must be restricted to one interface. Address parsing accepts literals only and
does not turn a configuration value into a DNS lookup. TCP and UDP may use the
same numeric port because they are distinct transports; advertise that mapping
at the application layer only after the UDP listener is ready.

For rate limits and audit identity, use `server.peer_endpoint`. It tracks only
the peer path authenticated by QUIC path validation, including migration and
NAT rebinding. Do not substitute untrusted forwarded headers for this value.

## Certificate reload

Build and validate a complete replacement `server.Configuration`, then call
`server.reload_certificates(listener, replacement)`. Validation finishes
before the listener swaps one certificate set. New handshakes see either the
old complete set or the new complete set; existing connections are unchanged.

Keep the previous certificate available until all expected old connections
have drained. A failed reload leaves the active set untouched.

## Operational keys

Ticket, address-token, and stateless-reset keys are distinct 32-byte secrets.
Load them from a secret manager; never embed them in source, logs, qlog, crash
dumps, or command-line arguments.

For each purpose:

1. Start with a `server.key_ring(current)`.
2. Generate a new independent key.
3. Call `server.rotate_key_ring`; the former current key becomes previous.
4. Assemble all three rings with `server.operational_keys`.
5. Atomically install them with `server.reload_operational_keys`.
6. Keep the previous generation through the maximum ticket/token lifetime and
   rollout window, then install a ring without it.

Persist current and previous generations across listener and node restarts.
Reusing one secret for multiple purposes is rejected by domain-separated
configuration.

## Session tickets and 0-RTT

0-RTT is disabled by default. `server.with_single_node_zero_rtt` enables only
a finite replay cache owned by one listener process. Restarting that process
safely rejects early data and continues with authenticated 1-RTT.

For multiple nodes, use `server.replay_guard` and
`server.with_external_zero_rtt`. The callback must perform one atomic
insert-if-absent in shared storage, keyed by
`server.replay_fingerprint(attempt)`, and retain it for at least
`server.replay_valid_for_milliseconds(attempt)`. Return `AcceptEarlyData` only
when the insertion succeeds for a previously unseen key. Return
`RejectEarlyData` for an existing key and `Error(Nil)` when the store is not
authoritative. The configured callback deadline is finite; rejection, store
failure, callback exit, and timeout reject only early data and continue the
authenticated connection at 1-RTT.

The callback currently runs behind the listener's finite handshake boundary.
Choose a short deadline appropriate for the shared store; full per-connection
actor isolation remains a separate release blocker. Even with transport replay
checks, applications must treat early requests as replayable and must
independently authorize every operation.

Client tickets can be persisted only through
`transport.export_resumption_ticket` using a caller-managed 32-byte storage
key. The ciphertext is versioned, authenticated, origin-bound, expiring, and
rejects tampering, a wrong key, or clock rollback. Rotate the storage key with
an application-managed overlap window; the library does not expose ticket
plaintext.

## qlog and telemetry

qlog is opt-in and can reveal traffic metadata and HTTP/3 event details.
Write it to a private, capacity-limited directory, monitor
`TelemetryStats`, rotate files outside the connection process, and apply a
short retention period. The shared `Telemetry` limit bounds waiting events
per writer, in addition to one active write. Writer failure must never become
a reason to expose secrets or disable protocol bounds.

## Shutdown and incident capture

Prefer graceful drain during routine deploys, then enforce the finite drain
deadline. For an incident, retain the fixed test seed, pcap where policy
permits it, privacy-redacted qlog, runtime profile, raw benchmark row, exact
source revision, and OTP version. Do not retain traffic secrets or certificate
private keys in the incident bundle.

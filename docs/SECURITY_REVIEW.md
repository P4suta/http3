# Pre-publication security review

## Review record

| Item | Value |
| --- | --- |
| Review date | 2026-08-24 |
| Implementation baseline | `b64ac4444b50c0ee84914bcedc1f3e01a98fec9a` |
| Runtime baseline | Gleam 1.18.1, Erlang/OTP 29.0.5 |
| Scope | Root public API and adapters, repository-owned QUIC/TLS/HTTP/3/QPACK core, production Erlang FFI, manifests, tests, and CI |
| Review type | Internal source and behavior review |
| Outcome | No unresolved critical, high, or known correctness finding in the reviewed v1 scope |

This is a pre-publication internal review, not a claim of formal verification,
cryptographic certification, or an independent third-party audit. The review
establishes that the intended trust boundaries are present in source and that
the repository's adversarial qualification gates pass.

## Threat model

The implementation treats all network packets, peer protocol state,
certificates, headers, settings, tickets presented by a peer, stream data, and
timing as hostile. It also treats public API arguments as untrusted and
validates them before network work or allocation.

The trusted computing base is:

- the Erlang VM and its `crypto`, `public_key`, and UDP facilities;
- the operating-system trust store, clock, entropy source, filesystem, and
  network stack;
- application-provided private keys, explicit trust anchors, and qlog
  directory permissions; and
- the Gleam compiler and locked production dependencies.

The library protects protocol authenticity, confidentiality, downgrade
resistance, bounded resource use, and deterministic ownership inside one BEAM
node. It cannot protect a compromised host or VM, malicious application code
that already owns opaque values, incorrect application authorization, exposed
private keys, traffic analysis, or denial of service that exhausts resources
outside the configured endpoint limits.

## Trust boundaries and data flow

The public modules export opaque client, connection, stream, listener, request,
push, ticket, priority, and qlog values. The compiler package-interface audit
rejects internal module names, backend handle types, or constructor bridges.

Root adapters normalize requests, responses, events, configuration errors, and
transport failures before crossing into the native package. Native Gleam
workers own all processes, socket lifetimes, protocol state, queue state, and
mailbox messages. The full data flow is documented in
[Architecture](ARCHITECTURE.md).

The production FFI was enumerated and reviewed:

- `src/http3_internal_transport_ffi.erl` has four functions that wrap opaque
  handles only;
- `gleam_quic_crypto_ffi.erl` exposes checked runtime crypto primitives;
- `gleam_quic_tls_ffi.erl` exposes checked X.509, key, signature, and
  constant-time operations;
- `gleam_quic_udp_ffi.erl` owns UDP, addressing, ECN ancillary data, and
  monotonic time; and
- `gleam_quic_qlog_ffi.erl` creates unique files and writes bounded
  diagnostic events.

No Erlang module parses or constructs a QUIC, TLS, HTTP/3, or QPACK wire
message, schedules recovery, or owns a protocol state machine.

## Cryptographic usage

Cryptographic primitives are delegated to Erlang/OTP rather than implemented
with application arithmetic. FFI guards require binaries and exact algorithm
sizes, catch runtime exceptions, and return closed errors. The native Gleam
layer coordinates:

- SHA-256/SHA-384, HMAC, HKDF extract/expand, and TLS 1.3 HKDF labels;
- X25519 key agreement;
- AES-128-GCM, AES-256-GCM, and ChaCha20-Poly1305 payload protection;
- AES-ECB and ChaCha20 QUIC header protection;
- QUIC v1/v2 Initial secrets and Retry integrity;
- CertificateVerify signatures and constant-time Finished/PSK/tag checks; and
- packet-number nonces, traffic-key updates, discard rules, and AEAD
  confidentiality/integrity usage limits.

Known-answer coverage includes RFC 4231, RFC 5869, RFC 7748, RFC 8448,
RFC 9001, and RFC 9369 examples plus tamper and invalid-size cases. Secret
values remain in internal state and are absent from public errors and qlog
events.

## TLS authentication and identity

The client always sends SNI for DNS names and validates both the certificate
path and the expected DNS or IP service identity. System trust roots are the
default; a custom CA set replaces only the roots. There is no public
verification-disable flag.

The TLS FFI decodes bounded PEM/DER material, validates paths with OTP
`public_key`, and checks the leaf identity. Tests cover trusted and untrusted
paths, DNS and IP identities, wildcard boundaries, mismatches, malformed
material, signature tampering, and custom CA behavior.

The server validates every certificate/key pair before listener startup.
Additional credentials use strict, single-label SNI wildcard matching; the
live UDP suite verifies that the selected certificate authenticates the
requested name.

## Version negotiation, Retry, and key lifecycle

QUIC v1 and v2 Initial keys and packet types are version specific. A client
that receives Version Negotiation accepts only an offered compatible version,
restarts with fresh version-specific state, and authenticates the negotiated
and available versions through RFC 9368 TLS transport parameters. Missing,
inconsistent, or downgrade information fails closed. Direct v2 remains
compatible with a peer that does not negotiate RFC 9368.

Retry integrity is verified before state changes. Retry preserves a valid PSK
resumption attempt but rejects early data. Initial and Handshake keys are
discarded only after their protocol conditions, and a key update keeps old
keys for the bounded acknowledgement/three-PTO window. Tests cover tampered
Version Negotiation, Retry, Finished, payloads, and key-phase transitions.

## Resumption and replay

Session tickets are AES-256-GCM protected and opaque to callers. Ticket
contents bind the verified server name, port, ALPN, cipher suite, QUIC version,
and remembered 0-RTT transport parameters. The implementation checks expiry
and obfuscated age modulo 2^32.

The server uses a bounded, time-windowed anti-replay cache. Saturation, replay,
clock rollback, changed transport parameters, Retry, or an invalid binder
rejects early data without weakening the authenticated 1-RTT path. The public
client permits only GET, HEAD, and OPTIONS before early-data acceptance is
known. If a peer rejects 0-RTT, queued request bytes are sent after 1-RTT keys
become available rather than being lost.

Applications must still treat every 0-RTT request as replayable at the
application layer. “Safe method” is a transport admission rule, not a promise
that a particular handler has no side effect.

## Amplification, paths, and stateless mechanisms

Before address validation, the server limits sent bytes to the QUIC
anti-amplification allowance. Retry and reusable address tokens are
authenticated, address bound, expiring, and version/context separated.
Stateless-reset tokens are derived and compared without exposing them.

New paths are challenged and validated before migration. Connection-ID
rotation and retirement prevent reuse below the peer watermark; the initial
connection ID can acquire its authenticated reset token regardless of frame
ordering. NAT rebinding, active migration, IPv4/IPv6, ECN failure, PMTU
changes, path loss, and post-migration requests have state-model or real-UDP
coverage.

## Parser and denial-of-service bounds

All incremental parsers accept explicit byte/count limits or enforce protocol
maximums before allocating. Reviewed peer-controlled state includes:

- packet and frame lengths, ACK ranges, CRYPTO and STREAM offsets, final sizes,
  overlap, and reassembly buffers;
- transport parameters, TLS messages/extensions, certificate chains,
  signatures, tickets, and transcript buffers;
- concurrent streams, connection and stream flow-control windows, send queues,
  pull waiters, datagram queues, and retained terminal stream entries;
- HTTP field counts and sizes, content lengths, DATA bodies, Capsules, push
  IDs, SETTINGS, and GOAWAY state;
- QPACK table capacity, insertions, references, blocked streams, instruction
  queues, Huffman expansion, and decompressed field-section size;
- packet history, ACK/loss state, retransmission, pacing, PTO, PMTU probes,
  connection IDs, tokens, paths, anti-replay entries, and old keys; and
- public operation, stream, listener, peer-runner, worker, and cleanup
  deadlines.

Invalid authentication is discarded before application dispatch. Queue
saturation returns typed pressure or cancels the affected stream; it does not
silently grow a mailbox. Terminal stream state uses bounded FIFO retention.
The 160,000-stream soak returns below its starting process count with zero
queued mailbox messages after cleanup.

## HTTP semantics and extensions

Request and response header validation rejects HTTP/3-forbidden
connection-specific fields, invalid names/values, inconsistent pseudo-fields,
duplicate or mismatched content lengths, and invalid informational/final,
DATA, or trailer ordering.

Critical control/QPACK stream closure, duplicate SETTINGS or critical streams,
invalid push/GOAWAY identifiers, field decompression failure, and stream
creation violations map to typed HTTP/3 errors. QPACK references are retained
until acknowledgement or cancellation, cannot be evicted while live, and are
limited by the peer's blocked-stream budget.

HTTP Datagrams require negotiated support and an Extended CONNECT request
association. Payload size follows the live path and QUIC DATAGRAM limits;
orphan and associated receive queues are bounded, and concurrent pulls are
rejected. Capsules are incrementally decoded with value and buffered-byte
limits.

## Logging and diagnostics

qlog is opt-in and requires an explicitly validated writable directory. Each
connection creates a unique trace, so client/server or concurrent connections
cannot overwrite one another. File creation retries are bounded and cleanup
closes the device.

Traces contain transport metadata and application-protocol details and must be
protected as sensitive data. The implementation does not log traffic secrets,
private keys, raw session-ticket fields, or certificate trust-store terms.
Public errors include protocol context and numeric codes without secret
material.

## Dependencies and source audit

The production closure is deliberately small:

- root: `gleam_http`, `gleam_stdlib`, and the local `gleam_quic` path
  package;
- native core: `gleam_erlang` and `gleam_stdlib`; and
- Erlang/OTP runtime applications already in the trusted computing base.

The lock manifest contains no external QUIC implementation. Searches of root
and native production source find no `erlang_quic`, `quic_h3`, or external
backend call. There is no NIF, port driver, C/Rust library, runtime downloader,
dynamic atom construction from user input, or backend-selection environment
variable.

Development peers are separately pinned: aioquic 1.3.0 has a
hash-locked Python dependency closure, and quic-go 0.61.0 has Go module
checksums. They execute as bounded out-of-process loopback peers and are absent
from package manifests.

## Adversarial verification

The reviewed baseline passes:

- 278 native tests and 108 public-package tests;
- 10,000 generated wire-codec properties;
- 10,000 generated parser cases plus 16 retained seeds;
- real-UDP duplication, corruption, delay, MTU restriction, loss, and
  reordering;
- bidirectional interoperability with aioquic 1.3.0 and quic-go 0.61.0,
  including explicit v1/v2, authenticated version negotiation, TLS identity,
  Datagram, migration, qlog, resumption, and observed 0-RTT; and
- fixed load and a 160,000-stream soak with process and mailbox convergence.

`mise run check` additionally enforces warnings-as-errors, compiler API
boundaries, documentation, source/prose/config/workflow/shell/spelling lint,
and REUSE licensing. Exact commands and performance rows are in
[Testing](TESTING.md) and [Performance](../benchmarks/README.md).

## Residual and operational risks

No unresolved implementation finding was identified, but operators must still
account for:

- the absence of an independent third-party security audit;
- application-level replay and authorization policy for 0-RTT;
- secure storage and rotation of certificate private keys and qlog files;
- operating-system trust-store quality, entropy, clock, UDP buffer, firewall,
  and PMTU behavior;
- capacity limits appropriate to the deployment rather than relying only on
  library defaults;
- UDP source spoofing and volumetric denial of service outside one endpoint's
  anti-amplification and resource bounds; and
- changes in future OTP cryptographic or X.509 behavior.

OTP 28 and 29 both pass clean root/native builds and all tests locally. Before
publication, observe the configured Linux/macOS/Windows hosted matrix and
review any dependency or standards errata that appeared after this dated
baseline. Before a production deployment, prefer an independent security
review and deployment-specific load testing.

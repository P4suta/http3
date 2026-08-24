# Architecture

## Scope and status

`http3` is an HTTP/3-only client and server for the Erlang target. HTTP/1.1,
HTTP/2, automatic fallback, and the JavaScript target are non-goals. The
repository-defined v1 implementation uses the in-tree `gleam_quic` package as
its only production transport; aioquic and quic-go are test peers, not runtime
dependencies.

The package version is required tool metadata. Architecture and quality gates
do not depend on a tag, hosted release, or package publication.

## Production data flow

```text
Application
    |
http3, http3/client, http3/server, http3/transport, http3/capsule
    |  opaque Client / Connection / Stream / Listener / Request values
http3/internal request, response, event, and error adapters
    |
gleam_quic/http3 client and server adapters
    |
Gleam-owned workers, HTTP/3 session, QPACK, QUIC driver, TLS, and recovery
    |
narrow Erlang runtime FFI: UDP, crypto, X.509, qlog file I/O
    |
operating-system UDP socket
```

Protocol state moves down this diagram and typed observations move up. A raw
PID, atom, reference, socket, map, record, mailbox message, traffic secret, or
native trust-store term cannot cross the public boundary.

## Public HTTP boundary

The public client and server use `gleam/http` methods, requests, responses,
headers, and status codes. This shares an HTTP data model; it does not add an
HTTP/1.1 or HTTP/2 implementation.

`Client`, `Connection`, `Stream`, `Listener`, `Request`, `Push`,
`ResumptionTicket`, and the transport control values are opaque. Public
operations return typed configuration, HTTP, transport, lifecycle, and limit
errors. The compiler-interface audit rejects internal module names, native
handle types, and constructor bridges in the exported package interface.

The bounded helpers are intentionally collectors with explicit request and
response limits. The streaming API is the unbounded-duration alternative, not
an unbounded-memory alternative:

- request writes synchronously retain QUIC flow-control pressure;
- response and request events are pulled by the consumer;
- every unconsumed per-stream queue has a configured byte bound;
- concurrent receives are rejected rather than creating ambiguous waiters;
- deadlines cover the whole operation, including handshake and cleanup; and
- cancellation, close, immediate stop, and graceful stop are observable and
  idempotent.

## Native HTTP/3 runtime

The root adapters call `gleam_quic/http3/client` and
`gleam_quic/http3/server`. Their Gleam workers own reusable connections,
listeners, stream registries, pull waiters, bounded queues, and operation
deadlines. The HTTP/3 session owns:

- the local and peer control streams and SETTINGS state;
- request, response, informational, DATA, trailer, push, and GOAWAY ordering;
- graceful drain and rejection of streams beyond the advertised boundary;
- Extended CONNECT, Capsules, and HTTP Datagrams associated with a request;
- RFC 9218 priority updates and scheduling; and
- QPACK encoder and decoder streams, dynamic-table references, blocked-stream
  limits, feedback, Huffman coding, and decompression bounds.

Terminal stream state is retained in a bounded FIFO registry so late messages
can be classified without accumulating state for every historical stream.
Datagrams that arrive before their request association are bounded as strictly
as associated queues.

The public server accepts one request head at a time per `accept` call while
the underlying listener continues to multiplex connections and request
streams. Multiple certificates can be configured; the TLS server selects a
matching credential from the strict ClientHello SNI name. Graceful stop sends
the HTTP/3 drain signal, rejects later accepts, permits active requests to
finish,
then closes the listener within its deadline.

## Native QUIC runtime

`packages/gleam_quic` contains the protocol implementation. Its driver joins
the following Gleam-owned components:

- invariant, long-header, short-header, frame, transport-parameter, and packet
  codecs for QUIC v1 and v2;
- authenticated compatible version negotiation and Retry handling;
- Initial, Handshake, 0-RTT, and 1-RTT packet spaces and key lifecycle;
- connection-ID issuance, retirement, routing, and stateless-reset tokens;
- connection and stream state, out-of-order reassembly, final-size checks,
  connection and stream flow control, and round-robin stream scheduling;
- ACK generation, RTT estimation, loss detection, PTO, retransmission,
  NewReno, CUBIC, pacing, and ECN validation;
- anti-amplification, authenticated address tokens, path challenge/response,
  NAT rebinding, active migration, and connection-ID rotation;
- IPv4 and IPv6 UDP operation, QUIC DATAGRAM, path statistics, and opt-in qlog;
  and
- DPLPMTUD probes that keep packets below the validated path MTU without
  relying on IP fragmentation.

The driver uses monotonic deadlines and bounded command polling. It drains
bursty handshake datagrams, retransmits after loss or corruption, validates a
new path before moving application traffic, and discards obsolete packet
protection keys according to the relevant packet-space and key-update rules.

## TLS and resumption

TLS 1.3 handshake messages, extensions, transcript coordination, key schedule,
PSK binders, QUIC transport parameters, and session-ticket contents are Gleam
code. The supported packet-protection families are AES-128-GCM,
AES-256-GCM, and ChaCha20-Poly1305 with the corresponding QUIC header
protection.

Client authentication always validates the certificate path and the DNS or IP
service identity. A custom CA changes trust anchors but does not disable either
check. The normal public surface has no insecure verification switch.

Session tickets are opaque and encrypted. They bind the verified server name,
port, ALPN, cipher, QUIC version, and the transport parameters that affect
0-RTT. Ticket ages are bounded, the server applies a time-windowed anti-replay
cache, Retry rejects early data, and changed remembered parameters reject
early data without preventing a safe 1-RTT resumption. Until acceptance is
known, the public client permits only GET, HEAD, and OPTIONS in early data.
Rejected early requests are retransmitted after 1-RTT keys become available.

## Erlang FFI boundary

Only five production Erlang modules exist:

| Module | Responsibility |
| --- | --- |
| `http3_internal_transport_ffi` | Wrap already opaque Gleam handles for the public transport facade |
| `gleam_quic_crypto_ffi` | Runtime hashes, HMAC, secure randomness, X25519, AEAD, and header-protection primitives |
| `gleam_quic_tls_ffi` | PEM/X.509/key decoding, path and identity validation, signing, verification, and constant-time comparison |
| `gleam_quic_udp_ffi` | UDP socket ownership, address conversion, ECN ancillary data, and monotonic time |
| `gleam_quic_qlog_ffi` | Unique trace-file creation and bounded JSON event output |

These modules validate Erlang term and binary shapes, catch runtime failures,
and return closed numeric or typed errors. They do not parse or construct
QUIC, TLS, HTTP/3, or QPACK wire messages and do not own a protocol state
machine. qlog serialization formats diagnostic events that have already been
selected and bounded by Gleam; it does not inspect network packets.

## Dependency and replacement boundary

The root package depends on the path package `gleam_quic`, `gleam_http`, and
`gleam_stdlib`. The native package depends only on `gleam_erlang` and
`gleam_stdlib`. No external QUIC library, NIF, C library, or alternative
production backend is selected at runtime.

Keeping the root adapter remains useful even with one backend: it normalizes
the lower-level native errors, prevents representation leakage, and lets the
public API describe HTTP behavior rather than driver machinery. A future
transport experiment must connect below this boundary and pass the same
observable behavior suite; it cannot introduce a public raw-handle escape
hatch.

## Resource ownership and shutdown

Every live resource has one owner:

- a one-shot client owns and closes its connection;
- a reusable client worker owns its UDP socket and all request streams;
- a listener worker owns the socket, accepted connections, and request
  handlers;
- each blocked call is monitored and has a fixed deadline; and
- owner termination initiates bounded cancellation and socket cleanup.

Peer-controlled lengths, counts, tables, stream windows, queues, capsules,
datagrams, packet histories, retained keys, terminal entries, timeouts, and
amplification credit all have explicit bounds. Cleanup tests require process
and mailbox convergence rather than treating a returned response as sufficient.

## Stable and experimental scope

Stable v1 implements published QUIC, HTTP/3, QPACK, priority, Extended CONNECT,
Capsules, and Datagram standards. WebSocket framing, MASQUE, and WebTransport
are application protocols that can be built above those primitives.

Internet-Drafts such as WebTransport over HTTP/3, QUIC multipath, ACK
Frequency, reliable stream reset, extended key update, receive timestamps, and
the evolving qlog schemas are not silently negotiated by this package. Draft
work belongs in an explicitly named, revision-pinned experimental package.

The complete implementation and evidence contract is recorded in
[Public v1 gate](V1.md), [Testing](TESTING.md), and the
[security review](SECURITY_REVIEW.md).

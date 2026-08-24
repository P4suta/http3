# Roadmap

The v1 roadmap is complete as of 2026-08-24. The phases remain here as a
record of dependency order and acceptance criteria. Completion refers to the
source implementation and locally executable qualification gates; publishing,
tagging, releasing, changing the metadata version, and uploading to Hex were
not performed.

This roadmap is exclusively for HTTP/3 on the Erlang target. HTTP/1.1,
HTTP/2, automatic protocol fallback, and the JavaScript target belong in other
projects. Every future change continues to use Red-Green-Refactor and the
verification layers in [Testing](TESTING.md).

## Completion summary

| Phase | Outcome | Status |
| --- | --- | --- |
| 1. Bounded buffered client | Secure one-shot requests with typed limits and cleanup | Complete |
| 2. Streaming and cancellation | Reusable multiplexed connections with bounded pull events and backpressure | Complete |
| 3. Server | Bounded and streaming listener with deterministic ownership | Complete |
| 4. Advanced capabilities | Datagram, priority, migration, resumption, qlog, statistics, and lifecycle extensions | Complete |
| 5. Native wire core | QUIC v1/v2 wire formats, invariants, frames, and parameters | Complete |
| 6. Native TLS and packet protection | Authenticated TLS 1.3, Retry, resumption, 0-RTT, and key lifecycle | Complete |
| 7. Transport, recovery, and paths | Live UDP, recovery, congestion, ECN, PMTU, CID, and migration | Complete |
| 8. HTTP/3 and QPACK | Full request/control semantics, push, drain, extensions, and QPACK | Complete |
| 9. Adapter cutover | Repository-owned core is the sole production backend | Complete |
| 10. v1 qualification | Two-peer interop, faults, fuzz/property, performance, and security review | Complete locally |

## 1. Bounded buffered client

**Completed:** 2026-08-23; requalified on the native core on 2026-08-24.

The client accepts `gleam/http` requests, performs real HTTP/3 work, and
returns bounded `BitArray` response bodies. Request validation rejects
non-HTTPS origins, invalid authority or request targets, forbidden headers,
invalid content lengths, non-byte-aligned data, and configured size violations
before network work.

One monotonic deadline includes connection setup, TLS, the response, and
shutdown. Certificate-chain and service-identity verification are mandatory.
The connection has one owner and converges after success, timeout, limit
failure, or peer termination.

## 2. Streaming, backpressure, and cancellation

**Completed:** 2026-08-23; requalified on the native core on 2026-08-24.

Reusable connections multiplex request streams. Writes synchronously preserve
transport flow control, reads pull one event at a time, and unconsumed data is
bounded per stream. Informational responses, final headers, DATA, trailers,
and end-of-stream remain separately observable.

Concurrent receive is rejected. Cancellation, a cancellation race, early
response, peer failure, owner death, close, and repeated close all have typed,
bounded outcomes. A buffered helper never weakens these streaming guarantees.

## 3. Server

**Completed:** 2026-08-23; requalified on the native core on 2026-08-24.

The server owns its UDP listener, accepted connections, request handlers, and
stream queues. It supports bounded and streaming requests and responses,
informational responses, trailers, concurrent streams, and concurrent clients.
Request and response limits are independent.

Credential material is validated before startup, and additional credentials
are selected by SNI. Immediate and graceful stop are idempotent; blocked
accept/read operations and owner termination release resources within fixed
deadlines.

## 4. Advanced capabilities

**Completed:** 2026-08-23; requalified and extended on 2026-08-24.

Opaque connection and stream facades expose:

- negotiated HTTP Datagrams on Extended CONNECT and bounded Capsules;
- RFC 9218 priority and scheduler updates;
- active migration, path, MTU, and connection statistics;
- NewReno/CUBIC selection, keepalive, and ping;
- opt-in, connection-isolated qlog traces;
- origin-bound session tickets and replay-constrained 0-RTT;
- server push, GOAWAY, and graceful draining; and
- QUIC v1/v2 selection and authenticated compatible version negotiation.

No control returns a raw process, socket, map, atom, or protocol message.

## 5. Native wire core

**Completed:** 2026-08-24.

The `gleam_quic` package implements bounded codecs for QUIC invariant,
version negotiation, long/short packet, packet number, every standard
transport frame including DATAGRAM, transport parameters, and coalesced
packets. It supports v1 and v2 mappings, unknown and reserved versions, Retry
separation, compatible version information, non-minimal permitted integers,
and strict semantic and allocation limits.

Published examples and negative tests cover truncation, ambiguity, invalid
roles, duplicate parameters, overflow, alignment, UTF-8, connection-ID and
reset-token sizes, ACK arithmetic, unknown types, and resource exhaustion.

## 6. Native TLS 1.3 and packet protection

**Completed:** 2026-08-24.

The Gleam TLS coordinator implements bounded handshake and extension codecs,
X25519, transcript rewriting for one HelloRetryRequest, TLS 1.3 key schedule,
certificate authentication, CertificateVerify and Finished, QUIC transport
parameters, and packet-space key installation/discard.

AES-128-GCM, AES-256-GCM, ChaCha20-Poly1305, AES and ChaCha header
protection, QUIC v1/v2 Initial derivation, and Retry integrity are verified
against published vectors. The live path supports post-handshake tickets,
authenticated PSK binders, resumption, real 0-RTT, anti-replay, remembered
transport-parameter checks, rejection fallback, AEAD usage limits, and key
updates with bounded old-key retention.

## 7. Native transport, recovery, and paths

**Completed:** 2026-08-24.

The connection driver assembles stream and connection flow control,
out-of-order CRYPTO/STREAM reassembly, ACK scheduling, RTT, packet/time loss,
PTO, retransmission, NewReno, CUBIC, pacing, and ECN validation over real UDP.

It enforces server anti-amplification, authenticated Retry and reusable address
tokens, stateless reset, connection-ID rotation and retirement, path
challenge/response, NAT rebinding, active migration, IPv4/IPv6 operation,
QUIC DATAGRAM, DPLPMTUD, keepalive, and deterministic close. Real-UDP faults
cover duplication, corruption, delay, loss, reordering, and constrained MTU.

## 8. Native HTTP/3 and QPACK

**Completed:** 2026-08-24.

The native session implements RFC 9114 control, request, response, push,
QPACK encoder, and QPACK decoder streams. SETTINGS, critical-stream rules,
message ordering, informational responses, DATA, trailers, content lengths,
push limits and cancellation, GOAWAY, and graceful draining are typed and
bounded.

QPACK includes the static and dynamic tables, encoder/decoder instructions,
feedback, reference retention, eviction safety, blocked-stream limits,
wrapped required-insert counts, and HPACK Huffman coding with expansion and
padding checks. Priority, Extended CONNECT, Capsules, and request-associated
HTTP Datagrams are integrated into the same session.

## 9. Adapter cutover

**Completed:** 2026-08-24.

The root behavior suite runs entirely on `gleam_quic`. The manifest contains
no external QUIC package, production source contains no external QUIC runtime
call, and the compiler API audit prevents a native handle or internal adapter
from leaking. The remaining root Erlang FFI contains only four opaque-wrapper
functions; all protocol work follows the native Gleam path described in
[Architecture](ARCHITECTURE.md).

## 10. Public v1 qualification

**Completed locally:** 2026-08-24.

The completion evidence includes:

- 278 native-core and 108 public-package tests;
- 10,000 reproducible property cases and 10,016 fuzz cases;
- deterministic real-UDP faults and lifecycle/resource convergence;
- bidirectional aioquic 1.3.0 and quic-go 0.61.0 interoperability, explicit
  QUIC v1/v2, RFC 9368, Datagram, migration, qlog, tickets, and observed 0-RTT;
- retained benchmark, 32-connection load, and 160,000-stream soak rows;
- a compiler public-interface and production dependency audit;
- a documented security review; and
- the full format, warnings-as-errors, test, docs, lint, workflow, spelling,
  shell, and REUSE gate.

OTP 28–29 and Linux/macOS/Windows build/test jobs are defined in the pinned CI
workflow. OTP 28 and 29 both pass the root and native suites locally; the OTP
28 run used an isolated official container. A hosted macOS/Windows result is a
publication preflight because this Linux workspace cannot produce those
runners; it is not an unfinished protocol implementation.

## Maintenance after v1

The roadmap now changes from feature construction to maintenance:

- add a failing regression for every defect;
- consume relevant published errata and security advisories;
- rerun every affected qualification layer;
- update pinned independent peers deliberately; and
- keep draft protocols in separate, revision-pinned experimental packages.

Publication remains a separate user-authorized operation.

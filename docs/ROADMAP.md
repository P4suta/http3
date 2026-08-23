# Roadmap

The phases below are ordered. Phases 1 through 4 are bootstrap API phases over
the temporary external backend; they do not constitute public v1. Later phases
replace that backend with the repository-owned QUIC stack and satisfy the
complete [public v1 gate](V1.md). Later phases may be designed early, but they do
not displace the compatibility and safety work required by earlier phases.
The roadmap is exclusively for HTTP/3 on the Erlang target. HTTP/1.1, HTTP/2,
automatic protocol fallback, and the JavaScript target belong in other
projects.

Every phase uses Red-Green-Refactor and the verification layers in
[Testing](TESTING.md). A new behavior begins with a failing test. Completion
is based on observable behavior, cleanup, interoperability, and conformance;
publishing to GitHub or Hex, tagging, creating a release, and changing the
tooling version are optional operations and never phase gates.

## 1. Bounded buffered client

**Status:** complete as of 2026-08-23. Verification includes pure tests, event
and error normalization, real-UDP loopback, a TLS-verified public-client
round trip with the independent aioquic 1.3.0 peer, the quic 1.8.1 HTTP/3
compliance module, and deterministic packet-loss, reordering, peer-termination,
timeout, and resource-limit scenarios. Exact evidence is recorded in
[Testing](TESTING.md).

Implement a real HTTP/3 client request-response flow using `gleam/http`
request and response concepts. Buffer request and response bodies
only within explicit limits, reject limit violations with typed errors, and
make connection ownership and deterministic shutdown clear.

Establish certificate-chain and hostname verification by default, bounded
operation timeouts, backend event and error normalization, and real UDP
loopback coverage. Do not export an operation until it performs the documented
protocol work.

## 2. Streaming, backpressure, and cancellation

**Status:** complete as of 2026-08-23. The reusable client exposes opaque
connection and stream values, synchronous producer backpressure, bounded
pull-based response events, total stream deadlines, race-safe idempotent
cancellation, and deterministic owner/connection cleanup. Verification covers
independent aioquic 1.3.0 streaming interoperation, backend conformance, real
UDP multiplexing, flow-control pressure, cancellation races, slow consumers,
packet loss, early responses, peer failure, and resource limits.

Add streaming request and response bodies without changing the bounded helper
into an unbounded collector. Preserve flow-control backpressure, expose
end-of-stream and transport failures, and make cancellation observable,
idempotent, and race-safe.

Cover slow producers and consumers, early response termination, cancellation
at each connection and stream state, and cleanup after both local and peer
failure.

## 3. Server

**Status:** complete as of 2026-08-23. The server exposes opaque configuration,
listener, and request values; bounded and pull-based streaming request bodies;
synchronous streaming responses; typed limits and failures; and deterministic
ownership and shutdown. Verification covers an independent aioquic 1.3.0
client, backend conformance, real-UDP bounded and streaming round trips,
same-connection multiplexing, concurrent accepts, peer failure, malformed
event normalization, declared content lengths, and resource limits.

Implement the HTTP/3 server after the client has exercised the shared
connection, stream, body, error, cancellation, and shutdown model. Add bounded
buffered handling first, then streaming handlers with backpressure and
deterministic ownership.

Keep listener, connection, and request-process lifetimes explicit. Test clean
shutdown, abrupt peer termination, malformed input, concurrent streams, and
resource limits without exposing backend handles or mailbox formats.

## 4. Advanced capabilities and escape hatch

**Status:** complete as of 2026-08-23. Typed connection and stream controls
cover HTTP Datagrams, RFC 9218 priority, active migration, replay-safe 0-RTT,
qlog, congestion control, ping, MTU, and transport statistics. Verification
includes real-UDP client/server coverage, independent aioquic 1.3.0 Datagram,
migration, qlog, and actual early-request interoperability, backend
conformance, negotiation and resource limits, concurrent receive, origin
binding, and replay-safety failures.

Add HTTP Datagrams, stream priority, connection migration, 0-RTT, qlog, and
other transport controls behind typed capabilities. Low-level access must
remain backend-neutral where possible and must not expose raw PIDs, atoms,
maps, or mailbox messages.

Any certificate-verification bypass remains confined to an explicitly named,
test-only surface.

## Continuous verification

**Status:** active and implemented. The repository retains fixed benchmark,
32-connection load, and 160,000-stream soak tasks with warm-up, repeated trials
where applicable, bounded cleanup, process and mailbox convergence checks,
environment metadata, and raw CSV results. These localhost measurements are
verification evidence rather than production throughput claims.

Verification is not deferred to a late implementation phase. Every change
uses the applicable pure, adapter, and real-UDP loopback tests and passes
`mise run check`. Each phase completes with an independent HTTP/3 peer,
conformance coverage, and relevant fault injection.

When performance becomes the focus, add controlled load and soak tests and a
reproducible benchmark methodology. Cover flow-control pressure, packet loss
and reordering, cancellation races, peer protocol violations, resource limits,
and graceful and abrupt shutdown. Retain raw results rather than publishing
isolated benchmark claims.

## 5. Native wire core

**Status:** in progress as of 2026-08-24. The separate `gleam_quic` package,
RFC 9000 variable-length integer codec, packet-number reconstruction, QUIC v1
and v2 long-header mappings, bounded invariant packet parsing, the complete
RFC 9000/RFC 9221 frame codec, and bounded transport parameters from RFC 9000,
RFC 9221, RFC 9287, and RFC 9368 are present. The package currently has 77
focused tests and its own format, warnings-as-errors build, docs, and lint
gate.

Implement QUIC invariants, v1 and v2 packet formats, frames, transport
parameters, version negotiation, strict bounds, and incremental parsers. Every
wire behavior starts with RFC vectors and negative/truncation tests.

## 6. Native TLS 1.3 and packet protection

**Status:** in progress as of 2026-08-24. RFC 5869 HKDF-SHA256/SHA384,
QUIC v1/v2 Initial key derivation, AES-128-GCM, AES-256-GCM and
ChaCha20-Poly1305 payload/header protection, packet-number encoding, and v1/v2
Retry integrity match published vectors. The TLS layer now has bounded
handshake, extension and authentication-message codecs, X25519, the TLS 1.3
transcript and key schedule, RFC 5280 path and RFC 9525 service-identity
validation, CertificateVerify, constant-time Finished verification, and a
client/server state-model handshake through 1-RTT key installation. Arbitrary
CRYPTO fragmentation, QUIC key-phase updates, three-PTO old-key retention, and
AEAD usage limits are also implemented. HelloRetryRequest, certificate
selection, key discard coordination, tickets, PSK binders, anti-replay, and
0-RTT remain open.

Implement the TLS 1.3 handshake coordination required by QUIC, transcript and
key schedule, transport-parameter extension, Retry integrity, header and
payload protection, key discard and update, session tickets, replay-safe
0-RTT, certificate paths, service identity, SNI, and secure server certificate
selection. Keep cryptographic and X.509 runtime primitives in a narrow FFI.

## 7. Native transport, recovery, and paths

**Status:** in progress as of 2026-08-24. Pure bounded models now cover RFC
9002 RTT estimation, packet/time-threshold loss detection, PTO calculation,
NewReno, connection and stream flow control, stream ID permissions,
anti-amplification, path challenge validation, PMTU probing, and out-of-order
CRYPTO/STREAM reassembly with overlap and final-size enforcement. These models
are not yet assembled into a live connection and UDP runtime; CUBIC, ECN,
Retry/tokens, stateless reset, connection-ID rotation, migration, and complete
recovery scheduling remain open.

Implement connection and stream state machines, flow control, loss recovery,
PTO, ECN, NewReno and CUBIC, pacing, anti-amplification, Retry and address
tokens, stateless reset, connection-ID rotation, PMTU discovery, IPv4/IPv6,
NAT rebinding, active migration, QUIC DATAGRAM, and deterministic shutdown.

## 8. Native HTTP/3 and QPACK

**Status:** not complete.

Implement RFC 9114 and RFC 9204 end to end: control and request streams,
settings, push, GOAWAY, graceful drain, all response stages and trailers,
static and dynamic QPACK with Huffman coding and blocked-stream limits,
priority, Extended CONNECT, Capsules, and correctly associated HTTP Datagrams.

## 9. Adapter cutover

**Status:** not complete.

Run the existing public API behavior suite against `gleam_quic`, close any
semantic gaps, make it the sole production backend, and remove the external
`quic` dependency and all runtime calls to `quic` or `quic_h3`. Preserve public
opaque types and typed errors unless a standards or safety correction requires
an intentional pre-v1 break.

## 10. Public v1 qualification

**Status:** not complete.

Complete two-peer client/server interop, QUIC v1/v2 conformance, TLS and QPACK
vectors, fuzzing, deterministic faults, real-UDP negative tests, security
review, supported OTP/OS matrices, load, soak, and benchmark gates. Resolve all
required rows in [Public v1 gate](V1.md), remove temporary nonconforming test
surfaces, run `mise run check`, and finish with signed local commits and a clean
tree.

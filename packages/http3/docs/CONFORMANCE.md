# Conformance matrix

This package matrix records detailed HTTP/3 implementation evidence. The
repository [`qualification.json`](../../../qualification.json) manifest and
generated [product conformance status](../../../docs/CONFORMANCE.md) are the
source of truth for release status, test counts, gate implementation, and
finding state. A package row is `Ready` only when its behavior is on the live
UDP path, bounded, covered by a negative or interoperability test, and
rechecked against applicable errata. Passing a codec unit test alone is not
enough.

Status values mean:

- `Ready`: the row's release requirement is implemented and has current
  evidence;
- `Partial`: useful behavior exists, but at least one named release condition
  is open;
- `Open`: the release behavior or its required evidence is missing; and
- `Excluded`: deliberately outside the stable v1 contract.

## Stable standards

| Specification | v1 requirement | Implementation and evidence | Status |
| --- | --- | --- | --- |
| RFC 8305 | Stagger IPv6 and IPv4 candidates, continue through all candidates, and cancel losers | The reusable client races interleaved candidates with a finite stagger and retains the most actionable failure. Local-bind and every socket-option policy are not yet public. | Partial |
| RFC 8446, RFC 5280, RFC 9525 | TLS 1.3, certificate paths, DNS/IP identity, supported credential algorithms, client authentication, and HelloRetryRequest | X25519/P-256 direct and HRR paths, mandatory server authentication, SNI, identity checks, certificate/key matching, RSA-PSS/ECDSA/Ed25519 server credentials, required/optional mTLS, clientAuth purpose checks, redacted identity, resumed reauthentication, and safe 0-RTT rejection have direct tests. The complete OTP 28/29 and external-peer credential matrix remains open. | Partial |
| RFC 8999 | QUIC version-independent invariants | Invariant and version parsing have vector, boundary, and fuzz coverage. Raw packet APIs are package-private. | Ready |
| RFC 9000 plus applicable errata | QUIC v1 transport, streams, connection IDs, Retry/tokens, migration, bounded peer state, and denial-of-service guidance | The live driver covers these areas. Duplicate `PATH_CHALLENGE` values are coalesced, pending responses are limited to 64, and overflow fails with a transport protocol violation, covering reported Erratum 8875. Datagrams at every encryption level are measured against the minimum of the validated path MTU and the peer's `max_udp_payload_size`, Don't-Fragment is requested when the socket is opened, and DPLPMTUD stays at the 1200-byte floor on a platform that refuses it ([evidence](evidence/2026-08-26-phase0.md)); loopback cannot exercise real fragmentation, as recorded in the security review. Per-connection actors, routed-mailbox credit, and aggregate memory admission have live isolation, pressure, crash, and recovery tests. A complete dated errata-by-errata audit remains open. | Partial |
| RFC 9001 | QUIC TLS mapping, packet protection, Retry integrity, key discard, and update | v1/v2 Initial vectors, AES-GCM, ChaCha20-Poly1305, header protection, Retry, handshake keys, default-off 0-RTT, finite single-node and external replay guards, failure fallback, and key update are exercised. The TLS algorithm/mTLS gaps above prevent a release-ready row. | Partial |
| RFC 9002 | ACK, RTT, loss, PTO, persistent congestion, ECN interaction, and application-limited behavior | Deterministic recovery, pacing, ECN, and loss/reorder tests exist. Pacing wake-ups are derived lazily from the congestion window and smoothed RTT current at each deadline computation, and the NewReno/CUBIC `max_datagram_size` follows the DPLPMTUD-validated path, both with state-model tests ([evidence](evidence/2026-08-26-phase0.md)). The independent CUBIC oracle and randomized transition model pass; the complete role-specific RFC/errata map remains open. | Partial |
| RFC 9114 | HTTP/3 control/request streams, SETTINGS, message semantics, push, GOAWAY, and graceful shutdown | Client/server live-UDP tests cover request/response streaming, informational responses, trailers, push, GOAWAY, drain, finite accept waiters, and configured stream/frame bounds. The complete requirement-to-test audit is still open. | Partial |
| RFC 9204 | QPACK static/dynamic tables, Required Insert Count, blocked streams, feedback, and Huffman coding | State and negative tests cover the implemented encoder/decoder. Required Insert Count and every verified erratum still need explicit matrix entries and differential coverage. | Partial |
| RFC 9218 | Extensible priority and live scheduling updates | Typed urgency/incremental values and client/server scheduling paths have state and loopback tests. | Ready |
| RFC 9220 | Extended CONNECT | The public API constructs and validates Extended CONNECT explicitly; ordinary requests cannot acquire Datagram association. | Ready |
| RFC 9221, RFC 9297 | QUIC Datagram and request-associated HTTP Datagrams | Negotiation, maximum payload, association checks, bounded byte/count queues, and loopback/interoperability paths exist. | Ready |
| RFC 9287 | Greasing the QUIC bit | Codec/state behavior exists; the release matrix still needs an explicit live-wire regression. | Partial |
| RFC 9368, RFC 9369 | Authenticated compatible version negotiation and QUIC v2 | v1/v2 vectors and retained aioquic/quic-go interop paths exist. The expanded four-peer release matrix is open. | Partial |
| RFC 9438 | CUBIC, Reno friendliness, fast convergence, large-integer safety, and application-limited periods | CUBIC implements fast convergence, Reno friendliness, application-limited accounting, MTU changes, and HyStart++ bounded slow-start exit. The executable independent integer oracle compares 200 ACK transitions, the PR model checks 10,000 randomized transitions, and eight nightly shards cover 1,000,000 transitions. The complete requirement and errata map remains open. | Partial |

## Diagnostic draft

qlog is diagnostic output, not a stable protocol guarantee. Output is pinned
to `draft-ietf-quic-qlog-main-schema-14`, QUIC events revision 13, and HTTP/3
events revision 13. The writer is opt-in, privacy-strict, asynchronous, and
bounded to 1024 waiting events plus one in-flight write, with
dropped/error/queued counters. Current
live client/server coverage records the configured connectivity, transport,
TLS, recovery, HTTP/3, and QPACK families. The configured `Telemetry` limit
reaches each asynchronous writer (default 1024 waiting plus one active write),
and the pinned schema, redaction, deterministic semantics, and qvis-compatible
start/activity/close ordering pass `mise run qlog-validate`.

## Open release findings

| ID | Finding | Release condition |
| --- | --- | --- |
| PRE-005 | P-256 direct/HRR key exchange, live RSA-PSS/ECDSA P-256/ECDSA P-384/Ed25519 server credentials, server `Disabled`/`Optional`/`Required` authentication, verified identity fingerprints, resumed reauthentication, and mTLS 0-RTT fallback pass locally. The six OS/OTP attestation rows are not yet collected. | Complete Ubuntu 24.04, macOS 15, and Windows 2025 on OTP 28/29 and pass the aggregate credential gate. |
| PRE-009 | Dialyzer/xref, exact-key gitleaks, repository Semgrep rules, OSV, REUSE, CycloneDX generation, dependency/action monitoring, PR and million-case sharded campaigns, hostile-resource families, and exact-semver three-package release simulation have executable gates. The OTP 29 simulation builds each archive twice, compiles empty consumers, and emits SBOM/provenance. Coverage thresholds, the expanded peer matrix, cross-protocol measurements, OTP 28 simulation evidence, and canonical-archive qualification remain incomplete. | Complete the remaining gates and retain reproducible canonical-archive evidence. |
| PRE-011 | No passing canonical-source candidate, third-party audit attestation, signed local commit, or clean-worktree proof exists for this reopened work. | Pass all automated gates from the canonical archive, then obtain the external audit and signed commit; do not tag, publish, upload, or push. |

## Closed findings in the current worktree

| ID | Resolution | Evidence |
| --- | --- | --- |
| PRE-001 | `quic_core` now exports generic client/server endpoints, opaque connections and streams, Datagram, migration, resumption/persistence, finite TLS/0-RTT and mTLS policy, typed failures, and redacted diagnostics. | Six audited public modules plus direct real-UDP tests for stream directions, Datagrams, negotiated ALPN/cipher, lifecycle, authenticated Retry/`NEW_TOKEN`, atomic three-ring rotation and live token refresh, restart-safe tickets, resumption, mTLS identity, and accepted/rejected 0-RTT; the live core test count is generated in the product conformance status. |
| PRE-002 | HTTP/3 sessions, QPACK, Capsules, and HTTP/3 workers moved from `quic_core` into package-owned `http3/internal` modules. No HTTP/3 production module imports a private core module. | All three packages build independently; compiler API, source import, and compiled xref gates enforce ownership, and the reproducibility gate rejects HTTP/3 or QPACK source or compiled modules in the core Hex tar. |
| PRE-003 | The core listener now supervises one labelled actor per accepted connection. Its router uses per-connection datagram and byte credit, and teardown synchronously releases admission ownership. | Real-UDP tests prove actor topology, progress beside a stalled flood, bounded mailbox occupancy, overflow accounting, crash cleanup, and neighbour routing. |
| PRE-004 | Server `EndpointMemory` now funds admission and every later receive-credit, send-buffer, and routed-mailbox growth before allocation; reservations return on release or actor crash. Clients reject a budget below the fixed admission reservation before actor or socket creation. | Aggregate pressure, backpressure, parallel-write, release/crash recovery, client refusal, and HTTP/3 client/server live-path tests pass through the public APIs. |
| PRE-006 | A finite external atomic replay guard is public. Its opaque input exposes only a domain-separated fingerprint and required retention interval. Rejection, callback error/exit, and timeout fail closed to 1-RTT without discarding authenticated resumption. | Direct deadline/accept/reject/error/timeout tests plus real-UDP accepted 0-RTT and guard-failure 1-RTT fallback tests. |
| PRE-007 | qlog schema, live event breadth, redaction, and qvis compatibility were incomplete. | The hash-pinned client/server report covers every configured QUIC, TLS, recovery, HTTP/3, and QPACK family with no missing live or per-trace family; deterministic writer failure proves bounded accounting and teardown. |
| PRE-008 | CUBIC reference differential and HyStart++ were missing. | The RFC 9438 integer oracle, deterministic boundary cases, randomized model, and default HyStart++ live state transitions now pass through `mise run model`; the nightly workflow shards 1,000,000 transitions. |
| PRE-010 | The unchanged fixed workloads measured benchmark median 586, load median 479, and soak 1,034 requests/second against 516/344/812 thresholds. The 160,000-stream soak, every retained A/B row, and every fixed row converged process counts and ended with zero mailbox messages, without retained timeout or peer-close. The `48a8b3b` paired A/B comparison also passed 5/5 pairs with +25.8% benchmark and +48.0% load median gains, while `tprof` removed the measured full-stream scans and reduced complete-response worker commands from three to one. | [2026-08-28 hot-path evidence](evidence/2026-08-28-hot-path.md) and [raw performance rows](../benchmarks/results/2026-08-28-hot-path.csv). |
| PRE-012 | HTTP/3 uses only the six audited public `quic_core` modules and opaque connection/stream values; Retry, token, version routing, UDP, TLS, and connection actors remain core-owned. | The comments-only allowlist has zero entries, and source scan, package-interface audit, and compiled xref reject every `quic_core/internal/**` reference. Public loopback fixtures cover v1/v2, streams, Datagram, migration, resumption, mTLS, 0-RTT, reload, GOAWAY, push, and QPACK behavior. |

## Historical package-only exclusions

Before the three-package product split, this package excluded HTTP/1.1,
HTTP/2, automatic fallback, Alt-Svc/SVCB policy, redirects, cookies, caching,
proxies, pooling, MASQUE, and WebSocket framing because they were outside the
HTTP/3 package boundary. They are no longer product exclusions: the root
package owns the applicable contracts in `docs/V1.md`. WebTransport,
multipath QUIC, ACK Frequency, reliable reset, extended key update, and the
JavaScript target remain outside the initial product scope. Certificate
verification bypasses, unlimited queues/deadlines, raw traffic-secret access,
and raw packet/frame codecs will not be added to the public API.

The errata review baseline and evidence date must be updated on the same day
as a release-candidate rerun. See the
[RFC 9000 errata index](https://www.rfc-editor.org/errata/rfc9000) and the
[qlog main-schema revision](https://datatracker.ietf.org/doc/html/draft-ietf-quic-qlog-main-schema-14).

# Conformance matrix

This matrix is the source of truth for the unpublished v1 candidate. A row is
`Ready` only when its behavior is on the live UDP path, bounded, covered by a
negative or interoperability test, and rechecked against applicable errata.
Passing a codec unit test alone is not enough.

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
| RFC 9000 plus applicable errata | QUIC v1 transport, streams, connection IDs, Retry/tokens, migration, bounded peer state, and denial-of-service guidance | The live driver covers these areas. Duplicate `PATH_CHALLENGE` values are coalesced, pending responses are limited to 64, and overflow fails with a transport protocol violation, covering reported Erratum 8875. Datagrams at every encryption level are measured against the minimum of the validated path MTU and the peer's `max_udp_payload_size`, Don't-Fragment is requested when the socket is opened, and DPLPMTUD stays at the 1200-byte floor on a platform that refuses it ([evidence](evidence/2026-08-26-phase0.md)); loopback cannot exercise real fragmentation, as recorded in the security review. A complete dated errata-by-errata audit and per-connection actor isolation remain open. | Partial |
| RFC 9001 | QUIC TLS mapping, packet protection, Retry integrity, key discard, and update | v1/v2 Initial vectors, AES-GCM, ChaCha20-Poly1305, header protection, Retry, handshake keys, default-off 0-RTT, finite single-node and external replay guards, failure fallback, and key update are exercised. The TLS algorithm/mTLS gaps above prevent a release-ready row. | Partial |
| RFC 9002 | ACK, RTT, loss, PTO, persistent congestion, ECN interaction, and application-limited behavior | Deterministic recovery, pacing, ECN, and loss/reorder tests exist. Pacing wake-ups are derived lazily from the congestion window and smoothed RTT current at each deadline computation, and the NewReno/CUBIC `max_datagram_size` follows the DPLPMTUD-validated path, both with state-model tests ([evidence](evidence/2026-08-26-phase0.md)). The release reference-model and full errata differential are not yet present. | Partial |
| RFC 9114 | HTTP/3 control/request streams, SETTINGS, message semantics, push, GOAWAY, and graceful shutdown | Client/server live-UDP tests cover request/response streaming, informational responses, trailers, push, GOAWAY, drain, finite accept waiters, and configured stream/frame bounds. The complete requirement-to-test audit is still open. | Partial |
| RFC 9204 | QPACK static/dynamic tables, Required Insert Count, blocked streams, feedback, and Huffman coding | State and negative tests cover the implemented encoder/decoder. Required Insert Count and every verified erratum still need explicit matrix entries and differential coverage. | Partial |
| RFC 9218 | Extensible priority and live scheduling updates | Typed urgency/incremental values and client/server scheduling paths have state and loopback tests. | Ready |
| RFC 9220 | Extended CONNECT | The public API constructs and validates Extended CONNECT explicitly; ordinary requests cannot acquire Datagram association. | Ready |
| RFC 9221, RFC 9297 | QUIC Datagram and request-associated HTTP Datagrams | Negotiation, maximum payload, association checks, bounded byte/count queues, and loopback/interoperability paths exist. | Ready |
| RFC 9287 | Greasing the QUIC bit | Codec/state behavior exists; the release matrix still needs an explicit live-wire regression. | Partial |
| RFC 9368, RFC 9369 | Authenticated compatible version negotiation and QUIC v2 | v1/v2 vectors and retained aioquic/quic-go interop paths exist. The expanded four-peer release matrix is open. | Partial |
| RFC 9438 | CUBIC, Reno friendliness, fast convergence, large-integer safety, and application-limited periods | CUBIC implements fast convergence and application-limited accounting with unit tests. A reference-model differential, Reno-friendliness corpus, MTU/ECN boundaries, and HyStart++ default slow start are missing. | Partial |

## Diagnostic draft

qlog is diagnostic output, not a stable protocol guarantee. Output is pinned
to `draft-ietf-quic-qlog-main-schema-14`, QUIC events revision 13, and HTTP/3
events revision 13. The writer is opt-in, privacy-strict, asynchronous, and
bounded to 1024 waiting events plus one in-flight write, with
dropped/error/queued counters. Current
coverage records connection, UDP, path, and close events. The configured
`Telemetry` limit reaches each asynchronous writer (default 1024 waiting plus
one active write); complete QUIC, TLS, recovery, HTTP/3, and QPACK event
coverage plus schema/qvis validation is open.

## Open release findings

| ID | Finding | Release condition |
| --- | --- | --- |
| PRE-003 | A listener actor still owns multiple connection states; one supervised actor per connection and global memory/admission budgets are not complete. | Isolate connections, bound actor credit/mailboxes/batches, and prove cleanup under a stalled connection. |
| PRE-004 | Every role-applicable per-endpoint and per-connection `Limits` field now reaches its live connection, handshake, stream, body, buffer, queue, frame, Datagram, QPACK, accept-waiter, or telemetry path. `EndpointMemory` is still only validated and carried; listener-wide accounting is not enforced. | Integrate `EndpointMemory` with the isolated connection actors and global admission budget required by PRE-003, then test aggregate pressure and recovery. |
| PRE-005 | P-256 direct/HRR key exchange and public client credentials, server `Disabled`/`Optional`/`Required` authentication, verified identity fingerprints, resumed reauthentication, and mTLS 0-RTT fallback are implemented. The full runtime/peer algorithm matrix is not qualified. | Complete OTP 28/29 credential and mTLS interop matrix. |
| PRE-007 | qlog event breadth, schema validation, and qvis validation are incomplete. Device-writer termination is now injected deterministically and proves bounded drop/error accounting plus idempotent teardown. | Pass the remaining pinned diagnostic-format gate without logging secrets. |
| PRE-008 | CUBIC reference differential and HyStart++ are incomplete. | Pass RFC 9438 model and boundary corpus. |
| PRE-009 | Dialyzer/xref, exact-key gitleaks, repository Semgrep rules, OSV, REUSE, CycloneDX generation, dependency/action monitoring, and a deterministic content-audited core Hex archive now have automated gates. The archive gate normalizes observed Gleam 1.18.1 dependency-order drift and proves two exports byte-identical. ngtcp2/nghttp3 and quiche, coverage thresholds, million-case nightly generation, expanded faults, clean-archive SBOM qualification, and exact-semver two-package release simulation remain absent or incomplete. | Complete the remaining gates and retain reproducible clean-archive evidence. |
| PRE-010 | The 2026-08-26 baseline on the current tree already met the benchmark threshold (594 median vs 516) while load stayed at 232 vs 344. After the Phase 0 path-MTU and pacing changes the load workload measured a 423 median (394–437) and benchmark a 583 median, so benchmark and load pass on the recorded host ([evidence](evidence/2026-08-26-phase0.md)). Soak (812) has not been rerun. The long-load bounded peer-close failure of 2026-08-25 did not reproduce in three Phase 0 load runs. | Meet all three 516/344/812 thresholds on the recorded host and preserve zero-idle-polling and cleanup bounds. |
| PRE-011 | No clean-archive release-candidate rerun, signed local commit, or clean-worktree proof exists for this reopened work. | Run all release gates from a clean source archive; do not tag, publish, upload, or push. |
| PRE-012 | Root-owned HTTP/3 workers still import package-private QUIC/TLS primitives instead of consuming only the generic public transport API. A three-layer boundary gate (Semgrep rule, `boundary` verb in the public API audit, and an xref mode) now fails any root import that is not in the shrink-only `api/boundary.allow` allowlist, which stands at 87 entries, and the root package owns its own varint and stream-identifier copies. | Move the HTTP/3 runtime onto opaque public core connections/streams and make any root import of `gleam_quic/internal/**` fail the boundary audit. |

## Closed findings in the current worktree

| ID | Resolution | Evidence |
| --- | --- | --- |
| PRE-001 | `gleam_quic` now exports generic client/server endpoints, opaque connections and streams, Datagram, migration, resumption/persistence, finite TLS/0-RTT and mTLS policy, typed failures, and redacted diagnostics. | Six audited public modules plus direct real-UDP tests for stream directions, Datagrams, negotiated ALPN/cipher, lifecycle, authenticated Retry/`NEW_TOKEN`, atomic three-ring rotation and live token refresh, restart-safe tickets, resumption, mTLS identity, and accepted/rejected 0-RTT; the core suite passes 208 tests. |
| PRE-002 | HTTP/3 sessions, QPACK, Capsules, and HTTP/3 workers moved from `gleam_quic` into root-owned `http3/internal` modules. No root production module imports a core HTTP/3/QPACK module. | Both packages build independently; 102 HTTP/3/QPACK/driver tests moved with ownership; the reproducibility gate rejects HTTP/3 or QPACK source or compiled modules in the core Hex tar. |
| PRE-006 | A finite external atomic replay guard is public. Its opaque input exposes only a domain-separated fingerprint and required retention interval. Rejection, callback error/exit, and timeout fail closed to 1-RTT without discarding authenticated resumption. | Direct deadline/accept/reject/error/timeout tests plus real-UDP accepted 0-RTT and guard-failure 1-RTT fallback tests. |

## Fixed exclusions

HTTP/1.1, HTTP/2, automatic fallback, Alt-Svc/SVCB policy, redirects, cookies,
caching, proxies, pooling, WebTransport, MASQUE, WebSocket framing,
multipath QUIC, ACK Frequency, reliable reset, extended key update, and the
JavaScript target are excluded from v1. Certificate verification bypasses,
unlimited queues/deadlines, raw traffic-secret access, and raw packet/frame
codecs will not be added to the public API.

The errata review baseline and evidence date must be updated on the same day
as a release-candidate rerun. See the
[RFC 9000 errata index](https://www.rfc-editor.org/errata/rfc9000) and the
[qlog main-schema revision](https://datatracker.ietf.org/doc/html/draft-ietf-quic-qlog-main-schema-14).

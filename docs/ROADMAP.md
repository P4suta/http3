# Roadmap

The v1 roadmap was reopened on 2026-08-25 after a publication-readiness
review found gaps that the former completion record did not capture. The
[conformance matrix](CONFORMANCE.md) owns exact findings; this roadmap gives
their dependency order.

## 1. Public package boundary

Status: partial.

- Keep raw packet, frame, TLS, and transport-parameter modules out of the
  `gleam_quic` compiler-exported interface. Completed.
- Implement application-protocol-independent client/server endpoint,
  connection, bidirectional/unidirectional stream, QUIC Datagram, migration,
  resumption, TLS configuration, and diagnostic values in `gleam_quic`.
  Completed with direct real-UDP tests.
- Move HTTP/3 session, QPACK, Capsule, and HTTP/3 worker ownership to `http3`.
  Completed.
- Remove every root import of a core-internal HTTP/3/QPACK module. Completed.
- Approve semantic API snapshot changes for both packages. Completed for the
  physical split and generic transport API.

Raw modules are hidden, physical ownership is split, the generic transport
surface exists, and snapshot checks cover it. Root-owned HTTP/3 workers still
need to migrate from package-private QUIC/TLS primitives to the opaque public
connections and streams before the package boundary is complete.

## 2. Runtime isolation and bounded admission

Status: partial.

The UDP path is event-driven through active-once delivery, protocol deadlines,
finite relay credit/batches, and no periodic idle poll. Client and server
response/request/Datagram queues use amortized O(1) FIFO structures with both
byte and count limits. Duplicate path challenges are coalesced and pending
responses are finite. Role-applicable public limits now reach connection and
handshake admission, streams, bodies, buffers, queues, frame parsing,
Datagrams, QPACK, accept waiters, and bounded qlog writers.

Still required:

- split the listener into UDP/CID router, admission controller, and one
  supervised actor per connection;
- bound every actor mailbox and inter-actor credit path;
- enforce global endpoint memory plus connection/handshake admission on every
  live path; and
- prove one stalled connection cannot delay unrelated connections.

## 3. Network, TLS, and operations

Status: partial.

Staggered dual-stack candidate racing, certificate hot reload, independent
current/previous ticket, address-token, and stateless-reset key rings,
authenticated Retry/`NEW_TOKEN`, restart-safe encrypted ticket storage,
default-off 0-RTT, a finite external replay guard with safe 1-RTT fallback,
X25519/P-256 key exchange and HelloRetryRequest, and public required/optional
mTLS with redacted verified identity access are implemented.

Still required:

- local bind, complete socket buffer/traffic-class policy, and listener
  dual-stack behavior across supported operating systems;
- OTP 28/29 and external-peer credential interoperability for RSA-PSS,
  ECDSA P-256/P-384, Ed25519, and mTLS resumption;
- complete redacted peer/local address diagnostics. Negotiated version,
  cipher, ALPN, early-data/resumption outcomes, path, connection, and telemetry
  snapshots are implemented.

## 4. Standards, observability, and performance

Status: partial.

- Close each stable row in the conformance matrix against applicable errata.
- Differential-test CUBIC against an RFC 9438 reference model and integrate
  HyStart++ as the default slow start.
- Expand qlog across QUIC/TLS/recovery/HTTP3/QPACK, validate JSON-SEQ and the
  pinned schemas, and confirm qvis compatibility. Deterministic device-writer
  failure and bounded error/drop accounting are covered.
- Profile actors, codecs, crypto, and queues; split oversized state/worker
  modules by responsibility.
- Reach the fixed 516/344/812 requests-per-second benchmark/load/soak gates
  without weakening cleanup, memory, mailbox, or idle-wakeup requirements.

## 5. Qualification and distribution

Status: open.

- Enforce line-coverage thresholds and direct public/error/security-branch
  coverage.
- Run 10,000 stateful/model cases per change and one million nightly, retaining
  minimized fixed seeds.
- Expand deterministic faults for ACK withholding, PATH/CID/token floods,
  QPACK blocking, NAT rebinding, MTU/ECN, rotation, clock rollback, and reload.
- Add ngtcp2/nghttp3 and quiche to the existing aioquic/quic-go matrix.
- Keep the implemented Dialyzer/xref, exact-key gitleaks, OSV, local Semgrep,
  REUSE, CycloneDX, and dependency/action monitoring gates clean; qualify their
  evidence again from the eventual clean release archive.
- Keep the implemented core Hex gate deterministic: it audits declared and
  actual contents, rejects private credentials and application-protocol
  modules, canonicalizes dependency order and tar attributes, and compares two
  exports byte for byte.
- Simulate a local registry release: build `gleam_quic`, replace the development
  path with an exact temporary registry version for `http3`, and build/test
  both archives in empty OTP 28/29 consumers with reproducible checksums.

Long fault, fuzz, load, soak, netem, and million-case tasks belong in scheduled
CI; pull requests run bounded subsets. Failures retain fixed seeds and
privacy-redacted diagnostics.

## Completion

Once every workstream and `PRE-*` finding is closed, rerun all gates from a
clean source archive, update dated evidence, approve both API snapshots, and
create a signed local commit with a clean worktree. Do not tag, change package
versions, publish, upload, create a hosted release, or push without a separate
explicit request.

# Roadmap

This package is one layer of the unpublished
`http -> http3 -> quic_core` product. The repository
[`qualification.json`](../../../qualification.json) manifest and generated
[product status](../../../docs/CONFORMANCE.md) are authoritative; this roadmap
only explains the dependency order of work that remains.

## Completed foundations

- `quic_core` exposes six audited public modules with opaque connection and
  stream values. HTTP/3 has no private-core imports, and the three-layer
  boundary allowlist is comments-only with zero entries.
- The core listener supervises one actor per connection. Connection,
  handshake, routed-mailbox, stream, and aggregate memory admission have live
  isolation, pressure, crash, and recovery tests.
- HTTP/3, QPACK, Capsules, push, Datagram, migration, resumption, mTLS, 0-RTT,
  reload, and graceful drain are owned by this package and run on public core
  connections and streams.
- The root package provides the common Body/Error, protocol-neutral server,
  Context, middleware, diagnostics, resource controller, H1/H2/H3 client
  selection, and finite partitioned policy stores.
- CUBIC has an RFC 9438 oracle and HyStart++; PR property, fuzz, model, and
  hostile-peer campaigns are executable and the nightly workflow defines
  million-case shards.
- The OTP 29 release simulation builds all three `0.1.0` archives twice,
  verifies exact archive dependencies and contents, runs empty consumers, and
  emits SBOM, provenance, and an ephemeral archive signature.

## 1. Standards and implementation closure

Status: blocked.

- Map every applicable MUST and SHOULD in the pinned 56-RFC inventory to
  role-specific implementation, tests, or a reviewed non-applicability
  reason, and complete the dated errata review.
- Keep the passing per-trace transport, TLS, recovery, QPACK, and HTTP/3 qlog
  profile, pinned schema, redaction, and qvis checks Green while the complete
  standards-event inventory is mapped.
- Complete general Brotli compressed meta-block decoding and the declared live
  protocol adapters for extensions. Retain independent OHTTP and MASQUE
  vectors and peer evidence.
- Keep local bind/socket policy and every remaining platform-specific behavior
  typed, bounded, and default-safe.

## 2. Adversarial and interoperability qualification

Status: blocked.

- Raise measured production coverage from the generated current baseline to
  95% line and 90% decision branch, and changed-source coverage to 100/100,
  without manual exclusions.
- Retain completed million-case property, fuzz, and model reports for every
  affected family, with minimized fixed failure seeds.
- Complete bidirectional curl, nghttp2, ngtcp2/nghttp3, quiche, Chromium,
  Firefox, independent MASQUE, and Go/TypeScript OHTTP rows in addition to the
  pinned aioquic and quic-go paths.
- Collect Ubuntu 24.04, macOS 15, and Windows 2025 credential reports on OTP
  28 and 29. The local OTP 29 algorithm and credential run is already complete.
- Record H1/H2/H3 client and server throughput, p99 latency, peak memory,
  idle-wakeup, mailbox, process, socket, and configured-memory-ceiling
  assertions against the declared baselines.

## 3. Canonical-source distribution evidence

Status: blocked.

- Repeat the release simulation on OTP 28 and retain both OTP reports.
- Build the canonical source archive, rerun every automated gate from that
  archive, and require all report source digests to match it.
- Assemble one deterministic audit bundle containing the threat model, RFC
  map, API and FFI audits, coverage, campaigns, peer/platform/performance
  evidence, SBOM, provenance, and residual risks.

## 4. External handoff

Status: external pending after every local gate is Ready.

Obtain an independently signed audit attestation for the exact audit-bundle
source digest, then create and verify a signed candidate commit with a clean
worktree. The release-candidate gate rejects an earlier signed `HEAD` when
candidate changes are still uncommitted. Do not tag, change versions, publish,
upload, create a hosted release, or push without a separate explicit request.

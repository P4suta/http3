# Pre-publication security review

## Decision

The three packages are not production-ready. They are unpublished, have not
completed the independent audit required by the release plan, and still have
open platform credential, standards/coverage/interoperability/performance,
canonical-archive, and external-handoff findings. No document or metadata version may be used to
describe the current tree as audited or production-ready.

## Enforced invariants

- Certificate-chain and hostname or IP identity verification are not
  disableable through the normal public client API.
- Public APIs do not expose PIDs, sockets, references, backend terms, native
  trust stores, traffic secrets, or raw key material.
- The common `Body` applies explicit read bounds, validates declared lengths,
  supports idempotent shared cancellation, and only permits replay through an
  explicit regeneration contract.
- Public errors expose stable categories and fixed redacted messages rather
  than backend exception strings or peer-controlled data.
- The common server admits resource credit before spawning a request worker,
  runs application handlers outside its executor actor, monitors panic/exit,
  and cancels each request body on failure, timeout, cancellation, or stop.
- The HTTP/1.1 listener isolates accepted connections in supervised actors,
  bounds heads, bodies, trailers, reads, requests, and connection admission,
  and runs application response pulls in monitored workers with finite
  deadlines and shared cancellation. Listener and socket ownership transfers
  require explicit receiver readiness before the public operation returns.
  Its fixed-size phase snapshot contains only saturating counters, lifecycle,
  and monotonic durations; a finite multi-writer retry reports inconsistency
  rather than blocking and never retains endpoints, request data, runtime
  handles, or backend reasons.
- The HTTP/2 listener and connection ownership transfers also require
  receiver acknowledgements. Its fixed-size snapshot separates accepted and
  active connections, drain request/command/receipt, GOAWAY attempt/write, and
  drain completion. The same finite multi-writer fallback exposes
  inconsistency without retaining endpoints, request data, TLS material,
  handles, or backend reasons.
- Application diagnostics contain no request payload or routing metadata.
  Capacity is acquired before a sink worker starts; sink error, exit, panic,
  and timeout are counted without entering the request path.
- CONNECT-UDP listener counter writers do not wait on one another. Snapshot
  consistency uses a finite active-writer/generation retry and explicitly
  reports an orphaned writer instead of blocking a diagnostic caller.
- CONNECT-UDP setup diagnostics use fixed-size monotonic phase durations and
  timeout bits. DNS and socket-open observations additionally separate bounded
  worker queue time from callback execution, record whether the callback ever
  started, and distinguish a supervisor deadline from an adapter-reported
  timeout. They retain no authority, endpoint, payload, callback error, PID, or
  socket value.
  Socket setup/adoption and established relay operations also have independent
  validated deadlines; neither path becomes unbounded when tuned separately.
- Existing QUIC and HTTP/3 queues, waits, datagrams, streams, and terminal
  registries are locally bounded where documented by their package reviews.
- CONNECT-UDP drops oversized exact-target payloads before they can enter an
  application mailbox. Its best-effort ICMP response has a finite deadline and
  per-tunnel rate limit, rejects prohibited addresses, caches unavailable raw
  socket capability, and exposes payload-free bounded diagnostics. Successful
  raw delivery is not claimed without privileged platform evidence.
- The default CONNECT-UDP socket is capped from a distinct connection-lifetime
  HTTP Datagram guarantee before it opens. The guarantee accounts for the QUIC
  1200-byte path floor and worst admitted ACK share, so migration, black-hole
  fallback, or later ACK fragmentation cannot make the fixed target receive
  ceiling larger than the transport can queue.
- qlog is opt-in and treated as sensitive application metadata.
- No runtime dependency provides an external QUIC, TLS, HTTP/3, or QPACK
  implementation.

## Open findings

1. `PRE-005`: the local credential/mTLS matrix passes, but the Ubuntu,
   macOS, and Windows attestations for OTP 28 and 29 are not all retained.
2. `PRE-009`: coverage thresholds, complete standards maps, expanded
   independent peers, cross-protocol performance, OTP 28 evidence, and a
   canonical-archive rerun remain incomplete.
3. `PRE-011`: no passing canonical-source candidate, third-party audit
   attestation, signed local commit, or clean-worktree handoff proof exists.

Each finding is closed by a failing regression or audit first, then the
smallest implementation, affected package suites, and a repository-wide gate.
The detailed status is maintained in [CONFORMANCE.md](CONFORMANCE.md).

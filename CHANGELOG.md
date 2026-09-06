# Changelog

## Unreleased

- Began the TDD migration to the three-package `http`, `http3`, and
  `quic_core` architecture without a compatibility namespace.
- Added the common bounded Body and typed/redacted Error contracts, strict
  HTTP/1.1 parsing and active-once transport, and the bounded HTTP/2 protocol
  foundation.
- Added a reusable unified client with finite policies, pooling, streaming
  exchange, safe redirects, and secret-free redirect history.
- Reduced the temporary HTTP/3-to-QUIC private-import allowlist and exposed a
  public nonnegative monotonic diagnostic clock from `quic_core`.
- Moved high-level HTTP/3 server, persisted-ticket, and client-actor behavior
  behind opaque QUIC adapter values, reducing the shrink-only boundary
  allowlist without changing their public APIs.
- Replaced the duplicate one-shot HTTP/3 transport with the shared opaque
  connection path, preserving exact-address dialing, QUIC v2, finite total
  deadlines, response limits, and socket cleanup while reducing the boundary
  allowlist.
- Hid server-side transport events, ECN markings, send outcomes, Datagram
  failures, credentials, replay caches, and external replay guards behind
  typed opaque connection contracts, reducing the shrink-only boundary
  allowlist to 41 entries.
- Completed the public-only HTTP/3-to-QUIC migration: the boundary allowlist is
  empty and source, compiler-interface, and compiled-xref gates reject private
  core imports.
- Isolated accepted QUIC connections into supervised actors and enforced
  grant-before-growth endpoint memory plus bounded routed-mailbox credit,
  including typed client and HTTP/3 live-path admission failures.
- Added the protocol-neutral server contract: standard streaming
  Request/Response handlers, typed Context keys, ordered middleware, atomic
  worker/memory leases, bounded payload-free diagnostics, panic/exit isolation,
  cancellation, atomic handler reload, and graceful drain.
- Added the active-once HTTP/1.1 TCP/TLS listener with isolated connection and
  response-pull workers, ordered finite pipelining, strict framing, deferred
  `100 Continue`, half-close and premature-EOF handling, plus post-handshake
  CONNECT and Upgrade client byte streams with optimistic payload denial.
- Added two-sided HTTP/1 listener/socket-owner readiness handshakes and a
  fixed-size, payload-free phase snapshot with bounded multi-writer reads,
  lifecycle retention, 20,000-update invariant races, and orphaned-writer
  fallback evidence.
- Added two-sided HTTP/2 listener/connection-owner readiness handshakes and a
  fixed-size drain snapshot that separates command delivery, GOAWAY write, and
  completion. Its live regression uses a causal write barrier, typed bounded
  wire trace, 20,000-update multi-writer model, and orphaned-writer fallback.
- Added manifest-scoped single-target stability replay with fresh-VM
  repetitions and non-qualifying bounded reports. The MASQUE duplicate event
  waiter regression now separates Busy admission from timeout scheduling and
  emits one payload-free registration-to-close counter trace on failure.
- Made generated test totals include public Gleam tests and exported Erlang
  EUnit `_test`/`_test_` entrypoints. A synthetic auditor contract fixes
  visibility and arity rules so FFI-side tests cannot silently disappear from
  conformance evidence.
- Made coverage discover tests from package test-source provenance plus
  compiled EUnit exports, retaining the entrypoint total in each capture. This
  includes Erlang test modules whose module name itself does not end in
  `_test`.
- Strengthened adaptive coverage capture from a 3..10/two-quiescent window to
  a bounded 10..30/three-quiescent window after the tenth repeated root suite
  still exposed new scheduling-dependent production paths. Stop-decision
  self-tests now derive their boundaries from the machine-readable policy.
- Replaced the bound MASQUE session's sleep-based concurrent-termination test
  with an owner-correct two-sided barrier, a bounded payload-free causal trace,
  and a dedicated fresh-VM stability target after coverage instrumentation
  exposed the cleanup deadline race.
- Separated the MASQUE socket's intentional five-millisecond cleanup timeout
  from its concurrent-close test, which now uses an owner-created release
  barrier, typed resource snapshots, and its own fresh-VM stability target.
- Split live MASQUE idle activity from no-activity expiry so instrumented sends
  cannot race the deadline being tested. Both paths now retain bounded causal
  traces, use dedicated stability targets, and redact unexpected I/O down to a
  typed transition kind and resource states.
- Made the production FFI inventory executable and expanded Dialyzer/xref to
  cover the same manifest-declared set of every discovered root, HTTP/3, and
  QUIC FFI module.
- Added distinct live and connection-lifetime Datagram capacity queries. The
  latter budgets path fallback and worst-case ACK debt, and the default
  CONNECT-UDP listener now fixes its target socket and Packet Too Big ceiling
  from that guarantee before sending 2xx.
- Added non-gating, same-VM instrumented target diagnostics to the coverage
  harness. Schema 2 reports retain every passed attempt plus the first failed
  attempt, full payload-free runtime deltas, bounded failure output, warm-up
  exclusion, nearest-rank p50/p95/p99 timings, and deterministic slowest-run
  attribution across as many as 1,000 repetitions.
- Strengthened opt-in qlog lifecycle evidence: one-shot and reusable HTTP/3
  clients now both honor the configured directory, every client and server
  connection owns exactly one trace, fixture failures retain their directory,
  and filenames are opened exclusively with bounded collision recovery. A
  connection-owned opaque application sink adds typed HTTP/3 frame and QPACK
  metadata to the same core trace without exposing close, statistics, text,
  headers, or payload bytes; the live validator now requires all configured
  protocol families independently in both vantage points.
- Hardened QUIC recovery around scheduling-sensitive loss. Early undecryptable
  1-RTT input no longer erases coalesced Handshake progress; PTO probes prefer
  queued delivery work, then transfer one reliable outstanding frame, and use
  PING only when no delivery work exists; amplification exhaustion retains
  prepared work as backpressure instead of failing the connection.
- Made pacing wake decisions observable as bounded scalar snapshots and fixed
  the lost-wakeup interval where work became pacing-ready between a bounded
  flush and deadline selection. Ready work now arms an immediate wake only
  while congestion credit exists, preserving the recovery-timer wait for a
  full window and preventing a zero-delay actor loop.
- Preserved authenticated, acknowledged stream bytes when peer connection
  close wins the application-read mailbox race. New work fails immediately,
  while already bounded receive buffers remain drainable behind the existing
  finite tombstone; the UDP socket and qlog writer still close immediately.
  A terminal read hands over only an outcome which is already decided, because
  no further bytes can arrive, and it advertises no receive credit: RFC 9000
  section 10.2.2 permits no frame beside the retained CONNECTION_CLOSE.
- Removed every `let assert` from the unified MASQUE runtime and re-enabled its
  `assert_ok_pattern` lint. A route range is now decoded once into a single
  address family, so the ordering and overlap scans read integers already known
  to exist instead of re-decoding the same four addresses on every comparison
  of the quadratic scan. The receive model is built before a socket can be
  attempted, so an invalid limit is a typed refusal rather than a socket opened
  and abandoned; the successful response derives its own status beside the
  fields it belongs to; and a Proxy-Status field which cannot be serialised is
  dropped, because the advisory field must not turn a refusal into a crash.
  Route advertisement tests now cover the reversed, mixed-family,
  unknown-protocol, misordered, wildcard-overlap, and numerically overlapping
  cross-family cases which the previous overlap test left to the ordering check.
- Classified datagrams received after Closing, Draining, or Closed as stale
  terminal input instead of converting the state-machine
  `ConnectionUnavailable` signal into a misleading peer QUIC failure.
- Added fixed-size, payload-free CONNECT-UDP setup phase timings and timeout
  attribution, including callback-start, scheduler-queue, callback-execution,
  and supervisor-expiry observations; independent finite setup/operation socket
  deadlines, production socket-adoption events, and fresh-BEAM stability
  coverage.

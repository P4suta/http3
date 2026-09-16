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
- Moved the connection ID with the path when migrating. RFC 9000 section 9.5
  forbids sending from a second local address under the identifier the first
  one used, and this endpoint kept using one: a peer that had offered three
  NEW_CONNECTION_ID values saw its own identifier arrive from a new address,
  read that as a rebinding rather than a migration, and never answered the path
  validation. An active migration now takes an unused identifier the peer
  supplied and asks for the previous one to be retired, which is what makes
  migration complete against an independent peer. When the peer supplied none
  the attempt continues on the current identifier as before, because this
  endpoint issues no identifiers of its own and refusing outright would make
  migration impossible between two of these endpoints; issuing them is the
  remaining half.
- Expanded path validation datagrams to the floor every QUIC path carries. RFC
  9000 section 8.2.1 requires the datagram holding a PATH_CHALLENGE, and section
  8.2.2 the one holding its PATH_RESPONSE, to reach 1200 bytes. This endpoint
  sent 43 of them. The expansion proves the new path carries a full-size
  datagram, and it funds the reply, because a peer answering across a path it
  has not validated may send only three times what it received there. The exact
  size is known only after protection, so the padding is measured and adjusted
  the way a DPLPMTUD probe's already was, and a live driver test pins the
  finished datagram at 1200 bytes.
- Fixed three things continuous integration found that a Linux checkout could
  not. The gzip vector asserted the header's OS byte, which RFC 1952 section
  2.3.1 leaves to the platform the compression ran on: Erlang's zlib reports 3
  on Linux and 19 on macOS, so the encoder is now checked around that one byte
  and through every byte this product decides. There was no `.gitattributes`,
  so a Windows checkout rewrote a byte-exact body fixture's line endings and
  changed its length, and would have done the same to two lock files that are
  compared by digest against a pin. And `golang.org/x/crypto` in the quic-go
  interoperability harness carried two advisories fixed in v0.56.0; it is
  bumped, with the pinned lock digest updated to match.
- Widened the static security rules to the public surface they are written
  about. All three public-API rules scanned only `quic_core/failure.gleam` out
  of the six public core modules, so `quic_core/client.gleam` -- the client
  path this repository's first prohibition is about -- was never checked for a
  certificate-verification bypass, and `quic_core/config.gleam`, where
  credentials and the congestion-control choice live, was never checked for a
  leaked key or an unimplemented BBR. A `pub fn verify_none` added to the
  client module passed the gate before this change and fails it now. The FFI
  rule likewise matched only Erlang modules directly under a source root, so a
  nested one could call `os:cmd` unseen. Nothing in the tree violated either
  rule, so both gaps are closed while they are still empty; the scan covers
  103 files where it covered 92.
- Made the documentation example gate discover the documentation. It read a
  list of the places examples happened to live, so a `gleam` block written
  anywhere else -- the contributing guide, the security policy, a package's
  test README -- was extracted by nothing: never compiled, never run, and free
  to rot while reading like verified documentation. It now scans every Markdown
  file in the repository, skipping only build output, vendored dependencies,
  and dot-directories.
- Closed a naming escape hatch in the FFI audit. It compared the declared
  inventory against the Erlang modules whose names end in `_ffi.erl`, so a
  module named outside that convention was discovered by nothing: absent from
  the inventory, and therefore absent from Dialyzer, from the compiled xref,
  and from the API leak checks that all read the same declared set. The audit
  now discovers every Erlang module in the production trees, and since the
  inventory accepts only `_ffi.erl` names, one that does not follow the
  convention fails the audit rather than passing unseen.
- Made the shell linters discover what they check. The list was written by
  hand and had drifted: `scripts/fresh_build.sh`, which every gate in this
  repository runs, along with the idle-wakeup and qlog live harnesses, were
  never passed to `shellcheck` or `shfmt`. All three were already clean, so
  nothing was hiding behind the gap -- but a gate that has to be edited to
  keep covering the tree is a gate that stops covering it. It now reads the
  tracked `*.sh` set, so a script cannot be added without being checked.
- Measured the coverage capture's settle window instead of assuming it. An
  unchanged http suite takes between 13 and 29 seconds to return the actors it
  owns under `cover`, so the 20-second cap sat inside its own observed range
  and no capture could ever finish: every run stopped at the first repetition
  reporting that the runtime had not converged. At 60 seconds the http and
  http3 captures converge to zero owned processes in every repetition and run
  to saturation, which is the first time this repository has been able to
  measure its own coverage.
- Gave the unified package's own README a quickstart. It had no code at all,
  so the first thing a reader saw was a package list. There are now two
  examples the documentation gate extracts, builds, and runs: one request with
  a bounded read, and a handler served over loopback and answered by this
  package's own client, which is the whole path in twenty lines.
- Ended abandoned QUIC connection attempts with the process that asked for
  them. Establishment blocks, so a client worker racing dual-stack candidates
  could not see its owner exit, and every candidate kept an open UDP socket
  until the connect deadline: a lost protocol race left one worker and two
  sockets alive for the rest of that window. The candidate race now watches the
  owner and cancels the candidates the moment it goes, which takes the release
  of an abandoned attempt from 24 seconds to none, and `OwnerGone` states the
  outcome as abandoned rather than as a timeout or a failure.
- Closed the HTTP/3 client a graceful-stop regression left open. Its listener
  had already drained, so nothing but the 30-second idle timeout could release
  the connection, and the suite could not prove it converges.
- Added the first independent-peer gate for the unified HTTP/1.1 and HTTP/2
  runtimes. A pinned curl drives the package's own TLS listeners and decides
  whether the wire behaviour is right: ALPN in both directions, including the
  downgrade an `http/1.1`-only listener must force on an HTTP/2-capable client;
  chunked and DATA request bodies; a non-2xx status; HEAD without a body;
  sequential HTTP/1.1 reuse; two multiplexed HTTP/2 streams; and a refusal when
  the pinned CA is withheld. The harness reads its pin from the interoperability
  profile and refuses to report against a different curl, so the evidence cannot
  drift away from the peer that produced it. The interoperability matrix now has
  eight unmet peer rows rather than nine.
- Fixed a racing MASQUE receive-credit regression and put it under the
  scheduling-sensitive matrix. The duplicate pull is only refused while the
  first pull is still waiting, but the first pull's deadline was a tenth of a
  second, so a loaded run could end it before the second was issued and turn
  the expected refusal into a timeout. The deadline now outlasts that
  scheduling delay, both fixed sleeps became bounded waits on the condition
  they were guessing at, and the matrix repeats the test in 30 isolated fresh
  BEAMs.
- Removed the last `let assert` expressions from `src` across all three
  packages and dropped every `assert_ok_pattern` suppression that covered a
  production module, so the lint gate now holds the whole production surface to
  the rule. A chunk split is a bit-array pattern instead of a length comparison
  guarding two slices that must not fail, a resolved key ring hands back its
  current key so no caller takes a list head which cannot be missing, and the
  Retry first byte matches its one random byte instead of asserting its shape.
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
- Bounded every TCP connect attempt by the RFC 8305 Connection Attempt Delay
  and carried the resolved-address list past an attempt that answered nothing.
  One black-holed address used to take the whole connect budget and then end
  the attempt outright, so a dual-stack name whose first address stalls was
  unreachable even when a later address answered at once; addresses that
  stalled are now walked again with the budget that is left, so a path slower
  than the delay is still reached. The walk stays sequential, so a server that
  answers one connect still sees one connection.
- Echoed and re-armed a received datagram in the UDP traffic-class fixture on
  hosts that deliver no ancillary data, and recorded the unobserved class as
  its sentinel instead of discarding the datagram. The RFC 9298 wire test now
  proves the relay round trip on every platform and the Not-ECT wire byte on
  the platforms that can read it back.
- Declared `bash` as the shell for the `semgrep` and `sbom` tasks and moved the
  MixGleam package cleanup out of the directory tree it deletes, so the
  pull-request gate runs on Windows, where mise uses `cmd.exe` and a `find`
  that cannot restore its initial working directory fails.
- Recorded the first direct measurement of the Windows UDP socket policy:
  Don't-Fragment constants, storage, and the 1472-byte IPv4 boundary on a real
  path, same-port dual-stack bind, honoured 4 MiB buffers, an unstealable bound
  port under `SO_REUSEADDR`, and the refused traffic-class options that justify
  excluding ECN there.
- Replaced the two `mapfile` reads in the shell gates with a loop every
  supported shell has, so the FFI audit and the structured-fields oracle setup
  run under the bash 3.2 that macOS ships instead of failing before they read
  anything, and recorded the `libmagic` the REUSE gate needs there.
- Waited for the dropped-datagram count a connection is told about on a later
  delivery rather than reading it through a drained actor, and waited for the
  HTTP Datagram capability a peer's SETTINGS negotiates instead of assuming an
  accepted request implies it. The coverage capture completes for all three
  packages with these, so the gate now fails on its thresholds rather than on a
  stopped run.
- Addressed the interoperability virtual environment by directory and looked
  for both interpreter layouts, so the hash-locked peer setup works where
  `uv venv` writes `Scripts/python.exe` instead of `bin/python`.
- Added RFC 7239 `Forwarded` as a strict bounded codec: node identifiers with
  obfuscated and unknown forms, per-element duplicate refusal, Host and scheme
  validation, RFC 5952 IPv6 rendering, automatic quoting where a value leaves
  the token production, and generated obfuscated identifiers so a proxy's
  default discloses nothing. It was the one specification in the pinned
  inventory with no implementation behind it.
- Covered the HTTP/1.1 connection and resource ceiling refusals, which the
  coverage gate reported as unreached: every value outside each range, the
  inclusive bounds themselves, and the rule that a line ceiling may not exceed
  the head it has to fit inside.
- Covered two HTTP/2 server paths the coverage gate reported as unreached: a
  request body that ends in a trailer section rather than an END_STREAM on its
  last DATA frame, which RFC 9113 section 8.1 permits, and a handler that
  returns an error, which still owes its peer a response unless the error is
  the stream already ending.
- Covered every HTTP/1.1 status line the server writes a reason phrase for,
  and the empty phrase a status it has none for still produces.
- Covered the CONNECT-UDP proxy listener's stopped state: the port accessor
  reports its typed failure once the listener underneath has gone, and stopping
  a listener that is already stopped says so rather than failing.
- Held the RFC 7239 `Forwarded` codec to the RFC 7230 quoted-string rules its
  grammar inherits: `,` and `;` inside a quoted value no longer end an element
  or a pair, a backslash stands for the character after it in both directions
  rather than being dropped on the way in and unwritten on the way out, and an
  unterminated quote or a trailing backslash is refused.
- Applied RFC 6797 section 6.1's appear-once rule to every
  `Strict-Transport-Security` directive rather than only to `max-age`: a field
  that repeats a directive, recognised or not, is now ignored whole. The
  seen-name list is bounded at sixteen directives.
- Refused a 100-continue expectation in both OHTTP directions, which RFC 9458
  section 5.1 requires: an encapsulated exchange carries one request and one
  response and cannot convey the interim response the expectation asks for, so
  the client declines to build one and the gateway answers an error rather than
  forwarding it. The token is matched on its own, so `not-100-continue` is a
  different expectation and is carried through.
- Read only the first `Strict-Transport-Security` field in a response, which
  RFC 6797 section 8.1 requires: a second field could previously revise or
  withdraw what the first said, so a `max-age=0` appended after a real policy
  cleared it.
- Refused an IP-literal host as an HSTS host, which RFC 6797 section 8.1.1
  requires. Both the bracketed and bare IPv6 forms and the dotted IPv4 form are
  refused before an entry exists, and on the persisted path as well, while a
  label that merely looks numeric inside a longer name is still a name.
- Classified a refused certificate as an authentication failure on every OTP
  release, not only the ones that report it as the TLS alert itself. OTP 28.5
  reports a hostname mismatch as a `handshake_failure` whose description spells
  out `hostname_check_failed`, so reading the alert atom alone answered
  `TlsHandshake` there and `TlsAuthentication` on 28.5.0.6 and 29. The
  description is now read as well, bounded at four kibibytes and only ever
  toward the certificate class.
- Withdrew an origin's discovered alternative on a 421 and ignored the
  `Alt-Svc` field such a response carries, which RFC 7838 section 6 requires: a
  misdirected-request answer previously taught the client a new alternative
  instead of retiring the one it had.
- Held `Alt-Svc` to the RFC 7230 quoted-string rules its grammar inherits, which
  RFC 7838 section 3 requires: `,` and `;` inside a quoted parameter value no
  longer end an alt-value or a parameter, and `ma` is accepted in the quoted
  form the grammar admits.
- Refused a service identity that is not already an A-label. RFC 9525 section
  6.3 requires a U-label in a reference identifier to be converted before
  comparison and nothing here performs that conversion, so such a name is now
  reported as invalid input rather than compared unconverted and reported as
  the certificate's fault.
- Refused a U-label host as an HSTS host for the same reason a U-label service
  identity is refused: nothing here implements IDNA, so a policy keyed on one
  would be stored under a name no later request could match.
- Generated an `Age` header field on a response served from the cache, which
  RFC 9111 section 4 requires and which was absent: a stored response went back
  to the caller looking as fresh as the moment it was fetched, and a stale
  `Age` it had arrived with was served unchanged. The field now counts the time
  held from the age the response already had, and replaces the stored one
  rather than joining it.
- Invalidated a cached response when an unsafe request to the same target
  succeeded, which RFC 9111 section 4.4 requires: a POST, PUT, or DELETE left
  the stored copy in place, so the read after a write served what the write had
  replaced until the entry expired on its own.
- Honoured `Cache-Control: no-store` on a request, which RFC 9111 section
  5.2.1.5 requires: the directive was unread, so a response to a request that
  forbade storing anything about it was stored like any other.
- Held every HTTP message signature component value to the characters RFC 9421
  sections 2 and 2.2 allow it. A derived value is now printable ASCII and a
  field value ASCII with tab, so neither can carry the newline that would write
  an attacker-chosen line into the signature base; the authority and the scheme
  must also arrive normalized, rather than a default port or an uppercase host
  being signed as though it were the canonical form.

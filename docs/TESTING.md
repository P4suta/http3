# Test-driven development

Every phase follows Red-Green-Refactor:

1. Add the smallest executable contract or regression and verify that it fails
   for the intended reason.
2. Make the smallest bounded implementation change that turns it green.
3. Run the affected package suite, then all upstream package suites.
4. Refactor only while those suites remain green.

Structural changes use executable package, API, boundary, and archive audits.
Protocol behavior uses unit, state-model, property, fault-injection, and live
loopback tests. A timeout is a failure, not a successful cancellation. Every
fixture owns and releases its processes, sockets, listeners, files, and
temporary directories.

Current test counts are discovered from public Gleam and exported zero-arity
Erlang EUnit entrypoints ending in `_test` or `_test_`, then rendered from
[`qualification.json`](../qualification.json) into the
[product conformance status](CONFORMANCE.md). The status auditor parses Erlang
forms rather than matching source text, and its synthetic discovery contract
rejects private Gleam functions, unexported Erlang functions, wrong arities,
and ordinary helpers. Counts are never maintained as handwritten documentation
values. The root suite covers common Body/Error
contracts; typed Context values; middleware order and short-circuiting;
grant-before-growth worker resources; bounded, redacted diagnostics; supervised
handler panic/exit isolation; streaming backpressure; cancellation; atomic
handler reload; graceful drain; strict HTTP/1.1 parsing and exchange behavior;
active-once TCP/TLS client and server paths; ordered finite pipelining;
deferred `100 Continue`; half-close and premature-EOF handling; isolated
stalled/exiting response sources; post-handshake CONNECT and Upgrade byte
streams; Client lifecycle, pooling, safe redirects; and the bounded HTTP/2
protocol foundation.

Cancellation qualification is event-driven. Context tests cover one-shot and
late subscriptions, explicit removal without a tagged mailbox residue,
subscriber and Context-owner exit, payload-free lifecycle snapshots, and 250
concurrent cancel/subscribe races. Live adapter tests prove that H1 returns a
finite 408, closes the affected connection, and never dispatches its pipelined
tail; H2 resets only the affected stream while parallel and later streams on the
same TLS connection progress; H3 emits both reset directions with local
H3_REQUEST_CANCELLED provenance. The common executor contains no periodic
cancellation polling interval.

HTTP/1 listener qualification records a fixed-size phase snapshot on the
context-cancellation observation boundary. A missing application Context can
therefore be attributed to listener readiness, socket acceptance, connection
actor handoff, request-head parsing, handler dispatch, or handler completion
without logging the endpoint or request. A live lifecycle test verifies
Running/Draining/Stopped retention and connection convergence. A separate
five-writer test performs 20,000 updates per writer while sampling invariants,
and an orphaned-writer fixture proves both reads and later writes remain finite
while the snapshot explicitly becomes inconsistent. The readiness protocol is
two-sided so no listener or accepted connection is reported started before its
new owner has acknowledged the transferred OTP resource.

Diagnostic qualification assigns every admitted request a payload-free opaque
ID and every accepted observation a reporter-local monotonic sequence. A test
deliberately blocks the Started sink until the corresponding Failed sink
finishes, then reconstructs causal order from sequence rather than callback
completion order. Another test races 250 emitters and rejects any missing,
duplicate, non-positive, or out-of-range sequence. The common-server test checks
that cancellation emits exactly one correlated Started/Failed pair with a
redacted `Cancelled` error. Emit/stop races run 500 times, and a blocked admitted
sink proves that stop waits for existing work while refusing every later event.

The retained HTTP/2 Red-Green cases include preface/frame fragmentation,
SETTINGS acknowledgement debt and peer limits, HPACK table-size changes,
stream and connection flow credit, RST admission release, bounded header-phase
cleanup, legacy priority observation, lossless standard-message conversion,
Content-Length/DATA agreement, bodyless response rules, explicit Extended
CONNECT opt-in, ORIGIN, RFC 9218 priority fields, RFC 9651 Structured Fields,
and finite wire-driver work limits. The retained HTTP/1.1 hostile cases include
Host authority validation, strict chunk-extension grammar, forbidden trailers,
TE/CL conflicts, duplicate lengths, bare LF, and finite head/body limits.
Network suites require permission to bind loopback sockets.

Every package-check and repository lint invocation enables glinter statistics.
The final log records the discovered file count, line count, and elapsed
milliseconds, which distinguishes a large cross-module analysis from a stopped
worker without weakening the warnings-as-errors result.

QUIC and HTTP/3 regressions keep payloads, endpoint identities, process values,
and cryptographic material out of their failure evidence. The public
application-to-qlog bridge accepts only typed HTTP/3 initiator, stream-role,
frame-kind, typed stream-ID, finite byte-count metadata, or a validated
nonnegative integer code. It has no operation for text, headers, body bytes,
transport events, writer statistics, or writer close. The supervised QUIC
connection remains the sole writer owner. Internal receive, pacing, recovery,
and lifecycle traces likewise use stable typed categories and bounded scalar
counters. qlog is explicit opt-in and creates exactly one asynchronously
written trace per connection for one-shot and reusable clients and for
servers. The live gate requires every client and server trace independently to
contain connectivity, packet, TLS-key, recovery, HTTP/3-frame, and QPACK
settings/stream-role families; an aggregate formed from one rich trace and one
transport-only trace fails. Trace files use exclusive creation with bounded
collision retries, and tests retain a qlog directory when exact cardinality or
an event assertion fails. Those files are sensitive diagnostic artifacts and
are never treated as shareable qualification evidence.

Retain an ephemeral failure directory before another run removes it with
`escript scripts/qlog_preserve.escript capture SOURCE_DIRECTORY ARTIFACT_NAME`.
The bounded collector accepts at most 256 regular `.qlog` files and validates
every JSON-SEQ header, event name, key, scalar range, empty endpoint, empty
header list, and length-only raw-data object against the strict writer schema
before making byte-identical copies under
`build/diagnostics/qlog-failures/ARTIFACT_NAME`. Its deterministic manifest
records source and artifact paths, per-trace and aggregate SHA-256 identities,
event counts and first/last times, duration percentiles, maximum event gaps,
and the receive-to-close quiet interval that exposes an otherwise hidden drain
outlier. Timestamp regressions and missing lifecycle endpoints are retained as
bounded sequence findings rather than preventing collection of the failure
that needs investigation. The manifest contains no payload, endpoint, header,
key, token, or process value; copied qlogs are payload-free but remain
explicitly non-shareable local evidence. Recheck a retained directory with
`escript scripts/qlog_preserve.escript verify ARTIFACT_NAME`.

For scheduling failures which appear only under OTP `cover`, the coverage
harness can repeat one exported zero-arity test in the same instrumented VM:

```sh
escript scripts/coverage.escript diagnose NAME SOURCE_ROOT EBIN MODULE TEST REPETITIONS
```

This mode is diagnostic and can never satisfy either coverage gate. Its schema
2 report records every attempted repetition, including the first failure, with
the typed outcome, duration, full payload-free runtime snapshot, deltas from
the initial and previous snapshots, and a bounded failure-reason tail. Timing
evidence includes nearest-rank p50/p95/p99 and a deterministic slowest
repetition for all attempts and separately after excluding the first warm-up;
a one-attempt run reports the post-warm-up distribution as `null`. Repetition
counts are bounded from 1 through 1,000 and each execution retains the same
finite four-minute watchdog. This provides a reproducible path from a rare
live failure to a focused Red case without weakening the complete-suite gate.

## Qualification campaigns

`mise run property`, `mise run fuzz`, and `mise run model` are deterministic
PR-scale gates. The generated corpus entrypoints also accept explicit seeds;
the nightly workflow divides one million cases or transitions across eight
independent shards. A shard report records its seed, size, source digest, and
result digest so repeating one failing shard does not require replaying the
whole campaign.

Before either campaign runs, the harness tests its own failure locator. On a
corpus failure it reruns deterministic prefixes with binary search, records the
smallest failing generated prefix and both case indexing conventions, and
writes a bounded exception reason, bounded stack trace, source digest, and
exact replay command to `build/campaign/<mode>/failure-shard-*.json`. A failure
that does not repeat is explicitly marked non-reproducible. Prior Ready reports
for the same shard are removed before execution so stale evidence cannot mask a
new failure. The source digest includes all three package manifests, the
campaign harness and selected corpora, and every file recursively discovered
under each production `src` tree. Harness self-tests reject a missing or
non-canonical production path, so changing implementation or FFI code always
invalidates older campaign evidence.

The PR property and fuzz gates each run 10,000 generated cases for three
independently reported families: HTTP/3 wire and QPACK, QUIC core wire and TLS,
and the unified HTTP MASQUE receive boundary. The MASQUE property family checks
every receive transition against an independent counter model. Every generated
property case also validates an HTTP/1 proxy request and executes a supervised,
default-deny DNS/socket setup through idempotent cleanup. Successful cases feed
both a spoofed source and the exact resolved address-and-port through the
target-socket transition, bind that socket to one request-stream resource, and
select socket-unusable, request-stream-ended, or application-close termination
from the reproducible seed. They then verify first-reason stability, duplicate
notification convergence, and that packets arriving afterwards are discarded
by the inactive lifetime check before source or payload inspection. Its fuzz
family
retains malformed variable-length integers, non-byte-aligned input, unknown
contexts, and oversized Context ID zero payloads, and injects every retained or
generated byte string as a resolver answer. Only exact IPv4/IPv6 widths may
reach the socket callback. Drop, abort, setup, and cleanup evidence contains
saturating counters and typed reasons but never retains input payloads, target
names, socket values, or callback exception terms.

The focused MASQUE fault suite additionally forces resolver and socket
timeouts, worker heap exhaustion, callback panics, deliberately malformed
Erlang return terms, over-limit and mixed DNS answers, DNS rebinding policy
filters, IPv6 literals, source-address and source-port spoofing, oversized
spoofed payloads, concurrent cleanup, and cleanup retry. A live unconnected
IPv4 loopback fixture also carries the operating system's observed ephemeral
source port through the same transition and closes both fixture sockets in
`after` blocks. Bound lifetime faults additionally force request-stream close
timeouts and abnormal exits while proving socket cleanup still runs, caller
mailboxes converge, and concurrent socket/stream notifications preserve the
first causal reason. Adapter return
validation runs inside the same monitored deadline/heap boundary as the
callback. Timeout paths wait for worker termination and assert caller-mailbox
convergence; resource snapshots expose only state and saturating cleanup
counters.
The bound-session concurrent-terminal regression uses a two-sided release
barrier created by the cleanup worker, so it proves first-reason and single-run
cleanup semantics without racing a sleep against the adapter deadline. Its one
payload-free trace retains both typed notification outcomes, closing/final
state, notification count, per-resource attempt counts, and cleanup-event
cardinality; the stability matrix repeats it in isolated fresh VMs.
The lower-level socket close race uses the same owner-created barrier and
retains both close outcomes plus in-progress/final resource snapshots. Timeout
and retry behavior remains a separate five-millisecond subcase, so neither
contract depends on scheduler timing from the other.
Idle activity and idle expiry also use separate live sessions. Sixty-four
successful sends run under a five-second idle window and finish by explicit
application close; an independent no-activity session drives the real owner
deadline. Both retain one bounded payload-free trace, and an unexpected send
is converted to a redacted I/O kind plus idle/lifetime/socket states before the
test fails, never the opaque session or native socket term.
Every generated MASQUE property case, and every valid-width fuzzed resolver
answer, derives different positive socket setup and operation deadlines. The
socket-open adapter must observe only the setup value and the eventual
first-reason cleanup must observe only the operation value. This turns deadline
separation into 10,000 reproducible cases per campaign instead of relying only
on the focused unit regression.

The production CONNECT-UDP socket tests use a real IPv4 loopback echo peer.
The setup callback creates a dedicated OTP socket owner and the stable caller
must adopt it before a finite setup lease expires, so a killed setup worker
cannot orphan the port. The owner grants at most eight command slots, arms the
socket with `active, once`, retains at most one delivered packet, and admits
only one receive waiter. Tests observe those limits while two replies are in
flight, distinguish busy from timeout, verify no late caller-mailbox reply,
and prove that unknown contexts and oversized payloads never reach the OS send
counter. Additional fault rows pass a closed production-shaped handle, kill or
suspend the socket actor, flood every command grant, and let the stable owner
process exit. They prove actor/mailbox/resource convergence. An independent
one-slot terminal-event waiter can remain outstanding alongside the datagram
waiter; a production-shaped `udp_closed` event drives the same
socket-unusable/request-stream cleanup transition without another datagram
operation. Tests distinguish event timeout, duplicate-waiter busy, actor crash,
and normal application close, and verify that the two waiter credits converge
independently. The duplicate-waiter regression keeps its first waiter on a
separate five-second budget, observes registration before attempting the
duplicate, and closes the session after `Busy`; timeout behavior remains in its
own focused test. One bounded assertion records registration, queued command,
timeout and rejection counters, both typed waiter terminals, close outcome, and
the final socket state without retaining the session, socket, endpoint, or
payload. Its snapshot reports requested and effective socket-buffer sizes,
command/packet credit,
Not-ECT and Don't-Fragment capability, traffic totals, timeout totals, and
socket-failure totals, but no endpoint, payload, PID, socket term, or OS reason.
The separate setup snapshot records monotonic elapsed milliseconds and timeout
bits for DNS, socket open, socket adoption, and cleanup. DNS and socket-open
traces also record callback-start state, scheduler queue time, callback time,
and whether the bounded supervisor itself expired. Tests cover success,
adapter-reported timeout, panic, malformed return, heap exhaustion, and hard
deadline expiry without retaining adapter results. The socket-deadline test
gives its preceding DNS phase a separate 2000 ms budget so fresh-VM code loading
cannot legitimately change the phase under test; DNS expiry remains covered by
its own test. A production loopback test verifies the adoption event pair. Both
the diagnostic test and command-credit flood run thirty times in isolated fresh
BEAMs; command I/O keeps its 1 ms deadline but socket-owner cold start receives
an independent 1000 ms setup budget.
Listener diagnostics are subjected to two 20,000-update multi-writer races.
They must retain all 80,000 outcome updates while every snapshot marked
consistent preserves the cross-counter invariant. A separately injected
orphaned active-writer epoch proves that later writers still finish and that a
reader returns `consistent: False` within its finite retry budget.
An oversized exact-source target reply has a separate regression boundary: a
live loopback test proves that its bytes are counted and then discarded before
the caller mailbox, where only a typed Packet Too Big report is visible. Exact
IPv4 Fragmentation Needed and IPv6 Packet Too Big vectors pin ICMP, quoted IP,
UDP, and pseudo-header checksums; maximum-length tests pin quote truncation and
advertised MTU arithmetic. Deterministic traces cover rate-limit exhaustion and
refill across BEAM's potentially negative monotonic epoch, prohibited multicast
destinations, overflow rejection, permanent capability caching, a writer left
behind an odd seqlock, and 20,000 concurrent snapshot observations. The
snapshot invariant requires one terminal outcome per oversized packet and
always reports zero retained payload bytes.

The default-listener regression also records both HTTP/3 capacity classes: its
pre-response guarantee must equal the post-response
`guaranteed_datagram_size`, must never exceed the point-in-time maximum, and
must survive thirty isolated fresh-BEAM repetitions. A pure QUIC state-machine
test drives a validated 9000-byte path, 256 retained ACK ranges, and a
black-hole reset to 1200 bytes; the same guaranteed payload must remain
queueable and the protected ACK-plus-DATAGRAM packet must fit the collapsed
path. This is the causal guard against confusing transient ACK clearance with a
safe fixed MASQUE socket ceiling.

Unprivileged development runs normally observe the typed `PermissionDenied`
raw-socket result. That is a passing finite-failure test, not evidence that an
ICMP packet reached a peer. Successful delivery requires the separate
privileged platform/interop qualification row; the deterministic wire vectors
remain runnable without elevated privileges.
A live H3 composition holds the event waiter, injects a production-shaped
socket failure, releases both waiters, runs first-reason cleanup once, and
observes H3_REQUEST_CANCELLED at the peer. The protocol-neutral Context bridge
and independent H1/H2/H3 cancellation cases fix the remaining adapter mapping.
Continuous post-success proxy-session consumers for every H1/H2/H3 tunnel
remain a separate open qualification step; the deterministic close fixture
explicitly injects OTP's canonical
`udp_closed` message after closing the real port because external close does
not itself notify the controlling process.

`mise run hostile-peer` starts each selected test module in a fresh BEAM and
covers stalled peers, UDP/mailbox floods, actor crashes, aggregate memory,
connection/handshake admission, client endpoint memory, parser bombs, and
slow-consumer backpressure. Its families, packages, and module selection live
in the machine-readable `hostile_matrix` section of `qualification.json`.
Both the runner and status generator consume that section; the latter resolves
the current test count from source and rejects a handwritten matrix count.
The runner removes its older Ready report before starting. Each selected module
runs in its own BEAM; on the first failure the runner writes the completed
package/module/test totals plus exit status, output digest, and a non-shareable
bounded base64 tail before returning nonzero. A successful report is accepted
only when the independent verifier sees every configured package, module, and
test completed under the current source digest.
The QUIC credit rows distinguish application queue completion from a FIN ACK
through the public `client.send_finished` probe. Pure sender, stream, and
connection tests permit one immediate DATA_BLOCKED or STREAM_DATA_BLOCKED
advisory per unchanged limit and rearm it only when MAX_DATA or
MAX_STREAM_DATA increases. The live flooded-connection recovery case arms a
bounded actor trace before traffic, records connection/path snapshots on an
ACK timeout, and has a 100-iteration local stress reproduction for socket,
process, and listener convergence. This prevents a blocked write from becoming
the previous 64-packets-per-worker-turn busy loop while keeping loss recovery
responsible for retransmitting an emitted advisory. The aggregate-memory
backpressure case also waits on a bounded, causal refusal barrier instead of
assuming that a stopped remote flood means the listener reply has already
reached the connection actor. A missed barrier retains only five finite
accounting values -- buffered, retained, unmeasured, granted, and refused --
so a loaded-run failure identifies the stalled grant transition without
retaining application payload or a native handle.

The HTTP/2 graceful-drain regression uses a release subject created by the
response-body worker and advertises that subject to the fixture only after the
pull has started. This ownership is part of the test contract: a Gleam subject
can be received only by the process that created it. A public fixed-size phase
snapshot records listener/connection readiness, drain request,
per-connection command and receipt, GOAWAY attempt and successful write, and
final drain completion. The test waits for the write-side causal barrier before
reading the wire under a separate 10-second deadline. Its bounded wire trace
records read attempts, byte count, observed GOAWAY pairs, and a typed terminal
phase; it never prints a socket or PID. GOAWAY observation, premature drain
reply, body release, and drain completion remain one causal assertion, then
socket/listener/executor cleanup is checked separately. Five concurrent
diagnostic writers perform 20,000 updates each while readers check cross-field
invariants, and an orphaned-writer test requires finite inconsistent fallback.

`mise run stability` turns scheduling-sensitive regressions into a repeatable
gate rather than a shell-loop anecdote. Its targets and repetition counts live
in `qualification.json`; the runner validates that schema, starts the selected
zero-arity test function in a new BEAM VM for every iteration, and removes an
older Ready report before the first execution. The success report records the
exact source digest, target identity, configured count, and completed count.
On the first failure it writes `build/fault/stability.json` before returning
nonzero, including the failing iteration and exit status, full-output SHA-256,
original byte count, and at most 16 KiB of base64-encoded output tail. That tail
is local diagnostic material and is not declared redacted or shareable; failed
reports never enter the audit bundle. The runner self-test rejects unsafe
module/function identifiers, unknown packages, duplicate targets, zero or
excessive repetitions, and invalid output bounds, and checks tail truncation
and digest metadata. It also starts an isolated child VM that must fail for an
injected reason, verifies the captured status and marker, and proves stale
report removal without needing a package build.

For investigation without replaying the whole matrix,
`escript scripts/test_matrix.escript stability <target> [runs]` selects only a
manifest-declared target and still starts a fresh BEAM for every run. It writes
`build/fault/stability-target-<target>.json` with the current source digest and
bounded first-failure evidence. The report is explicitly marked
`DiagnosticTarget` and `shareable: false`, uses a path separate from aggregate
evidence, and cannot satisfy the full stability gate. Target names and optional
1..1000 repetition overrides are covered by the runner self-test.

The audit-bundle gate independently recomputes the matrix runner's declared
source set and rejects stale hostile-peer, stability, or credential reports.
For stability evidence it also requires schema 1, a non-empty target set,
exact configured/completed totals, and a Ready result with complete repetitions
for every target. Its self-test proves that stale digests, partial aggregate or
target counts, and non-Ready reports are rejected before bundle assembly. The
hostile-peer, stability, and aggregate credential tasks invoke that verifier
immediately after writing their report, so stale evidence cannot survive until
a later source-candidate run.

`mise run credential-matrix-local` exercises live
RSA-PSS, ECDSA P-256/P-384, Ed25519, mTLS, HRR, rotation, resumption, 0-RTT
fallback, expiry, revocation, and mismatch behavior. The aggregate credential
gate accepts only reports for Ubuntu 24.04, macOS 15, and Windows 2025 on OTP
28 and 29 with the exact current source digest.

`mise run structured-fields-oracle-setup` obtains the HTTP Working Group's
Structured Field test corpus at the exact commit and per-file SHA-256 values
recorded in `standards/structured-fields-oracle.json`. It refuses a different
origin or a modified checkout. `mise run structured-fields-oracle` then starts
from a fresh package build, exercises all 1,591 parse vectors through the
public RFC 9651 API, checks canonical serialization for every mandatory valid
case, and writes corpus and implementation digests to
`build/structured-fields-oracle/report.json`. Its six advisory vectors are
reported separately: four are accepted, while missing base64 padding and
nonzero pad bits are rejected under the documented canonical RFC 4648 policy.
The runner's self-test covers all three field shapes and malformed lock,
fixture, digest, count, and implementation-result paths before the corpus is
trusted.

Coverage reports two deliberately bounded metrics across production Gleam,
Erlang, and FFI modules. The line metric is OTP `cover` execution of physical
lines in the generated Erlang artifact. The second metric enumerates
multi-clause alternatives in the compiled BEAM debug abstract forms. An
alternative is covered only when OTP `cover` reaches an observable artifact
line that belongs to that alternative and to no sibling alternative in the
same compiled decision. A missing sibling, observable line, or
sibling-exclusive witness fails the coordinate model instead of silently
removing the alternative. The policy and JSON retain the historical key name
`branches`, but this is an observable compiled clause-alternative metric. It is
not a claim of general branch coverage: short-circuit Boolean outcomes, guard
outcomes, receive timeouts, and exception paths are not counted unless they
appear as multi-clause alternatives in those forms. No manual or generated
clause exclusion is applied.

Execution coordinates never masquerade as original Gleam line numbers. Gleam
artifact lines are attributed by compiled `{name, arity}` to Glance function
spans, including attached attributes. Erlang and FFI attribution uses exact
source lines only after the source and build artifact are proven byte-identical.
Changed-source selection uses overlap with those source spans. If any changed
range cannot be attributed, the complete module is selected conservatively and
the fallback and unattributed ranges are retained in `changed_selection`.
Untracked source likewise selects the complete module. Reports therefore show
exact generated-artifact coordinates and the corresponding source span, not a
claim of exact Gleam execution lines.

`mise run coverage-coordinate-audit` checks all three freshly built packages
without running their suites. It binds each source, generated artifact, and
compiled BEAM; validates source regions, compiled functions, clause
alternatives, and sibling-exclusive OTP `cover` witnesses; and emits one
coordinate-model digest per package. `mise run coverage-capture` runs this
audit immediately after resetting stale coverage output and before the first
expensive repeated suite, so coordinate drift fails fast.

The changed-source gate requires 100% artifact-line and compiled
clause-alternative coverage; the whole-tree gate requires 95% and 90%
respectively. Thresholds, coordinate methodology, repetition bounds,
quiescence, and the complete capture source set live in
[`coverage-policy.json`](../coverage-policy.json). Both gates write a report
before returning nonzero, so a deficit remains auditable. Each capture first
tests the coverage harness itself, then runs each package suite repeatedly in
the same instrumented VM. It performs at least ten and at most thirty
repetitions, stopping successfully only after three consecutive repetitions add
no artifact-line or clause-alternative coverage. Hitting the finite maximum
without that quiescent tail is a failure. The wider bounded window was fixed
after a ten-run capture continued to discover scheduling-dependent production
paths in its final repetition. This makes suite re-entry and cleanup part of the
gate while forming an auditable union of scheduling-sensitive paths.

Package-specific `build/coverage/*.capture.json` artifacts retain each
repetition's duration, cumulative and newly reached artifact/source
coordinates, and payload-free process, port, network-port, OTP-socket, ETS,
mailbox, run-queue, and memory observations. Test time and cleanup-settle time
are recorded separately. Before taking that repetition's coverage snapshot or
starting the next repetition, the harness waits for a bounded runtime settle:
all globally enumerated fixed `quic_core.*` and `http3.*` actor labels, network
ports, and OTP sockets must return to their cold baseline, and after the first
fully settled repetition total process, port, and ETS counts must return to
that warmed baseline. Three restored, non-growing samples are required; a
nonzero stable plateau is not quiescence. The 20-second bound covers the finite
QUIC Closing/Draining lifetime and bounded qlog shutdown, and a timeout is
retained as a failed repetition rather than hidden by killing actors. Immediate
state, every 100-millisecond settle sample, per-label counts, observed peaks,
and cold/warm/final deltas remain in the JSON. Memory, run-queue, and mailbox
values remain diagnostic observations rather than allocator-sensitive
thresholds. This per-repetition barrier prevents a prior actor's terminal code
or scheduler/port load from contaminating the following repetition. Every capture is
bound to the complete production/test/fixture and harness source set, its
compiled artifacts and coordinate-model digest, OTP/ERTS version, and the
exported `.cover` digest. Reports reject stale, modified, incomplete, or
mismatched three-package captures, suppress repetitive OTP import notices, and
rank the ten modules with the largest combined artifact-line and compiled
clause-alternative deficit. The JSON report retains every module metric,
generated-artifact coordinate, source span, coordinate method, and changed
selection reason.

Coverage test discovery begins from each package's `test` source tree and then
inspects compiled exports for zero-arity `_test` and `_test_` entrypoints; it
therefore includes Erlang EUnit modules whose module name does not end in
`_test`. The entrypoint total is retained beside the module list, and synthetic
self-tests fix suffix and arity handling. A compact, source-bound
`coverage-evidence.json` is generated from the same validated report so the
conformance document never relies on hand-copied percentages or ephemeral
`build/` contents.

Documented Gleam examples are annotated with package and module identifiers.
`mise run examples` extracts every fence, rejects unannotated or duplicate
examples, compiles them offline against the package build, and executes each
`main` function. Current status and discovered counts are always read from the
generated [product conformance status](CONFORMANCE.md).

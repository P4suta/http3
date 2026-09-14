# Performance verification

The performance harness is a reproducible local verification workload, not a
production capacity claim. It uses the public `http3/client` and `http3/server`
APIs over real loopback UDP with certificate-chain and hostname verification
enabled. No backend handle or test-only verification bypass is used.

## Fixed workloads

Run the pinned toolchain and each fixed workload from the repository root:

```sh
mise install
mise run benchmark
mise run load
mise run soak
mise run hot-path-profile
mise run connection-barrier-self-test
mise run progress-trace-self-test
```

| Task | Warm-up | Measured trials | Connections | Requests per connection | Payload |
| --- | ---: | ---: | ---: | ---: | ---: |
| `benchmark` | 1 | 5 | 4 | 100 | 1 KiB |
| `load` | 1 | 3 | 32 | 100 | 16 KiB |
| `soak` | 1 | 1 | 8 | 10,000 | 1 KiB |

Each worker opens one TLS-verified reusable connection and sends sequential
streaming POST requests. The server reads and verifies each complete request
body, echoes it in a 200 response, and the client verifies the status and body.
Every worker must first reach a supervised all-connected barrier; no request
body is sent until every connection is authenticated. This prevents an early
subset from consuming the listener memory budget while a later connection is
still seeking admission, and makes all 32 connections part of the measured
load. A connection failure, duplicate worker arrival, barrier deadline, or
barrier-process exit releases every waiter and fails the trial. The standalone
barrier self-test fixes those transitions plus owner-exit cleanup.
After each client has taken its terminal transport and resource snapshots, it
waits on a second owner-supervised completion latch before closing. The owner
releases that latch only after the final server-side resource snapshot has
finished, preventing peer close from racing the inspection. The same self-test
covers early and late waiters, duplicate identities, unauthorized release,
explicit failure, deadline, stop, and owner exit for this latch.
The measured interval includes client connection establishment, all request
round trips, connection close, and listener stop. The bounded convergence wait
runs immediately afterward and remains a mandatory gate, but is not charged to
request throughput. Compilation, fixture loading, priming, and listener startup
are also excluded.
Before taking the resource baseline, each trial starts and fully stops a
disposable priming listener and verified client connection. This moves OTP/inet
lazy initialization outside the comparison while still requiring the primed
baseline to contain zero network-driver ports and zero `socket` API resources.
The real workload then records total ports, legacy inet TCP/UDP/SCTP ports, and
`socket:which_sockets/0` resources before and after, and waits at most ten
seconds for all three inventories plus the process count to converge.

Every network and process operation has a fixed timeout. A trial assigns one
shared absolute 15-minute deadline to every worker and checks it at each
server request boundary; awaiting a worker never starts a fresh 15-minute
window. Individual HTTP/3 operations have a 60-second bound, and cleanup has a
10-second bound. After a trial, the harness requires the
BEAM process count to return to or below its pre-workload value. It also records
the total queued mailbox messages across all BEAM processes before and after
the workload. A failed response, worker, shutdown, cleanup bound, or payload
comparison makes the task fail instead of emitting a successful row.
Before either endpoint closes, the harness also takes one payload-free
retained-resource snapshot. It fails with all nine observed counts if active
requests, the bounded terminal registry, adapter/core/transport stream handles,
parser inputs, transactions, push transactions, or QPACK-blocked streams exceed
their fixed ceilings. This makes lifetime regressions part of every performance
workload without adding a synchronous diagnostic query to each request.

Each fixed task preserves its complete local log plus canonical CSV and JSON in
`build/performance/current/`. It also preserves mode-specific host snapshots
immediately before and after the workload. The schema 3 report binds the result
to a digest of all three production source trees and validates the
manifest-owned workload shape, row count, process convergence, final mailbox
count, median threshold, snapshot ordering, stable runtime identity, probe
shape, and monotonic host counters.

Each row records BEAM runtime milliseconds, reductions, context switches,
garbage collections and reclaimed words, VM I/O bytes, and run queue before and
after. It also aggregates public transport diagnostics from every client:
initial and final RTT and congestion-window ranges, packets received and sent,
retransmissions, batch flushes, coalesced packets, and recovery/congestion
state. The initial snapshot is taken only after every verified connection has
reached the admission barrier, and the final snapshot follows the last response
and resource assertion.

The host snapshots read only fixed numeric counters. Where available they
include load average, CPU/memory/I/O pressure-stall information, aggregate CPU
ticks, memory availability, cgroup CPU use and throttling, cgroup memory state,
CPU-frequency ranges, and thermal ranges. Every probe is explicitly
`Available`, `Partial`, `Unavailable`, or `Invalid`; an invalid or malformed
probe fails the evidence gate, while an unsupported source remains visible
without making macOS or Windows inherently fail. The report derives CPU busy
time and counter deltas without treating high host pressure as an excuse to
relax the throughput threshold. Snapshots omit hostnames, command lines,
process arguments, cgroup names, environment variables, endpoints, and
payloads. They and the complete logs are local and marked non-shareable; the
log appears in the report only as a bounded base64 tail. Derived BEAM
utilization, reductions per request, host-pressure deltas, RTT, and
retransmission values help distinguish scheduling pressure from extra protocol
work or packet loss.

`hot-path-profile` runs a smaller fixed 200-request workload under OTP `tprof`
call counting. Its bounds live in `standards/performance-profile.json`. The gate
requires positive call-count sentinels for both endpoint resource snapshots,
exactly two public path snapshots per client and exactly one terminal traffic
snapshot per client at the HTTP/3, public QUIC, and QUIC actor-command layers.
This proves that the required diagnostics remain present while a disabled qlog
adds no extra traffic snapshots. The gate also requires zero retired PMTU phase
commands and caps handshake refresh, actor drive, command, and stream poll
volume. Machine-readable counts and violations are written to
`build/performance/hot-path-profile.json` and `.csv`; those generated files are
developer/audit evidence, not throughput measurements.

`mise run performance-audit` independently recomputes the manifest-owned
source digest and verifies the schema, profile digest, source digest, workload
configuration, transport fields, bounded log, host snapshots, and hot-path
report. Checked-in historical CSV files are counted for provenance but are not
accepted as current qualification merely because they contain a matching
string. The H3 client/server roles and the mailbox, process, and memory
and socket-convergence assertions are credited only when all three fixed H3
reports and the hot-path profile are current and `Ready`. H1/H2 role evidence
and idle-wakeup evidence remain explicit missing rows until their independent
workloads exist.

For a loaded-run stall investigation, `mise run load-diagnose` runs one warm-up
and one 32-connection trial while writing one progress CSV per trial under
`build/diagnostics/http3-load/progress/`. This trace is opt-in and is absent
from the fixed performance gates, so its one-second sampling overhead cannot
silently change a promoted throughput result. Each row records aggregate server
and client completion, the minimum and maximum completed request number, four
client phases, stalled-worker count, process/memory/mailbox/run-queue totals,
and runtime/reduction deltas. A worker is stalled only after five seconds with
work remaining.

While any worker is stalled, the trace also writes at most one bounded JSON
snapshot every 30 seconds. It includes only process IDs, status, MFA/arity,
queue length, memory, reductions, sanitized stack MFAs, and bounded port
counters. Message values, process dictionaries, function arguments, socket
endpoints, and application bodies are never inspected. The files are marked
payload-free but deliberately non-shareable because they are local operational
diagnostics. `mise run progress-trace-self-test` injects a marker into both a
mailbox and process dictionary, makes that process enter the captured top set,
and rejects any marker or unapproved field in the JSON.

`mise run load-diagnose-qlog` adds client and server qlog under the sibling
`qlog/` directory. It is deliberately separate because qlog changes timing and
contains sensitive connection metadata. Both diagnostic tasks compile with
warnings as errors and run the barrier and redaction self-tests before opening
a socket.

Custom exploratory workloads can use the positional interface below. The
fixed tasks above remain the comparison baseline.

```sh
mise exec -- gleam run -m http3_benchmark -- benchmark 5 4 100 1024
```

The arguments are mode, measured trials, concurrency, requests per worker, and
payload bytes. The harness bounds all inputs before allocating or starting
network work.

## Release thresholds

The reopened v1 gate requires at least 516 requests/second for `benchmark`,
344 for `load`, and 812 for `soak` on the same recorded host. All three must
also retain zero periodic idle polling, zero queued mailbox messages after
cleanup, process-count convergence, and the configured memory bounds.

The 2026-08-24 result below is exactly half the benchmark and load thresholds
and does not pass the release gate; it remains a comparison baseline, not
completion evidence. The 2026-08-26 runs recorded further down meet the
benchmark and load thresholds on that host but did not rerun soak. The
2026-08-28 hot-path candidate meets all three thresholds, the paired adoption
rule, and the cleanup requirements on the same host.

## Recorded native-core baseline

The 2026-08-24 run used the repository-owned `quic_core` backend and the
environment in
[`2026-08-24-environment.txt`](results/2026-08-24-environment.txt). Every row
is retained in
[`2026-08-24-local.csv`](results/2026-08-24-local.csv). Warm-up rows are
excluded from the summaries:

- The five baseline trials had a median 258 requests/second and a range from
  244 to 288 requests/second.
- The three 32-connection load trials had a median 172 requests/second and a
  range from 171 to 173 requests/second.
- The sustained measured trial completed 80,000 streams in 196.909174 seconds,
  or 406 requests/second. Its separate 80,000-stream warm-up took 206.950577
  seconds, so the soak task exercised 160,000 streams continuously.
- Every row returned from 48 processes to 47 and recorded zero total mailbox
  messages before and after. In the measured soak row, total BEAM memory
  changed from 40,497,800 to 40,687,280 bytes after cleanup, an increase of
  189,480 bytes (approximately 185 KiB).

These numbers describe one localhost run on an Intel Core i7-7700K with the
`powersave` governor and without CPU affinity. CPU frequency scaling,
background load, allocator high-water marks, scheduler placement, and one
machine's network stack introduce uncertainty. The one-trial soak result has
no statistical interval. Use the raw repeated trials for comparisons; do not
treat the fastest row as a general throughput guarantee or compare it directly
with a remote peer or the former external-backend baseline.

## 2026-08-25 diagnostic rerun

The reopened worktree was profiled with OTP `tprof`. Replacing an unconditional
all-connection send scan with a per-turn dirty-connection set reduced comparable
`session.prepare_datagram` calls from 49,874 to 23,574. Protocol timer expiry
still drives every connection, so loss recovery, idle timeout, keepalive, and
PMTU progress do not depend on new traffic.

The raw successful rows and environment are retained in
[`2026-08-25-diagnostic.csv`](results/2026-08-25-diagnostic.csv) and
[`2026-08-25-environment.txt`](results/2026-08-25-environment.txt):

- the five measured benchmark rows had a median of 477 requests/second and a
  range of 285–564; only two rows exceeded 516;
- two independent measured 32-connection load rows reached 212 and 200
  requests/second, still below 344; and
- every retained row converged its process count and ended with zero queued
  mailbox messages.

One separate full three-trial load invocation stopped during its first measured
trial with bounded peer-close failures after a successful warm-up. No
successful row was emitted for that trial, as required by the harness. The soak
rerun was not promoted as evidence once the prerequisite benchmark/load gates
had failed. This diagnostic set therefore does not replace the retained
baseline and does not pass the release performance gate.

## 2026-08-26 Phase 0 results

Two runs were recorded on the same host on 2026-08-26: a baseline on the
current `main` tip (`a2b5426`) and a post-Phase-0 run on
`feat/phase0-foundation` (`589a8d4`). Both used the repository-owned
`quic_core` backend. The baseline rows are in
[`2026-08-26-phase0-baseline.csv`](results/2026-08-26-phase0-baseline.csv) with
[`2026-08-26-phase0-baseline-environment.txt`](results/2026-08-26-phase0-baseline-environment.txt);
the Phase 0 rows are in
[`2026-08-26-phase0.csv`](results/2026-08-26-phase0.csv) with
[`2026-08-26-phase0-environment.txt`](results/2026-08-26-phase0-environment.txt).
Warm-up rows are excluded from the summaries.

| Mode | Threshold | Baseline median (range) | Phase 0 median (range) |
| --- | ---: | ---: | ---: |
| `benchmark` | 516 | 594 (590–601) | 583 (572–599) |
| `load` | 344 | 232 (205–233) | 423 (394–437) |

On this recorded host the benchmark threshold was already met by the baseline,
and the load threshold is met only after the Phase 0 pacing and path-MTU
changes: the load median rises from 232 to 423 requests/second. The benchmark
median moves down by 11 requests/second, which is inside the observed
run-to-run spread. Every retained row returned from 48 processes to 46 and
recorded zero total queued mailbox messages before and after.

The soak threshold of 812 requests/second was not rerun for either commit, so
the third fixed workload has no 2026-08-26 evidence and the release
performance gate remains open. The long-load bounded peer-close failure seen
on 2026-08-25 did not reproduce in the three measured Phase 0 load trials.

These numbers are still one localhost host: the same CPU-frequency scaling,
background load, allocator, and scheduler-placement uncertainty described
above applies, and no row should be treated as a general throughput guarantee
or compared directly with a remote peer.

Full gate output for this run is in
[`docs/evidence/2026-08-26-phase0.md`](../docs/evidence/2026-08-26-phase0.md).

## 2026-08-28 hot-path results

The baseline was fixed at `48a8b3b`; the candidate was that revision plus only
the internal active-stream queue and complete-small-response batching patch.
The same pinned toolchain and host were used for adjacent one-trial A/B pairs,
with pair order alternated. Raw A/B rows are in
[`2026-08-28-hot-path-ab.csv`](results/2026-08-28-hot-path-ab.csv), profile
counts are in
[`2026-08-28-hot-path-tprof.csv`](results/2026-08-28-hot-path-tprof.csv), and
the environment record is in
[`2026-08-28-hot-path-environment.txt`](results/2026-08-28-hot-path-environment.txt).

| Mode | Baseline median (range) | Candidate median (range) | Pair wins | Change |
| --- | ---: | ---: | ---: | ---: |
| `benchmark` | 497 (438-544) | 625 (527-664) | 5/5 | +25.8% |
| `load` | 344 (339-349) | 509 (485-533) | 5/5 | +48.0% |

Both modes exceed the adoption requirement of four wins and a 5% median
increase. `tprof` reduced the comparable full-stream scan calls from 104,389
to zero, and complete-response command handlers from 600 to 200 across 200
responses, confirming the required scan reduction and three-to-one worker
drive change.

The candidate then ran the unchanged fixed workloads. Raw rows are in
[`2026-08-28-hot-path.csv`](results/2026-08-28-hot-path.csv); warm-ups are
excluded below.

| Mode | Threshold | Candidate result |
| --- | ---: | ---: |
| `benchmark` | 516 | median 586 (570-610) |
| `load` | 344 | median 479 (476-487) |
| `soak` | 812 | 1,034 |

The soak task processed 160,000 streams across warm-up and measurement. Every
fixed row returned from 48 processes to 46 and ended with zero queued mailbox
messages; none reported timeout or peer-close. The complete profile, A/B,
fixed-workload, and correctness record is in
[`docs/evidence/2026-08-28-hot-path.md`](../docs/evidence/2026-08-28-hot-path.md).

# Public HTTP protocol measurements

Run `mise run protocol-performance` to exercise the public `http/client` and `http/server` APIs over verified TLS for HTTP/1.1, HTTP/2, and HTTP/3.
The task builds current sources, tests the bounded execution runner, measures the fixed workload, and independently verifies its retained execution evidence.

`mise run performance-contract-audit` is the fast, workload-free gate required by `mise run check`; the source-candidate sequence runs that check before every performance producer.
It binds the common process-supervisor ceiling of 5,400,000 ms to the fixed HTTP/3 deadlines (benchmark 5,400,000 ms, load 3,600,000 ms, soak 1,800,000 ms), the 60,000 ms idle run, the 120,000 ms hot-path profile, and each 300,000 ms protocol child.
Its adversarial controls reject a missing mode, an expanded or inconsistent deadline, reordered preflight invalidation, unsafe child-output retention, and producer/consumer or CI artifact-path drift.
It removes comments before inspecting required Erlang and shell operations, and binds `always()` and the exact path list to each named upload step.
The PR quality job always uploads `build/performance/contract-audit.json` and `build/performance/contract-audit-self-test.json`; absence is a CI failure.

Every task invalidates its prior public artifacts before self-tests or a fresh build.
A preflight failure therefore leaves a current `Failed` record instead of an older `Ready` result.
Fixed runs also empty the CSV, bounded log, and both host snapshots before starting, and remove the selected execution proof.
Idle runs empty their typed fixture and log, hot-path runs replace the CSV with its scalar header, and protocol runs replace the report and remove the proof.
The Failed record stays in place while current-source identity is computed, so a missing or unreadable source cannot reopen a stale-evidence gap.
The fixed and idle shell drivers still invoke their reporters after a workload failure so a bounded diagnostic report is retained.
Child output tails and their raw digests remain private; public failures contain only typed diagnostic categories and finite counters.

Each protocol has its own BEAM VM.
One warmup and five measured trials run in that same VM.
Each trial sends 100 sequential requests with 1024-byte request and response bodies, validates the bytes and trailers incrementally, and uses a client pool with one connection slot.
The fixed configuration lives in `standards/performance-profile.json`; the producer and auditor reject drift.
HTTP/1.1 and HTTP/2 also verify the listener's accepted-connection counter.
HTTP/3 records that counter as `null` because the public listener currently does not expose it.
It never treats an unavailable observation as zero.

Per-request timings start before `client.exchange`.
Header latency ends when that API returns the final response headers; complete latency ends after the body and trailers are verified.
A trial's request elapsed time includes connection establishment and all requests, and excludes listener/client startup and endpoint cleanup.
Throughput uses this measured elapsed time.
Warmup samples remain in the evidence but do not contribute to measured latency percentiles or throughput.
Percentiles use nearest rank over all 500 measured requests.
The report includes both aggregate throughput and the median of the five individual trial rates.

The observer separately samples the whole VM during the workload, including its endpoint startup and cleanup.
It reports memory, process counts, mailbox counts and maxima, ports, and network socket counts.
Peaks are sampled values,
not exact maxima.
Sampling runs every 10 ms with at most 4096 attempts; slow sampling, saturation, and an empty sample set fail the measurement.
Native monotonic time controls deadlines even when a regression test injects a different clock.
Sampler duration, observer memory and its process/heap limits are reported as overhead and are not subtracted from the measurements.

The observer requires a clean project/network baseline and checks final convergence against the real VM after cleanup.
It distinguishes workload,
cleanup, sampling and convergence failures.
Its helpers must terminate before the result is published.
Convergence requires two consecutive restored samples.
Every attempt records a fixed blocker classification, excess count,
monotonic offset and sampler duration.
The report retains the most recent 16 entries and an exact count of earlier entries, so a sustained failure remains bounded while its final causal sequence stays reviewable.
A test-injected convergence sampler can reproduce delay, failure and resource drift, but its report cannot qualify a run as successful.
The observer rechecks the native deadline before starting each final sample, which keeps an expired window classified as convergence timeout instead of sampler failure.

Each workload worker has a 4,194,304-word heap limit,
including shared binaries (32 MiB on a 64-bit runtime).
Work has at most 60 seconds; the measurement child reserves cleanup time within its 270-second absolute deadline.
Skipped rows remain visible and do not count as completed trials.
The outer runner imposes a separate five-minute deadline on each protocol VM, limits output to 8 MiB, disables crash dumps,
and confirms VM exit.
Any unexpected child output prevents qualification.

The result is `build/performance/current/protocols.json`.
A selected proof archive at `build/performance/current/protocols-execution-proof.tar` retains the exact child records and runner/observer BEAMs.
Source and fresh-build identities, configuration, run nonces, actual exit results, all six trials,
and recomputed statistics must agree.
Missing trials, forged success,
substituted code, unknown fields and private failure payloads are rejected.
Failure artifacts contain fixed classifications and bounded observations;
raw output is not uploaded.

Nightly collection names the same paths used by the producers.
The protocol job uploads the protocol report and selected proof with `if: always()`.
The soak job uploads its report, canonical CSV, sanitized log, execution report,
selected proof, and start/end host snapshots with the same condition.
Both jobs treat an entirely missing artifact set as an error.
The contract audit checks these lists exactly and rejects raw runner directories and diagnostic fixture trees from CI uploads.

The aggregate `mise run performance-audit` also invalidates `build/performance/report.json` before its self-test and collection phases.
Its replacement is staged, synced, bounded to 16 MiB, and renamed into place.
An unexpected failure publishes a redacted `Failed` record with a fixed phase classification and best-effort current-source/runtime identity.
An expected `Blocked` result keeps its complete missing-role and evidence violations for diagnosis instead of being replaced by a generic exception report.

Before taking the first baseline, the child performs bounded localhost name resolution and an authenticated TLS 1.3 exchange through OTP's public TCP upgrade API.
This initializes OTP services which persist for the VM lifetime.
The preparation joins its workers and closes every socket within five seconds;
it does not subtract processes or sockets from later resource observations.
An untrusted certificate still fails preparation.
The exact preparation BEAM is retained with the execution proof.

This workload supplements the existing HTTP/3 benchmark, load, soak, hot-path and idle-wakeup gates.
Successful local loopback measurements establish that the workload and observation completed.
They do not establish the declared performance ratios against independent pinned peers or a checked-in baseline.
Those comparisons still require executable evidence, and the aggregate performance audit remains blocked until they are implemented and pass.
Hosted CI timings are diagnostic; qualification needs the specified host conditions and complete current-source evidence.

# 2026-09-14 coverage-full

- Date: 2026-09-14
- Commit: 3ad1d06 plus the capture fixes in this change
- Gleam: 1.18.1
- Erlang/OTP: 29.0.5
- mise: 2026.9.6
- Host: macOS 15 (Darwin 25.6.0) arm64, 18 cores, 48 GiB

Command:

    mise run coverage-full

Result: the capture completed for all three packages for the first time; the
gate then failed on its thresholds rather than on a stopped capture.

    captured http:      78 modules, 64 test modules/552 entrypoints,
                        19 repetitions; paths saturated: true;
                        runtime resources converged: true
    captured http3:     64 modules, 58 test modules/319 entrypoints,
                        17 repetitions; paths saturated: true;
                        runtime resources converged: true
    captured quic_core: 75 modules, 65 test modules/432 entrypoints,
                        18 repetitions; paths saturated: true;
                        runtime resources converged: true

    full coverage: generated-artifact lines 78.95%,
                   observable compiled clause alternatives 65.26%
    coverage gate failed: {coverage_threshold_not_met,"full",7895,6526}

Against the manifest-owned 95.00/90.00 thresholds that leaves 2389 artifact
lines and 1742 clause alternatives uncovered across the ten modules the report
names. They are the workers and state machines, and what is unreached in them
is the error and boundary side rather than the ordinary path:

| Module | Lines | Alternatives |
| --- | --- | --- |
| `quic_core/internal/connection_state` | 83.05% | 71.54% |
| `quic_core/internal/tls/engine` | 85.89% | 64.53% |
| `quic_core/internal/runtime/connection_worker` | 75.21% | 65.38% |
| `quic_core/internal/runtime/client_worker` | 67.31% | 55.05% |
| `http3/internal/native/server_worker` | 78.65% | 63.47% |
| `http3/internal/native/client_worker` | 72.74% | 60.11% |
| `http/masque` | 79.22% | 66.48% |
| `http/internal/http1/server` | 68.97% | 54.01% |
| `http/internal/http2/server` | 74.87% | 62.75% |
| `http_masque_udp_ffi.erl` | 66.01% | 53.46% |

Two capture stops were found and fixed to reach this run. Both were defects
the instrumentation exposed rather than defects of the instrumentation, and
each one had made the capture stop before any package finished:

1. Three tests read the per-connection dropped-datagram counter through a
   drained actor. The listener keeps a drop it refuses until a later delivery
   carries the count, or until the empty delivery it sends once the actor has
   acknowledged everything and the window has reopened, so the count completes
   a round trip that finishes after the actor's mailbox is already empty. A
   drained actor is therefore not a barrier for it, and the tests read whatever
   had landed. They now wait for the report itself.
2. The advanced HTTP/3 transport test read the HTTP Datagram capability off an
   accepted request stream before the peer's SETTINGS had necessarily been
   read, which RFC 9114 section 6.2.1 permits.

Two further changes were tried and withdrawn, because neither could be shown to
be necessary and both changed behaviour on a platform they could not be checked
against from here. Starting the flood observation window when the flood starts
rather than when the caller computes it, and holding the connection actor still
for the overflow burst, each passed on macOS and Linux and each failed the
Windows smoke job on a test that had been passing. The capture completes
without them -- thirteen repetitions, paths saturated, resources converged --
so the barrier above is the whole of what the stop required.

`coverage-evidence.json` is source-bound and deliberately untracked: it is
invalidated by any source edit, so a clean checkout renders the unproven
status rather than a stale percentage.

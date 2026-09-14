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

Two capture stops were found and fixed to reach this run. Both were defects the
instrumentation exposed rather than defects of the instrumentation, and each
one had made the capture stop before any package finished:

1. The two windowed-flood tests in the QUIC credit suite measured their
   observation window from before the flooding process was spawned, so on a
   runtime slow enough for that setup to outlive the window the flood sent
   nothing and the sampler observed nothing.
2. The overflow test relied on a spoofed burst outrunning the connection
   actor, which is a race rather than a property of the burst, and
   instrumentation slows the sender as much as the consumer.
3. The advanced HTTP/3 transport test read the HTTP Datagram capability off an
   accepted request stream before the peer's SETTINGS had necessarily been
   read, which RFC 9114 section 6.2.1 permits.

`coverage-evidence.json` is source-bound and deliberately untracked: it is
invalidated by any source edit, so a clean checkout renders the unproven
status rather than a stale percentage.

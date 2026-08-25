# Optional BeamTrace diagnostics

This directory contains an opt-in development and incident-diagnostic path.
BeamTrace is not a runtime or Hex dependency of `http3` or `gleam_quic`, and
this path is not run by normal CI, release qualification, or performance
measurement.

Install or build BeamTrace v0.2.x separately, then expose its executable on
`PATH` or through `BEAMTRACE_BIN`. The runner never downloads it:

```sh
BEAMTRACE_BIN=/path/to/beamtrace mise run diagnose -- round-trip
```

The fixed scenarios are `round-trip`, `connection-isolation`,
`slow-consumer`, and `cleanup`. Each runs once as a warm-up before entering a
single `diagnostics@http3_diagnostic:trace_root/1` capture root. Protocol work
uses only the public client, server, and qlog APIs, with finite operation and
cleanup timeouts.

- `round-trip` sends and receives one streaming request.
- `connection-isolation` abandons an unanswered request, then proves that a
  separate connection remains usable.
- `slow-consumer` deterministically exceeds an eight-event consumer buffer.
- `cleanup` crashes a connection owner without closing, waits for process and
  mailbox convergence, then proves that a new connection remains usable.

The runner creates a unique temporary artifact directory and prints its path.
It contains the metadata-only `.beamtrace` container, a JSONL metadata export,
redacted strict-metadata qlog, a fixed environment summary, execution/export
logs, a clock self-check, and `summary.md`. It generates neither raw capture
nor pcap and uploads nothing.

BeamTrace v0.2.0 can expose a root call in the wall-clock domain while later
events use the monotonic domain. A patched local build normalizes this in the
target agent. The runner still checks that root, send, and receive timestamps
share one node-local domain and that root-relative durations are non-negative
and finite. On failure, the trace is retained for causal inspection, but the
summary explicitly disables timing and comparison.

To compare a reviewed, healthy baseline only when the clock check passes:

```sh
BEAMTRACE_COMPARE_BASELINE=/reviewed/good.beamtrace \
  mise run diagnose -- connection-isolation
```

Always review every selected artifact before attaching it to an issue.
Metadata traces and qlog can still contain diagnostic information even after
the fixed redaction checks. Never treat traced throughput or latency as the
516/344/812 performance gate; use the untraced benchmark tasks for that.

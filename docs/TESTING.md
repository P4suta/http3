# Testing

HTTP/3 combines protocol state machines, asynchronous messages, processes,
and UDP sockets. Tests must make failures reproducible and must leave the
runtime in a known state. This guide applies throughout implementation, not
only after a client or server API is complete.

## Development loop

Use Red-Green-Refactor for every behavior change:

1. **Red:** write the smallest test that describes the intended observable
   behavior and confirm that it fails for the expected reason.
2. **Green:** make the smallest implementation change that passes the new
   test and the existing suite.
3. **Refactor:** improve the implementation and test structure while keeping
   the suite green.

A bug fix must start with a regression test that reproduces the bug. Preserve
that test after the fix so the same failure cannot silently return. A test
that passes before the fix does not demonstrate the regression and must be
made more precise.

Documentation-only and configuration-only changes do not require invented
behavior tests, but they must still pass the complete local check.

## Verification layers

Every implementation change must exercise each applicable layer below. When
a layer is genuinely unaffected, record that fact in the change description
rather than adding a test with no useful assertion.

### For every implementation change

- Add pure unit tests for parsing, validation, limits, state transitions, and
  other deterministic logic.
- Test translation of backend events and failures into internal or public
  HTTP/3 events and errors. Raw backend atoms, maps, PIDs, references, and
  mailbox messages are test inputs below the adapter boundary, never public
  assertions.
- Exercise affected network behavior with a local loopback test over real UDP.
  An in-memory mock is useful for unit tests but does not replace this test.
- Run `mise run check` before considering the change complete.

A loopback request-response test must perform actual HTTP/3 work, use bounded
request and response bodies, and assert the response status, headers, and
body. Test-only certificate configuration may be used for a local fixture;
any verification bypass must remain in an explicitly named, test-only surface
and must not enter normal client configuration.

### At the end of each implementation phase

- Run interoperability tests against at least one independently implemented
  HTTP/3 peer. Pin or record the peer version so failures can be reproduced.
- Run the applicable conformance suite and retain the exact suite version and
  invocation.
- Run fault-injection scenarios relevant to the phase, including packet loss,
  reordering, malformed or unexpected events, peer termination, and resource
  exhaustion where applicable.

Using the same backend on both sides is valuable loopback coverage, but it is
not independent interoperability evidence.

### During performance work

- Use load tests to measure behavior under controlled concurrency and
  flow-control pressure.
- Use soak tests long enough to expose leaks, mailbox growth, and cleanup
  failures.
- Keep benchmarks reproducible: pin the toolchain and peer, record hardware
  and runtime settings, define payloads and concurrency, include warm-up and
  repeated trials, and retain raw results alongside summaries.

Performance claims must identify the benchmark procedure and uncertainty;
isolated best-case numbers are not sufficient.

## Timeouts

Every wait for a process, message, stream, connection, listener, or peer must
have a fixed upper bound. Do not use an unbounded receive or an arbitrary
sleep as synchronization. Prefer waiting for an observable readiness or
shutdown event, with a timeout that is long enough for supported CI systems
but short enough to make a stuck test fail promptly.

Timeouts are test failures, not successful cancellation. Include the
operation and relevant connection or stream identifier in the failure so the
blocked state can be diagnosed without rerunning the test interactively.

## Process and socket cleanup

Each fixture must have one clear owner for every process, connection, stream,
listener, and UDP socket that it creates. Register cleanup immediately after
acquiring a resource and run it even when setup, an assertion, or the test
body fails.

Cleanup must:

1. stop accepting new work;
2. cancel or close owned streams and connections;
3. close listeners and sockets;
4. wait, with a fixed timeout, for owned processes to terminate; and
5. fail the test if resources remain alive or cleanup reports an unexpected
   error.

Shutdown and cancellation paths must be idempotent. Tests should use
OS-assigned loopback ports rather than fixed shared ports, must not depend on
execution order, and must not leave messages that can affect a later test.

## Local completion check

Run the complete reproducible check from the repository root:

```sh
mise install
mise run check
```

This checks formatting, builds with warnings as errors, runs tests, builds all
configured documentation pages, and runs the source, Markdown, TOML, workflow,
spelling, and REUSE licence checks. The CI matrix additionally covers
Erlang/OTP 26 through 29 and smoke tests on Linux, macOS, and Windows.

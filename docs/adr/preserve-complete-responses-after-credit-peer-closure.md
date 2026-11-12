---
date: 2026-11-12
status: proposed
---

# Preserve complete responses after credit peer closure

## Context

An HTTP/2 peer can close after sending a complete response while body data remains buffered.
Returning receive credit invalidates the response if a closed peer rejects the write.
[RFC 9113](https://www.rfc-editor.org/rfc/rfc9113.html#section-5.2.1) defines credit as permission for future data on the connection.
Response completion remains determined by validated message framing.

## Decision

Preserve buffered data when validated completion precedes a typed transport closure during credit return.
Release the connection through its ownership guard without pooling it.
Keep incomplete responses, cancellation, deadlines, and other write failures as errors.

## Alternatives

Rejecting every credit failure loses complete responses after normal peer closure.
Ignoring every failure could conceal transport faults and reuse broken connections.
Skipping terminal updates leaves closure undetected before pool reuse.

## Consequences

Keep typed transport errors through the credit writer.
Reconsider if concurrent streams share the connection owner.

## Confirmation

Require socket tests for complete and incomplete responses, single release, and exclusion from the pool.
Run the exchange and client suites with their cancellation and timeout tests.
Owner review remains pending.

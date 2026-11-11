---
date: 2026-11-11
status: proposed
---

# Report cleanup failure after resource release

## Context

The recovered client reports cleanup failure as the logical exchange result while preserving a successful wire result.
A retained test instead expects logical success after cleanup timeout.
Immediate failure publication also precedes attempt completion when release races ahead.

## Decision

Preserve the recovered whole-exchange failure semantics.
Publish cleanup failure only after the attempt terminal and resource-release event.
Keep response bytes and the wire terminal independent of cleanup outcome.
Reject a later logical success after failure publication.

## Alternatives

Logical success after failed cleanup conceals an incomplete exchange lifecycle.
Immediate failure publication loses the required diagnostic event order.

## Consequences

Update the retained race test to require the typed cleanup failure after release.
The once-only logical terminal remains shared across attempts.
Reconsider if the public diagnostic contract defines logical completion as wire completion alone.

## Confirmation

Race, successful-upload, stalled-cleanup, and duplicate-terminal tests must pass.
Owner review remains pending.

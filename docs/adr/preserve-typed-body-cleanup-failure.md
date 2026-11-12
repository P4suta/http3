---
date: 2026-11-11
status: proposed
---

# Preserve typed body cleanup failure

## Context

HTTP/3 response cancellation receives a typed cleanup result, but its `Nil` callback kills itself on failure.
Body reports `Service` instead of the known timeout or cancellation cause.
Cancellation after response completion also needs the shared cleanup result after the request coordinator exits.

## Decision

Keep the public `from_pull` callback contract.
Add an internal constructor with a result callback and a closed scalar failure codec.
Successful cleanup still requires callback and controller joins.
Keep a known failure when release confirmation expires.
The separate release state stays pending until the registry observes controller termination.
Normal primary guardian termination keeps waiting for the delegated result within the original completion budget.
HTTP/3 shares the response cleanup result through completion and cancellation in one scalar cell.

## Alternatives

Keeping self-termination preserves generic failure but loses the observed cause.
Exposing native exceptions would widen the boundary and keep untrusted terms.

## Consequences

The private callback representation gains one variant.
No native failure text crosses the boundary.
Reconsider if another protocol needs more cleanup outcomes.

## Confirmation

Require typed timeout and cancellation regressions, ordinary callback compatibility, response disposal, and affected package checks.
Acceptance remains pending owner review.

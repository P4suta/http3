---
date: 2026-11-11
status: proposed
---

# Bound nested connection close by caller budget

## Context

The unified client's three-second lifecycle budget rejects healthy pooled connections during live close tests.
[RFC 9000](https://www.rfc-editor.org/rfc/rfc9000.html#section-10.2) distinguishes local closure from retained transport state.
Core success still requires confirmed cleanup and actor exit.

## Decision

Add an internal relative-budget close operation for the parent adapter.
Clamp the existing absolute plan once in the native clock domain.
Share one five-second deadline across unified lifecycle closure and resource release.
Reserve three quarters of a shorter nested budget for core completion.
Keep reply delivery within its existing bounded allowance.
Use the remaining protocol interval for graceful drain.
Keep standalone close unchanged.
Report a failed lifecycle join immediately while keeping unconfirmed resource charges quarantined.

## Alternatives

Keeping three seconds preserves latency but rejects the observed healthy closes.
Killing its owner without waiting can't prove nested cleanup.

## Consequences

A failed close can wait two more seconds for lifecycle termination.
A short budget can still report a typed timeout.
No phase may extend the clamped deadline.
Reconsider the allocation when live termination exceeds the five-second budget.

## Confirmation

Pure tests must verify clamping and invalid budgets.
Live pooled-client close and cleanup-failure tests must preserve truthful results.

---
date: 2026-11-11
status: proposed
---

# Limit bootstrap heaps by process role

## Context

The establishment group applies its 262,144-word resolver heap limit to the persistent client endpoint.
Live memory-pressure tests observe that endpoint exiting with `killed` during permitted sends after both controllers exited normally.
[OTP](https://www.erlang.org/doc/apps/erts/erlang.html#process_flag/2) counts collection workspace and optionally shared binaries, so heap limits differ from retained protocol bytes.

## Decision

Keep explicit heap limits on resolver callbacks, dial callbacks, and controllers.
Let persistent endpoints inherit the host VM's heap policy.
Keep links, monitors, finite admissions, absolute deadlines, and protocol limits.

## Alternatives

The uniform ceiling terminates valid workloads.
A larger fixed ceiling remains unrelated to endpoint configuration.
A public heap setting adds configuration before accounting covers the whole client.

## Consequences

The endpoint still lacks a memory bound across connections.
Reconsider when client-wide accounting defines a verified endpoint heap budget.

## Confirmation

Live pressure tests must preserve connections and recover released capacity.
Lifecycle tests must still join helpers after cancellation and controller heap exhaustion.
Owner review remains pending.

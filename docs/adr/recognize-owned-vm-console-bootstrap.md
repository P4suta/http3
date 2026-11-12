---
date: 2026-11-12
status: proposed
---

# Recognize owned virtual machine console bootstrap

## Context

An owned Windows Erlang VM validates its control results and exits successfully, but ConPTY records terminal initialization bytes.
The output checks require zero raw bytes and reject the healthy VM.
[OTP initializes its terminal driver even for a shell-free VM](https://github.com/erlang/otp/blob/OTP-29.1.2/lib/kernel/src/user_drv.erl).

## Decision

Accept empty output or the exact observed Windows bootstrap envelope with the pinned Erlang executable as its title.
Keep exit, process-tree, child-result, output-limit, and digest checks.
Preserve captured bytes and counts without removing terminal sequences.
Reject payload, a different title, and incomplete envelopes.

## Alternatives

Requiring zero raw bytes rejects the observed healthy console-attached VM.
Replacing ConPTY with ordinary pipes requires a separate console-isolation mechanism.
Removing arbitrary escape sequences could conceal child output.

## Consequences

The known bootstrap format becomes an explicit runtime contract.
A changed OTP or ConPTY envelope fails closed and requires review.

## Confirmation

Require controls for empty output, exact bootstrap, altered titles, truncated capture, and inserted payload.
Require live Windows empty and marked children and the isolated observer and multiplexing suites.
Owner review remains pending.

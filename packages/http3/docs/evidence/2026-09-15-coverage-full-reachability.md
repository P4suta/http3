# 2026-09-15 coverage-full reachability review

- Date: 2026-09-15
- Commit: d13064b plus this file
- Gleam: 1.18.1
- Erlang/OTP: 29.0.5
- mise: 2026.9.7
- Host: macOS 26.6.2 (Darwin 25.6.0) arm64, 18 cores, 48 GiB

Command:

    mise run coverage-full

This is not a new measurement. It is a review of what the
[2026-09-14 run](2026-09-14-coverage-full.md) left uncovered, written because
the answer changes what reaching the 95.00/90.00 thresholds would mean.

## What was reviewed

The 1742 uncovered clause alternatives that run reported were sampled module
by module, starting with `quic_core/internal/connection_state`, which holds
the largest single share of them. Each uncovered alternative was traced back
to the input that would reach it.

## Finding: some uncovered alternatives are unreachable by construction

`connection_state` builds its sub-state machines through thirteen sites of one
shape: call a constructor that returns a `Result`, and map its `Error` to
`InvalidConfiguration`. At five of those sites the constructor's arguments are
module constants, so the guard inside it cannot fail:

    fn create_rtt() -> Result(rtt.Estimator, Error) {
      case rtt.new(333) {
        Ok(estimator) -> Ok(estimator)
        Error(_) -> Error(InvalidConfiguration)
      }
    }

`rtt.new` returns `Error(InvalidInput)` only when its argument is not positive,
and 333 is a literal. The `Error` alternative here is not an untested path; it
is a path no input reaches. The same holds for `reassembler.new`,
`new_reno.new`, `cubic.new`, and `pacer.new` where each is called with only
module constants.

A second group is reachable in principle but not from outside the package.
`validate_client_config` refuses an empty application-protocol list and an
unsupported version, and both refusals sit behind the public setters
`with_application_protocols` and `with_version`, which already refuse the same
inputs. The inner refusal is defence in depth: it is what keeps the state
machine correct if a future caller reaches it another way, and it has no
current caller that can.

## What this means for the threshold

Both groups are deliberate. Neither is a defect, and removing either to raise a
percentage would make the code worse. A test written to reach one of them would
have to break the type system or the public API to do it, which is the opposite
of the mutation discipline the rest of the suite is held to: such a test would
pass against a broken implementation as readily as against a correct one.

So the 95.00/90.00 thresholds in `coverage-policy.json` were set before any
capture had ever completed, against an unmeasured denominator. Now that the
capture completes, the denominator includes alternatives that no test can
reach. This review does not say what the attainable ceiling is -- that needs
the same trace applied to all 1742, not to a sample -- and it does not change
the policy. It records that the gap between 65.26% and 90.00% is not all
missing tests, and that closing it by writing tests alone is not possible.

Nothing here is a reason to stop raising coverage. The reachable error and
boundary paths in the ten reported modules remain the work, and four batches of
them were added on this branch's base. It is a reason not to read the remaining
distance as a count of tests still owed.

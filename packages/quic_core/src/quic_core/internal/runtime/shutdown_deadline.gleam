//// Pure absolute-deadline plan for listener-owned connection fanout.

import gleam/int
import gleam/list

const maximum_milliseconds = 9_223_372_036_854_775_807

/// Invalid clock, timeout, cleanup tail, or actor count.
pub type Error {
  InvalidConfiguration
  DeadlineExpired
  DeadlineOutOfRange
}

/// One immutable listener cleanup window.
pub opaque type Plan {
  Plan(join_deadline_milliseconds: Int, final_deadline_milliseconds: Int)
}

/// Split one operation timeout into a normal join and a final forced-kill tail.
/// Both values are absolute and are calculated exactly once.
pub fn new(
  now_milliseconds: Int,
  timeout_milliseconds: Int,
  requested_cleanup_tail_milliseconds: Int,
) -> Result(Plan, Error) {
  case
    now_milliseconds >= 0
    && timeout_milliseconds > 0
    && requested_cleanup_tail_milliseconds >= 0
  {
    False -> Error(InvalidConfiguration)
    True -> {
      let deadline_milliseconds = now_milliseconds + timeout_milliseconds
      case deadline_milliseconds <= maximum_milliseconds {
        True ->
          Ok(build(
            now_milliseconds,
            timeout_milliseconds,
            requested_cleanup_tail_milliseconds,
          ))
        False -> Error(DeadlineOutOfRange)
      }
    }
  }
}

/// Split an injected future monotonic deadline without replacing or extending it.
/// A listener and every connection joiner consume this same boundary.
pub fn from_deadline(
  now_milliseconds: Int,
  deadline_milliseconds: Int,
  requested_cleanup_tail_milliseconds: Int,
) -> Result(Plan, Error) {
  case
    now_milliseconds >= 0
    && deadline_milliseconds >= 0
    && requested_cleanup_tail_milliseconds >= 0
  {
    False -> Error(InvalidConfiguration)
    True if deadline_milliseconds > maximum_milliseconds ->
      Error(DeadlineOutOfRange)
    True if deadline_milliseconds <= now_milliseconds -> Error(DeadlineExpired)
    True ->
      Ok(build(
        now_milliseconds,
        deadline_milliseconds - now_milliseconds,
        requested_cleanup_tail_milliseconds,
      ))
  }
}

/// Produce a finite plan even if a corrupted internal configuration reaches shutdown.
/// Runtime callers use this total form so cleanup never panics; the validating constructor remains available to deterministic probes.
pub fn bounded(
  now_milliseconds: Int,
  timeout_milliseconds: Int,
  requested_cleanup_tail_milliseconds: Int,
) -> Plan {
  build(
    int.max(0, now_milliseconds),
    int.max(1, timeout_milliseconds),
    int.max(0, requested_cleanup_tail_milliseconds),
  )
}

fn build(
  now_milliseconds: Int,
  timeout_milliseconds: Int,
  requested_cleanup_tail_milliseconds: Int,
) -> Plan {
  let final_deadline_milliseconds = now_milliseconds + timeout_milliseconds
  let cleanup_tail_milliseconds =
    int.min(timeout_milliseconds, requested_cleanup_tail_milliseconds)
  Plan(
    final_deadline_milliseconds - cleanup_tail_milliseconds,
    final_deadline_milliseconds,
  )
}

/// Absolute deadline shared by every normal termination join.
pub fn join_deadline_milliseconds(plan: Plan) -> Int {
  plan.join_deadline_milliseconds
}

/// Absolute boundary for forced-kill monitor convergence.
pub fn final_deadline_milliseconds(plan: Plan) -> Int {
  plan.final_deadline_milliseconds
}

/// Model the deadline handed to a fanout of any finite size.
/// This pure probe exists so regression tests can prove that connection count never turns one timeout into sequential `count * timeout` waiting.
pub fn fanout_deadlines(
  plan: Plan,
  connection_count: Int,
) -> Result(List(Int), Error) {
  case connection_count >= 0 {
    True ->
      Ok(list.repeat(join_deadline_milliseconds(plan), times: connection_count))
    False -> Error(InvalidConfiguration)
  }
}

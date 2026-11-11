//// Pure deadline contract for one client close and its diagnostic cleanup.

import gleam/int
import gleam/result

const maximum_milliseconds = 9_223_372_036_854_775_807

/// Invalid clock/allowance, an expired boundary, or an integer outside the portable non-negative deadline domain.
pub type Error {
  InvalidConfiguration
  DeadlineExpired
  DeadlineOutOfRange
}

/// Construct the one absolute boundary used by the default close operation.
/// The actor command, qlog flush, cleanup-owner join, and final result all consume this same window; no later phase recomputes or extends it.
pub fn from_allowances(
  now_milliseconds: Int,
  operation_milliseconds: Int,
  actor_reply_grace_milliseconds: Int,
  diagnostic_milliseconds: Int,
) -> Result(Int, Error) {
  case
    now_milliseconds >= 0
    && operation_milliseconds > 0
    && actor_reply_grace_milliseconds >= 0
    && diagnostic_milliseconds >= 0
  {
    False -> Error(InvalidConfiguration)
    True -> {
      let deadline =
        now_milliseconds
        + operation_milliseconds
        + actor_reply_grace_milliseconds
        + diagnostic_milliseconds
      case deadline <= maximum_milliseconds {
        True -> Ok(deadline)
        False -> Error(DeadlineOutOfRange)
      }
    }
  }
}

/// Validate an injected absolute deadline in the runtime monotonic domain.
/// A boundary equal to the current sample has already expired.
pub fn validate(
  now_milliseconds: Int,
  deadline_milliseconds: Int,
) -> Result(Nil, Error) {
  case now_milliseconds < 0 || deadline_milliseconds < 0 {
    True -> Error(InvalidConfiguration)
    False if deadline_milliseconds > maximum_milliseconds ->
      Error(DeadlineOutOfRange)
    False if deadline_milliseconds <= now_milliseconds -> Error(DeadlineExpired)
    False -> Ok(Nil)
  }
}

/// Remaining milliseconds without creating a replacement deadline.
pub fn remaining(
  now_milliseconds: Int,
  deadline_milliseconds: Int,
) -> Result(Int, Error) {
  use _ <- result.try(validate(now_milliseconds, deadline_milliseconds))
  Ok(deadline_milliseconds - now_milliseconds)
}

/// Reserve a forced actor-join tail inside an existing absolute boundary.
/// When less than the requested tail remains, forcing begins at `now`; this helper never creates a later deadline.
pub fn force_join_at(
  now_milliseconds: Int,
  deadline_milliseconds: Int,
  requested_tail_milliseconds: Int,
) -> Result(Int, Error) {
  case requested_tail_milliseconds < 0 {
    True -> Error(InvalidConfiguration)
    False -> {
      use _ <- result.try(validate(now_milliseconds, deadline_milliseconds))
      Ok(int.max(
        now_milliseconds,
        deadline_milliseconds - requested_tail_milliseconds,
      ))
    }
  }
}

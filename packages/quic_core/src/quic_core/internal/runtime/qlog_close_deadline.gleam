//// Pure absolute-deadline rules for confirmed qlog shutdown.

import gleam/int

const maximum_milliseconds = 9_223_372_036_854_775_807

/// Why a qlog close boundary cannot be used.
pub type Error {
  InvalidConfiguration
  DeadlineExpired
  DeadlineOutOfRange
}

/// Clamp an existing absolute deadline to the native qlog allowance.
///
/// The returned value is never later than `deadline_milliseconds`.
/// Sampling a later `now_milliseconds` therefore shortens or expires the operation; a scheduler stall can never rebase the caller's boundary.
pub fn effective(
  now_milliseconds: Int,
  deadline_milliseconds: Int,
  native_allowance_milliseconds: Int,
) -> Result(Int, Error) {
  case
    now_milliseconds >= 0
    && now_milliseconds <= maximum_milliseconds
    && native_allowance_milliseconds > 0
    && native_allowance_milliseconds <= maximum_milliseconds
  {
    False -> Error(InvalidConfiguration)
    True if deadline_milliseconds < 0 -> Error(InvalidConfiguration)
    True if deadline_milliseconds > maximum_milliseconds ->
      Error(DeadlineOutOfRange)
    True if deadline_milliseconds <= now_milliseconds -> Error(DeadlineExpired)
    True -> {
      let native_deadline = case
        native_allowance_milliseconds <= maximum_milliseconds - now_milliseconds
      {
        True -> now_milliseconds + native_allowance_milliseconds
        False -> maximum_milliseconds
      }
      Ok(int.min(deadline_milliseconds, native_deadline))
    }
  }
}

/// Build the compatibility relative-time boundary once at its API entrance.
/// New lifecycle code should retain and pass an absolute deadline instead.
pub fn from_remaining(
  now_milliseconds: Int,
  remaining_milliseconds: Int,
  native_allowance_milliseconds: Int,
) -> Result(Int, Error) {
  case
    now_milliseconds >= 0
    && now_milliseconds <= maximum_milliseconds
    && remaining_milliseconds > 0
    && native_allowance_milliseconds > 0
    && native_allowance_milliseconds <= maximum_milliseconds
  {
    False -> Error(InvalidConfiguration)
    True -> {
      let share = int.min(remaining_milliseconds, native_allowance_milliseconds)
      case share <= maximum_milliseconds - now_milliseconds {
        True -> Ok(now_milliseconds + share)
        False -> Error(DeadlineOutOfRange)
      }
    }
  }
}

//// PATH_CHALLENGE/PATH_RESPONSE validation with a fixed deadline.

import gleam/bit_array
import gleam/option.{type Option, None, Some}

/// Path validation progress.
pub type Phase {
  Idle
  Validating
  Validated
  Failed
}

/// One outstanding challenge per candidate path.
pub opaque type Validator {
  Validator(
    phase: Phase,
    challenge: Option(BitArray),
    deadline_milliseconds: Int,
  )
}

/// Invalid challenge/timing or a failed validation transition.
pub type Error {
  InvalidInput
  UnexpectedState
  ChallengeMismatch
  ValidationTimedOut
}

/// Create an idle candidate-path validator.
pub fn new() -> Validator {
  Validator(Idle, None, 0)
}

/// Start validation with an exact 8-byte unpredictable challenge.
pub fn start(
  validator: Validator,
  challenge: BitArray,
  now_milliseconds: Int,
  timeout_milliseconds: Int,
) -> Result(Validator, Error) {
  case
    validator.phase == Validating,
    bit_array.bit_size(challenge) == 64
    && now_milliseconds >= 0
    && timeout_milliseconds > 0
  {
    True, _ -> Error(UnexpectedState)
    _, False -> Error(InvalidInput)
    _, True ->
      Ok(Validator(
        Validating,
        Some(challenge),
        now_milliseconds + timeout_milliseconds,
      ))
  }
}

/// Authenticate a PATH_RESPONSE on the same candidate path before deadline.
pub fn receive_response(
  validator: Validator,
  response: BitArray,
  now_milliseconds: Int,
) -> Result(Validator, Error) {
  case validator.phase, validator.challenge {
    Validating, Some(_) if now_milliseconds >= validator.deadline_milliseconds ->
      Error(ValidationTimedOut)
    Validating, Some(challenge) ->
      case response == challenge {
        True -> Ok(Validator(Validated, None, 0))
        False -> Error(ChallengeMismatch)
      }
    _, _ -> Error(UnexpectedState)
  }
}

/// Mark a validation attempt failed once its fixed deadline elapses.
pub fn on_timeout(validator: Validator, now_milliseconds: Int) -> Validator {
  case
    validator.phase == Validating
    && now_milliseconds >= validator.deadline_milliseconds
  {
    True -> Validator(Failed, None, 0)
    False -> validator
  }
}

/// Return validation progress without exposing the challenge bytes.
pub fn phase(validator: Validator) -> Phase {
  validator.phase
}

/// Return the fixed validation deadline while a challenge is outstanding.
pub fn deadline(validator: Validator) -> Option(Int) {
  case validator.phase {
    Validating -> Some(validator.deadline_milliseconds)
    Idle | Validated | Failed -> None
  }
}

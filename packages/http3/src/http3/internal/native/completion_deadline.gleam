//// Pure deadline contract spanning protocol drain and bounded core cleanup.

import gleam/int

const maximum_milliseconds = 9_223_372_036_854_775_807

/// Invalid clock or non-finite phase allowance.
pub type Error {
  InvalidConfiguration
}

/// One immutable close attempt.
/// The protocol boundary is sent to the HTTP/3 actor; the completion boundary is retained by its caller while core qlog and listener cleanup finish.
pub opaque type Plan {
  Plan(
    started_milliseconds: Int,
    protocol_deadline_milliseconds: Int,
    completion_deadline_milliseconds: Int,
    caller_deadline_milliseconds: Int,
  )
}

/// Calculate both absolute boundaries once from injected monotonic time.
pub fn new(
  now_milliseconds: Int,
  protocol_timeout_milliseconds: Int,
  core_completion_allowance_milliseconds: Int,
  reply_grace_milliseconds: Int,
) -> Result(Plan, Error) {
  case
    now_milliseconds >= 0
    && protocol_timeout_milliseconds > 0
    && core_completion_allowance_milliseconds >= 0
    && reply_grace_milliseconds >= 0
  {
    False -> Error(InvalidConfiguration)
    True -> {
      let protocol_deadline_milliseconds =
        now_milliseconds + protocol_timeout_milliseconds
      let completion_deadline_milliseconds =
        protocol_deadline_milliseconds + core_completion_allowance_milliseconds
      let caller_deadline_milliseconds =
        completion_deadline_milliseconds + reply_grace_milliseconds
      case caller_deadline_milliseconds <= maximum_milliseconds {
        True ->
          Ok(Plan(
            now_milliseconds,
            protocol_deadline_milliseconds,
            completion_deadline_milliseconds,
            caller_deadline_milliseconds,
          ))
        False -> Error(InvalidConfiguration)
      }
    }
  }
}

/// Clamp a plan to a parent budget while reserving cleanup and reply intervals.
pub fn limit(
  plan: Plan,
  maximum_wait_milliseconds: Int,
) -> Result(Plan, Error) {
  let original_wait = total_wait_milliseconds(plan)
  case
    maximum_wait_milliseconds < 4
    || maximum_wait_milliseconds
    > maximum_milliseconds - plan.started_milliseconds
  {
    True -> Error(InvalidConfiguration)
    False if maximum_wait_milliseconds >= original_wait -> Ok(plan)
    False -> {
      let caller = plan.started_milliseconds + maximum_wait_milliseconds
      let reply =
        int.min(
          plan.caller_deadline_milliseconds
            - plan.completion_deadline_milliseconds,
          maximum_wait_milliseconds / 4,
        )
      let completion = caller - reply
      let core =
        int.min(
          plan.completion_deadline_milliseconds
            - plan.protocol_deadline_milliseconds,
          int.min(
            maximum_wait_milliseconds / 4 * 3,
            completion - plan.started_milliseconds - 1,
          ),
        )
      Ok(Plan(
        plan.started_milliseconds,
        int.min(plan.protocol_deadline_milliseconds, completion - core),
        completion,
        caller,
      ))
    }
  }
}

/// Absolute boundary for GOAWAY and application/transport convergence.
pub fn protocol_deadline_milliseconds(plan: Plan) -> Int {
  plan.protocol_deadline_milliseconds
}

/// Absolute boundary shared with bounded core completion.
///
/// Reply grace is deliberately outside this boundary.
/// It covers only delivery of the already-decided typed result back to the caller and cannot extend protocol, qlog, listener, or actor cleanup.
pub fn completion_deadline_milliseconds(plan: Plan) -> Int {
  plan.completion_deadline_milliseconds
}

/// Absolute boundary for delivery of the already-decided close result.
/// Cleanup cannot consume this final reply-only grace.
pub fn caller_deadline_milliseconds(plan: Plan) -> Int {
  plan.caller_deadline_milliseconds
}

/// Relative selector wait through completion plus bounded reply delivery.
pub fn total_wait_milliseconds(plan: Plan) -> Int {
  plan.caller_deadline_milliseconds - plan.started_milliseconds
}

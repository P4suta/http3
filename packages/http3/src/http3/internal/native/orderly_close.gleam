//// Deterministic RFC 9114 orderly-termination barrier.
////
//// HTTP/3 role state owns the two GOAWAY identifiers.
//// This module owns the causal boundary after those identifiers have been selected: both GOAWAY frames must be queued in order, accepted application work must become terminal, and every queued transport byte must be acknowledged before the connection can use the exact H3_NO_ERROR application close code.

import gleam/int
import gleam/option.{type Option, None, Some}
import gleam/result
import http3/internal/varint

/// Endpoint role, used to validate the wire type of each GOAWAY identifier.
pub type Role {
  Client
  Server
}

/// One payload-free step visible to deterministic probes.
pub type Step {
  InitialGoAway(identifier: Int)
  FinalGoAway(identifier: Int)
  AwaitApplication(remaining_milliseconds: Int)
  AwaitTransport(remaining_milliseconds: Int)
  CloseWithNoError(application_error_code: Int)
  AbortAfterDeadline
}

/// Result of sampling the application and transport barriers.
pub type Decision {
  Continue(State, Step)
  Close(State, Step)
  Abort(State, Step)
}

/// A finite, monotonic, two-stage close state.
pub opaque type State {
  State(
    role: Role,
    deadline_milliseconds: Int,
    refine_not_before_milliseconds: Int,
    last_observed_milliseconds: Int,
    initial_identifier: Option(Int),
    final_identifier: Option(Int),
    ready_to_close: Bool,
    closed: Bool,
  )
}

/// Invalid time, ordering, role-specific identifier, or close code.
pub type Error {
  InvalidConfiguration
  ClockMovedBackwards
  InitialGoAwayMissing
  FinalGoAwayMissing
  DuplicateInitialGoAway
  DuplicateFinalGoAway
  RefinementTooEarly(remaining_milliseconds: Int)
  RefinementDeadlineReached
  InvalidGoAwayIdentifier(Int)
  IncreasingGoAwayIdentifier
  NotReadyToClose
  InvalidCloseCode(Int)
  AlreadyClosed
}

/// Registered HTTP/3 application close used only after orderly convergence.
pub const h3_no_error = 0x100

/// Choose the immutable second-GOAWAY instant within one absolute drain window.
/// A drain window must leave at least one millisecond before its terminal boundary; otherwise it cannot provide a genuine peer-arrival interval and must use the bounded abort path.
pub fn refinement_not_before(
  now_milliseconds: Int,
  deadline_milliseconds: Int,
  delay_milliseconds: Int,
) -> Result(Int, Error) {
  case
    now_milliseconds >= 0
    && delay_milliseconds > 0
    && deadline_milliseconds > now_milliseconds + 1
  {
    True ->
      Ok(int.min(
        now_milliseconds + delay_milliseconds,
        deadline_milliseconds - 1,
      ))
    False -> Error(InvalidConfiguration)
  }
}

/// The largest legal first-stage GOAWAY for one endpoint role.
pub fn initial_goaway_identifier(role: Role) -> Int {
  case role {
    // A server GOAWAY carries a client-initiated bidirectional stream ID.
    Server -> varint.maximum - 3
    // A client GOAWAY carries a Push ID.
    Client -> varint.maximum
  }
}

/// Create one close attempt with immutable absolute refinement and terminal deadlines.
/// Callers calculate `refine_not_before_milliseconds` once; later arrivals can change the final identifier but can never extend either time.
pub fn new(
  role: Role,
  now_milliseconds: Int,
  timeout_milliseconds: Int,
  refine_not_before_milliseconds: Int,
) -> Result(State, Error) {
  let deadline_milliseconds = now_milliseconds + timeout_milliseconds
  case
    now_milliseconds >= 0
    && timeout_milliseconds > 0
    && refine_not_before_milliseconds > now_milliseconds
    && refine_not_before_milliseconds < deadline_milliseconds
  {
    True ->
      Ok(State(
        role:,
        deadline_milliseconds:,
        refine_not_before_milliseconds:,
        last_observed_milliseconds: now_milliseconds,
        initial_identifier: None,
        final_identifier: None,
        ready_to_close: False,
        closed: False,
      ))
    False -> Error(InvalidConfiguration)
  }
}

/// Record that the role-correct first GOAWAY was queued.
pub fn initial_queued(
  state: State,
  identifier: Int,
) -> Result(#(State, Step), Error) {
  use _ <- result.try(require_open(state))
  case state.initial_identifier {
    Some(_) -> Error(DuplicateInitialGoAway)
    None -> {
      use _ <- result.try(
        case identifier == initial_goaway_identifier(state.role) {
          True -> Ok(Nil)
          False -> Error(InvalidGoAwayIdentifier(identifier))
        },
      )
      Ok(#(
        State(..state, initial_identifier: Some(identifier)),
        InitialGoAway(identifier),
      ))
    }
  }
}

/// Record that the smaller, role-correct final GOAWAY was queued.
pub fn final_queued(
  state: State,
  identifier: Int,
  now_milliseconds: Int,
) -> Result(#(State, Step), Error) {
  use _ <- result.try(require_open(state))
  use _ <- result.try(validate_clock(state, now_milliseconds))
  use _ <- result.try(case now_milliseconds >= state.deadline_milliseconds {
    True -> Error(RefinementDeadlineReached)
    False -> Ok(Nil)
  })
  use _ <- result.try(
    case now_milliseconds >= state.refine_not_before_milliseconds {
      True -> Ok(Nil)
      False ->
        Error(RefinementTooEarly(
          state.refine_not_before_milliseconds - now_milliseconds,
        ))
    },
  )
  use initial <- result.try(case state.initial_identifier {
    Some(identifier) -> Ok(identifier)
    None -> Error(InitialGoAwayMissing)
  })
  use _ <- result.try(case state.final_identifier {
    Some(_) -> Error(DuplicateFinalGoAway)
    None -> Ok(Nil)
  })
  use _ <- result.try(validate_identifier(state.role, identifier))
  use _ <- result.try(case identifier <= initial {
    True -> Ok(Nil)
    False -> Error(IncreasingGoAwayIdentifier)
  })
  Ok(#(
    State(
      ..state,
      final_identifier: Some(identifier),
      last_observed_milliseconds: now_milliseconds,
    ),
    FinalGoAway(identifier),
  ))
}

/// Sample application completion and transport acknowledgement at one injected monotonic time.
/// The original deadline is never recomputed by later samples.
/// A sample at the deadline belongs to the bounded abort path.
pub fn observe(
  state: State,
  now_milliseconds: Int,
  application_settled: Bool,
  transport_flushed: Bool,
) -> Result(Decision, Error) {
  use _ <- result.try(require_open(state))
  use _ <- result.try(case state.final_identifier {
    Some(_) -> Ok(Nil)
    None -> Error(FinalGoAwayMissing)
  })
  use _ <- result.try(validate_clock(state, now_milliseconds))
  let state = State(..state, last_observed_milliseconds: now_milliseconds)
  case now_milliseconds >= state.deadline_milliseconds {
    True -> Ok(Abort(state, AbortAfterDeadline))
    False if !application_settled ->
      Ok(Continue(
        state,
        AwaitApplication(state.deadline_milliseconds - now_milliseconds),
      ))
    False if !transport_flushed ->
      Ok(Continue(
        state,
        AwaitTransport(state.deadline_milliseconds - now_milliseconds),
      ))
    False -> {
      let state = State(..state, ready_to_close: True)
      Ok(Close(state, CloseWithNoError(h3_no_error)))
    }
  }
}

/// Confirm the exact application code only after both barriers converged.
pub fn confirm_closed(state: State, code: Int) -> Result(State, Error) {
  use _ <- result.try(require_open(state))
  use _ <- result.try(case state.ready_to_close {
    True -> Ok(Nil)
    False -> Error(NotReadyToClose)
  })
  use _ <- result.try(case code == h3_no_error {
    True -> Ok(Nil)
    False -> Error(InvalidCloseCode(code))
  })
  Ok(State(..state, closed: True))
}

/// Immutable deadline used by actor selectors and audit probes.
pub fn deadline_milliseconds(state: State) -> Int {
  state.deadline_milliseconds
}

/// Earliest monotonic instant at which the second GOAWAY may be selected.
/// Actors include this absolute value in their selector instead of polling or extending it after traffic arrives.
pub fn refine_not_before_milliseconds(state: State) -> Int {
  state.refine_not_before_milliseconds
}

/// Whether the second GOAWAY was selected and queued.
pub fn final_goaway_queued(state: State) -> Bool {
  case state.final_identifier {
    Some(_) -> True
    None -> False
  }
}

fn validate_identifier(role: Role, identifier: Int) -> Result(Nil, Error) {
  case role {
    Client if identifier >= 0 && identifier <= varint.maximum -> Ok(Nil)
    Server
      if identifier >= 0 && identifier <= varint.maximum && identifier % 4 == 0
    -> Ok(Nil)
    _ -> Error(InvalidGoAwayIdentifier(identifier))
  }
}

fn require_open(state: State) -> Result(Nil, Error) {
  case state.closed {
    True -> Error(AlreadyClosed)
    False -> Ok(Nil)
  }
}

fn validate_clock(state: State, now_milliseconds: Int) -> Result(Nil, Error) {
  case now_milliseconds >= state.last_observed_milliseconds {
    True -> Ok(Nil)
    False -> Error(ClockMovedBackwards)
  }
}

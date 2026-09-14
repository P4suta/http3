//// RFC 9114 GOAWAY and deterministic graceful-drain coordination.

import gleam/list
import gleam/option.{type Option, None, Some}
import gleam/result
import http3/internal/varint

/// Role of this endpoint on the HTTP/3 connection.
pub type Role {
  Client
  Server
}

/// Observable graceful-shutdown phase.
pub type Phase {
  Open
  PeerGoAway
  LocalGoAway
  BidirectionalGoAway
  ReadyToClose
  Closed
}

/// Accepted or explicitly rejected peer-initiated work.
pub type Acceptance {
  Accepted(State)
  Rejected(State, identifier: Int)
}

/// Result of receiving or refining GOAWAY. Rejected identifiers are safe to
/// retry on another connection or must be cancelled at the transport layer.
pub type GoAwayOutcome {
  GoAwayOutcome(state: State, rejected: List(Int))
}

/// Timer outcome for deterministic graceful shutdown.
pub type TimerOutcome {
  Draining(State)
  DrainReady(State)
  DrainTimedOut(State, cancelled: List(Int))
}

/// GOAWAY cutoffs, active work, and a fixed local drain deadline.
pub opaque type State {
  State(
    role: Role,
    local_goaway: Option(Int),
    peer_goaway: Option(Int),
    active_requests: List(Int),
    active_pushes: List(Int),
    maximum_active: Int,
    drain_timeout_ms: Int,
    drain_deadline_ms: Option(Int),
    ready: Bool,
    closed: Bool,
  )
}

/// Invalid role, identifier, ordering, count, clock, or lifecycle use.
pub type Error {
  InvalidConfiguration
  InvalidTime
  InvalidRequestId(Int)
  InvalidPushId(Int)
  WrongRole
  NewWorkAfterGoAway
  IncreasingGoAwayIdentifier
  DuplicateIdentifier(Int)
  MissingIdentifier(Int)
  ActiveLimitExceeded(Int)
  AlreadyClosed
}

/// Create an open connection drain model.
pub fn new(
  role: Role,
  maximum_active: Int,
  drain_timeout_ms: Int,
) -> Result(State, Error) {
  case maximum_active > 0 && drain_timeout_ms > 0 {
    True ->
      Ok(State(
        role,
        None,
        None,
        [],
        [],
        maximum_active,
        drain_timeout_ms,
        None,
        False,
        False,
      ))
    False -> Error(InvalidConfiguration)
  }
}

/// Track a request newly initiated by this client.
pub fn open_request(state: State, stream_id: Int) -> Result(State, Error) {
  use _ <- result.try(require_open(state))
  use _ <- result.try(case state.role {
    Client -> Ok(Nil)
    Server -> Error(WrongRole)
  })
  use _ <- result.try(validate_request_id(stream_id))
  case state.peer_goaway {
    Some(_) -> Error(NewWorkAfterGoAway)
    None -> insert_request(state, stream_id)
  }
}

/// Accept or reject a request stream arriving at this server after local
/// GOAWAY. Rejected work is never inserted into the active set.
pub fn receive_request(
  state: State,
  stream_id: Int,
) -> Result(Acceptance, Error) {
  use _ <- result.try(require_open(state))
  use _ <- result.try(case state.role {
    Server -> Ok(Nil)
    Client -> Error(WrongRole)
  })
  use _ <- result.try(validate_request_id(stream_id))
  case state.local_goaway {
    Some(cutoff) if stream_id >= cutoff -> Ok(Rejected(state, stream_id))
    _ -> {
      use state <- result.try(insert_request(state, stream_id))
      Ok(Accepted(state))
    }
  }
}

/// Track a push newly promised by this server.
pub fn promise_push(state: State, push_id: Int) -> Result(State, Error) {
  use _ <- result.try(require_open(state))
  use _ <- result.try(case state.role {
    Server -> Ok(Nil)
    Client -> Error(WrongRole)
  })
  use _ <- result.try(validate_push_id(push_id))
  case state.peer_goaway {
    Some(_) -> Error(NewWorkAfterGoAway)
    None -> insert_push(state, push_id)
  }
}

/// Accept or reject a pushed response arriving at this client after local
/// GOAWAY.
pub fn receive_push(state: State, push_id: Int) -> Result(Acceptance, Error) {
  use _ <- result.try(require_open(state))
  use _ <- result.try(case state.role {
    Client -> Ok(Nil)
    Server -> Error(WrongRole)
  })
  use _ <- result.try(validate_push_id(push_id))
  case state.local_goaway {
    Some(cutoff) if push_id >= cutoff -> Ok(Rejected(state, push_id))
    _ -> {
      use state <- result.try(insert_push(state, push_id))
      Ok(Accepted(state))
    }
  }
}

/// Mark one active request stream complete or reset.
pub fn complete_request(state: State, stream_id: Int) -> Result(State, Error) {
  case list.contains(state.active_requests, stream_id) {
    False -> Error(MissingIdentifier(stream_id))
    True ->
      Ok(mark_ready(
        State(
          ..state,
          active_requests: list.filter(state.active_requests, fn(value) {
            value != stream_id
          }),
        ),
      ))
  }
}

/// Mark one active Push ID complete or cancelled.
pub fn complete_push(state: State, push_id: Int) -> Result(State, Error) {
  case list.contains(state.active_pushes, push_id) {
    False -> Error(MissingIdentifier(push_id))
    True ->
      Ok(mark_ready(
        State(
          ..state,
          active_pushes: list.filter(state.active_pushes, fn(value) {
            value != push_id
          }),
        ),
      ))
  }
}

/// Receive a monotonic GOAWAY from the peer and detach every locally initiated
/// request/push at or above its first-rejected cutoff.
pub fn receive_goaway(
  state: State,
  identifier: Int,
) -> Result(GoAwayOutcome, Error) {
  use _ <- result.try(require_open(state))
  use _ <- result.try(validate_peer_goaway(state.role, identifier))
  use _ <- result.try(validate_non_increasing(state.peer_goaway, identifier))
  let #(requests, pushes, rejected) = case state.role {
    Client -> {
      let #(kept, rejected) = partition_at(state.active_requests, identifier)
      #(kept, state.active_pushes, rejected)
    }
    Server -> {
      let #(kept, rejected) = partition_at(state.active_pushes, identifier)
      #(state.active_requests, kept, rejected)
    }
  }
  Ok(GoAwayOutcome(
    State(
      ..state,
      peer_goaway: Some(identifier),
      active_requests: requests,
      active_pushes: pushes,
    ),
    rejected,
  ))
}

/// Begin graceful shutdown with the maximum legal cutoff so in-flight work
/// can converge before a refined GOAWAY is sent.
pub fn start(state: State, now_ms: Int) -> Result(#(State, Int), Error) {
  use _ <- result.try(require_open(state))
  use _ <- result.try(validate_time(now_ms))
  let identifier = case state.role {
    Server -> varint.maximum - 3
    Client -> varint.maximum
  }
  use _ <- result.try(validate_non_increasing(state.local_goaway, identifier))
  let state =
    mark_ready(
      State(
        ..state,
        local_goaway: Some(identifier),
        drain_deadline_ms: Some(now_ms + state.drain_timeout_ms),
      ),
    )
  Ok(#(state, identifier))
}

/// Send a smaller final cutoff and return active peer work now rejected by it.
pub fn refine(state: State, identifier: Int) -> Result(GoAwayOutcome, Error) {
  use _ <- result.try(require_open(state))
  use _ <- result.try(validate_local_goaway(state.role, identifier))
  use _ <- result.try(validate_non_increasing(state.local_goaway, identifier))
  let #(requests, pushes, rejected) = case state.role {
    Server -> {
      let #(kept, rejected) = partition_at(state.active_requests, identifier)
      #(kept, state.active_pushes, rejected)
    }
    Client -> {
      let #(kept, rejected) = partition_at(state.active_pushes, identifier)
      #(state.active_requests, kept, rejected)
    }
  }
  let state =
    mark_ready(
      State(
        ..state,
        local_goaway: Some(identifier),
        active_requests: requests,
        active_pushes: pushes,
      ),
    )
  Ok(GoAwayOutcome(state, rejected))
}

/// Evaluate the fixed drain deadline and return transport identifiers that
/// must be cancelled if time expired.
pub fn on_timer(state: State, now_ms: Int) -> Result(TimerOutcome, Error) {
  use _ <- result.try(require_open(state))
  use _ <- result.try(validate_time(now_ms))
  case state.ready, state.drain_deadline_ms {
    True, _ -> Ok(DrainReady(state))
    False, None -> Ok(Draining(state))
    False, Some(deadline) if now_ms < deadline -> Ok(Draining(state))
    False, Some(_) -> {
      let cancelled = local_relevant_active(state)
      let state =
        State(
          ..state,
          active_requests: case state.role {
            Server -> []
            Client -> state.active_requests
          },
          active_pushes: case state.role {
            Client -> []
            Server -> state.active_pushes
          },
          ready: True,
        )
      Ok(DrainTimedOut(state, cancelled))
    }
  }
}

/// Record deterministic QUIC application close after drain convergence.
pub fn close(state: State) -> Result(State, Error) {
  case state.closed {
    True -> Ok(state)
    False -> Ok(State(..state, ready: True, closed: True))
  }
}

/// Current externally observable shutdown phase.
pub fn phase(state: State) -> Phase {
  case state.closed, state.ready, state.local_goaway, state.peer_goaway {
    True, _, _, _ -> Closed
    _, True, _, _ -> ReadyToClose
    _, _, Some(_), Some(_) -> BidirectionalGoAway
    _, _, Some(_), None -> LocalGoAway
    _, _, None, Some(_) -> PeerGoAway
    _, _, None, None -> Open
  }
}

fn insert_request(state: State, stream_id: Int) -> Result(State, Error) {
  use _ <- result.try(ensure_insertable(state, stream_id, state.active_requests))
  Ok(State(..state, active_requests: [stream_id, ..state.active_requests]))
}

fn insert_push(state: State, push_id: Int) -> Result(State, Error) {
  use _ <- result.try(ensure_insertable(state, push_id, state.active_pushes))
  Ok(State(..state, active_pushes: [push_id, ..state.active_pushes]))
}

fn ensure_insertable(
  state: State,
  identifier: Int,
  active: List(Int),
) -> Result(Nil, Error) {
  case list.contains(active, identifier), total_active(state) {
    True, _ -> Error(DuplicateIdentifier(identifier))
    False, count if count >= state.maximum_active ->
      Error(ActiveLimitExceeded(state.maximum_active))
    False, _ -> Ok(Nil)
  }
}

fn total_active(state: State) -> Int {
  list.length(state.active_requests) + list.length(state.active_pushes)
}

fn mark_ready(state: State) -> State {
  case state.local_goaway, local_relevant_active(state) {
    Some(_), [] -> State(..state, ready: True)
    _, _ -> state
  }
}

fn local_relevant_active(state: State) -> List(Int) {
  case state.role {
    Server -> state.active_requests
    Client -> state.active_pushes
  }
}

fn partition_at(values: List(Int), cutoff: Int) -> #(List(Int), List(Int)) {
  partition_values(values, cutoff, [], [])
}

fn partition_values(
  values: List(Int),
  cutoff: Int,
  kept: List(Int),
  rejected: List(Int),
) -> #(List(Int), List(Int)) {
  case values {
    [] -> #(list.reverse(kept), list.reverse(rejected))
    [value, ..rest] if value >= cutoff ->
      partition_values(rest, cutoff, kept, [value, ..rejected])
    [value, ..rest] -> partition_values(rest, cutoff, [value, ..kept], rejected)
  }
}

fn validate_peer_goaway(role: Role, identifier: Int) -> Result(Nil, Error) {
  case role {
    Client -> validate_request_id(identifier)
    Server -> validate_push_id(identifier)
  }
}

fn validate_local_goaway(role: Role, identifier: Int) -> Result(Nil, Error) {
  case role {
    Server -> validate_request_id(identifier)
    Client -> validate_push_id(identifier)
  }
}

fn validate_request_id(identifier: Int) -> Result(Nil, Error) {
  case identifier >= 0 && identifier <= varint.maximum && identifier % 4 == 0 {
    True -> Ok(Nil)
    False -> Error(InvalidRequestId(identifier))
  }
}

fn validate_push_id(identifier: Int) -> Result(Nil, Error) {
  case identifier >= 0 && identifier <= varint.maximum {
    True -> Ok(Nil)
    False -> Error(InvalidPushId(identifier))
  }
}

fn validate_non_increasing(
  previous: Option(Int),
  identifier: Int,
) -> Result(Nil, Error) {
  case previous {
    Some(value) if identifier > value -> Error(IncreasingGoAwayIdentifier)
    _ -> Ok(Nil)
  }
}

fn validate_time(now_ms: Int) -> Result(Nil, Error) {
  case now_ms >= 0 {
    True -> Ok(Nil)
    False -> Error(InvalidTime)
  }
}

fn require_open(state: State) -> Result(Nil, Error) {
  case state.closed {
    True -> Error(AlreadyClosed)
    False -> Ok(Nil)
  }
}

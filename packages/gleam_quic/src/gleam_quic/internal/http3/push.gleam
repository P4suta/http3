//// Bounded RFC 9114 server-push promise and stream coordination.

import gleam/dict.{type Dict}
import gleam/list
import gleam/option.{type Option, None, Some}
import gleam/result
import gleam_quic/internal/http3/header_semantics
import gleam_quic/internal/qpack/header.{type Header}
import gleam_quic/varint

/// Observable lifecycle of one Push ID.
pub type Status {
  Promised
  StreamPendingPromise
  Open
  Cancelled
  Complete
}

/// Snapshot used by connection orchestration and application events.
pub type Push {
  Push(
    push_id: Int,
    request_fields: Option(List(Header)),
    associated_request_streams: List(Int),
    push_stream_id: Option(Int),
    status: Status,
  )
}

type StoredPush {
  StoredPush(
    request_fields: Option(List(Header)),
    associated_request_streams: List(Int),
    push_stream_id: Option(Int),
    status: Status,
    promise_deadline_ms: Option(Int),
  )
}

/// Push-ID allowance, sequential allocator, and bounded active entries.
pub opaque type State {
  State(
    maximum_push_id: Option(Int),
    next_push_id: Int,
    pushes: Dict(Int, StoredPush),
    maximum_tracked_pushes: Int,
    promise_wait_timeout_ms: Int,
  )
}

/// Invalid ID, unsafe promise, inconsistent duplicate, timeout, or bound.
pub type Error {
  InvalidConfiguration
  PushIdDecreased
  PushIdNotAllowed(Int)
  PushLimitExceeded(Int)
  InvalidRequestStream(Int)
  InvalidPushStream(Int)
  InvalidPromisedRequest(header_semantics.Error)
  UnsafePromisedRequest
  InconsistentDuplicatePromise(Int)
  DuplicatePushStream(Int)
  MissingPush(Int)
  AlreadyTerminal(Int)
  InvalidTime
}

/// Start with push disabled until MAX_PUSH_ID is sent or received.
pub fn new(
  maximum_tracked_pushes: Int,
  promise_wait_timeout_ms: Int,
) -> Result(State, Error) {
  case maximum_tracked_pushes >= 0 && promise_wait_timeout_ms > 0 {
    True ->
      Ok(State(
        None,
        0,
        dict.new(),
        maximum_tracked_pushes,
        promise_wait_timeout_ms,
      ))
    False -> Error(InvalidConfiguration)
  }
}

/// Increase the Push ID allowance. It can never be reduced.
pub fn permit_through(
  state: State,
  maximum_push_id: Int,
) -> Result(State, Error) {
  case
    maximum_push_id >= 0 && maximum_push_id <= varint.maximum,
    state.maximum_push_id
  {
    False, _ -> Error(PushIdNotAllowed(maximum_push_id))
    True, Some(previous) if maximum_push_id < previous -> Error(PushIdDecreased)
    True, _ -> Ok(State(..state, maximum_push_id: Some(maximum_push_id)))
  }
}

/// Allocate the next sequential server Push ID and register its promise.
pub fn allocate_promise(
  state: State,
  associated_request_stream: Int,
  request_fields: List(Header),
) -> Result(#(State, Int), Error) {
  let push_id = state.next_push_id
  use state <- result.try(promise(
    state,
    push_id,
    associated_request_stream,
    request_fields,
  ))
  Ok(#(State(..state, next_push_id: push_id + 1), push_id))
}

/// Process PUSH_PROMISE. Repeated IDs are legal only with byte-identical,
/// equally ordered fields and add another associated request stream.
pub fn promise(
  state: State,
  push_id: Int,
  associated_request_stream: Int,
  request_fields: List(Header),
) -> Result(State, Error) {
  use _ <- result.try(validate_allowed(state, push_id))
  use _ <- result.try(validate_request_stream(associated_request_stream))
  use _ <- result.try(validate_promised_request(request_fields))
  case
    dict.get(state.pushes, push_id)
    |> result.map(Some)
    |> result.unwrap(None)
  {
    None -> {
      use _ <- result.try(ensure_capacity(state))
      Ok(
        State(
          ..state,
          pushes: dict.insert(
            state.pushes,
            push_id,
            StoredPush(
              Some(request_fields),
              [associated_request_stream],
              None,
              Promised,
              None,
            ),
          ),
        ),
      )
    }
    Some(StoredPush(None, associations, stream, status, _)) ->
      Ok(
        State(
          ..state,
          pushes: dict.insert(
            state.pushes,
            push_id,
            StoredPush(
              Some(request_fields),
              add_association(associations, associated_request_stream),
              stream,
              case status {
                StreamPendingPromise -> Open
                value -> value
              },
              None,
            ),
          ),
        ),
      )
    Some(StoredPush(Some(existing), associations, stream, status, deadline)) ->
      case existing == request_fields {
        False -> Error(InconsistentDuplicatePromise(push_id))
        True ->
          Ok(
            State(
              ..state,
              pushes: dict.insert(
                state.pushes,
                push_id,
                StoredPush(
                  Some(existing),
                  add_association(associations, associated_request_stream),
                  stream,
                  status,
                  deadline,
                ),
              ),
            ),
          )
      }
  }
}

/// Register a server push stream. It may arrive before PUSH_PROMISE and is
/// retained only until a fixed absolute deadline.
pub fn open_stream(
  state: State,
  push_id: Int,
  stream_id: Int,
  now_ms: Int,
) -> Result(State, Error) {
  use _ <- result.try(validate_allowed(state, push_id))
  use _ <- result.try(validate_push_stream(stream_id))
  use _ <- result.try(case now_ms >= 0 {
    True -> Ok(Nil)
    False -> Error(InvalidTime)
  })
  case
    dict.get(state.pushes, push_id)
    |> result.map(Some)
    |> result.unwrap(None)
  {
    None -> {
      use _ <- result.try(ensure_capacity(state))
      Ok(
        State(
          ..state,
          pushes: dict.insert(
            state.pushes,
            push_id,
            StoredPush(
              None,
              [],
              Some(stream_id),
              StreamPendingPromise,
              Some(now_ms + state.promise_wait_timeout_ms),
            ),
          ),
        ),
      )
    }
    Some(StoredPush(_, _, Some(_), status, _)) ->
      case status {
        Cancelled | Complete -> Error(AlreadyTerminal(push_id))
        _ -> Error(DuplicatePushStream(push_id))
      }
    Some(StoredPush(fields, associations, None, status, _)) ->
      case status {
        Cancelled | Complete -> Error(AlreadyTerminal(push_id))
        _ ->
          Ok(
            State(
              ..state,
              pushes: dict.insert(
                state.pushes,
                push_id,
                StoredPush(fields, associations, Some(stream_id), Open, None),
              ),
            ),
          )
      }
  }
}

/// Cancel a promised or reordered push and retain terminal knowledge until
/// the caller explicitly releases it.
pub fn cancel(state: State, push_id: Int) -> Result(State, Error) {
  update_terminal(state, push_id, Cancelled)
}

/// Process a reordered CANCEL_PUSH that can legally precede PUSH_PROMISE.
pub fn announce_cancellation(
  state: State,
  push_id: Int,
) -> Result(State, Error) {
  use _ <- result.try(validate_allowed(state, push_id))
  case
    dict.get(state.pushes, push_id)
    |> result.map(Some)
    |> result.unwrap(None)
  {
    None -> {
      use _ <- result.try(ensure_capacity(state))
      Ok(
        State(
          ..state,
          pushes: dict.insert(
            state.pushes,
            push_id,
            StoredPush(None, [], None, Cancelled, None),
          ),
        ),
      )
    }
    Some(StoredPush(_, _, _, Cancelled, _)) -> Ok(state)
    Some(StoredPush(_, _, _, Complete, _)) -> Ok(state)
    Some(_) -> cancel(state, push_id)
  }
}

/// Mark a pushed response complete.
pub fn complete(state: State, push_id: Int) -> Result(State, Error) {
  update_terminal(state, push_id, Complete)
}

/// Remove terminal state after application delivery and transport cleanup.
pub fn release(state: State, push_id: Int) -> Result(State, Error) {
  case dict.get(state.pushes, push_id) {
    Error(_) -> Error(MissingPush(push_id))
    Ok(StoredPush(_, _, _, Cancelled, _))
    | Ok(StoredPush(_, _, _, Complete, _)) ->
      Ok(State(..state, pushes: dict.delete(state.pushes, push_id)))
    Ok(_) -> Error(AlreadyTerminal(push_id))
  }
}

/// Abort reordered streams whose matching PUSH_PROMISE did not arrive in
/// time, returning their QUIC stream IDs for STOP_SENDING.
pub fn expire_pending(
  state: State,
  now_ms: Int,
) -> Result(#(State, List(Int)), Error) {
  case now_ms >= 0 {
    False -> Error(InvalidTime)
    True -> {
      let #(pushes, expired) =
        expire_entries(dict.to_list(state.pushes), state.pushes, now_ms, [])
      Ok(#(State(..state, pushes: pushes), list.reverse(expired)))
    }
  }
}

/// Reject and cancel every push at or above a received GOAWAY cutoff.
pub fn apply_goaway(
  state: State,
  first_rejected_push_id: Int,
) -> Result(State, Error) {
  case first_rejected_push_id >= 0 && first_rejected_push_id <= varint.maximum {
    False -> Error(PushIdNotAllowed(first_rejected_push_id))
    True ->
      Ok(
        State(
          ..state,
          pushes: cancel_from(
            dict.to_list(state.pushes),
            state.pushes,
            first_rejected_push_id,
          ),
        ),
      )
  }
}

/// Look up one tracked Push ID.
pub fn get(state: State, push_id: Int) -> Option(Push) {
  dict.get(state.pushes, push_id)
  |> result.map(fn(stored) {
    let StoredPush(fields, associations, stream, status, _) = stored
    Push(push_id, fields, associations, stream, status)
  })
  |> result.map(Some)
  |> result.unwrap(None)
}

/// Number of retained active and terminal Push IDs.
pub fn tracked(state: State) -> Int {
  dict.size(state.pushes)
}

fn validate_promised_request(fields: List(Header)) -> Result(Nil, Error) {
  case
    header_semantics.validate(fields, header_semantics.RequestSection, False)
  {
    Error(error) -> Error(InvalidPromisedRequest(error))
    Ok(header_semantics.Validated(
      header_semantics.RequestControlData(control),
      _,
      None,
    )) ->
      case control.method, control.authority {
        <<"GET">>, Some(_) -> Ok(Nil)
        <<"HEAD">>, Some(_) -> Ok(Nil)
        _, _ -> Error(UnsafePromisedRequest)
      }
    Ok(_) -> Error(UnsafePromisedRequest)
  }
}

fn validate_allowed(state: State, push_id: Int) -> Result(Nil, Error) {
  case state.maximum_push_id {
    Some(maximum) if push_id >= 0 && push_id <= maximum -> Ok(Nil)
    _ -> Error(PushIdNotAllowed(push_id))
  }
}

fn ensure_capacity(state: State) -> Result(Nil, Error) {
  case dict.size(state.pushes) < state.maximum_tracked_pushes {
    True -> Ok(Nil)
    False -> Error(PushLimitExceeded(state.maximum_tracked_pushes))
  }
}

fn validate_request_stream(stream_id: Int) -> Result(Nil, Error) {
  case stream_id >= 0 && stream_id <= varint.maximum && stream_id % 4 == 0 {
    True -> Ok(Nil)
    False -> Error(InvalidRequestStream(stream_id))
  }
}

fn validate_push_stream(stream_id: Int) -> Result(Nil, Error) {
  case stream_id >= 0 && stream_id <= varint.maximum && stream_id % 4 == 3 {
    True -> Ok(Nil)
    False -> Error(InvalidPushStream(stream_id))
  }
}

fn add_association(associations: List(Int), stream_id: Int) -> List(Int) {
  case list.contains(associations, stream_id) {
    True -> associations
    False -> list.append(associations, [stream_id])
  }
}

fn update_terminal(
  state: State,
  push_id: Int,
  status: Status,
) -> Result(State, Error) {
  case dict.get(state.pushes, push_id) {
    Error(_) -> Error(MissingPush(push_id))
    Ok(StoredPush(_, _, _, Cancelled, _))
    | Ok(StoredPush(_, _, _, Complete, _)) -> Error(AlreadyTerminal(push_id))
    Ok(StoredPush(fields, associations, stream, _, _)) ->
      Ok(
        State(
          ..state,
          pushes: dict.insert(
            state.pushes,
            push_id,
            StoredPush(fields, associations, stream, status, None),
          ),
        ),
      )
  }
}

fn expire_entries(
  entries: List(#(Int, StoredPush)),
  pushes: Dict(Int, StoredPush),
  now_ms: Int,
  expired_reversed: List(Int),
) -> #(Dict(Int, StoredPush), List(Int)) {
  case entries {
    [] -> #(pushes, expired_reversed)
    [
      #(
        push_id,
        StoredPush(_, _, Some(stream_id), StreamPendingPromise, Some(deadline)),
      ),
      ..rest
    ]
      if now_ms >= deadline
    ->
      expire_entries(rest, dict.delete(pushes, push_id), now_ms, [
        stream_id,
        ..expired_reversed
      ])
    [_, ..rest] -> expire_entries(rest, pushes, now_ms, expired_reversed)
  }
}

fn cancel_from(
  entries: List(#(Int, StoredPush)),
  pushes: Dict(Int, StoredPush),
  cutoff: Int,
) -> Dict(Int, StoredPush) {
  case entries {
    [] -> pushes
    [#(push_id, StoredPush(fields, associations, stream, status, _)), ..rest] -> {
      let pushes = case push_id >= cutoff, status {
        True, Promised | True, StreamPendingPromise | True, Open ->
          dict.insert(
            pushes,
            push_id,
            StoredPush(fields, associations, stream, Cancelled, None),
          )
        _, _ -> pushes
      }
      cancel_from(rest, pushes, cutoff)
    }
  }
}

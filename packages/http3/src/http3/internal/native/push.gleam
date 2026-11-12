//// Bounded RFC 9114 server-push promise and stream coordination.

import gleam/bit_array
import gleam/dict.{type Dict}
import gleam/list
import gleam/option.{type Option, None, Some}
import gleam/result
import gleam/string
import http3/internal/native/header_semantics
import http3/internal/native/origin
import http3/internal/qpack/header.{type Header, Header}
import http3/internal/varint

@external(erlang, "http3_push_policy_ffi", "sha256")
fn sha256(data: BitArray) -> BitArray

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

// Only peer-provided promises need identity after their response is released:
// the peer can repeat a Push ID on a later request stream.
// Locally allocated promises are sequential and never need that connection-lifetime retention.
type PromiseFingerprint {
  PromiseFingerprint(digest: BitArray, retain_after_release: Bool)
}

/// Push-ID allowance, sequential allocator, and bounded active entries.
pub opaque type State {
  State(
    maximum_push_id: Option(Int),
    next_push_id: Int,
    pushes: Dict(Int, StoredPush),
    promise_fingerprints: Dict(Int, PromiseFingerprint),
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
  PromisedRequestRejected(PromiseRejection)
  InconsistentDuplicatePromise(Int)
  DuplicatePushStream(Int)
  MissingPush(Int)
  AlreadyTerminal(Int)
  InvalidTime
}

/// Shareable reason why a syntactically valid promise must not be used.
///
/// These values deliberately exclude header names, values, and authorities.
pub type PromiseRejection {
  MethodNotKnownSafe
  RequestContentIndicated
  RequestNotConservativelyCacheable
  OriginNotAuthorized
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
        dict.new(),
        maximum_tracked_pushes,
        promise_wait_timeout_ms,
      ))
    False -> Error(InvalidConfiguration)
  }
}

/// Increase the Push ID allowance.
/// It can never be reduced.
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
  allocate_promise_with_authority_policies(
    state,
    associated_request_stream,
    request_fields,
    header_semantics.authority_policies(),
  )
}

/// Allocate a promise using one connection's custom-scheme policy.
fn allocate_promise_with_authority_policies(
  state: State,
  associated_request_stream: Int,
  request_fields: List(Header),
  authority_policies: header_semantics.AuthorityPolicies,
) -> Result(#(State, Int), Error) {
  let push_id = state.next_push_id
  use _ <- result.try(validate_allowed(state, push_id))
  use _ <- result.try(validate_request_stream(associated_request_stream))
  use _ <- result.try(validate_promised_request(
    request_fields,
    authority_policies,
  ))
  use state <- result.try(store_promise(
    state,
    push_id,
    associated_request_stream,
    request_fields,
    False,
  ))
  Ok(#(State(..state, next_push_id: push_id + 1), push_id))
}

/// Allocate a promise after binding it to the associated request origin.
pub fn allocate_promise_for_associated_request(
  state: State,
  associated_request_stream: Int,
  associated_request: header_semantics.RequestControl,
  request_fields: List(Header),
  authority_policies: header_semantics.AuthorityPolicies,
) -> Result(#(State, Int), Error) {
  let push_id = state.next_push_id
  use _ <- result.try(validate_allowed(state, push_id))
  use _ <- result.try(validate_request_stream(associated_request_stream))
  use rejection <- result.try(assess_promised_request(
    request_fields,
    associated_request,
    authority_policies,
  ))
  use _ <- result.try(case rejection {
    None -> Ok(Nil)
    Some(reason) -> Error(PromisedRequestRejected(reason))
  })
  use state <- result.try(store_promise(
    state,
    push_id,
    associated_request_stream,
    request_fields,
    False,
  ))
  Ok(#(State(..state, next_push_id: push_id + 1), push_id))
}

/// Process PUSH_PROMISE.
/// Repeated IDs are legal only with byte-identical,
/// equally ordered fields and add another associated request stream.
pub fn promise(
  state: State,
  push_id: Int,
  associated_request_stream: Int,
  request_fields: List(Header),
) -> Result(State, Error) {
  promise_with_authority_policies(
    state,
    push_id,
    associated_request_stream,
    request_fields,
    header_semantics.authority_policies(),
  )
}

/// Process a promise using one connection's custom-scheme policy.
pub fn promise_with_authority_policies(
  state: State,
  push_id: Int,
  associated_request_stream: Int,
  request_fields: List(Header),
  authority_policies: header_semantics.AuthorityPolicies,
) -> Result(State, Error) {
  use _ <- result.try(validate_allowed(state, push_id))
  use _ <- result.try(validate_request_stream(associated_request_stream))
  use _ <- result.try(validate_promised_request(
    request_fields,
    authority_policies,
  ))
  store_promise(state, push_id, associated_request_stream, request_fields, True)
}

/// Process a locally generated promise only when its origin is the same as the associated authenticated request origin.
pub fn promise_for_associated_request(
  state: State,
  push_id: Int,
  associated_request_stream: Int,
  associated_request: header_semantics.RequestControl,
  request_fields: List(Header),
  authority_policies: header_semantics.AuthorityPolicies,
) -> Result(State, Error) {
  use _ <- result.try(validate_allowed(state, push_id))
  use _ <- result.try(validate_request_stream(associated_request_stream))
  use rejection <- result.try(assess_promised_request(
    request_fields,
    associated_request,
    authority_policies,
  ))
  use _ <- result.try(case rejection {
    None -> Ok(Nil)
    Some(reason) -> Error(PromisedRequestRejected(reason))
  })
  store_promise(state, push_id, associated_request_stream, request_fields, True)
}

/// Validate a received promise and return a safe advisory rejection reason.
/// Malformed request fields remain protocol errors.
pub fn assess_promised_request(
  fields: List(Header),
  associated_request: header_semantics.RequestControl,
  authority_policies: header_semantics.AuthorityPolicies,
) -> Result(Option(PromiseRejection), Error) {
  case
    header_semantics.validate_with_authority_policies(
      fields,
      header_semantics.RequestSection,
      False,
      authority_policies,
    )
  {
    Error(error) -> Error(InvalidPromisedRequest(error))
    Ok(validated) ->
      Ok(classify_promised_request(validated, Some(associated_request)))
  }
}

/// Track a rejected Push ID without retaining its request fields.
/// The caller immediately sends CANCEL_PUSH and moves this entry to `Cancelled`.
pub fn remember_rejected_promise(
  state: State,
  push_id: Int,
  associated_request_stream: Int,
  request_fields: List(Header),
) -> Result(State, Error) {
  use _ <- result.try(validate_allowed(state, push_id))
  use _ <- result.try(validate_request_stream(associated_request_stream))
  let fingerprint = request_fingerprint(request_fields)
  use _ <- result.try(ensure_fingerprint_capacity(state, push_id, True))
  let stored =
    dict.get(state.pushes, push_id)
    |> result.map(Some)
    |> result.unwrap(None)
  let inconsistent = case stored {
    Some(StoredPush(Some(existing), _, _, _, _)) ->
      !request_fields_equal(existing, request_fields)
    Some(StoredPush(None, _, _, _, _)) ->
      fingerprint_mismatches(state, push_id, fingerprint)
    None -> False
  }
  case stored, inconsistent {
    _, True -> Error(InconsistentDuplicatePromise(push_id))
    None, False -> {
      case dict.get(state.promise_fingerprints, push_id) {
        Ok(PromiseFingerprint(existing, _)) if existing != fingerprint ->
          Error(InconsistentDuplicatePromise(push_id))
        Ok(_) -> {
          use _ <- result.try(ensure_capacity(state))
          Ok(
            State(
              ..state,
              pushes: dict.insert(
                state.pushes,
                push_id,
                StoredPush(
                  None,
                  [associated_request_stream],
                  None,
                  Cancelled,
                  None,
                ),
              ),
              promise_fingerprints: remember_fingerprint(
                state.promise_fingerprints,
                push_id,
                fingerprint,
                True,
              ),
            ),
          )
        }
        Error(Nil) -> {
          use _ <- result.try(ensure_capacity(state))
          Ok(
            State(
              ..state,
              pushes: dict.insert(
                state.pushes,
                push_id,
                StoredPush(
                  None,
                  [associated_request_stream],
                  None,
                  Promised,
                  None,
                ),
              ),
              promise_fingerprints: remember_fingerprint(
                state.promise_fingerprints,
                push_id,
                fingerprint,
                True,
              ),
            ),
          )
        }
      }
    }
    Some(StoredPush(_, associations, stream, status, deadline)), False ->
      Ok(
        State(
          ..state,
          pushes: dict.insert(
            state.pushes,
            push_id,
            StoredPush(
              None,
              add_association(associations, associated_request_stream),
              stream,
              status,
              deadline,
            ),
          ),
          promise_fingerprints: remember_fingerprint(
            state.promise_fingerprints,
            push_id,
            fingerprint,
            True,
          ),
        ),
      )
  }
}

fn store_promise(
  state: State,
  push_id: Int,
  associated_request_stream: Int,
  request_fields: List(Header),
  retain_after_release: Bool,
) -> Result(State, Error) {
  let fingerprint = request_fingerprint(request_fields)
  use _ <- result.try(ensure_fingerprint_capacity(
    state,
    push_id,
    retain_after_release,
  ))
  case
    dict.get(state.pushes, push_id)
    |> result.map(Some)
    |> result.unwrap(None)
  {
    None -> {
      case dict.get(state.promise_fingerprints, push_id) {
        Ok(PromiseFingerprint(existing, _)) if existing != fingerprint ->
          Error(InconsistentDuplicatePromise(push_id))
        Ok(_) -> {
          use _ <- result.try(ensure_capacity(state))
          Ok(
            State(
              ..state,
              pushes: dict.insert(
                state.pushes,
                push_id,
                StoredPush(
                  None,
                  [associated_request_stream],
                  None,
                  Cancelled,
                  None,
                ),
              ),
              promise_fingerprints: remember_fingerprint(
                state.promise_fingerprints,
                push_id,
                fingerprint,
                retain_after_release,
              ),
            ),
          )
        }
        Error(Nil) -> {
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
              promise_fingerprints: remember_fingerprint(
                state.promise_fingerprints,
                push_id,
                fingerprint,
                retain_after_release,
              ),
            ),
          )
        }
      }
    }
    Some(StoredPush(None, associations, stream, Cancelled, deadline)) -> {
      case fingerprint_mismatches(state, push_id, fingerprint) {
        True -> Error(InconsistentDuplicatePromise(push_id))
        False ->
          Ok(
            State(
              ..state,
              pushes: dict.insert(
                state.pushes,
                push_id,
                StoredPush(
                  None,
                  add_association(associations, associated_request_stream),
                  stream,
                  Cancelled,
                  deadline,
                ),
              ),
              promise_fingerprints: remember_fingerprint(
                state.promise_fingerprints,
                push_id,
                fingerprint,
                retain_after_release,
              ),
            ),
          )
      }
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
          promise_fingerprints: remember_fingerprint(
            state.promise_fingerprints,
            push_id,
            fingerprint,
            retain_after_release,
          ),
        ),
      )
    Some(StoredPush(Some(existing), associations, stream, status, deadline)) ->
      case request_fields_equal(existing, request_fields) {
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
              promise_fingerprints: remember_fingerprint(
                state.promise_fingerprints,
                push_id,
                fingerprint,
                retain_after_release,
              ),
            ),
          )
      }
  }
}

/// Register a server push stream.
/// It may arrive before PUSH_PROMISE and is retained only until a fixed absolute deadline.
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

/// Cancel a promised or reordered push and retain terminal knowledge until the caller explicitly releases it.
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
/// A peer-provided promise keeps only its fixed-size identity so a later duplicate cannot bypass the required field-by-field consistency check.
pub fn release(state: State, push_id: Int) -> Result(State, Error) {
  case dict.get(state.pushes, push_id) {
    Error(_) -> Error(MissingPush(push_id))
    Ok(StoredPush(_, _, _, Cancelled, _))
    | Ok(StoredPush(_, _, _, Complete, _)) -> {
      let promise_fingerprints = case
        dict.get(state.promise_fingerprints, push_id)
      {
        Ok(PromiseFingerprint(_, False)) ->
          dict.delete(state.promise_fingerprints, push_id)
        Ok(PromiseFingerprint(_, True)) | Error(Nil) ->
          state.promise_fingerprints
      }
      Ok(
        State(
          ..state,
          pushes: dict.delete(state.pushes, push_id),
          promise_fingerprints: promise_fingerprints,
        ),
      )
    }
    Ok(_) -> Error(AlreadyTerminal(push_id))
  }
}

/// Abort reordered streams whose matching PUSH_PROMISE did not arrive in time, returning their QUIC stream IDs for STOP_SENDING.
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
    True -> {
      let #(pushes, promise_fingerprints) =
        cancel_from(
          dict.to_list(state.pushes),
          state.pushes,
          state.promise_fingerprints,
          first_rejected_push_id,
        )
      Ok(
        State(
          ..state,
          pushes: pushes,
          promise_fingerprints: promise_fingerprints,
        ),
      )
    }
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

fn validate_promised_request(
  fields: List(Header),
  authority_policies: header_semantics.AuthorityPolicies,
) -> Result(Nil, Error) {
  case
    header_semantics.validate_with_authority_policies(
      fields,
      header_semantics.RequestSection,
      False,
      authority_policies,
    )
  {
    Error(error) -> Error(InvalidPromisedRequest(error))
    Ok(validated) ->
      case classify_promised_request(validated, None) {
        None -> Ok(Nil)
        Some(MethodNotKnownSafe) -> Error(UnsafePromisedRequest)
        Some(reason) -> Error(PromisedRequestRejected(reason))
      }
  }
}

fn classify_promised_request(
  validated: header_semantics.Validated,
  associated_request: Option(header_semantics.RequestControl),
) -> Option(PromiseRejection) {
  case validated {
    header_semantics.Validated(
      header_semantics.RequestControlData(control),
      regular,
      content_length,
    ) ->
      case
        known_safe_and_cacheable_method(control.method),
        content_length,
        promised_origin_authorized(control, associated_request),
        conservatively_cacheable_fields(regular)
      {
        False, _, _, _ -> Some(MethodNotKnownSafe)
        True, Some(length), _, _ if length > 0 -> Some(RequestContentIndicated)
        True, _, False, _ -> Some(OriginNotAuthorized)
        True, _, True, False -> Some(RequestNotConservativelyCacheable)
        True, _, True, True -> None
      }
    _ -> Some(MethodNotKnownSafe)
  }
}

fn known_safe_and_cacheable_method(method: BitArray) -> Bool {
  method == <<"GET">> || method == <<"HEAD">>
}

fn request_fingerprint(fields: List(Header)) -> BitArray {
  fields
  |> list.map(fn(field) {
    let Header(name, value, _) = field
    let name_size = bit_array.byte_size(name)
    let value_size = bit_array.byte_size(value)
    <<
      name_size:size(64),
      name:bits,
      value_size:size(64),
      value:bits,
    >>
  })
  |> bit_array.concat
  |> sha256
}

fn fingerprint_mismatches(
  state: State,
  push_id: Int,
  fingerprint: BitArray,
) -> Bool {
  case dict.get(state.promise_fingerprints, push_id) {
    Ok(PromiseFingerprint(existing, _)) -> existing != fingerprint
    Error(Nil) -> False
  }
}

fn remember_fingerprint(
  fingerprints: Dict(Int, PromiseFingerprint),
  push_id: Int,
  digest: BitArray,
  retain_after_release: Bool,
) -> Dict(Int, PromiseFingerprint) {
  let retain_after_release = case dict.get(fingerprints, push_id) {
    Ok(PromiseFingerprint(_, retained)) -> retained || retain_after_release
    Error(Nil) -> retain_after_release
  }
  dict.insert(
    fingerprints,
    push_id,
    PromiseFingerprint(digest, retain_after_release),
  )
}

fn request_fields_equal(first: List(Header), second: List(Header)) -> Bool {
  case first, second {
    [], [] -> True
    [Header(first_name, first_value, _), ..first],
      [Header(second_name, second_value, _), ..second]
    ->
      first_name == second_name
      && first_value == second_value
      && request_fields_equal(first, second)
    _, _ -> False
  }
}

fn promised_origin_authorized(
  promised: header_semantics.RequestControl,
  associated: Option(header_semantics.RequestControl),
) -> Bool {
  case associated {
    None -> option.is_some(promised.authority)
    Some(associated) ->
      case
        promised.scheme,
        promised.authority,
        associated.scheme,
        associated.authority
      {
        Some(promised_scheme),
          Some(promised_authority),
          Some(request_scheme),
          Some(request_authority)
        ->
          origin.same_authenticated_origin(
            promised_scheme,
            promised_authority,
            request_scheme,
            request_authority,
          )
        _, _, _, _ -> False
      }
  }
}

fn conservatively_cacheable_fields(fields: List(Header)) -> Bool {
  !list.any(fields, fn(field) {
    let Header(name, value, _) = field
    case name {
      <<"authorization">>
      | <<"cookie">>
      | <<"range">>
      | <<"if-match">>
      | <<"if-none-match">>
      | <<"if-modified-since">>
      | <<"if-unmodified-since">>
      | <<"if-range">> -> True
      <<"cache-control">> -> cache_control_prevents_reuse(value)
      <<"pragma">> -> directive_present(value, "no-cache")
      _ -> False
    }
  })
}

fn cache_control_prevents_reuse(value: BitArray) -> Bool {
  directive_present(value, "no-store")
  || directive_present(value, "no-cache")
  || directive_present(value, "private")
  || directive_present(value, "max-age=0")
}

fn directive_present(value: BitArray, expected: String) -> Bool {
  case bit_array.to_string(value) {
    Error(Nil) -> True
    Ok(value) ->
      value
      |> string.lowercase
      |> string.split(",")
      |> list.any(fn(directive) {
        let directive =
          directive
          |> string.trim
          |> string.replace(" ", "")
          |> string.replace("\t", "")
        directive == expected
        || {
          !string.contains(expected, "=")
          && string.starts_with(directive, expected <> "=")
        }
      })
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

// A peer may repeat any permitted Push ID until the connection ends.
// Retain only a configured number of fixed-size identities so an artificially large MAX_PUSH_ID allowance cannot turn duplicate checking into unbounded memory.
fn ensure_fingerprint_capacity(
  state: State,
  push_id: Int,
  retain_after_release: Bool,
) -> Result(Nil, Error) {
  case
    retain_after_release,
    dict.has_key(state.promise_fingerprints, push_id),
    dict.size(state.promise_fingerprints) < state.maximum_tracked_pushes
  {
    False, _, _ | True, True, _ | True, False, True -> Ok(Nil)
    True, False, False -> Error(PushLimitExceeded(state.maximum_tracked_pushes))
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
    Ok(StoredPush(original_fields, associations, stream, _, _)) -> {
      let promise_fingerprints = case original_fields {
        Some(fields) ->
          remember_fingerprint(
            state.promise_fingerprints,
            push_id,
            request_fingerprint(fields),
            False,
          )
        None -> state.promise_fingerprints
      }
      let fields = case status {
        Cancelled | Complete -> None
        _ -> original_fields
      }
      Ok(
        State(
          ..state,
          pushes: dict.insert(
            state.pushes,
            push_id,
            StoredPush(fields, associations, stream, status, None),
          ),
          promise_fingerprints: promise_fingerprints,
        ),
      )
    }
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
  promise_fingerprints: Dict(Int, PromiseFingerprint),
  cutoff: Int,
) -> #(Dict(Int, StoredPush), Dict(Int, PromiseFingerprint)) {
  case entries {
    [] -> #(pushes, promise_fingerprints)
    [#(push_id, StoredPush(fields, associations, stream, status, _)), ..rest] -> {
      let #(pushes, promise_fingerprints) = case push_id >= cutoff, status {
        True, Promised | True, StreamPendingPromise | True, Open -> {
          let fingerprints =
            cancelled_fingerprint(
              fields: fields,
              fingerprints: promise_fingerprints,
              push_id: push_id,
            )
          #(
            dict.insert(
              pushes,
              push_id,
              StoredPush(None, associations, stream, Cancelled, None),
            ),
            fingerprints,
          )
        }
        _, _ -> #(pushes, promise_fingerprints)
      }
      cancel_from(rest, pushes, promise_fingerprints, cutoff)
    }
  }
}

fn cancelled_fingerprint(
  fields fields: Option(List(Header)),
  fingerprints fingerprints: Dict(Int, PromiseFingerprint),
  push_id push_id: Int,
) -> Dict(Int, PromiseFingerprint) {
  case fields {
    Some(fields) ->
      remember_fingerprint(
        fingerprints,
        push_id,
        request_fingerprint(fields),
        False,
      )
    None -> fingerprints
  }
}

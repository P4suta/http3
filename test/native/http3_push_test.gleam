import gleam/list
import gleam/option.{None, Some}
import http3/internal/native/push
import http3/internal/qpack/header

fn promised(method: BitArray, path: BitArray) -> List(header.Header) {
  [
    header.Header(<<":method">>, method, False),
    header.Header(<<":scheme">>, <<"https">>, False),
    header.Header(<<":authority">>, <<"example.com">>, False),
    header.Header(<<":path">>, path, False),
  ]
}

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn coordinates_duplicate_promises_and_reordered_push_streams_test() -> Nil {
  let request = promised(<<"GET">>, <<"/style.css">>)
  let assert Ok(state) = push.new(3, 100)
  let assert Ok(state) = push.permit_through(state, 2)
  let assert Ok(state) = push.promise(state, 0, 0, request)
  let assert Ok(state) = push.promise(state, 0, 4, request)
  let assert Some(push.Push(0, Some(fields), [0, 4], None, push.Promised)) =
    push.get(state, 0)
  assert fields == request
  assert push.promise(state, 0, 8, promised(<<"GET">>, <<"/other">>))
    == Error(push.InconsistentDuplicatePromise(0))

  let assert Ok(state) = push.open_stream(state, 1, 3, 10)
  let assert Some(push.Push(1, None, [], Some(3), push.StreamPendingPromise)) =
    push.get(state, 1)
  let assert Ok(state) = push.promise(state, 1, 0, request)
  let assert Some(push.Push(1, Some(_), [0], Some(3), push.Open)) =
    push.get(state, 1)
  Nil
}

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn expires_unpromised_streams_and_enforces_push_bounds_test() -> Nil {
  let assert Ok(state) = push.new(1, 100)
  let assert Ok(state) = push.permit_through(state, 1)
  let assert Ok(state) = push.open_stream(state, 0, 3, 10)
  let assert Ok(#(state, [])) = push.expire_pending(state, 109)
  let assert Ok(#(state, [3])) = push.expire_pending(state, 110)
  assert push.tracked(state) == 0
  assert push.open_stream(state, 2, 7, 110) == Error(push.PushIdNotAllowed(2))

  let assert Ok(state) = push.promise(state, 0, 0, promised(<<"GET">>, <<"/">>))
  assert push.promise(state, 1, 4, promised(<<"HEAD">>, <<"/">>))
    == Error(push.PushLimitExceeded(1))
}

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn allocates_sequential_safe_promises_and_handles_terminal_states_test() -> Nil {
  let assert Ok(state) = push.new(2, 100)
  let assert Ok(state) = push.permit_through(state, 1)
  let assert Ok(#(state, 0)) =
    push.allocate_promise(state, 0, promised(<<"GET">>, <<"/a">>))
  let assert Ok(#(state, 1)) =
    push.allocate_promise(state, 0, promised(<<"HEAD">>, <<"/b">>))
  assert push.allocate_promise(state, 0, promised(<<"GET">>, <<"/c">>))
    == Error(push.PushIdNotAllowed(2))
  let assert Ok(state) = push.cancel(state, 1)
  let assert Some(push.Push(_, _, _, _, push.Cancelled)) = push.get(state, 1)
  let assert Ok(state) = push.release(state, 1)
  assert push.get(state, 1) == None
  let assert Ok(state) = push.apply_goaway(state, 0)
  let assert Some(push.Push(_, _, _, _, push.Cancelled)) = push.get(state, 0)
  Nil
}

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn rejects_unsafe_or_content_bearing_promised_requests_test() -> Nil {
  let assert Ok(state) = push.new(2, 100)
  let assert Ok(state) = push.permit_through(state, 1)
  assert push.promise(state, 0, 0, promised(<<"POST">>, <<"/">>))
    == Error(push.UnsafePromisedRequest)
  assert push.promise(
      state,
      0,
      0,
      list.append(promised(<<"GET">>, <<"/">>), [
        header.Header(<<"content-length">>, <<"1">>, False),
      ]),
    )
    == Error(push.UnsafePromisedRequest)
}

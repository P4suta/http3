import gleam/list
import gleam/option.{None, Some}
import http3/internal/native/header_semantics
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
    == Error(push.PromisedRequestRejected(push.RequestContentIndicated))
}

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn promise_policy_binds_origin_and_rejects_non_cacheable_inputs_test() -> Nil {
  let associated = request_control(<<"https">>, <<"example.com">>)
  let policies = header_semantics.authority_policies()
  assert push.assess_promised_request(
      promised(<<"GET">>, <<"/safe">>),
      associated,
      policies,
    )
    == Ok(None)
  assert push.assess_promised_request(
      promised_for_origin(<<"GET">>, <<"https">>, <<"EXAMPLE.COM:443">>),
      associated,
      policies,
    )
    == Ok(None)
  assert push.assess_promised_request(
      promised_for_origin(<<"GET">>, <<"http">>, <<"example.com">>),
      associated,
      policies,
    )
    == Ok(Some(push.OriginNotAuthorized))
  assert push.assess_promised_request(
      promised_for_origin(<<"GET">>, <<"https">>, <<"private.example">>),
      associated,
      policies,
    )
    == Ok(Some(push.OriginNotAuthorized))
  assert push.assess_promised_request(
      promised(<<"POST">>, <<"/unsafe">>),
      associated,
      policies,
    )
    == Ok(Some(push.MethodNotKnownSafe))
  assert push.assess_promised_request(
      list.append(promised(<<"GET">>, <<"/content">>), [
        header.Header(<<"content-length">>, <<"1">>, False),
      ]),
      associated,
      policies,
    )
    == Ok(Some(push.RequestContentIndicated))
  let private_requests = [
    header.Header(<<"authorization">>, <<"opaque">>, True),
    header.Header(<<"cookie">>, <<"opaque">>, True),
    header.Header(<<"cache-control">>, <<"no-store">>, False),
    header.Header(<<"range">>, <<"bytes=0-1">>, False),
  ]
  list.each(private_requests, fn(field) {
    assert push.assess_promised_request(
        list.append(promised(<<"GET">>, <<"/private">>), [field]),
        associated,
        policies,
      )
      == Ok(Some(push.RequestNotConservativelyCacheable))
  })
}

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn rejected_promise_retains_no_request_or_authority_bytes_test() -> Nil {
  let rejected =
    promised_for_origin(<<"GET">>, <<"https">>, <<"sensitive-tenant.example">>)
  let assert Ok(state) = push.new(1, 100)
  let assert Ok(state) = push.permit_through(state, 0)
  let assert Ok(state) = push.remember_rejected_promise(state, 0, 0, rejected)
  let assert Some(push.Push(0, None, [0], None, push.Promised)) =
    push.get(state, 0)
  let assert Ok(state) = push.cancel(state, 0)
  let assert Some(push.Push(0, None, [0], None, push.Cancelled)) =
    push.get(state, 0)
  Nil
}

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn cancellation_before_promise_never_restores_request_fields_test() -> Nil {
  let associated = request_control(<<"https">>, <<"example.com">>)
  let request = promised(<<"GET">>, <<"/cancelled">>)
  let policies = header_semantics.authority_policies()
  let assert Ok(state) = push.new(1, 100)
  let assert Ok(state) = push.permit_through(state, 0)
  let assert Ok(state) = push.announce_cancellation(state, 0)
  let assert Ok(state) =
    push.promise_for_associated_request(
      state,
      0,
      0,
      associated,
      request,
      policies,
    )
  let assert Some(push.Push(0, None, [0], None, push.Cancelled)) =
    push.get(state, 0)

  // A matching duplicate can add an association without reviving the push or retaining its fields.
  // A different decompressed field section remains a connection-level Push ID error even though the original bytes are gone.
  let assert Ok(state) =
    push.promise_for_associated_request(
      state,
      0,
      4,
      associated,
      request,
      policies,
    )
  let assert Some(push.Push(0, None, [0, 4], None, push.Cancelled)) =
    push.get(state, 0)
  assert push.promise_for_associated_request(
      state,
      0,
      8,
      associated,
      promised(<<"GET">>, <<"/different">>),
      policies,
    )
    == Error(push.InconsistentDuplicatePromise(0))
}

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn released_peer_promise_still_rejects_an_inconsistent_duplicate_test() -> Nil {
  let request = promised(<<"GET">>, <<"/completed">>)
  let assert Ok(state) = push.new(1, 100)
  let assert Ok(state) = push.permit_through(state, 0)
  let assert Ok(state) = push.promise(state, 0, 0, request)
  let assert Ok(state) = push.complete(state, 0)
  let assert Some(push.Push(0, None, [0], None, push.Complete)) =
    push.get(state, 0)
  let assert Ok(state) = push.release(state, 0)
  assert push.get(state, 0) == None
  assert push.tracked(state) == 0

  assert push.promise(state, 0, 4, promised(<<"GET">>, <<"/different">>))
    == Error(push.InconsistentDuplicatePromise(0))

  // An identical late promise is remembered only as a terminal tombstone.
  // It cannot revive fields or cause the already delivered response to reappear.
  let assert Ok(state) = push.promise(state, 0, 4, request)
  let assert Some(push.Push(0, None, [4], None, push.Cancelled)) =
    push.get(state, 0)
  let assert Ok(state) = push.release(state, 0)
  assert push.promise(state, 0, 8, promised(<<"HEAD">>, <<"/completed">>))
    == Error(push.InconsistentDuplicatePromise(0))
}

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn retired_peer_promise_identities_remain_finitely_bounded_test() -> Nil {
  let request = promised(<<"GET">>, <<"/first">>)
  let assert Ok(state) = push.new(1, 100)
  let assert Ok(state) = push.permit_through(state, 1)
  let assert Ok(state) = push.promise(state, 0, 0, request)
  let assert Ok(state) = push.complete(state, 0)
  let assert Ok(state) = push.release(state, 0)

  assert push.promise(state, 1, 4, promised(<<"GET">>, <<"/second">>))
    == Error(push.PushLimitExceeded(1))
  assert push.promise(state, 0, 8, promised(<<"GET">>, <<"/changed">>))
    == Error(push.InconsistentDuplicatePromise(0))
}

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn server_cannot_allocate_a_cross_origin_promise_test() -> Nil {
  let associated = request_control(<<"https">>, <<"example.com">>)
  let assert Ok(state) = push.new(1, 100)
  let assert Ok(state) = push.permit_through(state, 0)
  assert push.allocate_promise_for_associated_request(
      state,
      0,
      associated,
      promised_for_origin(<<"GET">>, <<"https">>, <<"other.example">>),
      header_semantics.authority_policies(),
    )
    == Error(push.PromisedRequestRejected(push.OriginNotAuthorized))
  let assert Ok(#(_, 0)) =
    push.allocate_promise_for_associated_request(
      state,
      0,
      associated,
      promised(<<"GET">>, <<"/accepted">>),
      header_semantics.authority_policies(),
    )
  Nil
}

fn promised_for_origin(
  method: BitArray,
  scheme: BitArray,
  authority: BitArray,
) -> List(header.Header) {
  [
    header.Header(<<":method">>, method, False),
    header.Header(<<":scheme">>, scheme, False),
    header.Header(<<":authority">>, authority, False),
    header.Header(<<":path">>, <<"/">>, False),
  ]
}

fn request_control(
  scheme: BitArray,
  authority: BitArray,
) -> header_semantics.RequestControl {
  header_semantics.RequestControl(
    method: <<"GET">>,
    scheme: Some(scheme),
    authority: Some(authority),
    path: Some(<<"/">>),
    protocol: None,
  )
}

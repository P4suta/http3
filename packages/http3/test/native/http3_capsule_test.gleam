import http3/internal/native/capsule

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn incrementally_decodes_capsules_and_preserves_following_bytes_test() -> Nil {
  let assert Ok(state) = capsule.new(8, 32)
  let assert Ok(state) = capsule.push(state, <<0>>)
  assert capsule.next(state) == Ok(capsule.NeedMore(state))
  let assert Ok(state) = capsule.push(state, <<3, "a">>)
  assert capsule.next(state) == Ok(capsule.NeedMore(state))
  let assert Ok(state) = capsule.push(state, <<"bc", 0x21, 1, "x">>)
  let assert Ok(capsule.CapsuleReady(state, capsule.Datagram(<<"abc">>))) =
    capsule.next(state)
  assert capsule.buffered_bytes(state) == 3
  let assert Ok(capsule.CapsuleReady(state, capsule.Unknown(0x21, <<"x">>))) =
    capsule.next(state)
  assert capsule.finish(state) == Ok(Nil)
}

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn enforces_capsule_value_and_buffer_bounds_test() -> Nil {
  let assert Ok(state) = capsule.new(4, 8)
  let assert Ok(state) = capsule.push(state, <<0, 5>>)
  assert capsule.next(state) == Error(capsule.CapsuleLimitExceeded(4))
  let assert Ok(empty) = capsule.new(4, 4)
  assert capsule.push(empty, <<0, 3, "abc">>)
    == Error(capsule.BufferLimitExceeded(4))
  assert capsule.finish(state) == Error(capsule.TruncatedCapsule)
  assert capsule.new(8, 7) == Error(capsule.InvalidConfiguration)
}

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn encodes_datagram_and_extension_capsules_test() -> Nil {
  assert capsule.encode(capsule.Datagram(<<"abc">>)) == Ok(<<0, 3, "abc">>)
  assert capsule.encode(capsule.Unknown(0x21, <<>>)) == Ok(<<0x21, 0>>)
}

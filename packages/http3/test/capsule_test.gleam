import gleam/list
import gleeunit/should
import http3/capsule

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn incrementally_decodes_bounded_capsules_test() -> Nil {
  let encoded =
    capsule.encode(capsule.Datagram(<<"payload":utf8>>))
    |> should.be_ok
  let decoder = capsule.decoder(64, 128) |> should.be_ok
  // nolint: assert_ok_pattern -- fixed encoded prefix is the assertion.
  let assert <<first:bytes-size(3), rest:bits>> = encoded
  let decoder = capsule.push(decoder, first) |> should.be_ok
  // nolint: assert_ok_pattern -- incremental state is the assertion.
  let assert Ok(capsule.NeedMore(decoder)) = capsule.next(decoder)
  let decoder = capsule.push(decoder, rest) |> should.be_ok
  // nolint: assert_ok_pattern -- decoded value is the assertion.
  let assert Ok(capsule.Ready(decoder, capsule.Datagram(<<"payload":utf8>>))) =
    capsule.next(decoder)
  assert capsule.buffered_bytes(decoder) == 0
  assert capsule.finish(decoder) == Ok(Nil)
}

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn rejects_capsule_limits_and_truncated_finish_test() -> Nil {
  let decoder = capsule.decoder(2, 4) |> should.be_ok
  let decoder = capsule.push(decoder, <<0, 3, "a">>) |> should.be_ok
  assert capsule.next(decoder) == Error(capsule.CapsuleLimitExceeded(2))
  assert capsule.finish(decoder) == Error(capsule.Truncated)
}

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn owns_quic_integer_boundaries_without_core_codec_test() -> Nil {
  [
    1,
    63,
    64,
    16_383,
    16_384,
    1_073_741_823,
    1_073_741_824,
    4_611_686_018_427_387_903,
  ]
  |> list.each(fn(capsule_type) {
    let encoded =
      capsule.Extension(capsule_type, <<>>)
      |> capsule.encode
      |> should.be_ok
    let decoder = capsule.decoder(0, 16) |> should.be_ok
    let decoder = capsule.push(decoder, encoded) |> should.be_ok
    // nolint: assert_ok_pattern -- each boundary must round-trip exactly.
    let assert Ok(capsule.Ready(decoded, capsule.Extension(actual, <<>>))) =
      capsule.next(decoder)
    assert actual == capsule_type
    assert capsule.finish(decoded) == Ok(Nil)
  })

  assert capsule.encode(capsule.Extension(-1, <<>>))
    == Error(capsule.InvalidCapsuleType)
  assert capsule.encode(capsule.Extension(4_611_686_018_427_387_904, <<>>))
    == Error(capsule.InvalidCapsuleType)
}

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn preserves_following_capsule_and_rejects_non_aligned_input_test() -> Nil {
  let decoder = capsule.decoder(8, 32) |> should.be_ok
  assert capsule.push(decoder, <<1:size(1)>>) == Error(capsule.NonByteAligned)
  let decoder =
    capsule.push(decoder, <<0, 1, "a", 0x21, 1, "b">>) |> should.be_ok
  // nolint: assert_ok_pattern -- the first complete capsule is the assertion.
  let assert Ok(capsule.Ready(decoder, capsule.Datagram(<<"a">>))) =
    capsule.next(decoder)
  assert capsule.buffered_bytes(decoder) == 3
  // nolint: assert_ok_pattern -- the retained capsule is the assertion.
  let assert Ok(capsule.Ready(decoded, capsule.Extension(0x21, <<"b">>))) =
    capsule.next(decoder)
  assert capsule.finish(decoded) == Ok(Nil)
}

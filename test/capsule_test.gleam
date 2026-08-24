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

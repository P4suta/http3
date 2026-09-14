import gleam/list
import gleeunit
import http/internal/http2/frame
import http/internal/http2/priority

pub fn main() -> Nil {
  gleeunit.main()
}

pub fn priority_fields_are_bounded_structured_dictionaries_test() -> Nil {
  assert priority.default() == priority.Priority(3, False)
  assert priority.encode(priority.Priority(5, True)) == Ok(<<"u=5, i">>)
  assert priority.parse(<<"u=1, i, x=token">>, maximum_bytes: 64)
    == Ok(priority.Priority(1, True))
  assert priority.parse(<<"u=7">>, maximum_bytes: 64)
    == Ok(priority.Priority(7, False))
  assert priority.parse(<<"u=8, i=7">>, maximum_bytes: 64)
    == Ok(priority.Priority(3, False))
  assert priority.parse(<<"u=4; source=app, i=?0">>, maximum_bytes: 64)
    == Ok(priority.Priority(4, False))
  assert priority.parse(<<"u=1, u=2">>, maximum_bytes: 64)
    == Ok(priority.Priority(2, False))
  assert priority.parse(<<>>, maximum_bytes: 64)
    == Ok(priority.Priority(3, False))
  assert priority.parse(<<"u=1,">>, maximum_bytes: 64)
    == Error(priority.InvalidDictionary)
  assert priority.parse(<<"u=1">>, maximum_bytes: 2)
    == Error(priority.FieldValueTooLarge(maximum: 2))
}

pub fn priority_fields_accept_complete_rfc9651_dictionary_syntax_test() -> Nil {
  assert priority.parse(
      <<
        "u=2, note=\"a,b;c\", group=(1 2;tag=\"x,y\");ready, bytes=:c2VjcmV0:, when=@1659578233, label=%\"F%c3%bc%c3%bc\", i":utf8,
      >>,
      maximum_bytes: 256,
    )
    == Ok(priority.Priority(2, True))
  assert priority.parse(
      <<"u=(1 2), i=\"wrong type\", x=token;a=?1, u=6, i=?0":utf8>>,
      maximum_bytes: 128,
    )
    == Ok(priority.Priority(6, False))
  assert priority.parse(<<"u=1, u=token, i, i=7":utf8>>, maximum_bytes: 64)
    == Ok(priority.default())
  assert priority.parse(<<" u=0\t,\ti ":utf8>>, maximum_bytes: 64)
    == Ok(priority.Priority(0, True))
}

pub fn priority_fields_reject_invalid_rfc9651_dictionary_syntax_test() -> Nil {
  let invalid = [
    <<"note=\"unterminated, u=1":utf8>>,
    <<"note=\"bad\\q\", u=1":utf8>>,
    <<"group=(1, 2), u=1":utf8>>,
    <<"n=1.2345, u=1":utf8>>,
    <<"bytes=:not base64:, u=1":utf8>>,
    <<"label=%\"bad%AF\", u=1":utf8>>,
    <<"Upper=token, u=1":utf8>>,
  ]
  list.each(invalid, fn(value) {
    assert priority.parse(value, maximum_bytes: 128)
      == Error(priority.InvalidDictionary)
  })
}

pub fn priority_update_payload_and_frame_round_trip_test() -> Nil {
  let update = priority.Update(3, priority.Priority(0, True))
  let payload = <<0:size(1), 3:size(31), "u=0, i":utf8>>
  assert priority.decode(
      frame.Header(10, frame.PriorityUpdate, 0xa5, 0),
      payload,
      maximum_field_value_bytes: 64,
    )
    == Ok(update)
  assert priority.encode_update(update, maximum_frame_bytes: 16_384)
    == Ok(<<
      0,
      0,
      10,
      0x10,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      3,
      "u=0, i":utf8,
    >>)
}

pub fn priority_update_rejects_invalid_envelope_and_target_test() -> Nil {
  assert priority.decode(
      frame.Header(4, frame.PriorityUpdate, 0, 1),
      <<0:size(32)>>,
      maximum_field_value_bytes: 64,
    )
    == Error(priority.InvalidStreamIdentifier)
  assert priority.decode(
      frame.Header(4, frame.PriorityUpdate, 0, 0),
      <<0:size(32)>>,
      maximum_field_value_bytes: 64,
    )
    == Error(priority.InvalidPrioritizedStream)
  assert priority.decode(
      frame.Header(3, frame.PriorityUpdate, 0, 0),
      <<1, 2, 3>>,
      maximum_field_value_bytes: 64,
    )
    == Error(priority.InvalidPayloadLength)
}

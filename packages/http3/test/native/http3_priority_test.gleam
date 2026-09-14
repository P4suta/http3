import gleam/list
import http3/internal/native/frame
import http3/internal/native/priority

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn parses_known_parameters_and_ignores_unknown_or_wrong_types_test() -> Nil {
  assert priority.encode(priority.Priority(5, True)) == Ok(<<"u=5, i">>)
  assert priority.parse(<<"u=1, i, x=token">>, 64)
    == Ok(priority.Priority(1, True))
  assert priority.parse(<<"u=8, i=7">>, 64) == Ok(priority.Priority(3, False))
  assert priority.parse(<<"u=4; source=app, i=?0">>, 64)
    == Ok(priority.Priority(4, False))
  assert priority.parse(<<"u=1, u=2">>, 64) == Ok(priority.Priority(2, False))
  assert priority.parse(<<>>, 64) == Ok(priority.Priority(3, False))
  assert priority.parse(<<"u=1,">>, 64) == Error(priority.InvalidDictionary)
  assert priority.parse(<<"u=1">>, 2) == Error(priority.FieldValueTooLarge(2))
}

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn parses_complete_rfc9651_dictionary_syntax_test() -> Nil {
  assert priority.parse(
      <<
        "u=2, note=\"a,b;c\", group=(1 2;tag=\"x,y\");ready, bytes=:c2VjcmV0:, when=@1659578233, label=%\"F%c3%bc%c3%bc\", i":utf8,
      >>,
      256,
    )
    == Ok(priority.Priority(2, True))
  assert priority.parse(
      <<"u=(1 2), i=\"wrong type\", x=token;a=?1, u=6, i=?0":utf8>>,
      128,
    )
    == Ok(priority.Priority(6, False))
  assert priority.parse(<<"u=1, u=token, i, i=7":utf8>>, 64)
    == Ok(priority.default())
  assert priority.parse(<<" u=0\t,\ti ":utf8>>, 64)
    == Ok(priority.Priority(0, True))
}

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn rejects_invalid_rfc9651_dictionary_syntax_test() -> Nil {
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
    assert priority.parse(value, 128) == Error(priority.InvalidDictionary)
  })
}

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn priority_update_frames_round_trip_and_validate_targets_test() -> Nil {
  let update = priority.RequestUpdate(8, priority.Priority(0, True))
  let assert Ok(encoded) = priority.encode_update(update)
  let assert Ok(#(decoded_frame, <<>>)) =
    frame.decode(encoded, frame.default_limits())
  assert priority.from_frame(decoded_frame, 64) == Ok(update)

  let push = priority.PushUpdate(7, priority.Priority(6, False))
  let assert Ok(outgoing) = priority.to_frame(push)
  assert priority.from_frame(outgoing, 64) == Ok(push)
  assert priority.to_frame(priority.RequestUpdate(
      3,
      priority.Priority(1, False),
    ))
    == Error(priority.InvalidElementId(3))
  assert priority.from_frame(frame.Data(<<>>), 64)
    == Error(priority.NotPriorityUpdate)
}

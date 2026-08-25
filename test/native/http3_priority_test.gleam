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
  assert priority.parse(<<"u=1, u=2">>, 64)
    == Error(priority.DuplicateParameter("u"))
  assert priority.parse(<<"u=1,">>, 64) == Error(priority.InvalidDictionary)
  assert priority.parse(<<"u=1">>, 2) == Error(priority.FieldValueTooLarge(2))
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

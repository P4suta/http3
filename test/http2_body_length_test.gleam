import gleam/option.{None, Some}
import gleeunit
import http/internal/http2/body_length

pub fn main() -> Nil {
  gleeunit.main()
}

pub fn exact_length_completes_only_at_the_declared_octet_count_test() -> Nil {
  let assert Ok(state) = body_length.new(2)
  let assert Ok(state) =
    body_length.start(state, stream_id: 1, expected: Some(3), end_stream: False)
  let assert Ok(body_length.Updated(state, 1)) =
    body_length.receive_data(state, stream_id: 1, octets: 2, end_stream: False)
  assert body_length.receive_data(
      state,
      stream_id: 1,
      octets: 0,
      end_stream: True,
    )
    == Error(body_length.LengthMismatch(expected: 3, received: 2))

  let assert Ok(body_length.Updated(state, 0)) =
    body_length.receive_data(state, stream_id: 1, octets: 1, end_stream: True)
  assert body_length.tracked(state) == 0
}

pub fn body_overrun_is_rejected_before_state_changes_test() -> Nil {
  let assert Ok(state) = body_length.new(1)
  let assert Ok(state) =
    body_length.start(state, stream_id: 1, expected: Some(3), end_stream: False)
  assert body_length.receive_data(
      state,
      stream_id: 1,
      octets: 4,
      end_stream: False,
    )
    == Error(body_length.BodyTooLong(expected: 3, received: 4))
  let assert Ok(body_length.Updated(_, 0)) =
    body_length.receive_data(state, stream_id: 1, octets: 3, end_stream: True)
  Nil
}

pub fn unknown_length_finishes_with_data_or_trailers_test() -> Nil {
  let assert Ok(state) = body_length.new(2)
  let assert Ok(state) =
    body_length.start(state, stream_id: 1, expected: None, end_stream: False)
  let assert Ok(body_length.Updated(state, -1)) =
    body_length.receive_data(state, stream_id: 1, octets: 9, end_stream: False)
  let assert Ok(state) = body_length.receive_trailers(state, stream_id: 1)
  assert body_length.tracked(state) == 0

  let assert Ok(state) =
    body_length.start(state, stream_id: 3, expected: None, end_stream: False)
  let assert Ok(body_length.Updated(state, -1)) =
    body_length.receive_data(state, stream_id: 3, octets: 2, end_stream: True)
  assert body_length.tracked(state) == 0
}

pub fn reset_and_finite_admission_release_tracking_test() -> Nil {
  let assert Ok(state) = body_length.new(1)
  let assert Ok(state) =
    body_length.start(state, stream_id: 1, expected: None, end_stream: False)
  assert body_length.start(
      state,
      stream_id: 3,
      expected: None,
      end_stream: False,
    )
    == Error(body_length.TooManyTracked(maximum: 1))
  let state = body_length.reset(state, stream_id: 1)
  let assert Ok(state) =
    body_length.start(state, stream_id: 3, expected: Some(0), end_stream: True)
  assert body_length.tracked(state) == 0
}

pub fn invalid_configuration_identifiers_and_lengths_are_rejected_test() -> Nil {
  assert body_length.new(0) == Error(body_length.InvalidLimit)
  let assert Ok(state) = body_length.new(1)
  assert body_length.start(
      state,
      stream_id: 0,
      expected: None,
      end_stream: False,
    )
    == Error(body_length.InvalidStreamIdentifier)
  assert body_length.start(
      state,
      stream_id: 1,
      expected: Some(-1),
      end_stream: False,
    )
    == Error(body_length.InvalidLength)
}

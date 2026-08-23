import gleam/option.{Some}
import gleam/result
import gleam_quic/internal/http3/message_stream

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn sequences_request_body_trailers_and_finish_test() -> Nil {
  let state = message_stream.new(message_stream.Request)
  assert message_stream.receive_data(state, <<"bad">>, 16)
    == Error(message_stream.DataBeforeFinalHeaders)
  let assert Ok(state) =
    message_stream.receive_headers(state, message_stream.Final)
  let assert Ok(state) = message_stream.receive_data(state, <<"body">>, 4)
  assert message_stream.body_bytes(state) == 4
  let assert Ok(state) =
    message_stream.receive_headers(state, message_stream.Trailers)
  assert message_stream.receive_data(state, <<1>>, 16)
    == Error(message_stream.DataAfterTrailers)
  let assert Ok(state) = message_stream.finish(state)
  assert message_stream.receive_headers(state, message_stream.Trailers)
    == Error(message_stream.FrameAfterFinished)
}

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn permits_informational_responses_and_bounds_body_test() -> Nil {
  let state = message_stream.new(message_stream.Response)
  let assert Ok(state) =
    message_stream.receive_headers(state, message_stream.Informational)
  let assert Ok(state) =
    message_stream.receive_headers(state, message_stream.Informational)
  let assert Ok(state) =
    message_stream.receive_headers(state, message_stream.Final)
  assert message_stream.receive_headers(state, message_stream.Final)
    == Error(message_stream.DuplicateFinalHeaders)
  assert message_stream.receive_data(state, <<1, 2, 3>>, 2)
    == Error(message_stream.BodyLimitExceeded(2))

  let request = message_stream.new(message_stream.Request)
  assert message_stream.receive_headers(request, message_stream.Informational)
    == Error(message_stream.InformationalRequestHeaders)
  assert message_stream.finish(request)
    == Error(message_stream.MissingFinalHeaders)
}

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn enforces_declared_content_length_at_stream_end_test() -> Nil {
  let state = message_stream.new(message_stream.Request)
  let assert Ok(state) =
    message_stream.receive_headers_with_length(
      state,
      message_stream.Final,
      Some(4),
    )
  let assert Ok(state) = message_stream.receive_data(state, <<"abc">>, 16)
  assert message_stream.finish(state)
    == Error(message_stream.ContentLengthMismatch(4, 3))
  let assert Ok(state) = message_stream.receive_data(state, <<"d">>, 16)
  assert message_stream.finish(state) |> result.is_ok
}

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn rejects_content_length_overrun_at_the_data_frame_test() -> Nil {
  let state = message_stream.new(message_stream.Response)
  let assert Ok(state) =
    message_stream.receive_headers_with_length(
      state,
      message_stream.Final,
      Some(3),
    )
  assert message_stream.receive_data(state, <<"four">>, 16)
    == Error(message_stream.ContentLengthExceeded(3, 4))
}

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn connect_mode_allows_data_but_forbids_more_headers_test() -> Nil {
  let state = message_stream.new(message_stream.Response)
  assert message_stream.establish_connect(state)
    == Error(message_stream.ConnectBeforeFinalHeaders)
  let assert Ok(state) =
    message_stream.receive_headers(state, message_stream.Final)
  let assert Ok(state) = message_stream.establish_connect(state)
  let assert Ok(_) = message_stream.receive_data(state, <<"tunnel">>, 16)
  assert message_stream.receive_headers(state, message_stream.Trailers)
    == Error(message_stream.HeadersAfterConnect)
}

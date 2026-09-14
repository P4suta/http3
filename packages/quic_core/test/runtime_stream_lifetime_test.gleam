import quic_core/internal/runtime/stream_lifetime
import quic_core/stream_id

// nolint: unused_exports -- gleeunit discovers public tests by suffix.
pub fn bidirectional_streams_begin_with_two_live_directions_test() -> Nil {
  assert stream_lifetime.initial_terminal_directions(stream_id.Client, 0)
    == #(False, False)
  assert stream_lifetime.initial_terminal_directions(stream_id.Client, 1)
    == #(False, False)
  assert stream_lifetime.initial_terminal_directions(stream_id.Server, 0)
    == #(False, False)
  assert stream_lifetime.initial_terminal_directions(stream_id.Server, 1)
    == #(False, False)
}

// nolint: unused_exports -- gleeunit discovers public tests by suffix.
pub fn local_unidirectional_stream_has_no_receive_direction_test() -> Nil {
  assert stream_lifetime.initial_terminal_directions(stream_id.Client, 2)
    == #(False, True)
  assert stream_lifetime.initial_terminal_directions(stream_id.Server, 3)
    == #(False, True)
}

// nolint: unused_exports -- gleeunit discovers public tests by suffix.
pub fn peer_unidirectional_stream_has_no_send_direction_test() -> Nil {
  assert stream_lifetime.initial_terminal_directions(stream_id.Client, 3)
    == #(True, False)
  assert stream_lifetime.initial_terminal_directions(stream_id.Server, 2)
    == #(True, False)
}

// nolint: unused_exports -- gleeunit discovers public tests by suffix.
pub fn invalid_identifier_is_conservative_test() -> Nil {
  assert stream_lifetime.initial_terminal_directions(stream_id.Client, -1)
    == #(False, False)
}

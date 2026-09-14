import gleeunit
import http/internal/http2/stream_state

pub fn main() -> Nil {
  gleeunit.main()
}

pub fn locally_opened_stream_closes_each_direction_independently_test() -> Nil {
  let assert Ok(state) = stream_state.send_headers(stream_state.Idle, False)
  assert state == stream_state.Open
  let assert Ok(state) = stream_state.receive_data(state, True)
  assert state == stream_state.HalfClosedRemote
  let assert Ok(state) = stream_state.send_data(state, True)
  assert state == stream_state.Closed
}

pub fn end_stream_on_initial_headers_half_closes_the_sender_test() -> Nil {
  let assert Ok(state) = stream_state.send_headers(stream_state.Idle, True)
  assert state == stream_state.HalfClosedLocal
  let assert Ok(state) = stream_state.receive_headers(state, False)
  assert state == stream_state.HalfClosedLocal
  let assert Ok(state) = stream_state.receive_data(state, True)
  assert state == stream_state.Closed
}

pub fn closed_direction_and_idle_data_are_rejected_test() -> Nil {
  assert stream_state.send_data(stream_state.Idle, False)
    == Error(stream_state.FrameOnIdle)
  assert stream_state.receive_data(stream_state.Idle, False)
    == Error(stream_state.FrameOnIdle)
  assert stream_state.send_data(stream_state.HalfClosedLocal, False)
    == Error(stream_state.LocalSideClosed)
  assert stream_state.receive_headers(stream_state.HalfClosedRemote, True)
    == Error(stream_state.RemoteSideClosed)
  assert stream_state.send_headers(stream_state.Closed, False)
    == Error(stream_state.StreamClosed)
}

pub fn promised_stream_reservations_have_directional_transitions_test() -> Nil {
  let assert Ok(local) = stream_state.reserve_local(stream_state.Idle)
  assert local == stream_state.ReservedLocal
  let assert Ok(local) = stream_state.send_headers(local, False)
  assert local == stream_state.HalfClosedRemote

  let assert Ok(remote) = stream_state.reserve_remote(stream_state.Idle)
  assert remote == stream_state.ReservedRemote
  let assert Ok(remote) = stream_state.receive_headers(remote, True)
  assert remote == stream_state.Closed
  assert stream_state.send_headers(stream_state.ReservedRemote, False)
    == Error(stream_state.WrongReservation)
}

pub fn reset_closes_non_idle_streams_and_is_idempotently_observed_test() -> Nil {
  assert stream_state.receive_reset(stream_state.Idle)
    == Error(stream_state.FrameOnIdle)
  assert stream_state.receive_reset(stream_state.Open)
    == Ok(stream_state.Closed)
  assert stream_state.receive_reset(stream_state.Closed)
    == Ok(stream_state.Closed)
}

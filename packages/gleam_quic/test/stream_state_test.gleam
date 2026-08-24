import gleam/option.{None, Some}
import gleam_quic/frame
import gleam_quic/internal/stream_state
import gleam_quic/stream_id

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn reassembles_stream_data_and_returns_receive_credit_test() -> Nil {
  let assert Ok(stream) =
    stream_state.new(0, stream_id.Server, 10, 10, 30, 10, 10, 10, 30)
  let assert Ok(#(stream, 10)) =
    stream_state.receive_data(stream, 5, <<"world">>, True)
  let assert Ok(stream_state.ReadPending(stream)) = stream_state.read(stream, 7)
  let assert Ok(#(stream, 0)) =
    stream_state.receive_data(stream, 0, <<"hello">>, False)
  let assert Ok(stream_state.ReadData(stream, <<"hellowo">>, False, Some(20))) =
    stream_state.read(stream, 7)
  let assert Ok(stream_state.ReadData(stream, <<"rld">>, True, None)) =
    stream_state.read(stream, 7)
  let assert Ok(stream_state.ReadFinished(stream)) =
    stream_state.read(stream, 7)
  let assert Ok(#(_, 0)) =
    stream_state.receive_data(stream, 5, <<"world">>, True)
  Nil
}

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn reset_discards_buffer_and_consumes_authenticated_final_size_test() -> Nil {
  let assert Ok(stream) =
    stream_state.new(2, stream_id.Server, 10, 10, 30, 0, 10, 10, 30)
  let assert Ok(#(stream, 3)) =
    stream_state.receive_data(stream, 0, <<"abc">>, False)
  let assert Ok(#(stream, 2)) = stream_state.receive_reset(stream, 42, 5)
  let assert Ok(stream_state.ReadReset(stream, 42, 5, Some(20))) =
    stream_state.read(stream, 10)
  assert stream_state.buffered_receive_bytes(stream) == 0
  let assert Ok(stream_state.ReadFinished(_)) = stream_state.read(stream, 10)
  Nil
}

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn applies_send_backpressure_flow_control_ack_and_loss_test() -> Nil {
  let assert Ok(stream) =
    stream_state.new(0, stream_id.Client, 10, 10, 30, 5, 10, 6, 30)
  let assert Ok(stream) = stream_state.queue_send(stream, <<"abcdef">>, False)
  assert stream_state.queue_send(stream, <<"g">>, False)
    == Error(stream_state.SendBufferLimitExceeded(7))
  let assert Ok(stream) = stream_state.queue_send(stream, <<>>, True)

  let assert Ok(stream_state.Emit(stream, first)) =
    stream_state.poll_send(stream, 4)
  assert first == frame.Stream(0, 0, <<"abcd">>, False)
  let assert Ok(stream_state.Emit(stream, second)) =
    stream_state.poll_send(stream, 4)
  assert second == frame.Stream(0, 4, <<"e">>, False)
  let assert Ok(stream_state.SendBlocked(stream, 5)) =
    stream_state.poll_send(stream, 4)

  let stream = stream_state.update_send_limit(stream, 10)
  let assert Ok(stream_state.Emit(stream, final)) =
    stream_state.poll_send(stream, 4)
  assert final == frame.Stream(0, 5, <<"f">>, True)
  assert stream_state.buffered_send_bytes(stream) == 6

  let assert Ok(stream) = stream_state.on_frame_acked(stream, first)
  assert stream_state.buffered_send_bytes(stream) == 2
  let assert Ok(stream) = stream_state.on_frame_lost(stream, second)
  let assert Ok(stream_state.Emit(stream, retransmission)) =
    stream_state.poll_send(stream, 4)
  assert retransmission == second
  let assert Ok(stream) = stream_state.on_frame_acked(stream, retransmission)
  let assert Ok(stream) = stream_state.on_frame_acked(stream, final)
  assert stream_state.buffered_send_bytes(stream) == 0
  assert stream_state.send_finished(stream)
  let assert Ok(stream_state.SendIdle(_)) = stream_state.poll_send(stream, 4)
  Nil
}

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn enforces_direction_and_generates_reset_final_size_test() -> Nil {
  let assert Ok(receive_only) =
    stream_state.new(2, stream_id.Server, 10, 10, 20, 0, 10, 10, 20)
  assert stream_state.queue_send(receive_only, <<"x">>, False)
    == Error(stream_state.WrongDirection)

  let assert Ok(send_only) =
    stream_state.new(2, stream_id.Client, 0, 1, 1, 10, 1, 10, 20)
  assert stream_state.receive_data(send_only, 0, <<"x">>, False)
    == Error(stream_state.WrongDirection)
  let assert Ok(send_only) =
    stream_state.queue_send(send_only, <<"abc">>, False)
  let assert Ok(stream_state.Emit(send_only, _)) =
    stream_state.poll_send(send_only, 3)
  let assert Ok(#(send_only, reset)) = stream_state.reset_send(send_only, 99)
  assert reset == frame.ResetStream(2, 99, 3)
  assert stream_state.buffered_send_bytes(send_only) == 0
  assert stream_state.queue_send(send_only, <<"x">>, False)
    == Error(stream_state.SendClosed)
}

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn rejects_invalid_stream_configuration_and_final_sizes_test() -> Nil {
  assert stream_state.new(-1, stream_id.Client, 1, 1, 1, 1, 1, 1, 1)
    == Error(stream_state.InvalidInput)
  let assert Ok(stream) =
    stream_state.new(0, stream_id.Server, 3, 3, 3, 0, 3, 3, 10)
  assert stream_state.receive_data(stream, 0, <<"abcd">>, False)
    == Error(stream_state.FlowControlFailure)
  let assert Ok(#(stream, 3)) =
    stream_state.receive_data(stream, 0, <<"abc">>, False)
  assert stream_state.receive_reset(stream, 1, 2)
    == Error(stream_state.FinalSizeFailure)
}

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn becomes_terminal_only_after_every_available_direction_closes_test() -> Nil {
  let assert Ok(stream) =
    stream_state.new(0, stream_id.Client, 10, 10, 30, 10, 10, 10, 30)
  let assert Ok(#(stream, 1)) =
    stream_state.receive_data(stream, 0, <<"r">>, True)
  let assert Ok(stream_state.ReadData(stream, <<"r">>, True, _)) =
    stream_state.read(stream, 10)
  assert !stream_state.is_terminal(stream)

  let assert Ok(stream) = stream_state.queue_send(stream, <<"q">>, True)
  let assert Ok(stream_state.Emit(stream, sent)) =
    stream_state.poll_send(stream, 10)
  assert !stream_state.is_terminal(stream)
  let assert Ok(stream) = stream_state.on_frame_acked(stream, sent)

  assert stream_state.is_terminal(stream)
}

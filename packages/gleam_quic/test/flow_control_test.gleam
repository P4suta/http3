import gleam/option.{None, Some}
import gleam_quic/internal/flow_control

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn enforces_receive_credit_and_emits_bounded_window_updates_test() -> Nil {
  let assert Ok(receiver) = flow_control.new_receiver(100, 100, 400)
  let assert Ok(receiver) = flow_control.receive(receiver, 60)
  assert flow_control.receive(receiver, 41)
    == Error(flow_control.FlowControlLimitExceeded)
  let assert Ok(#(receiver, None)) = flow_control.consume(receiver, 40)
  let assert Ok(#(receiver, Some(200))) = flow_control.consume(receiver, 20)
  assert flow_control.receiver_limit(receiver) == 200
  let assert Ok(receiver) = flow_control.receive(receiver, 140)
  assert flow_control.receive(receiver, 1)
    == Error(flow_control.FlowControlLimitExceeded)
}

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn enforces_sender_credit_and_monotonic_max_data_test() -> Nil {
  let assert Ok(sender) = flow_control.new_sender(10)
  let assert Ok(sender) = flow_control.reserve(sender, 10)
  assert flow_control.blocked_at(sender) == Some(10)
  assert flow_control.reserve(sender, 1)
    == Error(flow_control.FlowControlBlocked(10))
  let sender = flow_control.update_sender_limit(sender, 9)
  assert flow_control.sender_limit(sender) == 10
  let sender = flow_control.update_sender_limit(sender, 20)
  let assert Ok(sender) = flow_control.reserve(sender, 10)
  assert flow_control.sent_bytes(sender) == 20
}

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn enforces_peer_stream_count_without_id_reuse_test() -> Nil {
  let assert Ok(limit) = flow_control.new_stream_limit(2)
  let assert Ok(limit) = flow_control.open_stream(limit, 0)
  let assert Ok(limit) = flow_control.open_stream(limit, 1)
  assert flow_control.open_stream(limit, 1)
    == Error(flow_control.StreamAlreadyOpened)
  assert flow_control.open_stream(limit, 2)
    == Error(flow_control.StreamLimitExceeded(2))
  let limit = flow_control.update_stream_limit(limit, 3)
  let assert Ok(limit) = flow_control.open_stream(limit, 2)
  assert flow_control.opened_streams(limit) == 3
}

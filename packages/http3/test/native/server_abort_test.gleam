import gleam/erlang/process
import gleam/option.{None}
import http3/internal/native/protocol
import http3/internal/native/server_connection
import quic_core/failure
import quic_core/server

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn peer_cancelled_send_direction_does_not_abort_the_connection_test() -> Nil {
  let reset_called = process.new_subject()
  let stopped = process.new_subject()
  let outcome =
    server_connection.abort_directions(
      fn() {
        process.send(reset_called, Nil)
        Error(server.StreamFinished)
      },
      fn() {
        process.send(stopped, Nil)
        Ok(Nil)
      },
    )
  let receive_reset = process.receive(reset_called, within: 0)
  let receive_stopped = process.receive(stopped, within: 0)
  assert #(outcome, receive_reset, receive_stopped)
    == #(Ok(Nil), Ok(Nil), Ok(Nil))
  assert process.receive(reset_called, within: 0) == Error(Nil)
  assert process.receive(stopped, within: 0) == Error(Nil)
}

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn connection_failure_during_reset_remains_a_connection_failure_test() -> Nil {
  let reset_called = process.new_subject()
  let stopped = process.new_subject()
  let outcome =
    server_connection.abort_directions(
      fn() {
        process.send(reset_called, Nil)
        Error(server.Failure(failure.Closed(failure.Peer, None)))
      },
      fn() {
        process.send(stopped, Nil)
        Ok(Nil)
      },
    )
  assert outcome == Error(protocol.ResourceClosed)
  assert process.receive(reset_called, within: 0) == Ok(Nil)
  assert process.receive(stopped, within: 0) == Ok(Nil)
  assert process.receive(reset_called, within: 0) == Error(Nil)
  assert process.receive(stopped, within: 0) == Error(Nil)
}

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn connection_failure_during_stop_remains_a_connection_failure_test() -> Nil {
  let reset_called = process.new_subject()
  let stop_called = process.new_subject()
  let outcome =
    server_connection.abort_stream_directions(
      0,
      fn() {
        process.send(reset_called, Nil)
        Ok(Nil)
      },
      fn() {
        process.send(stop_called, Nil)
        Error(server.Failure(failure.Closed(failure.Peer, None)))
      },
    )
  assert outcome == Error(protocol.ResourceClosed)
  assert process.receive(reset_called, within: 0) == Ok(Nil)
  assert process.receive(stop_called, within: 0) == Ok(Nil)
  assert process.receive(reset_called, within: 0) == Error(Nil)
  assert process.receive(stop_called, within: 0) == Error(Nil)
}

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn local_push_stream_abort_uses_only_its_send_direction_test() -> Nil {
  let reset_called = process.new_subject()
  let stop_called = process.new_subject()
  let outcome =
    server_connection.abort_stream_directions(
      3,
      fn() {
        process.send(reset_called, Nil)
        Ok(Nil)
      },
      fn() {
        process.send(stop_called, Nil)
        Error(server.InvalidDirection)
      },
    )
  assert outcome == Ok(Nil)
  assert process.receive(reset_called, within: 0) == Ok(Nil)
  assert process.receive(stop_called, within: 0) == Error(Nil)
  assert process.receive(reset_called, within: 0) == Error(Nil)
}

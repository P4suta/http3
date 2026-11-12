import gleam/erlang/process
import gleam/result
import http3/internal/native/client_connection
import http3/internal/native/protocol
import quic_core/client

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn finished_send_direction_still_stops_malformed_response_receive_direction_test() -> Nil {
  let reset_called = process.new_subject()
  let stopped = process.new_subject()
  let outcome =
    client_connection.abort_directions(
      fn() {
        process.send(reset_called, Nil)
        Error(client.StreamFinished)
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
pub fn remote_push_stream_abort_uses_only_its_receive_direction_test() -> Nil {
  let reset_called = process.new_subject()
  let stop_called = process.new_subject()
  let outcome =
    client_connection.abort_stream_directions(
      3,
      fn() {
        process.send(reset_called, Nil)
        Error(client.InvalidDirection)
      },
      fn() {
        process.send(stop_called, Nil)
        Ok(Nil)
      },
    )
  assert outcome == Ok(Nil)
  assert process.receive(reset_called, within: 0) == Error(Nil)
  assert process.receive(stop_called, within: 0) == Ok(Nil)
  assert process.receive(stop_called, within: 0) == Error(Nil)
}

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn client_resource_abort_routes_remote_push_to_stop_sending_only_test() -> Nil {
  let reset_called = process.new_subject()
  let stop_called = process.new_subject()
  let adapter =
    protocol.Resource(
      open_bidirectional: fn(connection) { Ok(#(connection, 0)) },
      open_unidirectional: fn(connection) { Ok(#(connection, 2)) },
      write: fn(connection, _identifier, _bytes, _finished) { Ok(connection) },
      abort: fn(connection, identifier, _code) {
        use Nil <- result.try(
          client_connection.abort_stream_directions(
            identifier,
            fn() {
              process.send(reset_called, Nil)
              Error(client.InvalidDirection)
            },
            fn() {
              process.send(stop_called, Nil)
              Ok(Nil)
            },
          ),
        )
        Ok(connection)
      },
      send_datagram: fn(connection, _bytes) { Ok(connection) },
      maximum_datagram_size: fn(_connection) { Ok(1200) },
      guaranteed_datagram_size: fn(_connection) { Ok(600) },
    )
  let protocol.Resource(abort: abort, ..) = adapter
  let outcome = abort(Nil, 3, 0x10e)
  assert outcome == Ok(Nil)
  assert process.receive(reset_called, within: 0) == Error(Nil)
  assert process.receive(stop_called, within: 0) == Ok(Nil)
  assert process.receive(stop_called, within: 0) == Error(Nil)
}

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn bidirectional_invalid_direction_is_not_hidden_and_both_operations_run_test() -> Nil {
  let reset_called = process.new_subject()
  let stop_called = process.new_subject()
  let outcome =
    client_connection.abort_stream_directions(
      0,
      fn() {
        process.send(reset_called, Nil)
        Error(client.InvalidDirection)
      },
      fn() {
        process.send(stop_called, Nil)
        Ok(Nil)
      },
    )
  assert outcome == Error(protocol.InvalidResourceOperation)
  assert process.receive(reset_called, within: 0) == Ok(Nil)
  assert process.receive(stop_called, within: 0) == Ok(Nil)
  assert process.receive(reset_called, within: 0) == Error(Nil)
  assert process.receive(stop_called, within: 0) == Error(Nil)
}

import gleam/option.{Some}
import gleeunit
import http/internal/http2/flow_control
import http/internal/http2/stream_registry
import http/internal/http2/stream_state

pub fn main() -> Nil {
  gleeunit.main()
}

pub fn local_stream_identifiers_follow_endpoint_parity_test() -> Nil {
  let assert Ok(client) = stream_registry.new(stream_registry.Client, 4)
  let assert Ok(stream_registry.Opened(client, 1)) =
    stream_registry.open_local(client, False)
  let assert Ok(stream_registry.Opened(client, 3)) =
    stream_registry.open_local(client, True)
  assert stream_registry.stream_state(client, 1) == stream_state.Open
  assert stream_registry.stream_state(client, 3) == stream_state.HalfClosedLocal

  let assert Ok(server) = stream_registry.new(stream_registry.Server, 4)
  let assert Ok(stream_registry.Opened(_, 2)) =
    stream_registry.open_local(server, False)
  Nil
}

pub fn peer_stream_identifiers_require_parity_and_monotonicity_test() -> Nil {
  let assert Ok(server) = stream_registry.new(stream_registry.Server, 4)
  assert stream_registry.receive_headers(server, 2, False)
    == Error(stream_registry.WrongInitiator(stream_id: 2))

  let assert Ok(stream_registry.Updated(server, stream_state.Open)) =
    stream_registry.receive_headers(server, 1, False)
  let assert Ok(stream_registry.Updated(server, stream_state.HalfClosedRemote)) =
    stream_registry.receive_headers(server, 5, True)
  assert stream_registry.highest_peer_stream_id(server) == Some(5)
  assert stream_registry.stream_state(server, 3) == stream_state.Closed
  assert stream_registry.receive_headers(server, 3, False)
    == Error(stream_registry.NonMonotonicPeerStream(previous: 5, received: 3))
}

pub fn clients_cannot_accept_unreserved_server_streams_test() -> Nil {
  let assert Ok(client) = stream_registry.new(stream_registry.Client, 4)
  assert stream_registry.receive_headers(client, 2, False)
    == Error(stream_registry.UnreservedPeerStream(stream_id: 2))

  let assert Ok(client) = stream_registry.reserve_remote(client, 2)
  let assert Ok(stream_registry.Updated(client, stream_state.HalfClosedLocal)) =
    stream_registry.receive_headers(client, 2, False)
  assert stream_registry.stream_state(client, 2) == stream_state.HalfClosedLocal
}

pub fn active_stream_admission_is_released_when_a_stream_closes_test() -> Nil {
  let assert Ok(server) = stream_registry.new(stream_registry.Server, 1)
  let assert Ok(stream_registry.Updated(server, stream_state.Open)) =
    stream_registry.receive_headers(server, 1, False)
  assert stream_registry.active_count(server) == 1
  assert stream_registry.receive_headers(server, 3, False)
    == Error(stream_registry.TooManyActiveStreams(maximum: 1))

  let assert Ok(stream_registry.Updated(server, stream_state.HalfClosedRemote)) =
    stream_registry.receive_data(server, 1, True)
  let assert Ok(stream_registry.Updated(server, stream_state.Closed)) =
    stream_registry.send_data(server, 1, True)
  assert stream_registry.active_count(server) == 0

  let assert Ok(stream_registry.Updated(server, stream_state.Open)) =
    stream_registry.receive_headers(server, 3, False)
  assert stream_registry.active_count(server) == 1
}

pub fn invalid_stream_registry_limit_is_rejected_test() -> Nil {
  assert stream_registry.new(stream_registry.Client, 0)
    == Error(stream_registry.InvalidLimit)
}

pub fn stream_data_windows_are_consumed_and_restored_transactionally_test() -> Nil {
  let assert Ok(client) = stream_registry.new(stream_registry.Client, 2)
  let assert Ok(stream_registry.Opened(client, 1)) =
    stream_registry.open_local(client, False)
  assert stream_registry.send_window(client, 1) == Ok(65_535)
  assert stream_registry.receive_window(client, 1) == Ok(65_535)

  let assert Ok(stream_registry.Updated(client, stream_state.Open)) =
    stream_registry.consume_send_data(client, 1, 1024, False)
  assert stream_registry.send_window(client, 1) == Ok(64_511)

  let assert Ok(client) = stream_registry.increase_send_window(client, 1, 1024)
  assert stream_registry.send_window(client, 1) == Ok(65_535)

  let assert Ok(stream_registry.Updated(client, stream_state.Open)) =
    stream_registry.consume_receive_data(client, 1, 65_535, False)
  assert stream_registry.receive_window(client, 1) == Ok(0)
  assert stream_registry.consume_receive_data(client, 1, 1, False)
    == Error(stream_registry.FlowControlFailure(
      flow_control.FlowControlExceeded,
    ))
  let assert Ok(client) = stream_registry.restore_receive_window(client, 1, 7)
  assert stream_registry.receive_window(client, 1) == Ok(7)
}

pub fn peer_initial_window_changes_apply_to_every_active_stream_test() -> Nil {
  let assert Ok(client) = stream_registry.new(stream_registry.Client, 3)
  let assert Ok(stream_registry.Opened(client, 1)) =
    stream_registry.open_local(client, False)
  let assert Ok(stream_registry.Updated(client, _)) =
    stream_registry.consume_send_data(client, 1, 1024, False)
  let assert Ok(stream_registry.Opened(client, 3)) =
    stream_registry.open_local(client, False)

  let assert Ok(client) =
    stream_registry.apply_peer_initial_window_size(client, 0)
  assert stream_registry.send_window(client, 1) == Ok(-1024)
  assert stream_registry.send_window(client, 3) == Ok(0)
  assert stream_registry.consume_send_data(client, 1, 1, False)
    == Error(stream_registry.FlowControlFailure(
      flow_control.FlowControlExceeded,
    ))

  let assert Ok(stream_registry.Opened(client, 5)) =
    stream_registry.open_local(client, False)
  assert stream_registry.send_window(client, 5) == Ok(0)
}

pub fn initial_window_overflow_does_not_mutate_the_prior_registry_test() -> Nil {
  let assert Ok(client) = stream_registry.new(stream_registry.Client, 1)
  let assert Ok(stream_registry.Opened(client, 1)) =
    stream_registry.open_local(client, False)
  let increment = 0x7fff_ffff - 65_535
  let assert Ok(client) =
    stream_registry.increase_send_window(client, 1, increment)
  assert stream_registry.send_window(client, 1) == Ok(0x7fff_ffff)
  assert stream_registry.apply_peer_initial_window_size(client, 65_536)
    == Error(stream_registry.FlowControlFailure(flow_control.WindowOverflow))
  assert stream_registry.send_window(client, 1) == Ok(0x7fff_ffff)
}

pub fn local_and_peer_active_counts_are_kept_separate_test() -> Nil {
  let assert Ok(client) = stream_registry.new(stream_registry.Client, 4)
  let assert Ok(stream_registry.Opened(client, 1)) =
    stream_registry.open_local(client, False)
  let assert Ok(stream_registry.Opened(client, 3)) =
    stream_registry.open_local(client, False)
  let assert Ok(client) = stream_registry.reserve_remote(client, 2)
  assert stream_registry.local_active_count(client) == 2
  assert stream_registry.peer_active_count(client) == 1
  assert stream_registry.active_count(client) == 3
}

pub fn reset_releases_admission_and_duplicate_closed_reset_is_harmless_test() -> Nil {
  let assert Ok(server) = stream_registry.new(stream_registry.Server, 1)
  let assert Ok(stream_registry.Updated(server, _)) =
    stream_registry.receive_headers(server, 1, False)
  let assert Ok(stream_registry.Updated(server, stream_state.Closed)) =
    stream_registry.receive_reset(server, 1)
  assert stream_registry.active_count(server) == 0
  let assert Ok(stream_registry.Updated(server, stream_state.Closed)) =
    stream_registry.receive_reset(server, 1)
  assert stream_registry.receive_reset(server, 3)
    == Error(stream_registry.StreamFailure(stream_state.FrameOnIdle))
}

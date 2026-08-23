import gleam_quic/internal/http3/drain
import gleam_quic/varint

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn peer_goaway_detaches_retryable_requests_and_stops_new_work_test() -> Nil {
  let assert Ok(state) = drain.new(drain.Client, 8, 1000)
  let assert Ok(state) = drain.open_request(state, 0)
  let assert Ok(state) = drain.open_request(state, 4)
  let assert Ok(drain.GoAwayOutcome(state, [4])) =
    drain.receive_goaway(state, 4)
  assert drain.phase(state) == drain.PeerGoAway
  assert drain.open_request(state, 8) == Error(drain.NewWorkAfterGoAway)
  assert drain.receive_goaway(state, 8)
    == Error(drain.IncreasingGoAwayIdentifier)
  let assert Ok(drain.GoAwayOutcome(state, [0])) =
    drain.receive_goaway(state, 0)
  assert drain.complete_request(state, 0) == Error(drain.MissingIdentifier(0))
}

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn server_two_stage_drain_rejects_cutoff_and_converges_test() -> Nil {
  let assert Ok(state) = drain.new(drain.Server, 8, 1000)
  let assert Ok(drain.Accepted(state)) = drain.receive_request(state, 0)
  let assert Ok(drain.Accepted(state)) = drain.receive_request(state, 4)
  let assert Ok(#(state, identifier)) = drain.start(state, 100)
  assert identifier == varint.maximum - 3
  assert drain.phase(state) == drain.LocalGoAway
  let assert Ok(drain.GoAwayOutcome(state, [4])) = drain.refine(state, 4)
  let assert Ok(drain.Rejected(_, 8)) = drain.receive_request(state, 8)
  let assert Ok(state) = drain.complete_request(state, 0)
  assert drain.phase(state) == drain.ReadyToClose
  let assert Ok(drain.DrainReady(state)) = drain.on_timer(state, 101)
  let assert Ok(state) = drain.close(state)
  assert drain.phase(state) == drain.Closed
}

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn fixed_drain_timeout_returns_transport_cleanup_targets_test() -> Nil {
  let assert Ok(state) = drain.new(drain.Server, 4, 50)
  let assert Ok(drain.Accepted(state)) = drain.receive_request(state, 0)
  let assert Ok(drain.Accepted(state)) = drain.receive_request(state, 4)
  let assert Ok(#(state, _)) = drain.start(state, 10)
  let assert Ok(drain.Draining(_)) = drain.on_timer(state, 59)
  let assert Ok(drain.DrainTimedOut(state, cancelled)) =
    drain.on_timer(state, 60)
  assert cancelled == [4, 0] || cancelled == [0, 4]
  assert drain.phase(state) == drain.ReadyToClose
}

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn client_goaway_controls_pushes_and_server_promises_test() -> Nil {
  let assert Ok(client) = drain.new(drain.Client, 4, 100)
  let assert Ok(drain.Accepted(client)) = drain.receive_push(client, 0)
  let assert Ok(#(client, initial_cutoff)) = drain.start(client, 0)
  assert initial_cutoff == varint.maximum
  let assert Ok(drain.GoAwayOutcome(client, [0])) = drain.refine(client, 0)
  let assert Ok(drain.Rejected(_, 1)) = drain.receive_push(client, 1)

  let assert Ok(server) = drain.new(drain.Server, 4, 100)
  let assert Ok(server) = drain.promise_push(server, 0)
  let assert Ok(drain.GoAwayOutcome(server, [0])) =
    drain.receive_goaway(server, 0)
  assert drain.promise_push(server, 1) == Error(drain.NewWorkAfterGoAway)
  assert drain.complete_push(server, 0) == Error(drain.MissingIdentifier(0))
}

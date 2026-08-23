import gleam_quic/internal/new_reno

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn grows_reduces_and_bounds_new_reno_window_test() -> Nil {
  let assert Ok(state) = new_reno.new(1200)
  assert new_reno.snapshot(state)
    == new_reno.Snapshot(12_000, 0, new_reno.SlowStart)
  let assert Ok(state) = new_reno.on_packet_sent(state, 1200, True)
  assert new_reno.bytes_in_flight(state) == 1200
  let assert Ok(state) = new_reno.on_packet_acked(state, 1200, 10, False)
  assert new_reno.snapshot(state)
    == new_reno.Snapshot(13_200, 0, new_reno.SlowStart)

  let assert Ok(state) = new_reno.on_packet_sent(state, 1200, True)
  let assert Ok(state) = new_reno.on_packet_lost(state, 1200, 10, 20)
  assert new_reno.snapshot(state)
    == new_reno.Snapshot(6600, 0, new_reno.Recovery)
  let assert Ok(state) = new_reno.on_packet_lost(state, 0, 15, 21)
  assert new_reno.congestion_window(state) == 6600

  let assert Ok(state) = new_reno.on_packet_acked(state, 0, 21, False)
  assert new_reno.snapshot(state)
    == new_reno.Snapshot(6600, 0, new_reno.CongestionAvoidance)
  let state = new_reno.on_persistent_congestion(state)
  assert new_reno.snapshot(state)
    == new_reno.Snapshot(2400, 0, new_reno.SlowStart)
}

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn enforces_flight_and_configuration_bounds_test() -> Nil {
  assert new_reno.new(1199) == Error(new_reno.InvalidMaximumDatagramSize)
  let assert Ok(state) = new_reno.new(1200)
  assert new_reno.can_send(state, 12_000)
  assert !new_reno.can_send(state, 12_001)
  assert new_reno.on_packet_sent(state, -1, True)
    == Error(new_reno.InvalidInput)
  assert new_reno.on_packet_acked(state, 1, 0, False)
    == Error(new_reno.BytesInFlightUnderflow)
}

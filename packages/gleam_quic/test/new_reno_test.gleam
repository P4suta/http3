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
pub fn floors_the_window_at_the_new_maximum_datagram_size_test() -> Nil {
  let assert Ok(state) = new_reno.new(1200)
  let assert Ok(state) = new_reno.set_maximum_datagram_size(state, 9000)

  // Raising the size leaves the window exactly where it was: only the RFC 9002
  // section 7.2 reductions follow the path.
  assert new_reno.congestion_window(state) == 12_000

  // A loss event now floors the window at two 9000-byte datagrams rather than
  // two 1200-byte ones, so a single path-sized datagram still fits.
  let assert Ok(state) = new_reno.on_packet_sent(state, 9000, True)
  let assert Ok(state) = new_reno.on_packet_lost(state, 9000, 10, 20)
  assert new_reno.congestion_window(state) == 18_000
  assert new_reno.can_send(state, 9000)

  let state = new_reno.on_persistent_congestion(state)
  assert new_reno.congestion_window(state) == 18_000
  assert new_reno.set_maximum_datagram_size(state, 1199)
    == Error(new_reno.InvalidMaximumDatagramSize)
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

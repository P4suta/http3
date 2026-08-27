import gleam_quic/internal/cubic

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn follows_cubic_growth_and_recovery_test() -> Nil {
  let assert Ok(state) = cubic.new(1200)
  assert cubic.snapshot(state) == cubic.Snapshot(12_000, 0, cubic.SlowStart)

  let assert Ok(state) = cubic.on_packet_sent(state, 1200, True)
  assert cubic.bytes_in_flight(state) == 1200
  let assert Ok(state) = cubic.on_packet_acked(state, 1200, 10, 20, 10, False)
  assert cubic.snapshot(state) == cubic.Snapshot(13_200, 0, cubic.SlowStart)

  let assert Ok(state) = cubic.on_packet_sent(state, 1200, True)
  let assert Ok(state) = cubic.on_packet_lost(state, 1200, 30, 40)
  assert cubic.snapshot(state) == cubic.Snapshot(9240, 0, cubic.Recovery)

  // More loss from the same recovery epoch must not reduce the window again.
  let assert Ok(state) = cubic.on_packet_lost(state, 0, 35, 41)
  assert cubic.congestion_window(state) == 9240

  // An ACK for a packet sent after recovery enters congestion avoidance.
  let assert Ok(state) = cubic.on_packet_sent(state, 1200, True)
  let assert Ok(state) = cubic.on_packet_acked(state, 1200, 41, 50, 10, False)
  assert cubic.phase(state) == cubic.CongestionAvoidance
  let before_growth = cubic.congestion_window(state)
  let assert Ok(state) = cubic.on_packet_sent(state, 1200, True)
  let assert Ok(state) =
    cubic.on_packet_acked(state, 1200, 60, 1050, 100, False)
  assert cubic.congestion_window(state) > before_growth

  let state = cubic.on_persistent_congestion(state)
  assert cubic.congestion_window(state) == 2400
  assert cubic.phase(state) == cubic.SlowStart
}

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn floors_the_window_at_the_new_maximum_datagram_size_test() -> Nil {
  let assert Ok(state) = cubic.new(1200)
  let assert Ok(state) = cubic.set_maximum_datagram_size(state, 9000)

  // Raising the size leaves the window exactly where it was: only the RFC 9002
  // section 7.2 reductions and the RFC 9438 curve follow the path.
  assert cubic.congestion_window(state) == 12_000

  // A loss event now floors the window at two 9000-byte datagrams rather than
  // two 1200-byte ones, so a single path-sized datagram still fits.
  let assert Ok(state) = cubic.on_packet_sent(state, 9000, True)
  let assert Ok(state) = cubic.on_packet_lost(state, 9000, 10, 20)
  assert cubic.congestion_window(state) == 18_000
  assert cubic.can_send(state, 9000)

  let state = cubic.on_persistent_congestion(state)
  assert cubic.congestion_window(state) == 18_000
  assert cubic.set_maximum_datagram_size(state, 1199)
    == Error(cubic.InvalidMaximumDatagramSize)
}

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn excludes_application_limited_time_and_enforces_bounds_test() -> Nil {
  assert cubic.new(1199) == Error(cubic.InvalidMaximumDatagramSize)
  let assert Ok(state) = cubic.new(1200)
  assert cubic.can_send(state, 12_000)
  assert !cubic.can_send(state, 12_001)
  assert cubic.on_packet_sent(state, -1, True) == Error(cubic.InvalidInput)
  assert cubic.on_packet_acked(state, 1, 0, 1, 1, False)
    == Error(cubic.BytesInFlightUnderflow)

  let assert Ok(state) = cubic.on_packet_sent(state, 1200, True)
  let assert Ok(state) = cubic.on_packet_lost(state, 1200, 1, 2)
  let assert Ok(state) = cubic.on_packet_sent(state, 1200, True)
  let assert Ok(state) = cubic.on_packet_acked(state, 1200, 3, 4, 10, False)
  let before_idle = cubic.congestion_window(state)
  let assert Ok(state) = cubic.on_packet_sent(state, 1200, True)
  let assert Ok(state) = cubic.on_packet_acked(state, 1200, 5, 60_004, 10, True)
  assert cubic.congestion_window(state) == before_idle
  let assert Ok(state) = cubic.on_packet_sent(state, 1200, True)
  let assert Ok(state) =
    cubic.on_packet_acked(state, 1200, 60_005, 60_014, 10, False)
  assert cubic.congestion_window(state) < before_idle * 3 / 2
}

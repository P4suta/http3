import quic_core/internal/cubic

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn follows_cubic_growth_and_recovery_test() -> Nil {
  let assert Ok(state) = cubic.new(1200)
  assert cubic.snapshot(state) == cubic.Snapshot(12_000, 0, cubic.SlowStart)

  let assert Ok(state) = cubic.on_packet_sent(state, 12_000, True)
  assert cubic.bytes_in_flight(state) == 12_000
  let assert Ok(state) = cubic.on_packet_acked(state, 1200, 10, 20, 10, False)
  assert cubic.snapshot(state)
    == cubic.Snapshot(13_200, 10_800, cubic.SlowStart)
  let assert Ok(state) = cubic.abandon_in_flight(state, 10_800)

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
  let assert Ok(state) = cubic.on_packet_sent(state, before_growth, True)
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
pub fn ecn_reaches_one_datagram_then_applies_bounded_rate_backoff_test() -> Nil {
  let assert Ok(state) = cubic.new(1200)
  let state = apply_ecn_events(state, 7, 1)
  assert cubic.congestion_window(state) == 1200
  assert cubic.ecn_response_snapshot(state)
    == cubic.EcnResponseSnapshot(0, 1200)

  let assert Ok(state) = cubic.on_congestion_experienced(state, 8)
  assert cubic.congestion_window(state) == 1200
  assert cubic.ecn_response_snapshot(state) == cubic.EcnResponseSnapshot(1, 600)

  let assert Ok(state) = cubic.on_congestion_experienced(state, 9)
  assert cubic.ecn_response_snapshot(state) == cubic.EcnResponseSnapshot(2, 300)
  assert cubic.on_congestion_experienced(state, -1) == Error(cubic.InvalidInput)
}

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn topology_choice_is_explicit_in_curve_diagnostics_test() -> Nil {
  let assert Ok(enabled) = cubic.new_with_fast_convergence(1200, True)
  let assert Ok(disabled) = cubic.new_with_fast_convergence(1200, False)
  let assert Ok(enabled) = cubic.on_packet_lost(enabled, 0, 1, 1)
  let assert Ok(disabled) = cubic.on_packet_lost(disabled, 0, 1, 1)
  let assert Ok(enabled) = cubic.on_packet_lost(enabled, 0, 2, 2)
  let assert Ok(disabled) = cubic.on_packet_lost(disabled, 0, 2, 2)

  // The second lower saturation point is shortened only in the multi-flow
  // fast-convergence mode. The snapshot makes that topology-dependent choice
  // inspectable without exposing packets or application data.
  assert cubic.curve_snapshot(enabled)
    == cubic.CurveSnapshot(7140, 8400, 0, True)
  assert cubic.curve_snapshot(disabled)
    == cubic.CurveSnapshot(8400, 8400, 0, False)
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

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn sparse_flight_cannot_grow_a_cwnd_based_controller_test() -> Nil {
  let assert Ok(state) = cubic.new(1200)
  let initial = cubic.congestion_window(state)
  let assert Ok(state) = cubic.on_packet_sent(state, 1200, True)

  // Even when a caller misses the application-limited hint, RFC 9438 section
  // 4.6 and its QUIC requirement prohibit cwnd growth when flight is smaller
  // than cwnd. The controller itself is the final enforcement boundary.
  let assert Ok(state) = cubic.on_packet_acked(state, 1200, 10, 20, 10, False)
  assert cubic.congestion_window(state) == initial
}

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn paced_hystart_does_not_cap_ack_growth_at_eight_datagrams_test() -> Nil {
  let assert Ok(state) = cubic.new(1200)
  let assert Ok(state) = cubic.on_packet_sent(state, 12_000, True)

  // RFC 9406 recommends L=infinity for a paced implementation. One ACK that
  // newly acknowledges ten datagrams therefore contributes all 12,000 bytes,
  // rather than the non-paced L=8 ceiling of 9,600 bytes.
  let assert Ok(state) = cubic.on_packet_acked(state, 12_000, 10, 20, 10, False)
  assert cubic.congestion_window(state) == 24_000
}

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn hystart_enters_conservative_slow_start_on_persistent_delay_test() -> Nil {
  let assert Ok(state) = cubic.new(1200)
  let state = acknowledge_round(state, 10, 10, 0)
  assert cubic.slow_start_mode(state) == cubic.StandardSlowStart

  // The previous round minimum is 10 ms, so the RFC 9406 threshold is the
  // 4 ms floor. Eight samples at 14 ms trigger CSS.
  let state = acknowledge_samples(state, 8, 14, 100)
  assert cubic.slow_start_mode(state) == cubic.ConservativeSlowStart

  let before = cubic.congestion_window(state)
  let fill = before - cubic.bytes_in_flight(state)
  let assert Ok(state) = cubic.on_packet_sent(state, fill, True)
  let assert Ok(state) = cubic.on_packet_acked(state, 1200, 200, 214, 14, False)
  assert cubic.congestion_window(state) == before + 300
}

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn hystart_resumes_standard_slow_start_after_jitter_test() -> Nil {
  let assert Ok(state) = cubic.new(1200)
  let state = acknowledge_round(state, 10, 10, 0)
  let state = acknowledge_samples(state, 8, 14, 100)
  assert cubic.slow_start_mode(state) == cubic.ConservativeSlowStart

  // Once a CSS round has enough observations, a minimum below the baseline
  // proves the delay spike was transient and restores ordinary slow start.
  let state = acknowledge_samples(state, 8, 9, 300)
  assert cubic.slow_start_mode(state) == cubic.StandardSlowStart
}

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn hystart_persistent_delay_exits_after_exactly_five_css_rounds_test() -> Nil {
  let assert Ok(state) = cubic.new(1200)
  let state = acknowledge_round(state, 10, 10, 0)
  let state = acknowledge_samples(state, 8, 14, 100)
  assert cubic.hystart_snapshot(state)
    == cubic.HystartSnapshot(True, cubic.ConservativeSlowStart, 0, 8)

  let #(state, time) = finish_css_round(state, 0, 300, 256)
  assert cubic.hystart_snapshot(state)
    == cubic.HystartSnapshot(True, cubic.ConservativeSlowStart, 1, 0)
  let #(state, time) = finish_css_round(state, 1, time, 256)
  assert cubic.hystart_snapshot(state)
    == cubic.HystartSnapshot(True, cubic.ConservativeSlowStart, 2, 0)
  let #(state, time) = finish_css_round(state, 2, time, 256)
  assert cubic.hystart_snapshot(state)
    == cubic.HystartSnapshot(True, cubic.ConservativeSlowStart, 3, 0)
  let #(state, time) = finish_css_round(state, 3, time, 256)
  assert cubic.hystart_snapshot(state)
    == cubic.HystartSnapshot(True, cubic.ConservativeSlowStart, 4, 0)
  let #(state, _) = finish_css_round(state, 4, time, 256)
  assert cubic.hystart_snapshot(state)
    == cubic.HystartSnapshot(False, cubic.StandardSlowStart, 5, 0)
  assert cubic.phase(state) == cubic.CongestionAvoidance
}

fn apply_ecn_events(
  state: cubic.State,
  remaining: Int,
  now: Int,
) -> cubic.State {
  case remaining {
    0 -> state
    _ -> {
      let assert Ok(state) = cubic.on_congestion_experienced(state, now)
      apply_ecn_events(state, remaining - 1, now + 1)
    }
  }
}

fn finish_css_round(
  state: cubic.State,
  completed_before: Int,
  time: Int,
  remaining: Int,
) -> #(cubic.State, Int) {
  let cubic.HystartSnapshot(_, _, completed, _) = cubic.hystart_snapshot(state)
  case completed > completed_before {
    True -> #(state, time)
    False -> {
      let assert True = remaining > 0
      let assert Ok(state) = cubic.on_packet_sent(state, 1200, True)
      let assert Ok(state) =
        cubic.on_packet_acked(state, 1200, time, time + 14, 14, False)
      finish_css_round(state, completed_before, time + 15, remaining - 1)
    }
  }
}

fn acknowledge_round(
  state: cubic.State,
  packets: Int,
  rtt: Int,
  time: Int,
) -> cubic.State {
  acknowledge_samples(state, packets, rtt, time)
}

fn acknowledge_samples(
  state: cubic.State,
  remaining: Int,
  rtt: Int,
  time: Int,
) -> cubic.State {
  case remaining {
    0 -> state
    _ -> {
      let assert Ok(state) = cubic.on_packet_sent(state, 1200, True)
      let assert Ok(state) =
        cubic.on_packet_acked(state, 1200, time, time + rtt, rtt, False)
      acknowledge_samples(state, remaining - 1, rtt, time + rtt + 1)
    }
  }
}

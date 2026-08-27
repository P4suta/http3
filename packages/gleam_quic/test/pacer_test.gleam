import gleam_quic/internal/pacer

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn spaces_packets_and_caps_idle_burst_test() -> Nil {
  let assert Ok(state) = pacer.new(2400, 0)
  let assert Ok(pacer.Decision(state, pacer.SendNow)) =
    pacer.reserve(state, 1200, 0, 12_000, 100)
  let assert Ok(pacer.Decision(state, pacer.SendNow)) =
    pacer.reserve(state, 1200, 0, 12_000, 100)
  let assert Ok(pacer.Decision(state, pacer.WaitUntil(deadline))) =
    pacer.reserve(state, 1200, 0, 12_000, 100)
  assert deadline > 0
  let assert Ok(pacer.Decision(_state, pacer.SendNow)) =
    pacer.reserve(state, 1200, 1000, 12_000, 100)
  Nil
}

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn scales_the_burst_to_the_validated_path_test() -> Nil {
  let assert Ok(state) = pacer.new(10 * 1200, 0)

  // A burst fixed at ten 1200-byte datagrams cannot hold one 16_384-byte
  // datagram at all, so the pacer refuses the question instead of answering
  // it: neither a send nor a wake can be derived from that.
  assert pacer.reserve(state, 16_384, 0, 24_000, 100)
    == Error(pacer.InvalidInput)

  // Once the burst scales with the validated path the same datagram gets a
  // real answer. Resizing gifts no tokens, so the balance is still the old
  // burst and the datagram is delayed rather than released.
  let assert Ok(scaled) = pacer.resize_burst(state, 10 * 16_384)
  let assert Ok(pacer.Decision(scaled, pacer.WaitUntil(release))) =
    pacer.reserve(scaled, 16_384, 0, 24_000, 100)
  assert release > 0
  let assert Ok(pacer.Decision(_, pacer.SendNow)) =
    pacer.reserve(scaled, 16_384, release, 24_000, 100)

  // Shrinking clamps the balance instead of leaving a burst the path can no
  // longer carry.
  let assert Ok(shrunk) = pacer.resize_burst(scaled, 1200)
  assert pacer.reserve(shrunk, 16_384, release, 24_000, 100)
    == Error(pacer.InvalidInput)
  let assert Ok(pacer.Decision(_, pacer.SendNow)) =
    pacer.reserve(shrunk, 1200, release, 24_000, 100)
  Nil
}

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn rejects_invalid_pacing_inputs_test() -> Nil {
  assert pacer.new(0, 0) == Error(pacer.InvalidInput)
  let assert Ok(state) = pacer.new(1200, 0)
  assert pacer.reserve(state, 1200, 0, 0, 100) == Error(pacer.InvalidInput)
  assert pacer.resize_burst(state, 0) == Error(pacer.InvalidInput)
}

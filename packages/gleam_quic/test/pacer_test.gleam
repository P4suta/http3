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
pub fn rejects_invalid_pacing_inputs_test() -> Nil {
  assert pacer.new(0, 0) == Error(pacer.InvalidInput)
  let assert Ok(state) = pacer.new(1200, 0)
  assert pacer.reserve(state, 1200, 0, 0, 100) == Error(pacer.InvalidInput)
}

import gleam/option.{None, Some}
import gleam_quic/internal/ecn

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn validates_monotonic_ecn_feedback_and_reports_new_ce_test() -> Nil {
  let state = ecn.new()
  let assert Ok(state) = ecn.record_sent(state, ecn.Ect0, 3)
  let assert Ok(ecn.AckResult(state, 1)) =
    ecn.on_ack(state, 2, ecn.Acknowledged(3, 0), Some(ecn.Counts(2, 0, 1)))
  assert ecn.phase(state) == ecn.Capable
  let assert Ok(state) = ecn.record_sent(state, ecn.Ect0, 1)
  let assert Ok(ecn.AckResult(state, 1)) =
    ecn.on_ack(state, 3, ecn.Acknowledged(1, 0), Some(ecn.Counts(2, 0, 2)))
  assert ecn.phase(state) == ecn.Capable
}

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn disables_ecn_on_missing_remarked_or_decreasing_feedback_test() -> Nil {
  let state = ecn.new()
  let assert Ok(state) = ecn.record_sent(state, ecn.Ect0, 1)
  let assert Ok(ecn.AckResult(state, 0)) =
    ecn.on_ack(state, 1, ecn.Acknowledged(1, 0), None)
  assert ecn.phase(state) == ecn.Failed

  let state = ecn.new()
  let assert Ok(state) = ecn.record_sent(state, ecn.Ect0, 1)
  let assert Ok(ecn.AckResult(state, 0)) =
    ecn.on_ack(state, 1, ecn.Acknowledged(1, 0), Some(ecn.Counts(0, 1, 0)))
  assert ecn.phase(state) == ecn.Failed

  // A validation failure is permanent for this path.
  let assert Ok(state) = ecn.record_sent(state, ecn.Ect1, 1)
  let assert Ok(ecn.AckResult(state, 0)) =
    ecn.on_ack(state, 2, ecn.Acknowledged(0, 1), Some(ecn.Counts(0, 1, 0)))
  assert ecn.phase(state) == ecn.Failed
}

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn bounds_cumulative_feedback_and_testing_duration_test() -> Nil {
  let state = ecn.new()
  let assert Ok(state) = ecn.record_sent(state, ecn.Ect0, 1)
  let assert Ok(state) = ecn.record_sent(state, ecn.Ect1, 1)
  let assert Ok(ecn.AckResult(state, 0)) =
    ecn.on_ack(state, 1, ecn.Acknowledged(1, 1), Some(ecn.Counts(1, 1, 1)))
  assert ecn.phase(state) == ecn.Failed

  let state = ecn.new()
  let state = ecn.on_probe_timeout(state)
  let state = ecn.on_probe_timeout(state)
  assert ecn.phase(state) == ecn.Testing
  let state = ecn.on_probe_timeout(state)
  assert ecn.phase(state) == ecn.Unknown
}

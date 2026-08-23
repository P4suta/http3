import gleam/option.{Some}
import gleam_quic/internal/recovery
import gleam_quic/internal/rtt

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn applies_rfc9002_rtt_ack_delay_and_pto_formulas_test() -> Nil {
  let assert Ok(estimator) = rtt.new(333)
  assert rtt.snapshot(estimator) == rtt.Snapshot(0, 333, 166, 0)
  let assert Ok(estimator) = rtt.sample(estimator, 100, 0, 25, False)
  assert rtt.snapshot(estimator) == rtt.Snapshot(100, 100, 50, 100)
  let assert Ok(estimator) = rtt.sample(estimator, 120, 20, 25, True)
  assert rtt.snapshot(estimator) == rtt.Snapshot(120, 100, 37, 100)
  let assert Ok(estimator) = rtt.sample(estimator, 140, 100, 25, True)
  assert rtt.snapshot(estimator) == rtt.Snapshot(140, 101, 31, 100)
  assert rtt.probe_timeout(estimator, 25, True, 0, 1) == Ok(250)
  assert rtt.probe_timeout(estimator, 25, False, 0, 1) == Ok(225)
  assert rtt.loss_delay(estimator, 1) == 157
}

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn detects_packet_and_time_threshold_losses_test() -> Nil {
  let assert Ok(estimator) = rtt.new(333)
  let assert Ok(estimator) = rtt.sample(estimator, 100, 0, 0, False)
  let sent = [
    recovery.SentPacket(1, 0, True, True, 1200),
    recovery.SentPacket(2, 50, True, True, 1200),
    recovery.SentPacket(3, 100, True, True, 1200),
  ]
  let assert Ok(recovery.Detection(lost, remaining, next_loss_time)) =
    recovery.detect(sent, 4, 200, estimator, 1)
  assert lost
    == [
      recovery.SentPacket(1, 0, True, True, 1200),
      recovery.SentPacket(2, 50, True, True, 1200),
    ]
  assert remaining == [recovery.SentPacket(3, 100, True, True, 1200)]
  assert next_loss_time == Some(212)
}

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn rejects_invalid_recovery_inputs_test() -> Nil {
  assert rtt.new(0) == Error(rtt.InvalidInput)
  let assert Ok(estimator) = rtt.new(333)
  assert rtt.sample(estimator, -1, 0, 0, False) == Error(rtt.InvalidInput)
  assert rtt.probe_timeout(estimator, 0, True, -1, 1) == Error(rtt.InvalidInput)
  assert recovery.detect([], -1, 0, estimator, 1)
    == Error(recovery.InvalidInput)
}

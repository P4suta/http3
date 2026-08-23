import gleam/option.{None, Some}
import gleam_quic/frame
import gleam_quic/internal/ecn
import gleam_quic/internal/packet_space
import gleam_quic/internal/rtt

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn schedules_bounded_ack_ranges_and_reports_ecn_test() -> Nil {
  let assert Ok(space) = packet_space.new(packet_space.Application, 25, 3, 16)

  let assert Ok(packet_space.Accepted(space, packet_space.DelayedUntil(125))) =
    packet_space.receive(space, 0, True, packet_space.Ect0, 100)
  assert packet_space.ack_due(space, 124) == False

  let assert Ok(packet_space.Accepted(space, packet_space.SendImmediately)) =
    packet_space.receive(space, 2, True, packet_space.NotEct, 101)
  assert packet_space.ack_due(space, 101)
  let assert Ok(#(space, Some(ack))) = packet_space.take_ack(space, 101, 3)
  assert ack
    == frame.Acknowledgement(
      0,
      [frame.AckRange(2, 2), frame.AckRange(0, 0)],
      Some(frame.EcnCounts(1, 0, 0)),
    )

  let assert Ok(packet_space.Accepted(space, packet_space.SendImmediately)) =
    packet_space.receive(
      space,
      1,
      True,
      packet_space.CongestionExperienced,
      102,
    )
  let assert Ok(packet_space.Duplicate(space)) =
    packet_space.receive(space, 1, True, packet_space.NotEct, 103)
  let assert Ok(#(space, Some(ack))) = packet_space.take_ack(space, 103, 0)
  assert ack
    == frame.Acknowledgement(
      2000,
      [frame.AckRange(0, 2)],
      Some(frame.EcnCounts(1, 0, 1)),
    )

  let assert Ok(packet_space.Accepted(space, packet_space.DelayedUntil(225))) =
    packet_space.receive(space, 3, True, packet_space.NotEct, 200)
  assert packet_space.ack_due(space, 224) == False
  assert packet_space.ack_due(space, 225)
  let assert Ok(#(_, Some(ack))) = packet_space.take_ack(space, 225, 0)
  assert ack.delay == 25_000
}

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn initial_space_acks_immediately_and_bounds_history_test() -> Nil {
  let assert Ok(space) = packet_space.new(packet_space.Initial, 25, 2, 8)
  let assert Ok(packet_space.Accepted(space, packet_space.SendImmediately)) =
    packet_space.receive(space, 10, True, packet_space.NotEct, 0)
  let assert Ok(packet_space.Accepted(space, packet_space.SendImmediately)) =
    packet_space.receive(space, 8, True, packet_space.NotEct, 1)
  let assert Ok(packet_space.Duplicate(space)) =
    packet_space.receive(space, 6, True, packet_space.NotEct, 2)
  assert packet_space.received_ranges(space)
    == [frame.AckRange(10, 10), frame.AckRange(8, 8)]
  let assert Ok(#(_, Some(frame.Acknowledgement(delay, _, None)))) =
    packet_space.take_ack(space, 2, 0)
  assert delay == 0
}

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn acknowledges_packets_detects_losses_and_samples_rtt_test() -> Nil {
  let assert Ok(space) = packet_space.new(packet_space.Application, 25, 8, 8)
  let assert Ok(#(space, _)) =
    packet_space.record_sent(space, 0, True, True, 1200, [frame.Ping], ecn.Ect0)
  let assert Ok(#(space, _)) =
    packet_space.record_sent(space, 1, True, True, 1200, [frame.Ping], ecn.Ect0)
  let assert Ok(#(space, _)) =
    packet_space.record_sent(space, 2, True, True, 1200, [frame.Ping], ecn.Ect0)
  let assert Ok(#(space, sent_three)) =
    packet_space.record_sent(space, 3, True, True, 1200, [frame.Ping], ecn.Ect0)
  assert sent_three.packet_number == 3
  assert packet_space.next_packet_number(space) == 4
  assert packet_space.outstanding_count(space) == 4

  let assert Ok(estimator) = rtt.new(333)
  let acknowledgement = frame.Acknowledgement(0, [frame.AckRange(3, 3)], None)
  let assert Ok(packet_space.AckOutcome(
    space,
    estimator,
    [acked],
    [lost],
    Some(375),
  )) = packet_space.on_ack(space, acknowledgement, 0, 3, estimator, True, 1)
  assert acked.packet_number == 3
  assert lost.packet_number == 0
  assert packet_space.outstanding_count(space) == 2
  assert rtt.snapshot(estimator) == rtt.Snapshot(0, 333, 166, 0)
  assert packet_space.probe_timeout_count(space) == 0

  let assert Ok(sample_space) =
    packet_space.new(packet_space.Application, 25, 8, 8)
  let assert Ok(#(sample_space, _)) =
    packet_space.record_sent(
      sample_space,
      100,
      True,
      True,
      100,
      [frame.Ping],
      ecn.NotEct,
    )
  let assert Ok(packet_space.AckOutcome(_, sampled, [_], [], None)) =
    packet_space.on_ack(
      sample_space,
      frame.Acknowledgement(5000, [frame.AckRange(0, 0)], None),
      1,
      125,
      estimator,
      True,
      1,
    )
  assert rtt.snapshot(sampled) == rtt.Snapshot(25, 25, 12, 25)
}

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn rejects_invalid_ack_ranges_and_unsent_packets_test() -> Nil {
  let assert Ok(space) = packet_space.new(packet_space.Application, 25, 8, 8)
  let assert Ok(estimator) = rtt.new(333)
  assert packet_space.on_ack(
      space,
      frame.Acknowledgement(0, [frame.AckRange(0, 0)], None),
      0,
      0,
      estimator,
      True,
      1,
    )
    == Error(packet_space.AcknowledgesUnsentPacket)
  assert packet_space.on_ack(
      space,
      frame.Acknowledgement(
        0,
        [frame.AckRange(5, 7), frame.AckRange(7, 8)],
        None,
      ),
      0,
      0,
      estimator,
      True,
      1,
    )
    == Error(packet_space.InvalidAcknowledgement)
}

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn drives_pto_backoff_and_discards_key_spaces_test() -> Nil {
  let assert Ok(space) = packet_space.new(packet_space.Handshake, 25, 8, 8)
  let assert Ok(#(space, _)) =
    packet_space.record_sent(
      space,
      0,
      True,
      True,
      1200,
      [frame.Ping],
      ecn.NotEct,
    )
  let assert Ok(estimator) = rtt.new(100)
  assert packet_space.timer_deadline(space, estimator, False, 1)
    == Ok(Some(300))
  assert packet_space.on_timeout(space, 299, estimator, False, 1)
    == Ok(packet_space.NoTimeout(space))
  let assert Ok(packet_space.ProbeTimeout(space, 2)) =
    packet_space.on_timeout(space, 300, estimator, False, 1)
  assert packet_space.probe_timeout_count(space) == 1
  assert packet_space.timer_deadline(space, estimator, False, 1)
    == Ok(Some(600))

  let space = packet_space.discard(space)
  assert packet_space.is_discarded(space)
  assert packet_space.outstanding_count(space) == 0
  assert packet_space.record_sent(space, 301, True, True, 1, [], ecn.NotEct)
    == Error(packet_space.SpaceDiscarded)
  assert packet_space.take_ack(space, 301, 0)
    == Error(packet_space.SpaceDiscarded)
}

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn validates_configuration_and_sent_ledger_bounds_test() -> Nil {
  assert packet_space.new(packet_space.Application, -1, 8, 8)
    == Error(packet_space.InvalidInput)
  let assert Ok(space) = packet_space.new(packet_space.Application, 0, 1, 1)
  let assert Ok(#(space, _)) =
    packet_space.record_sent(space, 0, True, True, 1, [], ecn.NotEct)
  assert packet_space.record_sent(space, 0, True, True, 1, [], ecn.NotEct)
    == Error(packet_space.SentLedgerFull(1))
  let assert Ok(#(space, _)) =
    packet_space.record_sent(space, 0, False, False, 0, [], ecn.NotEct)
  assert packet_space.next_packet_number(space) == 2
}

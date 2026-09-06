import gleam/option.{None, Some}
import quic_core/frame
import quic_core/internal/ecn
import quic_core/internal/packet_space
import quic_core/internal/rtt

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
    packet_space.record_sent(
      space,
      0,
      True,
      True,
      1200,
      [frame.Ping],
      ecn.Ect0,
      False,
    )
  let assert Ok(#(space, _)) =
    packet_space.record_sent(
      space,
      1,
      True,
      True,
      1200,
      [frame.Ping],
      ecn.Ect0,
      False,
    )
  let assert Ok(#(space, _)) =
    packet_space.record_sent(
      space,
      2,
      True,
      True,
      1200,
      [frame.Ping],
      ecn.Ect0,
      False,
    )
  let assert Ok(#(space, sent_three)) =
    packet_space.record_sent(
      space,
      3,
      True,
      True,
      1200,
      [frame.Ping],
      ecn.Ect0,
      False,
    )
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
    False,
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
      False,
    )
  let assert Ok(packet_space.AckOutcome(_, sampled, [_], [], None, False)) =
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
pub fn samples_only_a_new_largest_ack_and_uses_that_packets_send_time_test() -> Nil {
  let assert Ok(estimator) = rtt.new(333)
  let assert Ok(space) = packet_space.new(packet_space.Application, 25, 8, 8)
  let space = record_ping(space, 190, False)
  let space = record_ping(space, 200, False)
  let assert Ok(packet_space.AckOutcome(space, estimator, [_], [], _, False)) =
    packet_space.on_ack(
      space,
      frame.Acknowledgement(0, [frame.AckRange(1, 1)], None),
      0,
      300,
      estimator,
      True,
      1,
    )
  assert rtt.snapshot(estimator) == rtt.Snapshot(100, 100, 50, 100)

  // Packet 1 is repeated and only older packet 0 is newly acknowledged. The
  // frame's largest packet is not new, so this ACK cannot create a second RTT
  // sample from packet 0's much older send time.
  let assert Ok(packet_space.AckOutcome(_, unchanged, [_], [], _, False)) =
    packet_space.on_ack(
      space,
      frame.Acknowledgement(0, [frame.AckRange(0, 1)], None),
      0,
      400,
      estimator,
      True,
      1,
    )
  assert rtt.snapshot(unchanged) == rtt.snapshot(estimator)

  // The largest newly acknowledged packet need not itself be ack-eliciting.
  // When another newly acknowledged packet is, RFC 9002 samples the largest
  // packet's send time, because ACK Delay describes that packet.
  let assert Ok(mixed) = packet_space.new(packet_space.Application, 25, 8, 8)
  let mixed = record_ping(mixed, 100, False)
  let assert Ok(#(mixed, _)) =
    packet_space.record_sent(
      mixed,
      200,
      False,
      True,
      100,
      [frame.Padding(1)],
      ecn.NotEct,
      False,
    )
  let assert Ok(fresh_estimator) = rtt.new(333)
  let assert Ok(packet_space.AckOutcome(_, sampled, [_, _], [], _, False)) =
    packet_space.on_ack(
      mixed,
      frame.Acknowledgement(0, [frame.AckRange(0, 1)], None),
      0,
      300,
      fresh_estimator,
      True,
      1,
    )
  assert rtt.snapshot(sampled) == rtt.Snapshot(100, 100, 50, 100)
}

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn detects_persistent_congestion_and_rejects_an_acked_interval_test() -> Nil {
  let assert Ok(estimator) = rtt.new(333)
  let assert Ok(estimator) = rtt.sample(estimator, 100, 0, 25, True)
  assert rtt.persistent_congestion_duration(estimator, 25, 1) == Ok(975)

  let assert Ok(space) = packet_space.new(packet_space.Application, 25, 8, 8)
  let assert Ok(#(space, _)) =
    packet_space.record_sent(
      space,
      300,
      True,
      True,
      100,
      [frame.Ping],
      ecn.NotEct,
      True,
    )
  let assert Ok(#(space, _)) =
    packet_space.record_sent(
      space,
      1400,
      True,
      True,
      100,
      [frame.Ping],
      ecn.NotEct,
      True,
    )
  let assert Ok(#(space, _)) =
    packet_space.record_sent(
      space,
      1900,
      True,
      True,
      100,
      [frame.Ping],
      ecn.NotEct,
      True,
    )
  let assert Ok(packet_space.AckOutcome(_, _, [_], [first, second], _, True)) =
    packet_space.on_ack(
      space,
      frame.Acknowledgement(0, [frame.AckRange(2, 2)], None),
      0,
      2000,
      estimator,
      True,
      1,
    )
  assert #(first.packet_number, second.packet_number) == #(0, 1)

  // An ACKed packet sent strictly inside the two lost boundary packets must
  // split the interval, even when it is acknowledged in the same ACK frame.
  let assert Ok(split) = packet_space.new(packet_space.Application, 25, 8, 8)
  let assert Ok(#(split, _)) =
    packet_space.record_sent(
      split,
      300,
      True,
      True,
      100,
      [frame.Ping],
      ecn.NotEct,
      True,
    )
  let assert Ok(#(split, _)) =
    packet_space.record_sent(
      split,
      800,
      True,
      True,
      100,
      [frame.Ping],
      ecn.NotEct,
      True,
    )
  let assert Ok(#(split, _)) =
    packet_space.record_sent(
      split,
      1600,
      True,
      True,
      100,
      [frame.Ping],
      ecn.NotEct,
      True,
    )
  let assert Ok(#(split, _)) =
    packet_space.record_sent(
      split,
      2100,
      True,
      True,
      100,
      [frame.Ping],
      ecn.NotEct,
      True,
    )
  let assert Ok(packet_space.AckOutcome(_, _, [_, _], [_, _], _, False)) =
    packet_space.on_ack(
      split,
      frame.Acknowledgement(
        0,
        [frame.AckRange(3, 3), frame.AckRange(1, 1)],
        None,
      ),
      0,
      2200,
      estimator,
      True,
      1,
    )
  Nil
}

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn persistent_congestion_requires_prior_rtt_and_retains_ack_boundaries_test() -> Nil {
  let assert Ok(estimator) = rtt.new(333)
  let assert Ok(estimator) = rtt.sample(estimator, 100, 0, 25, True)

  // Reading the estimator only when loss is detected is insufficient. Both
  // boundary packets remember that no sample existed at their send time, so a
  // later estimator sample cannot retroactively qualify their interval.
  let assert Ok(no_prior) = packet_space.new(packet_space.Application, 25, 8, 8)
  let no_prior = record_ping(no_prior, 300, False)
  let no_prior = record_ping(no_prior, 1400, False)
  let no_prior = record_ping(no_prior, 1900, True)
  let assert Ok(packet_space.AckOutcome(_, _, [_], [_, _], _, False)) =
    packet_space.on_ack(
      no_prior,
      frame.Acknowledgement(0, [frame.AckRange(2, 2)], None),
      0,
      2000,
      estimator,
      True,
      1,
    )

  // Packet 1 is acknowledged in an earlier ACK while packet 0 is still below
  // both loss thresholds. Its send time must remain as a bounded barrier until
  // packet 0 is resolved, otherwise a later ACK would falsely join packets 0
  // and 2 into one persistent-congestion interval.
  let assert Ok(history) = packet_space.new(packet_space.Application, 25, 8, 8)
  let history = record_ping(history, 300, True)
  let history = record_ping(history, 350, True)
  let assert Ok(packet_space.AckOutcome(history, estimator, [_], [], _, False)) =
    packet_space.on_ack(
      history,
      frame.Acknowledgement(0, [frame.AckRange(1, 1)], None),
      0,
      400,
      estimator,
      True,
      1,
    )
  let history = record_ping(history, 1400, True)
  let history = record_ping(history, 1900, True)
  let assert Ok(packet_space.AckOutcome(_, _, [_], [oldest, newest], _, False)) =
    packet_space.on_ack(
      history,
      frame.Acknowledgement(0, [frame.AckRange(3, 3)], None),
      0,
      2000,
      estimator,
      True,
      1,
    )
  assert #(oldest.packet_number, newest.packet_number) == #(0, 2)
}

fn record_ping(
  space: packet_space.State,
  now_milliseconds: Int,
  rtt_sample_available_when_sent: Bool,
) -> packet_space.State {
  let assert Ok(#(space, _)) =
    packet_space.record_sent(
      space,
      now_milliseconds,
      True,
      True,
      100,
      [frame.Ping],
      ecn.NotEct,
      rtt_sample_available_when_sent,
    )
  space
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
      False,
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
  assert packet_space.record_sent(
      space,
      301,
      True,
      True,
      1,
      [],
      ecn.NotEct,
      False,
    )
    == Error(packet_space.SpaceDiscarded)
  assert packet_space.take_ack(space, 301, 0)
    == Error(packet_space.SpaceDiscarded)
}

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn time_threshold_loss_timer_takes_precedence_over_pto_test() -> Nil {
  let assert Ok(estimator) = rtt.new(333)
  let assert Ok(estimator) = rtt.sample(estimator, 100, 0, 25, True)
  let assert Ok(space) = packet_space.new(packet_space.Application, 25, 8, 8)
  let space = record_ping(space, 0, True)
  let space = record_ping(space, 100, True)
  let space = record_ping(space, 140, True)

  // Packet 0 has crossed the time threshold; packet 1 has not. Recovery must
  // arm packet 1's remaining loss time rather than the later PTO.
  let assert Ok(packet_space.AckOutcome(
    space,
    estimator,
    [_acknowledged],
    [first_loss],
    Some(loss_deadline),
    False,
  )) =
    packet_space.on_ack(
      space,
      frame.Acknowledgement(0, [frame.AckRange(2, 2)], None),
      0,
      150,
      estimator,
      True,
      1,
    )
  assert first_loss.packet_number == 0
  assert loss_deadline == 199
  assert packet_space.timer_deadline(space, estimator, True, 1) == Ok(Some(199))
  let assert Ok(packet_space.LossTimeout(space, [second_loss], None)) =
    packet_space.on_timeout(space, 199, estimator, True, 1)
  assert second_loss.packet_number == 1
  assert packet_space.probe_timeout_count(space) == 0
}

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn retry_reset_preserves_packet_numbers_and_exposes_retransmission_test() -> Nil {
  let assert Ok(space) = packet_space.new(packet_space.Initial, 25, 8, 8)
  let crypto = frame.Crypto(0, <<"client hello">>)
  let assert Ok(#(space, _)) =
    packet_space.record_sent(
      space,
      0,
      True,
      True,
      1200,
      [crypto, frame.Padding(100)],
      ecn.NotEct,
      False,
    )
  let assert Ok(estimator) = rtt.new(100)
  let assert Ok(packet_space.ProbeTimeout(space, 2)) =
    packet_space.on_timeout(space, 300, estimator, False, 1)
  assert packet_space.outstanding_frames(space) == [crypto, frame.Padding(100)]

  let space = packet_space.reset_recovery(space)
  assert packet_space.next_packet_number(space) == 1
  assert packet_space.outstanding_count(space) == 0
  assert packet_space.probe_timeout_count(space) == 0
  assert packet_space.outstanding_frames(space) == []
}

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn validates_configuration_and_sent_ledger_bounds_test() -> Nil {
  assert packet_space.new(packet_space.Application, -1, 8, 8)
    == Error(packet_space.InvalidInput)
  let assert Ok(space) = packet_space.new(packet_space.Application, 0, 1, 1)
  let assert Ok(#(space, _)) =
    packet_space.record_sent(space, 0, True, True, 1, [], ecn.NotEct, False)
  assert packet_space.record_sent(
      space,
      0,
      True,
      True,
      1,
      [],
      ecn.NotEct,
      False,
    )
    == Error(packet_space.SentLedgerFull(1))
  let assert Ok(#(space, _)) =
    packet_space.record_sent(space, 0, False, False, 0, [], ecn.NotEct, False)
  assert packet_space.next_packet_number(space) == 2
}

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn pto_probe_recovery_reserve_is_exactly_two_packets_test() -> Nil {
  let assert Ok(space) = packet_space.new(packet_space.Application, 0, 1, 1)
  let assert Ok(#(space, _)) =
    packet_space.record_sent(
      space,
      0,
      True,
      True,
      1,
      [frame.Ping],
      ecn.NotEct,
      False,
    )

  // The ordinary bound remains closed once its single slot is occupied.
  assert packet_space.record_sent(
      space,
      1,
      True,
      True,
      1,
      [frame.Ping],
      ecn.NotEct,
      False,
    )
    == Error(packet_space.SentLedgerFull(1))

  // A PTO may consume two fixed emergency slots so both required probes can
  // remain in flight and participate in loss recovery.
  let assert Ok(#(space, first_probe)) =
    packet_space.record_probe_sent(
      space,
      1,
      True,
      True,
      1,
      [frame.Ping],
      ecn.NotEct,
      False,
    )
  let assert Ok(#(space, second_probe)) =
    packet_space.record_probe_sent(
      space,
      2,
      True,
      True,
      1,
      [frame.Ping],
      ecn.NotEct,
      False,
    )
  assert first_probe.packet_number == 1
  assert second_probe.packet_number == 2
  assert packet_space.outstanding_count(space) == 3

  // The reserve is finite: a third probe cannot grow recovery state.
  assert packet_space.record_probe_sent(
      space,
      3,
      True,
      True,
      1,
      [frame.Ping],
      ecn.NotEct,
      False,
    )
    == Error(packet_space.SentLedgerFull(3))
}

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn transfers_reliable_frame_ownership_to_a_pto_probe_test() -> Nil {
  let let_ack =
    frame.Ack(frame.Acknowledgement(0, [frame.AckRange(0, 0)], None))
  let crypto = frame.Crypto(0, <<"finished">>)
  let datagram = frame.Datagram(<<"unreliable">>)
  let control = frame.MaxData(4096)
  let assert Ok(space) = packet_space.new(packet_space.Handshake, 0, 4, 4)
  let assert Ok(#(space, _)) =
    packet_space.record_sent(
      space,
      0,
      True,
      True,
      1200,
      [let_ack, crypto, frame.Padding(8), frame.Ping],
      ecn.NotEct,
      False,
    )
  let assert Ok(#(space, _)) =
    packet_space.record_sent(
      space,
      1,
      True,
      True,
      64,
      [datagram, control],
      ecn.NotEct,
      False,
    )
  let retained = packet_space.retained_bytes(space)

  let assert #(space, Some(first)) = packet_space.take_probe_frame(space)
  assert first == crypto
  assert packet_space.outstanding_count(space) == 2
  assert packet_space.retained_bytes(space) == retained
  assert packet_space.outstanding_frames(space)
    == [let_ack, frame.Padding(8), frame.Ping, datagram, control]

  let assert #(space, Some(second)) = packet_space.take_probe_frame(space)
  assert second == control
  assert packet_space.outstanding_frames(space)
    == [let_ack, frame.Padding(8), frame.Ping, datagram]
  let assert #(_, None) = packet_space.take_probe_frame(space)
  Nil
}

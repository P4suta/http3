//// Bounded ACK scheduling and RFC 9002 recovery for one packet-number space.

import gleam/list
import gleam/option.{type Option, None, Some}
import gleam/result
import gleam_quic/frame
import gleam_quic/internal/ecn
import gleam_quic/internal/recovery
import gleam_quic/internal/rtt
import gleam_quic/varint

/// QUIC maintains independent packet numbers and ACK state at each level.
pub type Kind {
  Initial
  Handshake
  Application
}

/// ECN codepoint observed on a successfully authenticated incoming packet.
pub type ReceivedCodepoint {
  NotEct
  Ect0
  Ect1
  CongestionExperienced
}

/// The ACK action resulting from one newly authenticated packet.
pub type AckSchedule {
  NoAckScheduled
  DelayedUntil(deadline_milliseconds: Int)
  SendImmediately
}

/// Duplicate and deliberately forgotten old packets are never processed twice.
pub type Receipt {
  Accepted(State, AckSchedule)
  Duplicate(State)
}

/// Retransmission and congestion metadata retained for an outstanding packet.
pub type SentPacket {
  SentPacket(
    packet_number: Int,
    time_sent_milliseconds: Int,
    ack_eliciting: Bool,
    in_flight: Bool,
    sent_bytes: Int,
    frames: List(frame.Frame),
    ecn: ecn.Codepoint,
  )
}

/// State, path RTT, newly acknowledged packets, losses, and next loss deadline.
pub type AckOutcome {
  AckOutcome(
    State,
    rtt.Estimator,
    acknowledged: List(SentPacket),
    lost: List(SentPacket),
    next_loss_time_milliseconds: Option(Int),
  )
}

/// Result of firing this space's loss-detection timer.
pub type TimeoutOutcome {
  NoTimeout(State)
  LossTimeout(State, List(SentPacket), Option(Int))
  ProbeTimeout(State, probe_packets: Int)
}

/// A bounded packet-number space. RTT remains path-owned and is threaded in.
pub opaque type State {
  State(
    kind: Kind,
    maximum_ack_delay_milliseconds: Int,
    maximum_ack_ranges: Int,
    maximum_outstanding_packets: Int,
    received_ranges: List(frame.AckRange),
    largest_received: Option(Int),
    largest_received_at_milliseconds: Int,
    ack_eliciting_since_last_ack: Int,
    ack_deadline_milliseconds: Option(Int),
    ack_immediate: Bool,
    received_ect0: Int,
    received_ect1: Int,
    received_ce: Int,
    next_packet_number: Int,
    sent_packets: List(SentPacket),
    largest_acknowledged: Option(Int),
    loss_time_milliseconds: Option(Int),
    probe_timeout_count: Int,
    discarded: Bool,
  )
}

/// Invalid timing, capacity, ACK, or state transition.
pub type Error {
  InvalidInput
  SpaceDiscarded
  PacketNumberExhausted
  SentLedgerFull(Int)
  InvalidAcknowledgement
  AcknowledgesUnsentPacket
}

/// Configure bounded receive history and sent-packet retention.
pub fn new(
  kind: Kind,
  maximum_ack_delay_milliseconds: Int,
  maximum_ack_ranges: Int,
  maximum_outstanding_packets: Int,
) -> Result(State, Error) {
  case
    maximum_ack_delay_milliseconds >= 0
    && maximum_ack_delay_milliseconds <= varint.maximum
    && maximum_ack_ranges > 0
    && maximum_outstanding_packets > 0
  {
    False -> Error(InvalidInput)
    True ->
      Ok(State(
        kind: kind,
        maximum_ack_delay_milliseconds: maximum_ack_delay_milliseconds,
        maximum_ack_ranges: maximum_ack_ranges,
        maximum_outstanding_packets: maximum_outstanding_packets,
        received_ranges: [],
        largest_received: None,
        largest_received_at_milliseconds: 0,
        ack_eliciting_since_last_ack: 0,
        ack_deadline_milliseconds: None,
        ack_immediate: False,
        received_ect0: 0,
        received_ect1: 0,
        received_ce: 0,
        next_packet_number: 0,
        sent_packets: [],
        largest_acknowledged: None,
        loss_time_milliseconds: None,
        probe_timeout_count: 0,
        discarded: False,
      ))
  }
}

/// Record one authenticated packet and update ACK scheduling exactly once.
pub fn receive(
  state: State,
  packet_number: Int,
  ack_eliciting: Bool,
  codepoint: ReceivedCodepoint,
  now_milliseconds: Int,
) -> Result(Receipt, Error) {
  case state.discarded {
    True -> Error(SpaceDiscarded)
    False ->
      case
        packet_number >= 0
        && packet_number <= varint.maximum
        && now_milliseconds >= 0
      {
        False -> Error(InvalidInput)
        True ->
          receive_valid(
            state,
            packet_number,
            ack_eliciting,
            codepoint,
            now_milliseconds,
          )
      }
  }
}

/// Return whether an immediate or delayed ACK can be emitted now.
pub fn ack_due(state: State, now_milliseconds: Int) -> Bool {
  case state.discarded || now_milliseconds < 0 {
    True -> False
    False ->
      state.ack_immediate
      || case state.ack_deadline_milliseconds {
        Some(deadline) -> now_milliseconds >= deadline
        None -> False
      }
  }
}

/// Build an ACK_ECN when due and reset only the scheduling counters.
///
/// ACK Delay is encoded in microseconds divided by 2^ack_delay_exponent.
pub fn take_ack(
  state: State,
  now_milliseconds: Int,
  ack_delay_exponent: Int,
) -> Result(#(State, Option(frame.Acknowledgement)), Error) {
  case state.discarded {
    True -> Error(SpaceDiscarded)
    False ->
      case
        now_milliseconds >= 0
        && ack_delay_exponent >= 0
        && ack_delay_exponent <= 20
      {
        False -> Error(InvalidInput)
        True ->
          case ack_due(state, now_milliseconds) {
            False -> Ok(#(state, None))
            True -> take_due_ack(state, now_milliseconds, ack_delay_exponent)
          }
      }
  }
}

/// Return retained receive ranges in descending packet-number order.
pub fn received_ranges(state: State) -> List(frame.AckRange) {
  state.received_ranges
}

/// Apply the peer's authenticated max_ack_delay transport parameter.
pub fn update_maximum_ack_delay(
  state: State,
  maximum_milliseconds: Int,
) -> Result(State, Error) {
  case maximum_milliseconds >= 0 && maximum_milliseconds <= varint.maximum {
    True ->
      Ok(State(..state, maximum_ack_delay_milliseconds: maximum_milliseconds))
    False -> Error(InvalidInput)
  }
}

/// Allocate and retain one newly emitted packet's recovery metadata.
pub fn record_sent(
  state: State,
  now_milliseconds: Int,
  ack_eliciting: Bool,
  in_flight: Bool,
  sent_bytes: Int,
  frames: List(frame.Frame),
  codepoint: ecn.Codepoint,
) -> Result(#(State, SentPacket), Error) {
  case state.discarded {
    True -> Error(SpaceDiscarded)
    False if state.next_packet_number > varint.maximum ->
      Error(PacketNumberExhausted)
    False if now_milliseconds < 0 || sent_bytes < 0 -> Error(InvalidInput)
    False ->
      record_valid_packet(
        state,
        now_milliseconds,
        ack_eliciting,
        in_flight,
        sent_bytes,
        frames,
        codepoint,
      )
  }
}

/// Process a peer ACK, take at most one RTT sample, and classify new losses.
pub fn on_ack(
  state: State,
  acknowledgement: frame.Acknowledgement,
  ack_delay_exponent: Int,
  now_milliseconds: Int,
  estimator: rtt.Estimator,
  handshake_confirmed: Bool,
  timer_granularity_milliseconds: Int,
) -> Result(AckOutcome, Error) {
  let frame.Acknowledgement(delay, ranges, _) = acknowledgement
  case state.discarded {
    True -> Error(SpaceDiscarded)
    False ->
      case
        now_milliseconds >= 0
        && ack_delay_exponent >= 0
        && ack_delay_exponent <= 20
        && timer_granularity_milliseconds > 0
        && delay >= 0
        && delay <= varint.maximum
        && sent_before(state.sent_packets, now_milliseconds)
      {
        False -> Error(InvalidInput)
        True ->
          process_valid_ack(
            state,
            delay,
            ranges,
            ack_delay_exponent,
            now_milliseconds,
            estimator,
            handshake_confirmed,
            timer_granularity_milliseconds,
          )
      }
  }
}

/// Return the current time-threshold loss deadline or exponentially backed PTO.
pub fn timer_deadline(
  state: State,
  estimator: rtt.Estimator,
  handshake_confirmed: Bool,
  timer_granularity_milliseconds: Int,
) -> Result(Option(Int), Error) {
  case timer_granularity_milliseconds <= 0 {
    True -> Error(InvalidInput)
    False ->
      case state.discarded, state.loss_time_milliseconds {
        True, _ -> Ok(None)
        False, Some(deadline) -> Ok(Some(deadline))
        False, None ->
          probe_deadline(
            state,
            estimator,
            handshake_confirmed,
            timer_granularity_milliseconds,
          )
      }
  }
}

/// Fire a due loss timer or request two ack-eliciting probe packets.
pub fn on_timeout(
  state: State,
  now_milliseconds: Int,
  estimator: rtt.Estimator,
  handshake_confirmed: Bool,
  timer_granularity_milliseconds: Int,
) -> Result(TimeoutOutcome, Error) {
  case state.discarded {
    True -> Error(SpaceDiscarded)
    False if now_milliseconds < 0 || timer_granularity_milliseconds <= 0 ->
      Error(InvalidInput)
    False -> {
      use deadline <- result.try(timer_deadline(
        state,
        estimator,
        handshake_confirmed,
        timer_granularity_milliseconds,
      ))
      case deadline {
        None -> Ok(NoTimeout(state))
        Some(deadline) if now_milliseconds < deadline -> Ok(NoTimeout(state))
        Some(_) ->
          fire_timeout(
            state,
            now_milliseconds,
            estimator,
            timer_granularity_milliseconds,
          )
      }
    }
  }
}

/// Irreversibly clear packet history when the corresponding keys are dropped.
pub fn discard(state: State) -> State {
  State(
    ..state,
    received_ranges: [],
    sent_packets: [],
    ack_eliciting_since_last_ack: 0,
    ack_deadline_milliseconds: None,
    ack_immediate: False,
    loss_time_milliseconds: None,
    discarded: True,
  )
}

/// Return the packet number that the next successful send will consume.
pub fn next_packet_number(state: State) -> Int {
  state.next_packet_number
}

/// Reconstruct the next received packet number from the largest accepted one.
pub fn expected_packet_number(state: State) -> Int {
  case state.largest_received {
    None -> 0
    Some(largest) -> largest + 1
  }
}

/// Largest packet number acknowledged by the peer in this space, if any.
pub fn largest_acknowledged(state: State) -> Option(Int) {
  state.largest_acknowledged
}

/// Return the number of retained ack-eliciting or in-flight packets.
pub fn outstanding_count(state: State) -> Int {
  list.length(state.sent_packets)
}

/// Return this space's current exponential PTO backoff count.
pub fn probe_timeout_count(state: State) -> Int {
  state.probe_timeout_count
}

/// Return whether packet protection and recovery state were discarded.
pub fn is_discarded(state: State) -> Bool {
  state.discarded
}

fn receive_valid(
  state: State,
  packet_number: Int,
  ack_eliciting: Bool,
  codepoint: ReceivedCodepoint,
  now_milliseconds: Int,
) -> Result(Receipt, Error) {
  let #(inserted, was_new) =
    insert_received(
      state.received_ranges,
      packet_number,
      state.maximum_ack_ranges,
    )
  case was_new {
    False -> Ok(Duplicate(state))
    True -> {
      let out_of_order = case state.largest_received {
        Some(largest) -> packet_number < largest
        None -> False
      }
      let #(largest, largest_at) = case state.largest_received {
        Some(previous) if packet_number <= previous -> #(
          state.largest_received,
          state.largest_received_at_milliseconds,
        )
        _ -> #(Some(packet_number), now_milliseconds)
      }
      let ack_eliciting_count =
        state.ack_eliciting_since_last_ack
        + case ack_eliciting {
          True -> 1
          False -> 0
        }
      let state =
        State(
          ..state,
          received_ranges: inserted,
          largest_received: largest,
          largest_received_at_milliseconds: largest_at,
          ack_eliciting_since_last_ack: ack_eliciting_count,
        )
        |> record_received_ecn(codepoint)
      let state =
        schedule_ack(
          state,
          ack_eliciting,
          out_of_order,
          codepoint == CongestionExperienced,
          now_milliseconds,
        )
      Ok(Accepted(state, current_schedule(state)))
    }
  }
}

fn schedule_ack(
  state: State,
  ack_eliciting: Bool,
  out_of_order: Bool,
  congestion_experienced: Bool,
  now_milliseconds: Int,
) -> State {
  let immediate =
    state.ack_immediate
    || out_of_order
    || congestion_experienced
    || { state.kind != Application && ack_eliciting }
    || state.ack_eliciting_since_last_ack >= 2
  case immediate {
    True -> State(..state, ack_deadline_milliseconds: None, ack_immediate: True)
    False if !ack_eliciting -> state
    False -> {
      let deadline = case state.ack_deadline_milliseconds {
        Some(existing) -> Some(existing)
        None -> Some(now_milliseconds + state.maximum_ack_delay_milliseconds)
      }
      State(..state, ack_deadline_milliseconds: deadline)
    }
  }
}

fn current_schedule(state: State) -> AckSchedule {
  case state.ack_immediate, state.ack_deadline_milliseconds {
    True, _ -> SendImmediately
    False, Some(deadline) -> DelayedUntil(deadline)
    False, None -> NoAckScheduled
  }
}

fn record_received_ecn(state: State, codepoint: ReceivedCodepoint) -> State {
  case codepoint {
    NotEct -> state
    Ect0 -> State(..state, received_ect0: state.received_ect0 + 1)
    Ect1 -> State(..state, received_ect1: state.received_ect1 + 1)
    CongestionExperienced -> State(..state, received_ce: state.received_ce + 1)
  }
}

fn take_due_ack(
  state: State,
  now_milliseconds: Int,
  ack_delay_exponent: Int,
) -> Result(#(State, Option(frame.Acknowledgement)), Error) {
  case state.received_ranges {
    [] -> Ok(#(reset_ack_schedule(state), None))
    ranges -> {
      use delay <- result.try(encoded_ack_delay(
        state,
        now_milliseconds,
        ack_delay_exponent,
      ))
      Ok(#(
        reset_ack_schedule(state),
        Some(frame.Acknowledgement(delay, ranges, received_ecn_counts(state))),
      ))
    }
  }
}

fn encoded_ack_delay(
  state: State,
  now_milliseconds: Int,
  ack_delay_exponent: Int,
) -> Result(Int, Error) {
  case state.kind {
    Initial | Handshake -> Ok(0)
    Application -> {
      let elapsed = now_milliseconds - state.largest_received_at_milliseconds
      case elapsed < 0 {
        True -> Error(InvalidInput)
        False ->
          Ok(minimum(
            elapsed * 1000 / power_of_two(ack_delay_exponent),
            varint.maximum,
          ))
      }
    }
  }
}

fn received_ecn_counts(state: State) -> Option(frame.EcnCounts) {
  case state.received_ect0 + state.received_ect1 + state.received_ce {
    0 -> None
    _ ->
      Some(frame.EcnCounts(
        state.received_ect0,
        state.received_ect1,
        state.received_ce,
      ))
  }
}

fn reset_ack_schedule(state: State) -> State {
  State(
    ..state,
    ack_eliciting_since_last_ack: 0,
    ack_deadline_milliseconds: None,
    ack_immediate: False,
  )
}

fn insert_received(
  ranges: List(frame.AckRange),
  packet_number: Int,
  maximum_ranges: Int,
) -> #(List(frame.AckRange), Bool) {
  let #(inserted, was_new) = insert_number(ranges, packet_number)
  let bounded = take_ranges(inserted, maximum_ranges, [])
  #(bounded, was_new && range_contains(bounded, packet_number))
}

fn insert_number(
  ranges: List(frame.AckRange),
  packet_number: Int,
) -> #(List(frame.AckRange), Bool) {
  case ranges {
    [] -> #([frame.AckRange(packet_number, packet_number)], True)
    [frame.AckRange(smallest, largest) as current, ..rest] ->
      case Nil {
        _ if packet_number > largest + 1 -> #(
          [frame.AckRange(packet_number, packet_number), current, ..rest],
          True,
        )
        _ if packet_number == largest + 1 -> #(
          [frame.AckRange(smallest, packet_number), ..rest],
          True,
        )
        _ if packet_number >= smallest -> #(ranges, False)
        _ if packet_number == smallest - 1 ->
          case rest {
            [frame.AckRange(next_smallest, next_largest), ..tail]
              if next_largest == packet_number - 1
            -> #([frame.AckRange(next_smallest, largest), ..tail], True)
            _ -> #([frame.AckRange(packet_number, largest), ..rest], True)
          }
        _ -> {
          let #(lower, was_new) = insert_number(rest, packet_number)
          #([current, ..lower], was_new)
        }
      }
  }
}

fn take_ranges(
  ranges: List(frame.AckRange),
  remaining: Int,
  reversed: List(frame.AckRange),
) -> List(frame.AckRange) {
  case remaining, ranges {
    0, _ | _, [] -> list.reverse(reversed)
    count, [range, ..rest] -> take_ranges(rest, count - 1, [range, ..reversed])
  }
}

fn range_contains(ranges: List(frame.AckRange), packet_number: Int) -> Bool {
  list.any(ranges, fn(range) {
    let frame.AckRange(smallest, largest) = range
    packet_number >= smallest && packet_number <= largest
  })
}

fn record_valid_packet(
  state: State,
  now_milliseconds: Int,
  ack_eliciting: Bool,
  in_flight: Bool,
  sent_bytes: Int,
  frames: List(frame.Frame),
  codepoint: ecn.Codepoint,
) -> Result(#(State, SentPacket), Error) {
  let packet =
    SentPacket(
      packet_number: state.next_packet_number,
      time_sent_milliseconds: now_milliseconds,
      ack_eliciting: ack_eliciting,
      in_flight: in_flight,
      sent_bytes: sent_bytes,
      frames: frames,
      ecn: codepoint,
    )
  let retained = ack_eliciting || in_flight
  case
    retained
    && list.length(state.sent_packets) >= state.maximum_outstanding_packets
  {
    True -> Error(SentLedgerFull(state.maximum_outstanding_packets))
    False -> {
      let sent_packets = case retained {
        True -> list.append(state.sent_packets, [packet])
        False -> state.sent_packets
      }
      Ok(#(
        State(
          ..state,
          next_packet_number: state.next_packet_number + 1,
          sent_packets: sent_packets,
        ),
        packet,
      ))
    }
  }
}

fn process_valid_ack(
  state: State,
  encoded_delay: Int,
  ranges: List(frame.AckRange),
  ack_delay_exponent: Int,
  now_milliseconds: Int,
  estimator: rtt.Estimator,
  handshake_confirmed: Bool,
  timer_granularity_milliseconds: Int,
) -> Result(AckOutcome, Error) {
  case valid_ack_ranges(ranges), ranges {
    False, _ | True, [] -> Error(InvalidAcknowledgement)
    True, [frame.AckRange(_, largest), ..] ->
      process_acknowledgement(
        state,
        encoded_delay,
        ranges,
        largest,
        ack_delay_exponent,
        now_milliseconds,
        estimator,
        handshake_confirmed,
        timer_granularity_milliseconds,
      )
  }
}

fn process_acknowledgement(
  state: State,
  encoded_delay: Int,
  ranges: List(frame.AckRange),
  largest: Int,
  ack_delay_exponent: Int,
  now_milliseconds: Int,
  estimator: rtt.Estimator,
  handshake_confirmed: Bool,
  timer_granularity_milliseconds: Int,
) -> Result(AckOutcome, Error) {
  case largest >= state.next_packet_number {
    True -> Error(AcknowledgesUnsentPacket)
    False -> {
      let #(acknowledged, remaining) =
        partition_acknowledged(state.sent_packets, ranges, [], [])
      use estimator <- result.try(update_rtt(
        estimator,
        acknowledged,
        state.kind,
        encoded_delay,
        ack_delay_exponent,
        now_milliseconds,
        state.maximum_ack_delay_milliseconds,
        handshake_confirmed,
      ))
      let largest_acknowledged =
        maximum_option(state.largest_acknowledged, largest)
      let state =
        State(
          ..state,
          sent_packets: remaining,
          largest_acknowledged: Some(largest_acknowledged),
          probe_timeout_count: reset_probe_count(
            state.probe_timeout_count,
            acknowledged,
          ),
        )
      use #(state, lost, next_loss_time) <- result.try(detect_losses(
        state,
        largest_acknowledged,
        now_milliseconds,
        estimator,
        timer_granularity_milliseconds,
      ))
      Ok(AckOutcome(state, estimator, acknowledged, lost, next_loss_time))
    }
  }
}

fn reset_probe_count(current: Int, acknowledged: List(SentPacket)) -> Int {
  case has_ack_eliciting(acknowledged) {
    True -> 0
    False -> current
  }
}

fn valid_ack_ranges(ranges: List(frame.AckRange)) -> Bool {
  case ranges {
    [] -> False
    [first, ..rest] -> {
      let frame.AckRange(smallest, largest) = first
      smallest >= 0
      && smallest <= largest
      && largest <= varint.maximum
      && valid_lower_ranges(rest, smallest)
    }
  }
}

fn valid_lower_ranges(
  ranges: List(frame.AckRange),
  previous_smallest: Int,
) -> Bool {
  case ranges {
    [] -> True
    [frame.AckRange(smallest, largest), ..rest] ->
      smallest >= 0
      && smallest <= largest
      && largest <= previous_smallest - 2
      && valid_lower_ranges(rest, smallest)
  }
}

fn partition_acknowledged(
  packets: List(SentPacket),
  ranges: List(frame.AckRange),
  acknowledged_reversed: List(SentPacket),
  remaining_reversed: List(SentPacket),
) -> #(List(SentPacket), List(SentPacket)) {
  case packets {
    [] -> #(
      list.reverse(acknowledged_reversed),
      list.reverse(remaining_reversed),
    )
    [packet, ..rest] ->
      case range_contains(ranges, packet.packet_number) {
        True ->
          partition_acknowledged(
            rest,
            ranges,
            [packet, ..acknowledged_reversed],
            remaining_reversed,
          )
        False ->
          partition_acknowledged(rest, ranges, acknowledged_reversed, [
            packet,
            ..remaining_reversed
          ])
      }
  }
}

fn update_rtt(
  estimator: rtt.Estimator,
  acknowledged: List(SentPacket),
  kind: Kind,
  encoded_delay: Int,
  ack_delay_exponent: Int,
  now_milliseconds: Int,
  maximum_ack_delay_milliseconds: Int,
  handshake_confirmed: Bool,
) -> Result(rtt.Estimator, Error) {
  case largest_ack_eliciting(acknowledged, None) {
    None -> Ok(estimator)
    Some(packet) ->
      sample_acknowledged_packet(
        estimator,
        packet,
        kind,
        encoded_delay,
        ack_delay_exponent,
        now_milliseconds,
        maximum_ack_delay_milliseconds,
        handshake_confirmed,
      )
  }
}

fn sample_acknowledged_packet(
  estimator: rtt.Estimator,
  packet: SentPacket,
  kind: Kind,
  encoded_delay: Int,
  ack_delay_exponent: Int,
  now_milliseconds: Int,
  maximum_ack_delay_milliseconds: Int,
  handshake_confirmed: Bool,
) -> Result(rtt.Estimator, Error) {
  let latest = now_milliseconds - packet.time_sent_milliseconds
  case latest <= 0 {
    True -> Ok(estimator)
    False -> {
      let delay = decoded_ack_delay(kind, encoded_delay, ack_delay_exponent)
      case
        rtt.sample(
          estimator,
          latest,
          delay,
          maximum_ack_delay_milliseconds,
          handshake_confirmed,
        )
      {
        Ok(updated) -> Ok(updated)
        Error(_) -> Error(InvalidInput)
      }
    }
  }
}

fn decoded_ack_delay(kind: Kind, encoded: Int, exponent: Int) -> Int {
  case kind {
    Initial | Handshake -> 0
    Application -> encoded * power_of_two(exponent) / 1000
  }
}

fn largest_ack_eliciting(
  packets: List(SentPacket),
  largest: Option(SentPacket),
) -> Option(SentPacket) {
  case packets {
    [] -> largest
    [packet, ..rest] -> {
      let next = case packet.ack_eliciting, largest {
        False, _ -> largest
        True, None -> Some(packet)
        True, Some(previous) if packet.packet_number > previous.packet_number ->
          Some(packet)
        True, Some(_) -> largest
      }
      largest_ack_eliciting(rest, next)
    }
  }
}

fn has_ack_eliciting(packets: List(SentPacket)) -> Bool {
  list.any(packets, fn(packet) { packet.ack_eliciting })
}

fn detect_losses(
  state: State,
  largest_acknowledged: Int,
  now_milliseconds: Int,
  estimator: rtt.Estimator,
  timer_granularity_milliseconds: Int,
) -> Result(#(State, List(SentPacket), Option(Int)), Error) {
  let recovery_packets = list.map(state.sent_packets, to_recovery_packet)
  case
    recovery.detect(
      recovery_packets,
      largest_acknowledged,
      now_milliseconds,
      estimator,
      timer_granularity_milliseconds,
    )
  {
    Error(_) -> Error(InvalidInput)
    Ok(recovery.Detection(lost_metadata, _, next_loss_time)) -> {
      let #(lost, remaining) =
        partition_lost(state.sent_packets, lost_metadata, [], [])
      Ok(#(
        State(
          ..state,
          sent_packets: remaining,
          loss_time_milliseconds: next_loss_time,
        ),
        lost,
        next_loss_time,
      ))
    }
  }
}

fn to_recovery_packet(packet: SentPacket) -> recovery.SentPacket {
  recovery.SentPacket(
    packet.packet_number,
    packet.time_sent_milliseconds,
    packet.ack_eliciting,
    packet.in_flight,
    packet.sent_bytes,
  )
}

fn partition_lost(
  packets: List(SentPacket),
  lost_metadata: List(recovery.SentPacket),
  lost_reversed: List(SentPacket),
  remaining_reversed: List(SentPacket),
) -> #(List(SentPacket), List(SentPacket)) {
  case packets {
    [] -> #(list.reverse(lost_reversed), list.reverse(remaining_reversed))
    [packet, ..rest] ->
      case recovery_contains(lost_metadata, packet.packet_number) {
        True ->
          partition_lost(
            rest,
            lost_metadata,
            [packet, ..lost_reversed],
            remaining_reversed,
          )
        False ->
          partition_lost(rest, lost_metadata, lost_reversed, [
            packet,
            ..remaining_reversed
          ])
      }
  }
}

fn recovery_contains(
  packets: List(recovery.SentPacket),
  packet_number: Int,
) -> Bool {
  list.any(packets, fn(packet) { packet.packet_number == packet_number })
}

fn probe_deadline(
  state: State,
  estimator: rtt.Estimator,
  handshake_confirmed: Bool,
  timer_granularity_milliseconds: Int,
) -> Result(Option(Int), Error) {
  case latest_in_flight_ack_eliciting(state.sent_packets, None) {
    None -> Ok(None)
    Some(packet) -> {
      let application_data = state.kind == Application && handshake_confirmed
      case
        rtt.probe_timeout(
          estimator,
          state.maximum_ack_delay_milliseconds,
          application_data,
          state.probe_timeout_count,
          timer_granularity_milliseconds,
        )
      {
        Ok(duration) -> Ok(Some(packet.time_sent_milliseconds + duration))
        Error(_) -> Error(InvalidInput)
      }
    }
  }
}

fn latest_in_flight_ack_eliciting(
  packets: List(SentPacket),
  latest: Option(SentPacket),
) -> Option(SentPacket) {
  case packets {
    [] -> latest
    [packet, ..rest] -> {
      let next = case packet.ack_eliciting && packet.in_flight, latest {
        False, _ -> latest
        True, None -> Some(packet)
        True, Some(previous)
          if packet.time_sent_milliseconds >= previous.time_sent_milliseconds
        -> Some(packet)
        True, Some(_) -> latest
      }
      latest_in_flight_ack_eliciting(rest, next)
    }
  }
}

fn fire_timeout(
  state: State,
  now_milliseconds: Int,
  estimator: rtt.Estimator,
  timer_granularity_milliseconds: Int,
) -> Result(TimeoutOutcome, Error) {
  case state.loss_time_milliseconds, state.largest_acknowledged {
    Some(loss_time), Some(largest) if now_milliseconds >= loss_time -> {
      use #(state, lost, next_loss_time) <- result.try(detect_losses(
        state,
        largest,
        now_milliseconds,
        estimator,
        timer_granularity_milliseconds,
      ))
      Ok(LossTimeout(state, lost, next_loss_time))
    }
    _, _ if state.probe_timeout_count >= 62 -> Error(InvalidInput)
    _, _ ->
      Ok(ProbeTimeout(
        State(..state, probe_timeout_count: state.probe_timeout_count + 1),
        2,
      ))
  }
}

fn sent_before(packets: List(SentPacket), now_milliseconds: Int) -> Bool {
  list.all(packets, fn(packet) {
    packet.time_sent_milliseconds <= now_milliseconds
  })
}

fn maximum_option(existing: Option(Int), candidate: Int) -> Int {
  case existing {
    Some(value) if value > candidate -> value
    _ -> candidate
  }
}

fn power_of_two(exponent: Int) -> Int {
  case exponent {
    0 -> 1
    _ -> 2 * power_of_two(exponent - 1)
  }
}

fn minimum(left: Int, right: Int) -> Int {
  case left < right {
    True -> left
    False -> right
  }
}

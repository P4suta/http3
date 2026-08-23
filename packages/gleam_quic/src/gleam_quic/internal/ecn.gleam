//// RFC 9000 per-path ECN capability and cumulative-count validation.

import gleam/option.{type Option, None, Some}
import gleam_quic/varint

/// IP ECN codepoint applied to outgoing packets.
pub type Codepoint {
  NotEct
  Ect0
  Ect1
}

/// Path ECN validation progress.
pub type Phase {
  Testing
  Unknown
  Capable
  Failed
}

/// Peer cumulative ACK_ECN counters.
pub type Counts {
  Counts(ect0: Int, ect1: Int, congestion_experienced: Int)
}

/// Newly acknowledged packets by their original ECT marking.
pub type Acknowledged {
  Acknowledged(ect0: Int, ect1: Int)
}

/// Validated state plus newly reported CE packets for congestion control.
pub type AckResult {
  AckResult(state: State, newly_congestion_experienced: Int)
}

/// Per-path sent totals and last accepted peer counters.
pub opaque type State {
  State(
    phase: Phase,
    sent_ect0: Int,
    sent_ect1: Int,
    marked_sent: Int,
    validation_probe_timeouts: Int,
    largest_acknowledged: Int,
    peer_counts: Counts,
  )
}

/// Invalid count or packet-number input.
pub type Error {
  InvalidInput
}

/// Begin the RFC sample algorithm in testing state.
pub fn new() -> State {
  State(Testing, 0, 0, 0, 0, -1, Counts(0, 0, 0))
}

/// Account for outgoing packet markings on this path.
pub fn record_sent(
  state: State,
  codepoint: Codepoint,
  packet_count: Int,
) -> Result(State, Error) {
  case packet_count < 0 {
    True -> Error(InvalidInput)
    False -> {
      let ect0 = case codepoint {
        Ect0 -> state.sent_ect0 + packet_count
        _ -> state.sent_ect0
      }
      let ect1 = case codepoint {
        Ect1 -> state.sent_ect1 + packet_count
        _ -> state.sent_ect1
      }
      let marked = case codepoint {
        Ect0 | Ect1 -> state.marked_sent + packet_count
        NotEct -> state.marked_sent
      }
      let next_phase = case state.phase == Testing && marked >= 10 {
        True -> Unknown
        False -> state.phase
      }
      Ok(
        State(
          ..state,
          phase: next_phase,
          sent_ect0: ect0,
          sent_ect1: ect1,
          marked_sent: marked,
        ),
      )
    }
  }
}

/// Stop the initial ECN experiment after three probe timeouts without proof.
pub fn on_probe_timeout(state: State) -> State {
  case state.phase {
    Testing -> {
      let timeouts = state.validation_probe_timeouts + 1
      State(
        ..state,
        phase: case timeouts >= 3 {
          True -> Unknown
          False -> Testing
        },
        validation_probe_timeouts: timeouts,
      )
    }
    _ -> state
  }
}

/// Validate one ACK's ECN section against newly acknowledged markings.
pub fn on_ack(
  state: State,
  largest_acknowledged: Int,
  acknowledged: Acknowledged,
  feedback: Option(Counts),
) -> Result(AckResult, Error) {
  let Acknowledged(acked_ect0, acked_ect1) = acknowledged
  case
    largest_acknowledged < 0
    || largest_acknowledged > varint.maximum
    || acked_ect0 < 0
    || acked_ect1 < 0
  {
    True -> Error(InvalidInput)
    False if largest_acknowledged <= state.largest_acknowledged ->
      Ok(AckResult(state, 0))
    False ->
      Ok(validate_new_ack(
        state,
        largest_acknowledged,
        acked_ect0,
        acked_ect1,
        feedback,
      ))
  }
}

/// Return whether this path may send ECT-marked packets.
pub fn phase(state: State) -> Phase {
  state.phase
}

fn validate_new_ack(
  state: State,
  largest_acknowledged: Int,
  acknowledged_ect0: Int,
  acknowledged_ect1: Int,
  feedback: Option(Counts),
) -> AckResult {
  case state.phase {
    Failed -> AckResult(state, 0)
    _ -> {
      let acknowledged_marked = acknowledged_ect0 + acknowledged_ect1
      case feedback {
        None if acknowledged_marked > 0 -> AckResult(fail(state), 0)
        None ->
          AckResult(
            State(..state, largest_acknowledged: largest_acknowledged),
            0,
          )
        Some(counts) ->
          validate_counts(
            state,
            largest_acknowledged,
            acknowledged_ect0,
            acknowledged_ect1,
            counts,
          )
      }
    }
  }
}

fn validate_counts(
  state: State,
  largest_acknowledged: Int,
  acknowledged_ect0: Int,
  acknowledged_ect1: Int,
  counts: Counts,
) -> AckResult {
  let Counts(previous_ect0, previous_ect1, previous_ce) = state.peer_counts
  let Counts(ect0, ect1, ce) = counts
  let delta_ect0 = ect0 - previous_ect0
  let delta_ect1 = ect1 - previous_ect1
  let delta_ce = ce - previous_ce
  case
    valid_counts(counts)
    && delta_ect0 >= 0
    && delta_ect1 >= 0
    && delta_ce >= 0
    && ect0 <= state.sent_ect0
    && ect1 <= state.sent_ect1
    && ect0 + ect1 + ce <= state.marked_sent
    && delta_ect0 + delta_ce >= acknowledged_ect0
    && delta_ect1 + delta_ce >= acknowledged_ect1
  {
    False -> AckResult(fail(state), 0)
    True -> {
      let validated_phase = case acknowledged_ect0 + acknowledged_ect1 > 0 {
        True -> Capable
        False -> state.phase
      }
      AckResult(
        State(
          ..state,
          phase: validated_phase,
          largest_acknowledged: largest_acknowledged,
          peer_counts: counts,
        ),
        delta_ce,
      )
    }
  }
}

fn valid_counts(counts: Counts) -> Bool {
  counts.ect0 >= 0
  && counts.ect0 <= varint.maximum
  && counts.ect1 >= 0
  && counts.ect1 <= varint.maximum
  && counts.congestion_experienced >= 0
  && counts.congestion_experienced <= varint.maximum
}

fn fail(state: State) -> State {
  State(..state, phase: Failed)
}

//// RFC 9001 1-RTT key-phase update and old-read-key retention model.

import gleam/option.{type Option, None, Some}
import gleam/result
import gleam_quic/internal/traffic_keys
import gleam_quic/varint

/// The protected short-header Key Phase bit.
pub type KeyPhase {
  PhaseZero
  PhaseOne
}

/// Why a particular read key is a candidate for packet authentication.
pub type CandidateKind {
  Current
  Next
  Previous
}

/// One ordered authentication candidate. Key material remains internal.
pub type ReadCandidate {
  ReadCandidate(kind: CandidateKind, keys: traffic_keys.TrafficKeys)
}

type PreviousReadKeys {
  PreviousReadKeys(
    phase: KeyPhase,
    keys: traffic_keys.TrafficKeys,
    discard_at_milliseconds: Int,
  )
}

/// Synchronized local and peer 1-RTT key generations.
pub opaque type State {
  State(
    phase: KeyPhase,
    write_keys: traffic_keys.TrafficKeys,
    read_keys: traffic_keys.TrafficKeys,
    next_read_keys: traffic_keys.TrafficKeys,
    previous_read_keys: Option(PreviousReadKeys),
    handshake_confirmed: Bool,
    first_sent_in_phase: Option(Int),
    current_phase_acknowledged: Bool,
    earliest_next_update_milliseconds: Int,
    first_received_in_phase: Option(Int),
    largest_received: Int,
  )
}

/// A key-update state or derivation failure.
pub type Error {
  InvalidInput
  KeyMismatch
  HandshakeNotConfirmed
  UpdateNotAcknowledged
  UpdateTooSoon(Int)
  UnexpectedKeyPhase
  PacketNumberRollback
  TrafficKeyFailure(traffic_keys.Error)
}

/// Install the initial generation of directional 1-RTT traffic keys.
pub fn new(
  write_keys: traffic_keys.TrafficKeys,
  read_keys: traffic_keys.TrafficKeys,
) -> Result(State, Error) {
  case
    write_keys.version == read_keys.version
    && write_keys.cipher_suite == read_keys.cipher_suite
  {
    False -> Error(KeyMismatch)
    True -> {
      use next_read_keys <- result.try(advance(read_keys))
      Ok(State(
        phase: PhaseZero,
        write_keys: write_keys,
        read_keys: read_keys,
        next_read_keys: next_read_keys,
        previous_read_keys: None,
        handshake_confirmed: False,
        first_sent_in_phase: None,
        current_phase_acknowledged: True,
        earliest_next_update_milliseconds: 0,
        first_received_in_phase: None,
        largest_received: -1,
      ))
    }
  }
}

/// Permit updates after QUIC handshake confirmation.
pub fn confirm_handshake(state: State) -> State {
  State(..state, handshake_confirmed: True)
}

/// Initiate a local key update and retain old read keys for three PTOs.
pub fn initiate(
  state: State,
  first_packet_number first_packet_number: Int,
  now_milliseconds now_milliseconds: Int,
  probe_timeout_milliseconds probe_timeout_milliseconds: Int,
) -> Result(State, Error) {
  use Nil <- result.try(validate_transition_input(
    first_packet_number,
    now_milliseconds,
    probe_timeout_milliseconds,
  ))
  use Nil <- result.try(require_update_allowed(state, now_milliseconds))
  use next_write_keys <- result.try(advance(state.write_keys))
  let next_phase = toggle(state.phase)
  use next_next_read_keys <- result.try(advance(state.next_read_keys))
  let discard_at = now_milliseconds + { 3 * probe_timeout_milliseconds }
  Ok(
    State(
      ..state,
      phase: next_phase,
      write_keys: next_write_keys,
      read_keys: state.next_read_keys,
      next_read_keys: next_next_read_keys,
      previous_read_keys: Some(PreviousReadKeys(
        state.phase,
        state.read_keys,
        discard_at,
      )),
      first_sent_in_phase: Some(first_packet_number),
      current_phase_acknowledged: False,
      earliest_next_update_milliseconds: discard_at,
      first_received_in_phase: None,
    ),
  )
}

/// Record the first locally sent packet after responding to a peer update.
pub fn record_sent(
  state: State,
  packet_number packet_number: Int,
) -> Result(State, Error) {
  case valid_packet_number(packet_number) {
    False -> Error(InvalidInput)
    True -> {
      let first_sent = case state.first_sent_in_phase {
        None -> Some(packet_number)
        existing -> existing
      }
      Ok(State(..state, first_sent_in_phase: first_sent))
    }
  }
}

/// Observe an acknowledgment and unlock the next generation when applicable.
pub fn acknowledge(state: State, packet_number: Int) -> State {
  case state.first_sent_in_phase {
    Some(first) if packet_number >= first ->
      State(..state, current_phase_acknowledged: True)
    _ -> state
  }
}

/// Return read-key candidates without committing a peer-initiated update.
pub fn read_candidates(
  state: State,
  observed_phase: KeyPhase,
  packet_number: Int,
  now_milliseconds: Int,
) -> List(ReadCandidate) {
  case valid_packet_number(packet_number) && now_milliseconds >= 0 {
    False -> []
    True ->
      candidate_for_valid_packet(
        state,
        observed_phase,
        packet_number,
        now_milliseconds,
      )
  }
}

/// Commit a peer update only after the `Next` candidate authenticated.
pub fn commit_peer_update(
  state: State,
  observed_phase observed_phase: KeyPhase,
  packet_number packet_number: Int,
  now_milliseconds now_milliseconds: Int,
  probe_timeout_milliseconds probe_timeout_milliseconds: Int,
) -> Result(State, Error) {
  use Nil <- result.try(validate_transition_input(
    packet_number,
    now_milliseconds,
    probe_timeout_milliseconds,
  ))
  case observed_phase == state.phase {
    True -> Error(UnexpectedKeyPhase)
    False ->
      commit_distinct_peer_phase(
        state,
        observed_phase,
        packet_number,
        now_milliseconds,
        probe_timeout_milliseconds,
      )
  }
}

/// Record a successfully authenticated packet in the current phase.
pub fn record_received(
  state: State,
  packet_number packet_number: Int,
) -> Result(State, Error) {
  case valid_packet_number(packet_number) {
    False -> Error(InvalidInput)
    True -> {
      let first_received = case state.first_received_in_phase {
        None -> Some(packet_number)
        existing -> existing
      }
      let largest = case packet_number > state.largest_received {
        True -> packet_number
        False -> state.largest_received
      }
      Ok(
        State(
          ..state,
          first_received_in_phase: first_received,
          largest_received: largest,
        ),
      )
    }
  }
}

/// Return the Key Phase bit for outgoing short-header packets.
pub fn phase(state: State) -> KeyPhase {
  state.phase
}

/// Return the candidate category without exposing key fields to callers.
pub fn candidate_kind(candidate: ReadCandidate) -> CandidateKind {
  candidate.kind
}

/// Return candidate packet keys to the internal packet-protection adapter.
pub fn candidate_keys(candidate: ReadCandidate) -> traffic_keys.TrafficKeys {
  candidate.keys
}

/// Return current write keys without exposing them outside the internal core.
pub fn write_keys(state: State) -> traffic_keys.TrafficKeys {
  state.write_keys
}

/// Return current read keys to synchronize the connection's directional set.
pub fn read_keys(state: State) -> traffic_keys.TrafficKeys {
  state.read_keys
}

/// Bounded key set used to remove short-header protection. Authentication and
/// packet-number rules are checked separately before a phase transition.
pub fn decryption_candidates(
  state: State,
  now_milliseconds: Int,
) -> List(ReadCandidate) {
  let current = ReadCandidate(Current, state.read_keys)
  let next = ReadCandidate(Next, state.next_read_keys)
  case state.previous_read_keys {
    Some(PreviousReadKeys(_, keys, discard_at))
      if now_milliseconds >= 0 && now_milliseconds < discard_at
    -> [current, next, ReadCandidate(Previous, keys)]
    _ -> [current, next]
  }
}

fn candidate_for_valid_packet(
  state: State,
  observed_phase: KeyPhase,
  packet_number: Int,
  now_milliseconds: Int,
) -> List(ReadCandidate) {
  case observed_phase == state.phase {
    True -> [ReadCandidate(Current, state.read_keys)]
    False ->
      distinct_phase_candidates(
        state,
        observed_phase,
        packet_number,
        now_milliseconds,
      )
  }
}

fn distinct_phase_candidates(
  state: State,
  observed_phase: KeyPhase,
  packet_number: Int,
  now_milliseconds: Int,
) -> List(ReadCandidate) {
  case
    usable_previous(
      state.previous_read_keys,
      observed_phase,
      packet_number,
      state.first_received_in_phase,
      now_milliseconds,
    )
  {
    Some(keys) -> [ReadCandidate(Previous, keys)]
    None ->
      case packet_number <= state.largest_received {
        True -> []
        False -> [ReadCandidate(Next, state.next_read_keys)]
      }
  }
}

fn usable_previous(
  previous: Option(PreviousReadKeys),
  observed_phase: KeyPhase,
  packet_number: Int,
  first_received: Option(Int),
  now_milliseconds: Int,
) -> Option(traffic_keys.TrafficKeys) {
  case previous {
    Some(PreviousReadKeys(phase, keys, discard_at))
      if phase == observed_phase && now_milliseconds < discard_at
    ->
      case first_received {
        None -> Some(keys)
        Some(first) if packet_number < first -> Some(keys)
        Some(_) -> None
      }
    _ -> None
  }
}

fn commit_distinct_peer_phase(
  state: State,
  observed_phase: KeyPhase,
  packet_number: Int,
  now_milliseconds: Int,
  probe_timeout_milliseconds: Int,
) -> Result(State, Error) {
  case state.handshake_confirmed {
    False -> Error(HandshakeNotConfirmed)
    True if packet_number <= state.largest_received ->
      Error(PacketNumberRollback)
    True if now_milliseconds < state.earliest_next_update_milliseconds ->
      Error(UpdateTooSoon(state.earliest_next_update_milliseconds))
    True -> {
      use next_write_keys <- result.try(advance(state.write_keys))
      use next_next_read_keys <- result.try(advance(state.next_read_keys))
      let discard_at = now_milliseconds + { 3 * probe_timeout_milliseconds }
      Ok(
        State(
          ..state,
          phase: observed_phase,
          write_keys: next_write_keys,
          read_keys: state.next_read_keys,
          next_read_keys: next_next_read_keys,
          previous_read_keys: Some(PreviousReadKeys(
            state.phase,
            state.read_keys,
            discard_at,
          )),
          first_sent_in_phase: None,
          current_phase_acknowledged: False,
          earliest_next_update_milliseconds: discard_at,
          first_received_in_phase: Some(packet_number),
          largest_received: packet_number,
        ),
      )
    }
  }
}

fn require_update_allowed(
  state: State,
  now_milliseconds: Int,
) -> Result(Nil, Error) {
  case
    state.handshake_confirmed,
    state.current_phase_acknowledged,
    now_milliseconds < state.earliest_next_update_milliseconds
  {
    False, _, _ -> Error(HandshakeNotConfirmed)
    _, False, _ -> Error(UpdateNotAcknowledged)
    _, _, True -> Error(UpdateTooSoon(state.earliest_next_update_milliseconds))
    _, _, _ -> Ok(Nil)
  }
}

fn validate_transition_input(
  packet_number: Int,
  now_milliseconds: Int,
  probe_timeout_milliseconds: Int,
) -> Result(Nil, Error) {
  case
    valid_packet_number(packet_number)
    && now_milliseconds >= 0
    && probe_timeout_milliseconds > 0
  {
    True -> Ok(Nil)
    False -> Error(InvalidInput)
  }
}

fn valid_packet_number(packet_number: Int) -> Bool {
  packet_number >= 0 && packet_number <= varint.maximum
}

fn advance(
  keys: traffic_keys.TrafficKeys,
) -> Result(traffic_keys.TrafficKeys, Error) {
  use secret <- result.try(
    traffic_keys.next_secret(keys) |> map_traffic_key_result,
  )
  traffic_keys.from_secret(keys.version, keys.cipher_suite, secret)
  |> map_traffic_key_result
}

fn toggle(phase: KeyPhase) -> KeyPhase {
  case phase {
    PhaseZero -> PhaseOne
    PhaseOne -> PhaseZero
  }
}

fn map_traffic_key_result(
  value: Result(output, traffic_keys.Error),
) -> Result(output, Error) {
  case value {
    Ok(output) -> Ok(output)
    Error(error) -> Error(TrafficKeyFailure(error))
  }
}

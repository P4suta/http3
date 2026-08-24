//// RFC 9002 NewReno congestion window for one validated path.

import gleam/option.{type Option, None, Some}
import gleam/result

/// Observable congestion-control mode.
pub type Phase {
  SlowStart
  Recovery
  CongestionAvoidance
}

/// Safe diagnostic values for one path.
pub type Snapshot {
  Snapshot(congestion_window: Int, bytes_in_flight: Int, phase: Phase)
}

/// Per-path NewReno state.
pub opaque type State {
  State(
    maximum_datagram_size: Int,
    congestion_window: Int,
    bytes_in_flight: Int,
    slow_start_threshold: Option(Int),
    recovery_start_milliseconds: Option(Int),
    congestion_avoidance_acked_bytes: Int,
  )
}

/// An invalid path MTU, size, time, or flight-accounting transition.
pub type Error {
  InvalidMaximumDatagramSize
  InvalidInput
  BytesInFlightUnderflow
}

/// Initialize the RFC 9002 congestion window for a path.
pub fn new(maximum_datagram_size: Int) -> Result(State, Error) {
  case maximum_datagram_size >= 1200 && maximum_datagram_size <= 65_527 {
    False -> Error(InvalidMaximumDatagramSize)
    True ->
      Ok(State(
        maximum_datagram_size: maximum_datagram_size,
        congestion_window: initial_window(maximum_datagram_size),
        bytes_in_flight: 0,
        slow_start_threshold: None,
        recovery_start_milliseconds: None,
        congestion_avoidance_acked_bytes: 0,
      ))
  }
}

/// Add a congestion-controlled datagram to bytes in flight.
pub fn on_packet_sent(
  state: State,
  sent_bytes: Int,
  in_flight: Bool,
) -> Result(State, Error) {
  case sent_bytes < 0 {
    True -> Error(InvalidInput)
    False ->
      case in_flight {
        True ->
          Ok(
            State(..state, bytes_in_flight: state.bytes_in_flight + sent_bytes),
          )
        False -> Ok(state)
      }
  }
}

/// Remove acknowledged bytes and grow outside recovery or application limits.
pub fn on_packet_acked(
  state: State,
  sent_bytes: Int,
  time_sent_milliseconds: Int,
  application_or_flow_control_limited: Bool,
) -> Result(State, Error) {
  use state <- result.try(subtract_in_flight(
    state,
    sent_bytes,
    time_sent_milliseconds,
  ))
  let state = exit_recovery_for_newer_packet(state, time_sent_milliseconds)
  case
    application_or_flow_control_limited
    || in_recovery(state, time_sent_milliseconds)
  {
    True -> Ok(state)
    False -> Ok(grow_window(state, sent_bytes))
  }
}

/// Remove lost bytes and halve the window once per recovery period.
pub fn on_packet_lost(
  state: State,
  sent_bytes: Int,
  time_sent_milliseconds: Int,
  now_milliseconds: Int,
) -> Result(State, Error) {
  use state <- result.try(subtract_in_flight(
    state,
    sent_bytes,
    time_sent_milliseconds,
  ))
  case now_milliseconds < 0 || time_sent_milliseconds > now_milliseconds {
    True -> Error(InvalidInput)
    False ->
      case in_recovery(state, time_sent_milliseconds) {
        True -> Ok(state)
        False -> {
          let reduced =
            maximum(
              state.congestion_window / 2,
              minimum_window(state.maximum_datagram_size),
            )
          Ok(
            State(
              ..state,
              congestion_window: reduced,
              slow_start_threshold: Some(reduced),
              recovery_start_milliseconds: Some(now_milliseconds),
              congestion_avoidance_acked_bytes: 0,
            ),
          )
        }
      }
  }
}

/// Collapse to the minimum window and reenter slow start.
pub fn on_persistent_congestion(state: State) -> State {
  State(
    ..state,
    congestion_window: minimum_window(state.maximum_datagram_size),
    slow_start_threshold: None,
    recovery_start_milliseconds: None,
    congestion_avoidance_acked_bytes: 0,
  )
}

/// Return whether a normal congestion-controlled send fits the window.
pub fn can_send(state: State, sent_bytes: Int) -> Bool {
  sent_bytes >= 0
  && state.bytes_in_flight + sent_bytes <= state.congestion_window
}

/// Return the congestion window in bytes.
pub fn congestion_window(state: State) -> Int {
  state.congestion_window
}

/// Return outstanding congestion-controlled bytes.
pub fn bytes_in_flight(state: State) -> Int {
  state.bytes_in_flight
}

/// Remove bytes belonging to rejected 0-RTT packets without treating their
/// rejection as a congestion signal.
pub fn abandon_in_flight(state: State, bytes: Int) -> Result(State, Error) {
  case bytes < 0 || bytes > state.bytes_in_flight {
    True -> Error(BytesInFlightUnderflow)
    False -> Ok(State(..state, bytes_in_flight: state.bytes_in_flight - bytes))
  }
}

/// Return stable path diagnostics.
pub fn snapshot(state: State) -> Snapshot {
  Snapshot(state.congestion_window, state.bytes_in_flight, phase(state))
}

fn phase(state: State) -> Phase {
  case state.recovery_start_milliseconds, state.slow_start_threshold {
    Some(_), _ -> Recovery
    None, Some(threshold) if state.congestion_window >= threshold ->
      CongestionAvoidance
    _, _ -> SlowStart
  }
}

fn subtract_in_flight(
  state: State,
  sent_bytes: Int,
  time_sent_milliseconds: Int,
) -> Result(State, Error) {
  case sent_bytes < 0 || time_sent_milliseconds < 0 {
    True -> Error(InvalidInput)
    False if sent_bytes > state.bytes_in_flight -> Error(BytesInFlightUnderflow)
    False ->
      Ok(State(..state, bytes_in_flight: state.bytes_in_flight - sent_bytes))
  }
}

fn exit_recovery_for_newer_packet(state: State, time_sent: Int) -> State {
  case state.recovery_start_milliseconds {
    Some(start) if time_sent > start ->
      State(..state, recovery_start_milliseconds: None)
    _ -> state
  }
}

fn in_recovery(state: State, time_sent: Int) -> Bool {
  case state.recovery_start_milliseconds {
    Some(start) -> time_sent <= start
    None -> False
  }
}

fn grow_window(state: State, acknowledged_bytes: Int) -> State {
  case state.slow_start_threshold {
    None ->
      State(
        ..state,
        congestion_window: state.congestion_window + acknowledged_bytes,
      )
    Some(threshold) if state.congestion_window < threshold ->
      State(
        ..state,
        congestion_window: state.congestion_window + acknowledged_bytes,
      )
    Some(_) -> grow_congestion_avoidance(state, acknowledged_bytes)
  }
}

fn grow_congestion_avoidance(state: State, acknowledged_bytes: Int) -> State {
  let accumulated = state.congestion_avoidance_acked_bytes + acknowledged_bytes
  case accumulated >= state.congestion_window {
    False -> State(..state, congestion_avoidance_acked_bytes: accumulated)
    True ->
      State(
        ..state,
        congestion_window: state.congestion_window + state.maximum_datagram_size,
        congestion_avoidance_acked_bytes: accumulated - state.congestion_window,
      )
  }
}

fn initial_window(maximum_datagram_size: Int) -> Int {
  minimum(
    10 * maximum_datagram_size,
    maximum(2 * maximum_datagram_size, 14_720),
  )
}

fn minimum_window(maximum_datagram_size: Int) -> Int {
  2 * maximum_datagram_size
}

fn minimum(left: Int, right: Int) -> Int {
  case left < right {
    True -> left
    False -> right
  }
}

fn maximum(left: Int, right: Int) -> Int {
  case left > right {
    True -> left
    False -> right
  }
}

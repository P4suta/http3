//// Conservative DPLPMTUD search without relying on IP fragmentation.

import gleam/option.{type Option, None, Some}

const minimum_quic_datagram_size = 1200

/// One path's confirmed size, search ceiling, and outstanding probe.
pub opaque type State {
  State(
    current: Int,
    configured_ceiling: Int,
    upper_bound: Int,
    probe: Option(Int),
  )
}

/// Invalid MTU configuration or probe transition.
pub type Error {
  InvalidMaximumSize
  ProbeAlreadyOutstanding
  NoLargerProbe
  UnexpectedProbe
}

/// Begin at QUIC's 1200-byte minimum and search up to a path ceiling.
pub fn new(maximum_datagram_size: Int) -> Result(State, Error) {
  case
    maximum_datagram_size >= minimum_quic_datagram_size
    && maximum_datagram_size <= 65_527
  {
    True ->
      Ok(State(
        minimum_quic_datagram_size,
        maximum_datagram_size,
        maximum_datagram_size,
        None,
      ))
    False -> Error(InvalidMaximumSize)
  }
}

/// Schedule the midpoint of the remaining search interval as a padded probe.
pub fn start_probe(state: State) -> Result(#(State, Int), Error) {
  case state.probe {
    Some(_) -> Error(ProbeAlreadyOutstanding)
    None if state.upper_bound <= state.current -> Error(NoLargerProbe)
    None -> {
      let size = state.current + { state.upper_bound - state.current + 1 } / 2
      Ok(#(State(..state, probe: Some(size)), size))
    }
  }
}

/// Raise the confirmed PMTU when the exact padded probe is acknowledged.
pub fn probe_acked(state: State, size: Int) -> Result(State, Error) {
  case state.probe {
    Some(expected) if expected == size ->
      Ok(State(..state, current: size, probe: None))
    _ -> Error(UnexpectedProbe)
  }
}

/// Lower the search ceiling only when smaller packets prove congestion unlikely.
pub fn probe_lost(
  state: State,
  size: Int,
  smaller_packets_acknowledged: Bool,
) -> Result(State, Error) {
  case state.probe {
    Some(expected) if expected == size ->
      case smaller_packets_acknowledged {
        True -> Ok(State(..state, upper_bound: size - 1, probe: None))
        False -> Ok(State(..state, probe: None))
      }
    _ -> Error(UnexpectedProbe)
  }
}

/// Recover a path that stopped delivering previously confirmed large packets.
pub fn black_hole_detected(state: State) -> State {
  State(..state, current: minimum_quic_datagram_size, probe: None)
}

/// Return the largest size confirmed without fragmentation.
pub fn current(state: State) -> Int {
  state.current
}

/// Return the exact padded datagram size currently under test.
pub fn outstanding_probe(state: State) -> Option(Int) {
  state.probe
}

/// Cap discovery by the peer's authenticated maximum UDP payload size.
pub fn set_peer_maximum(state: State, maximum: Int) -> Result(State, Error) {
  case maximum < minimum_quic_datagram_size || maximum > 65_527 {
    True -> Error(InvalidMaximumSize)
    False -> {
      let upper_bound = minimum(state.configured_ceiling, maximum)
      let probe = case state.probe {
        Some(size) if size > upper_bound -> None
        existing -> existing
      }
      Ok(State(..state, upper_bound: upper_bound, probe: probe))
    }
  }
}

fn minimum(left: Int, right: Int) -> Int {
  case left < right {
    True -> left
    False -> right
  }
}

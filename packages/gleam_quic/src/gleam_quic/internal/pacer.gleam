//// RFC 9002 window-derived token-bucket pacing with bounded bursts.

/// Whether a congestion-controlled packet can be emitted now.
pub type Availability {
  SendNow
  WaitUntil(deadline_milliseconds: Int)
}

/// Updated pacing state and send decision.
pub type Decision {
  Decision(state: State, availability: Availability)
}

/// Path-local burst capacity and token balance in bytes.
pub opaque type State {
  State(maximum_burst_bytes: Int, available_bytes: Int, updated_at: Int)
}

/// Invalid size, clock, congestion window, or RTT input.
pub type Error {
  InvalidInput
}

/// Start with one bounded burst available.
pub fn new(
  maximum_burst_bytes: Int,
  now_milliseconds: Int,
) -> Result(State, Error) {
  case maximum_burst_bytes > 0 && now_milliseconds >= 0 {
    True ->
      Ok(State(maximum_burst_bytes, maximum_burst_bytes, now_milliseconds))
    False -> Error(InvalidInput)
  }
}

/// Resize the burst for a new path MTU. Tokens are never gifted: a smaller
/// burst clamps the balance, a larger one refills at the pacing rate.
pub fn resize_burst(
  state: State,
  maximum_burst_bytes: Int,
) -> Result(State, Error) {
  case maximum_burst_bytes > 0 {
    True ->
      Ok(
        State(
          ..state,
          maximum_burst_bytes: maximum_burst_bytes,
          available_bytes: minimum(state.available_bytes, maximum_burst_bytes),
        ),
      )
    False -> Error(InvalidInput)
  }
}

/// Refill at 1.25*cwnd/smoothed_rtt and reserve one complete packet.
pub fn reserve(
  state: State,
  packet_bytes: Int,
  now_milliseconds: Int,
  congestion_window_bytes: Int,
  smoothed_rtt_milliseconds: Int,
) -> Result(Decision, Error) {
  case
    packet_bytes > 0
    && packet_bytes <= state.maximum_burst_bytes
    && now_milliseconds >= state.updated_at
    && congestion_window_bytes > 0
    && smoothed_rtt_milliseconds > 0
  {
    False -> Error(InvalidInput)
    True ->
      Ok(reserve_valid(
        state,
        packet_bytes,
        now_milliseconds,
        congestion_window_bytes,
        smoothed_rtt_milliseconds,
      ))
  }
}

fn reserve_valid(
  state: State,
  packet_bytes: Int,
  now_milliseconds: Int,
  congestion_window_bytes: Int,
  smoothed_rtt_milliseconds: Int,
) -> Decision {
  let elapsed = now_milliseconds - state.updated_at
  let rate_numerator = 5 * congestion_window_bytes
  let rate_denominator = 4 * smoothed_rtt_milliseconds
  let refilled =
    minimum(
      state.maximum_burst_bytes,
      state.available_bytes + { elapsed * rate_numerator / rate_denominator },
    )
  let updated =
    State(..state, available_bytes: refilled, updated_at: now_milliseconds)
  case refilled >= packet_bytes {
    True ->
      Decision(
        State(..updated, available_bytes: refilled - packet_bytes),
        SendNow,
      )
    False -> {
      let deficit = packet_bytes - refilled
      let wait = ceiling_divide(deficit * rate_denominator, rate_numerator)
      Decision(updated, WaitUntil(now_milliseconds + wait))
    }
  }
}

fn ceiling_divide(numerator: Int, denominator: Int) -> Int {
  { numerator + denominator - 1 } / denominator
}

fn minimum(left: Int, right: Int) -> Int {
  case left < right {
    True -> left
    False -> right
  }
}

//// RFC 9438 CUBIC congestion control for one validated QUIC path.
////
//// Window calculations use fixed-point integers so transport behavior is
//// reproducible and does not depend on floating-point support in an FFI.

import gleam/option.{type Option, None, Some}
import gleam/result

const window_scale = 1_000_000

const cubic_time_denominator = 5_000_000_000

const hystart_min_rtt_threshold_milliseconds = 4

const hystart_max_rtt_threshold_milliseconds = 16

const hystart_rtt_divisor = 8

const hystart_minimum_samples = 8

const hystart_css_growth_divisor = 4

const hystart_css_rounds = 5

// Bound persistent-CE rate backoff so hostile feedback cannot make integer
// arithmetic unbounded. 2^20 RTTs is already an operational stop while still
// leaving the controller recoverable after valid unmarked acknowledgements.
const maximum_ecn_pacing_backoff = 20

/// Observable congestion-control mode.
pub type Phase {
  SlowStart
  Recovery
  CongestionAvoidance
}

/// The RFC 9406 mode used during the initial slow start.
pub type SlowStartMode {
  StandardSlowStart
  ConservativeSlowStart
}

/// Safe diagnostic values for one path.
pub type Snapshot {
  Snapshot(congestion_window: Int, bytes_in_flight: Int, phase: Phase)
}

/// Payload-free developer diagnostics for the RFC 9438 ECN response.
pub type EcnResponseSnapshot {
  EcnResponseSnapshot(backoff: Int, pacing_window: Int)
}

/// Payload-free developer diagnostics for the RFC 9406 state machine.
pub type HystartSnapshot {
  HystartSnapshot(
    enabled: Bool,
    mode: SlowStartMode,
    css_rounds_completed: Int,
    current_round_rtt_samples: Int,
  )
}

/// Payload-free developer diagnostics for the CUBIC curve and topology mode.
pub type CurveSnapshot {
  CurveSnapshot(
    maximum_window: Int,
    previous_window: Int,
    k_milliseconds: Int,
    fast_convergence_enabled: Bool,
  )
}

/// Per-path CUBIC state.
pub opaque type State {
  State(
    maximum_datagram_size: Int,
    congestion_window_scaled: Int,
    bytes_in_flight: Int,
    slow_start_threshold: Option(Int),
    recovery_start_milliseconds: Option(Int),
    congestion_window_prior: Int,
    maximum_window: Int,
    fast_convergence_enabled: Bool,
    epoch_start_milliseconds: Option(Int),
    last_update_milliseconds: Option(Int),
    estimated_reno_window_scaled: Int,
    k_milliseconds: Int,
    hystart_enabled: Bool,
    slow_start_mode: SlowStartMode,
    last_round_min_rtt_milliseconds: Option(Int),
    current_round_min_rtt_milliseconds: Option(Int),
    current_round_rtt_samples: Int,
    current_round_ack_target: Int,
    current_round_acknowledged: Int,
    css_baseline_min_rtt_milliseconds: Option(Int),
    css_rounds_completed: Int,
    ecn_pacing_backoff: Int,
  )
}

/// An invalid path MTU, size, time, RTT, or flight-accounting transition.
pub type Error {
  InvalidMaximumDatagramSize
  InvalidInput
  BytesInFlightUnderflow
}

/// Initialize the RFC 9002 congestion window for a CUBIC path.
pub fn new(maximum_datagram_size: Int) -> Result(State, Error) {
  new_with_fast_convergence(maximum_datagram_size, True)
}

/// Initialize CUBIC with an explicit RFC 9438 fast-convergence topology mode.
pub fn new_with_fast_convergence(
  maximum_datagram_size: Int,
  fast_convergence_enabled: Bool,
) -> Result(State, Error) {
  case maximum_datagram_size >= 1200 && maximum_datagram_size <= 65_527 {
    False -> Error(InvalidMaximumDatagramSize)
    True -> {
      let initial = initial_window(maximum_datagram_size)
      Ok(State(
        maximum_datagram_size: maximum_datagram_size,
        congestion_window_scaled: initial * window_scale,
        bytes_in_flight: 0,
        slow_start_threshold: None,
        recovery_start_milliseconds: None,
        congestion_window_prior: initial,
        maximum_window: 0,
        fast_convergence_enabled: fast_convergence_enabled,
        epoch_start_milliseconds: None,
        last_update_milliseconds: None,
        estimated_reno_window_scaled: initial * window_scale,
        k_milliseconds: 0,
        hystart_enabled: True,
        slow_start_mode: StandardSlowStart,
        last_round_min_rtt_milliseconds: None,
        current_round_min_rtt_milliseconds: None,
        current_round_rtt_samples: 0,
        current_round_ack_target: initial,
        current_round_acknowledged: 0,
        css_baseline_min_rtt_milliseconds: None,
        css_rounds_completed: 0,
        ecn_pacing_backoff: 0,
      ))
    }
  }
}

/// Follow the size the datagrams on this path are actually built at.
///
/// RFC 9002 section 7.2 derives the minimum window - the floor a loss event
/// or persistent congestion reduces to - from `max_datagram_size`, and
/// RFC 9438 scales the CUBIC curve by it. A controller left at the
/// pre-validation size would floor the window below a single datagram once
/// DPLPMTUD raises the path, stalling path-sized sends until the window
/// regrew. The window itself is never changed here: it is the reductions and
/// the curve that follow the new size.
pub fn set_maximum_datagram_size(
  state: State,
  maximum_datagram_size: Int,
) -> Result(State, Error) {
  case maximum_datagram_size >= 1200 && maximum_datagram_size <= 65_527 {
    False -> Error(InvalidMaximumDatagramSize)
    True -> Ok(State(..state, maximum_datagram_size: maximum_datagram_size))
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
  acknowledged_bytes: Int,
  time_sent_milliseconds: Int,
  now_milliseconds: Int,
  smoothed_rtt_milliseconds: Int,
  application_or_flow_control_limited: Bool,
) -> Result(State, Error) {
  // RFC 9438 section 4.6 requires a cwnd-based QUIC implementation to
  // independently prevent growth when flight does not fill cwnd. Keep this
  // guard inside the ordinary API so a missed caller hint cannot inflate the
  // next congestion response.
  let congestion_window_fully_utilized =
    state.bytes_in_flight >= congestion_window(state)
  on_packet_acked_in_batch(
    state,
    acknowledged_bytes,
    time_sent_milliseconds,
    now_milliseconds,
    smoothed_rtt_milliseconds,
    application_or_flow_control_limited,
    congestion_window_fully_utilized,
  )
}

/// Apply one packet from an ACK batch using its pre-removal flight snapshot.
///
/// Every packet in one ACK observes the same application-limited decision;
/// processing the batch sequentially must not turn a full flight into a sparse
/// one after its first packet is removed.
pub fn on_packet_acked_in_batch(
  state: State,
  acknowledged_bytes: Int,
  time_sent_milliseconds: Int,
  now_milliseconds: Int,
  smoothed_rtt_milliseconds: Int,
  application_or_flow_control_limited: Bool,
  congestion_window_fully_utilized: Bool,
) -> Result(State, Error) {
  use _ <- result.try(validate_ack_input(
    state,
    acknowledged_bytes,
    time_sent_milliseconds,
    now_milliseconds,
    smoothed_rtt_milliseconds,
  ))
  let state =
    State(..state, bytes_in_flight: state.bytes_in_flight - acknowledged_bytes)
  let state = exit_recovery_for_newer_packet(state, time_sent_milliseconds)

  case in_recovery(state, time_sent_milliseconds) {
    True -> Ok(state)
    False -> {
      let growth_limited =
        application_or_flow_control_limited || !congestion_window_fully_utilized
      case growth_limited, state.slow_start_threshold, state.hystart_enabled {
        // HyStart++ still consumes bounded RTT observations while the window
        // is held. Otherwise an application-limited initial flight could hide
        // a persistent delay increase from the startup state machine.
        True, None, True ->
          Ok(observe_hystart_ack(
            state,
            acknowledged_bytes,
            smoothed_rtt_milliseconds,
          ))
        True, _, _ -> Ok(pause_epoch(state, now_milliseconds))
        False, _, _ ->
          Ok(grow_window(
            state,
            acknowledged_bytes,
            now_milliseconds,
            smoothed_rtt_milliseconds,
          ))
      }
    }
  }
}

/// Remove lost bytes and apply CUBIC's 0.7 decrease once per recovery period.
pub fn on_packet_lost(
  state: State,
  sent_bytes: Int,
  time_sent_milliseconds: Int,
  now_milliseconds: Int,
) -> Result(State, Error) {
  use _ <- result.try(validate_loss_input(
    state,
    sent_bytes,
    time_sent_milliseconds,
    now_milliseconds,
  ))
  let state =
    State(..state, bytes_in_flight: state.bytes_in_flight - sent_bytes)
  case in_recovery(state, time_sent_milliseconds) {
    True -> Ok(state)
    False -> {
      let prior = congestion_window(state)
      let reduced =
        maximum(prior * 7 / 10, minimum_window(state.maximum_datagram_size))
      let maximum_window = case
        state.fast_convergence_enabled && prior < state.maximum_window
      {
        // RFC 9438 fast convergence: cwnd * (1 + beta) / 2.
        True -> prior * 17 / 20
        False -> prior
      }
      Ok(
        State(
          ..state,
          congestion_window_scaled: reduced * window_scale,
          slow_start_threshold: Some(reduced),
          recovery_start_milliseconds: Some(now_milliseconds),
          congestion_window_prior: prior,
          maximum_window: maximum_window,
          epoch_start_milliseconds: None,
          last_update_milliseconds: None,
          estimated_reno_window_scaled: reduced * window_scale,
          k_milliseconds: 0,
          hystart_enabled: False,
          slow_start_mode: StandardSlowStart,
          current_round_min_rtt_milliseconds: None,
          current_round_rtt_samples: 0,
          current_round_acknowledged: 0,
          css_baseline_min_rtt_milliseconds: None,
          css_rounds_completed: 0,
          ecn_pacing_backoff: 0,
        ),
      )
    }
  }
}

/// Apply one independently timed RFC 9438 ECN congestion event.
///
/// Unlike packet loss, repeated ECN events reduce the window to one maximum
/// datagram. Once that floor is reached, each further event halves the rate
/// supplied to the pacer while leaving one complete datagram sendable.
pub fn on_congestion_experienced(
  state: State,
  now_milliseconds: Int,
) -> Result(State, Error) {
  case now_milliseconds < 0 {
    True -> Error(InvalidInput)
    False ->
      case in_recovery(state, now_milliseconds) {
        True -> Ok(state)
        False -> Ok(reduce_for_ecn(state, now_milliseconds))
      }
  }
}

/// Collapse to the RFC 9002 minimum window after persistent congestion.
pub fn on_persistent_congestion(state: State) -> State {
  let current = congestion_window(state)
  let minimum = minimum_window(state.maximum_datagram_size)
  State(
    ..state,
    congestion_window_scaled: minimum * window_scale,
    slow_start_threshold: Some(maximum(current * 7 / 10, minimum)),
    recovery_start_milliseconds: None,
    epoch_start_milliseconds: None,
    last_update_milliseconds: None,
    estimated_reno_window_scaled: minimum * window_scale,
    k_milliseconds: 0,
    hystart_enabled: False,
    slow_start_mode: StandardSlowStart,
    current_round_min_rtt_milliseconds: None,
    current_round_rtt_samples: 0,
    current_round_acknowledged: 0,
    css_baseline_min_rtt_milliseconds: None,
    css_rounds_completed: 0,
    ecn_pacing_backoff: 0,
  )
}

/// Return whether a normal congestion-controlled send fits the window.
pub fn can_send(state: State, sent_bytes: Int) -> Bool {
  sent_bytes >= 0
  && state.bytes_in_flight + sent_bytes <= congestion_window(state)
}

/// Return the congestion window in whole bytes.
pub fn congestion_window(state: State) -> Int {
  state.congestion_window_scaled / window_scale
}

/// Return outstanding congestion-controlled bytes.
pub fn bytes_in_flight(state: State) -> Int {
  state.bytes_in_flight
}

/// Remove bytes belonging to rejected 0-RTT packets without reducing the
/// congestion window.
pub fn abandon_in_flight(state: State, bytes: Int) -> Result(State, Error) {
  case bytes < 0 || bytes > state.bytes_in_flight {
    True -> Error(BytesInFlightUnderflow)
    False -> Ok(State(..state, bytes_in_flight: state.bytes_in_flight - bytes))
  }
}

/// Return the observable congestion-control phase.
pub fn phase(state: State) -> Phase {
  let current = congestion_window(state)
  case state.recovery_start_milliseconds, state.slow_start_threshold {
    Some(_), _ -> Recovery
    None, Some(threshold) if current >= threshold -> CongestionAvoidance
    _, _ -> SlowStart
  }
}

/// Return stable path diagnostics.
pub fn snapshot(state: State) -> Snapshot {
  Snapshot(congestion_window(state), state.bytes_in_flight, phase(state))
}

/// Return the effective pacing window after persistent ECN backoff.
pub fn pacing_window(state: State) -> Int {
  maximum(congestion_window(state) / power_of_two(state.ecn_pacing_backoff), 1)
}

/// Return stable, payload-free ECN-response diagnostics.
pub fn ecn_response_snapshot(state: State) -> EcnResponseSnapshot {
  EcnResponseSnapshot(state.ecn_pacing_backoff, pacing_window(state))
}

/// Return stable, payload-free HyStart++ diagnostics.
pub fn hystart_snapshot(state: State) -> HystartSnapshot {
  HystartSnapshot(
    state.hystart_enabled,
    state.slow_start_mode,
    state.css_rounds_completed,
    state.current_round_rtt_samples,
  )
}

/// Return stable CUBIC curve diagnostics without packet or application data.
pub fn curve_snapshot(state: State) -> CurveSnapshot {
  CurveSnapshot(
    state.maximum_window,
    state.congestion_window_prior,
    state.k_milliseconds,
    state.fast_convergence_enabled,
  )
}

/// Return whether initial slow start is using normal or conservative growth.
pub fn slow_start_mode(state: State) -> SlowStartMode {
  state.slow_start_mode
}

fn validate_ack_input(
  state: State,
  acknowledged_bytes: Int,
  time_sent: Int,
  now: Int,
  smoothed_rtt: Int,
) -> Result(Nil, Error) {
  case
    acknowledged_bytes < 0
    || time_sent < 0
    || now < 0
    || time_sent > now
    || smoothed_rtt <= 0
  {
    True -> Error(InvalidInput)
    False if acknowledged_bytes > state.bytes_in_flight ->
      Error(BytesInFlightUnderflow)
    False -> Ok(Nil)
  }
}

fn validate_loss_input(
  state: State,
  sent_bytes: Int,
  time_sent: Int,
  now: Int,
) -> Result(Nil, Error) {
  case sent_bytes < 0 || time_sent < 0 || now < 0 || time_sent > now {
    True -> Error(InvalidInput)
    False if sent_bytes > state.bytes_in_flight -> Error(BytesInFlightUnderflow)
    False -> Ok(Nil)
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

fn grow_window(
  state: State,
  acknowledged_bytes: Int,
  now: Int,
  smoothed_rtt: Int,
) -> State {
  let current = congestion_window(state)
  let grown = case state.slow_start_threshold {
    None if state.hystart_enabled ->
      grow_hystart_slow_start(state, acknowledged_bytes, smoothed_rtt)
    None -> grow_slow_start(state, acknowledged_bytes)
    Some(threshold) if current < threshold ->
      grow_slow_start(state, acknowledged_bytes)
    Some(_) ->
      grow_congestion_avoidance(state, acknowledged_bytes, now, smoothed_rtt)
  }
  case congestion_window(grown) > current {
    True -> State(..grown, ecn_pacing_backoff: 0)
    False -> grown
  }
}

fn reduce_for_ecn(state: State, now: Int) -> State {
  let prior = congestion_window(state)
  let ecn_floor = state.maximum_datagram_size
  let reduced = maximum(prior * 7 / 10, ecn_floor)
  let threshold = maximum(reduced, minimum_window(state.maximum_datagram_size))
  let maximum_window = case
    state.fast_convergence_enabled && prior < state.maximum_window
  {
    True -> prior * 17 / 20
    False -> prior
  }
  let backoff = case prior <= ecn_floor {
    True -> minimum(state.ecn_pacing_backoff + 1, maximum_ecn_pacing_backoff)
    False -> 0
  }
  State(
    ..state,
    congestion_window_scaled: reduced * window_scale,
    slow_start_threshold: Some(threshold),
    recovery_start_milliseconds: Some(now),
    congestion_window_prior: prior,
    maximum_window: maximum_window,
    epoch_start_milliseconds: None,
    last_update_milliseconds: None,
    estimated_reno_window_scaled: reduced * window_scale,
    k_milliseconds: 0,
    hystart_enabled: False,
    slow_start_mode: StandardSlowStart,
    current_round_min_rtt_milliseconds: None,
    current_round_rtt_samples: 0,
    current_round_acknowledged: 0,
    css_baseline_min_rtt_milliseconds: None,
    css_rounds_completed: 0,
    ecn_pacing_backoff: backoff,
  )
}

fn grow_hystart_slow_start(
  state: State,
  acknowledged_bytes: Int,
  rtt_milliseconds: Int,
) -> State {
  let mode_before_sample = state.slow_start_mode
  let state = record_hystart_rtt(state, rtt_milliseconds)
  let state = case mode_before_sample {
    StandardSlowStart -> grow_slow_start(state, acknowledged_bytes)
    ConservativeSlowStart ->
      grow_conservative_slow_start(state, acknowledged_bytes)
  }
  let state = case mode_before_sample {
    StandardSlowStart -> maybe_enter_conservative_slow_start(state)
    ConservativeSlowStart -> maybe_resume_standard_slow_start(state)
  }
  finish_hystart_round_when_ready(state, acknowledged_bytes)
}

fn observe_hystart_ack(
  state: State,
  acknowledged_bytes: Int,
  rtt_milliseconds: Int,
) -> State {
  let mode_before_sample = state.slow_start_mode
  let state = record_hystart_rtt(state, rtt_milliseconds)
  let state = case mode_before_sample {
    StandardSlowStart -> maybe_enter_conservative_slow_start(state)
    ConservativeSlowStart -> maybe_resume_standard_slow_start(state)
  }
  finish_hystart_round_when_ready(state, acknowledged_bytes)
}

fn grow_conservative_slow_start(
  state: State,
  acknowledged_bytes: Int,
) -> State {
  State(
    ..state,
    congestion_window_scaled: state.congestion_window_scaled
      + acknowledged_bytes
      * window_scale
      / hystart_css_growth_divisor,
  )
}

fn record_hystart_rtt(state: State, rtt_milliseconds: Int) -> State {
  let minimum_rtt = case state.current_round_min_rtt_milliseconds {
    None -> rtt_milliseconds
    Some(current) -> minimum(current, rtt_milliseconds)
  }
  State(
    ..state,
    current_round_min_rtt_milliseconds: Some(minimum_rtt),
    current_round_rtt_samples: state.current_round_rtt_samples + 1,
  )
}

fn maybe_enter_conservative_slow_start(state: State) -> State {
  case
    state.current_round_rtt_samples >= hystart_minimum_samples,
    state.last_round_min_rtt_milliseconds,
    state.current_round_min_rtt_milliseconds
  {
    True, Some(last), Some(current) -> {
      let threshold =
        last / hystart_rtt_divisor
        |> maximum(hystart_min_rtt_threshold_milliseconds)
        |> minimum(hystart_max_rtt_threshold_milliseconds)
      case current >= last + threshold {
        True ->
          State(
            ..state,
            slow_start_mode: ConservativeSlowStart,
            css_baseline_min_rtt_milliseconds: Some(current),
            css_rounds_completed: 0,
          )
        False -> state
      }
    }
    _, _, _ -> state
  }
}

fn maybe_resume_standard_slow_start(state: State) -> State {
  case
    state.current_round_rtt_samples >= hystart_minimum_samples,
    state.current_round_min_rtt_milliseconds,
    state.css_baseline_min_rtt_milliseconds
  {
    True, Some(current), Some(baseline) if current < baseline ->
      State(
        ..state,
        slow_start_mode: StandardSlowStart,
        css_baseline_min_rtt_milliseconds: None,
        css_rounds_completed: 0,
      )
    _, _, _ -> state
  }
}

fn finish_hystart_round_when_ready(
  state: State,
  acknowledged_bytes: Int,
) -> State {
  let acknowledged = state.current_round_acknowledged + acknowledged_bytes
  case acknowledged >= state.current_round_ack_target {
    False -> State(..state, current_round_acknowledged: acknowledged)
    True -> {
      let completed = case state.slow_start_mode {
        StandardSlowStart -> state.css_rounds_completed
        ConservativeSlowStart -> state.css_rounds_completed + 1
      }
      let state =
        State(
          ..state,
          last_round_min_rtt_milliseconds: state.current_round_min_rtt_milliseconds,
          current_round_min_rtt_milliseconds: None,
          current_round_rtt_samples: 0,
          current_round_ack_target: congestion_window(state),
          current_round_acknowledged: 0,
          css_rounds_completed: completed,
        )
      case
        state.slow_start_mode == ConservativeSlowStart
        && completed >= hystart_css_rounds
      {
        True ->
          State(
            ..state,
            slow_start_threshold: Some(congestion_window(state)),
            hystart_enabled: False,
            slow_start_mode: StandardSlowStart,
            css_baseline_min_rtt_milliseconds: None,
          )
        False -> state
      }
    }
  }
}

fn grow_slow_start(state: State, acknowledged_bytes: Int) -> State {
  State(
    ..state,
    congestion_window_scaled: state.congestion_window_scaled
      + acknowledged_bytes
      * window_scale,
  )
}

fn grow_congestion_avoidance(
  state: State,
  acknowledged_bytes: Int,
  now: Int,
  smoothed_rtt: Int,
) -> State {
  let state = ensure_epoch(state, now)
  let state = update_estimated_reno_window(state, acknowledged_bytes)
  let elapsed = elapsed_milliseconds(state, now)
  let cubic_now = cubic_window_scaled(state, elapsed)
  let state = case cubic_now < state.estimated_reno_window_scaled {
    True ->
      State(
        ..state,
        congestion_window_scaled: maximum(
          state.congestion_window_scaled,
          state.estimated_reno_window_scaled,
        ),
      )
    False -> grow_cubic_window(state, acknowledged_bytes, elapsed, smoothed_rtt)
  }
  State(..state, last_update_milliseconds: Some(now))
}

fn ensure_epoch(state: State, now: Int) -> State {
  case state.epoch_start_milliseconds {
    Some(_) -> state
    None -> {
      let current = congestion_window(state)
      let difference = maximum(state.maximum_window - current, 0)
      let k_cubed =
        difference * 5 * 1_000_000_000 / { 2 * state.maximum_datagram_size }
      State(
        ..state,
        epoch_start_milliseconds: Some(now),
        last_update_milliseconds: Some(now),
        estimated_reno_window_scaled: current * window_scale,
        k_milliseconds: integer_cube_root(k_cubed),
      )
    }
  }
}

fn update_estimated_reno_window(
  state: State,
  acknowledged_bytes: Int,
) -> State {
  let alpha_numerator = case
    state.estimated_reno_window_scaled
    >= state.congestion_window_prior * window_scale
  {
    True -> 17
    False -> 9
  }
  let increment =
    window_scale
    * alpha_numerator
    * state.maximum_datagram_size
    * acknowledged_bytes
    / { 17 * maximum(congestion_window(state), 1) }
  State(
    ..state,
    estimated_reno_window_scaled: state.estimated_reno_window_scaled + increment,
  )
}

fn grow_cubic_window(
  state: State,
  acknowledged_bytes: Int,
  elapsed: Int,
  smoothed_rtt: Int,
) -> State {
  let current = state.congestion_window_scaled
  let calculated_target = cubic_window_scaled(state, elapsed + smoothed_rtt)
  let target =
    calculated_target
    |> maximum(current)
    |> minimum(current * 3 / 2)
  let increment =
    { target - current }
    * acknowledged_bytes
    / maximum(congestion_window(state), 1)
  State(..state, congestion_window_scaled: current + increment)
}

fn cubic_window_scaled(state: State, elapsed: Int) -> Int {
  let offset = elapsed - state.k_milliseconds
  let delta =
    state.maximum_datagram_size
    * 2
    * offset
    * offset
    * offset
    * window_scale
    / cubic_time_denominator
  maximum(state.maximum_window * window_scale + delta, 0)
}

fn elapsed_milliseconds(state: State, now: Int) -> Int {
  case state.epoch_start_milliseconds {
    Some(start) -> maximum(now - start, 0)
    None -> 0
  }
}

fn pause_epoch(state: State, now: Int) -> State {
  case state.epoch_start_milliseconds, state.last_update_milliseconds {
    Some(epoch), Some(last_update) ->
      State(
        ..state,
        epoch_start_milliseconds: Some(epoch + maximum(now - last_update, 0)),
        last_update_milliseconds: Some(now),
      )
    _, _ -> state
  }
}

fn integer_cube_root(value: Int) -> Int {
  case value <= 0 {
    True -> 0
    False -> cube_root_between(value, 0, cube_root_upper_bound(value, 1))
  }
}

fn cube_root_upper_bound(value: Int, candidate: Int) -> Int {
  case cube(candidate) > value {
    True -> candidate
    False -> cube_root_upper_bound(value, candidate * 2)
  }
}

fn cube_root_between(value: Int, lower: Int, upper: Int) -> Int {
  case upper - lower <= 1 {
    True -> lower
    False -> {
      let middle = lower + { upper - lower } / 2
      case cube(middle) <= value {
        True -> cube_root_between(value, middle, upper)
        False -> cube_root_between(value, lower, middle)
      }
    }
  }
}

fn cube(value: Int) -> Int {
  value * value * value
}

fn power_of_two(exponent: Int) -> Int {
  case exponent {
    0 -> 1
    _ -> 2 * power_of_two(exponent - 1)
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

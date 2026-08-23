//// RFC 9002 path RTT estimator, loss delay, and probe timeout.

/// Observable estimator values in milliseconds.
pub type Snapshot {
  Snapshot(
    latest_rtt: Int,
    smoothed_rtt: Int,
    rtt_variation: Int,
    minimum_rtt: Int,
  )
}

/// One path's private RTT estimator.
pub opaque type Estimator {
  Estimator(
    latest_rtt: Int,
    smoothed_rtt: Int,
    rtt_variation: Int,
    minimum_rtt: Int,
    has_sample: Bool,
  )
}

/// Invalid time, delay, granularity, or backoff input.
pub type Error {
  InvalidInput
}

/// Initialize with the RFC-recommended 333 ms or another positive estimate.
pub fn new(initial_rtt_milliseconds: Int) -> Result(Estimator, Error) {
  case initial_rtt_milliseconds > 0 {
    True ->
      Ok(Estimator(
        latest_rtt: 0,
        smoothed_rtt: initial_rtt_milliseconds,
        rtt_variation: initial_rtt_milliseconds / 2,
        minimum_rtt: 0,
        has_sample: False,
      ))
    False -> Error(InvalidInput)
  }
}

/// Incorporate a newly acknowledged ack-eliciting packet's RTT sample.
pub fn sample(
  estimator: Estimator,
  latest_rtt_milliseconds: Int,
  acknowledgment_delay_milliseconds: Int,
  maximum_acknowledgment_delay_milliseconds: Int,
  handshake_confirmed: Bool,
) -> Result(Estimator, Error) {
  case
    latest_rtt_milliseconds > 0
    && acknowledgment_delay_milliseconds >= 0
    && maximum_acknowledgment_delay_milliseconds >= 0
  {
    False -> Error(InvalidInput)
    True ->
      sample_valid(
        estimator,
        latest_rtt_milliseconds,
        acknowledgment_delay_milliseconds,
        maximum_acknowledgment_delay_milliseconds,
        handshake_confirmed,
      )
  }
}

/// Compute PTO with optional application-data ACK delay and exponential backoff.
pub fn probe_timeout(
  estimator: Estimator,
  maximum_acknowledgment_delay_milliseconds: Int,
  application_data: Bool,
  pto_count: Int,
  timer_granularity_milliseconds: Int,
) -> Result(Int, Error) {
  case
    maximum_acknowledgment_delay_milliseconds >= 0
    && pto_count >= 0
    && pto_count <= 62
    && timer_granularity_milliseconds > 0
  {
    False -> Error(InvalidInput)
    True -> {
      let variation =
        maximum(4 * estimator.rtt_variation, timer_granularity_milliseconds)
      let ack_delay = case application_data {
        True -> maximum_acknowledgment_delay_milliseconds
        False -> 0
      }
      Ok(backoff(estimator.smoothed_rtt + variation + ack_delay, pto_count))
    }
  }
}

/// Compute the 9/8 RTT time threshold, bounded by timer granularity.
pub fn loss_delay(
  estimator: Estimator,
  timer_granularity_milliseconds: Int,
) -> Int {
  let threshold = 9 * maximum(estimator.latest_rtt, estimator.smoothed_rtt) / 8
  maximum(threshold, timer_granularity_milliseconds)
}

/// Read estimator values without exposing mutation state.
pub fn snapshot(estimator: Estimator) -> Snapshot {
  Snapshot(
    estimator.latest_rtt,
    estimator.smoothed_rtt,
    estimator.rtt_variation,
    estimator.minimum_rtt,
  )
}

fn sample_valid(
  estimator: Estimator,
  latest_rtt: Int,
  ack_delay: Int,
  maximum_ack_delay: Int,
  handshake_confirmed: Bool,
) -> Result(Estimator, Error) {
  case estimator.has_sample {
    False ->
      Ok(Estimator(
        latest_rtt: latest_rtt,
        smoothed_rtt: latest_rtt,
        rtt_variation: latest_rtt / 2,
        minimum_rtt: latest_rtt,
        has_sample: True,
      ))
    True ->
      Ok(update_existing(
        estimator,
        latest_rtt,
        ack_delay,
        maximum_ack_delay,
        handshake_confirmed,
      ))
  }
}

fn update_existing(
  estimator: Estimator,
  latest_rtt: Int,
  ack_delay: Int,
  maximum_ack_delay: Int,
  handshake_confirmed: Bool,
) -> Estimator {
  let minimum_rtt = minimum(estimator.minimum_rtt, latest_rtt)
  let bounded_ack_delay = case handshake_confirmed {
    True -> minimum(ack_delay, maximum_ack_delay)
    False -> ack_delay
  }
  let adjusted_rtt = case latest_rtt >= minimum_rtt + bounded_ack_delay {
    True -> latest_rtt - bounded_ack_delay
    False -> latest_rtt
  }
  let variation_sample = absolute(estimator.smoothed_rtt - adjusted_rtt)
  Estimator(
    latest_rtt: latest_rtt,
    smoothed_rtt: { 7 * estimator.smoothed_rtt + adjusted_rtt } / 8,
    rtt_variation: { 3 * estimator.rtt_variation + variation_sample } / 4,
    minimum_rtt: minimum_rtt,
    has_sample: True,
  )
}

fn backoff(value: Int, count: Int) -> Int {
  case count {
    0 -> value
    _ -> backoff(value * 2, count - 1)
  }
}

fn absolute(value: Int) -> Int {
  case value < 0 {
    True -> 0 - value
    False -> value
  }
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

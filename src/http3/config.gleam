//// Shared, finite HTTP/3 and QUIC operating policy.
////
//// Defaults are immediately usable. Custom values are validated once, then
//// attached atomically to a client or server configuration.

import gleam/bool
import http3/failure

const maximum_milliseconds = 3_600_000

const maximum_limit = 2_147_483_647

/// IP-family policy for clients and listeners.
pub type AddressFamily {
  Ipv4
  Ipv6
  DualStack
}

/// Finite DNS, transport, application, and lifecycle deadlines.
pub opaque type Deadlines {
  Deadlines(
    dns: Int,
    connect: Int,
    handshake: Int,
    operation: Int,
    idle: Int,
    drain: Int,
    total: Int,
  )
}

/// Finite endpoint, stream, buffer, queue, and telemetry limits.
///
/// Every role-applicable field is enforced by the current runtime except
/// `EndpointMemory`. That aggregate budget is validated and retained for the
/// intended API, but remains an explicit pre-release blocker until listener
/// connections have isolated accounting.
pub opaque type Limits {
  Limits(
    connections: Int,
    handshakes: Int,
    bidirectional_streams: Int,
    unidirectional_streams: Int,
    request_body: Int,
    response_body: Int,
    buffer: Int,
    endpoint_memory: Int,
    queue: Int,
    frame: Int,
    datagram: Int,
    qpack_table: Int,
    qpack_blocked_streams: Int,
    accept_waiters: Int,
    telemetry: Int,
  )
}

/// Invalid finite policy input.
pub type Error {
  InvalidDeadline(phase: failure.TimeoutPhase, milliseconds: Int)
  InvalidLimit(resource: failure.Resource, maximum: Int)
}

/// Secure deadlines used by a new client or server.
pub fn default_deadlines() -> Deadlines {
  Deadlines(
    dns: 5000,
    connect: 10_000,
    handshake: 10_000,
    operation: 30_000,
    idle: 30_000,
    drain: 30_000,
    total: 30_000,
  )
}

/// Bounded resource limits used by a new client or server.
pub fn default_limits() -> Limits {
  Limits(
    connections: 1024,
    handshakes: 128,
    bidirectional_streams: 100,
    unidirectional_streams: 100,
    request_body: 8_388_608,
    response_body: 8_388_608,
    buffer: 262_144,
    endpoint_memory: 67_108_864,
    queue: 1024,
    frame: 65_536,
    datagram: 65_527,
    qpack_table: 4096,
    qpack_blocked_streams: 16,
    accept_waiters: 1,
    telemetry: 1024,
  )
}

/// Return one configured deadline in milliseconds.
pub fn deadline(
  deadlines deadlines: Deadlines,
  phase phase: failure.TimeoutPhase,
) -> Int {
  case phase {
    failure.Dns -> deadlines.dns
    failure.Connect -> deadlines.connect
    failure.Handshake -> deadlines.handshake
    failure.Operation -> deadlines.operation
    failure.Idle -> deadlines.idle
    failure.Drain -> deadlines.drain
    failure.Total -> deadlines.total
  }
}

/// Change one finite deadline from one millisecond through one hour.
pub fn with_deadline(
  deadlines deadlines: Deadlines,
  phase phase: failure.TimeoutPhase,
  milliseconds milliseconds: Int,
) -> Result(Deadlines, Error) {
  use <- bool.guard(
    when: milliseconds <= 0 || milliseconds > maximum_milliseconds,
    return: Error(InvalidDeadline(phase, milliseconds)),
  )
  Ok(case phase {
    failure.Dns -> Deadlines(..deadlines, dns: milliseconds)
    failure.Connect -> Deadlines(..deadlines, connect: milliseconds)
    failure.Handshake -> Deadlines(..deadlines, handshake: milliseconds)
    failure.Operation -> Deadlines(..deadlines, operation: milliseconds)
    failure.Idle -> Deadlines(..deadlines, idle: milliseconds)
    failure.Drain -> Deadlines(..deadlines, drain: milliseconds)
    failure.Total -> Deadlines(..deadlines, total: milliseconds)
  })
}

/// Construct the legacy single-timeout policy without permitting infinity.
pub fn uniform_deadlines(milliseconds: Int) -> Result(Deadlines, Error) {
  use <- bool.guard(
    when: milliseconds <= 0 || milliseconds > maximum_milliseconds,
    return: Error(InvalidDeadline(failure.Total, milliseconds)),
  )
  Ok(Deadlines(
    milliseconds,
    milliseconds,
    milliseconds,
    milliseconds,
    milliseconds,
    milliseconds,
    milliseconds,
  ))
}

/// Return one configured resource maximum.
pub fn limit(
  limits limits: Limits,
  resource resource: failure.Resource,
) -> Int {
  case resource {
    failure.Connections -> limits.connections
    failure.Handshakes -> limits.handshakes
    failure.BidirectionalStreams -> limits.bidirectional_streams
    failure.UnidirectionalStreams -> limits.unidirectional_streams
    failure.RequestBody -> limits.request_body
    failure.ResponseBody -> limits.response_body
    failure.Buffer -> limits.buffer
    failure.EndpointMemory -> limits.endpoint_memory
    failure.Queue -> limits.queue
    failure.Frame -> limits.frame
    failure.Datagram -> limits.datagram
    failure.QpackTable -> limits.qpack_table
    failure.QpackBlockedStreams -> limits.qpack_blocked_streams
    failure.AcceptWaiters -> limits.accept_waiters
    failure.Telemetry -> limits.telemetry
  }
}

/// Change one resource maximum while rejecting zero and infinity sentinels.
pub fn with_limit(
  limits limits: Limits,
  resource resource: failure.Resource,
  maximum maximum: Int,
) -> Result(Limits, Error) {
  use <- bool.guard(
    when: maximum <= 0 || maximum > maximum_limit,
    return: Error(InvalidLimit(resource, maximum)),
  )
  Ok(case resource {
    failure.Connections -> Limits(..limits, connections: maximum)
    failure.Handshakes -> Limits(..limits, handshakes: maximum)
    failure.BidirectionalStreams ->
      Limits(..limits, bidirectional_streams: maximum)
    failure.UnidirectionalStreams ->
      Limits(..limits, unidirectional_streams: maximum)
    failure.RequestBody -> Limits(..limits, request_body: maximum)
    failure.ResponseBody -> Limits(..limits, response_body: maximum)
    failure.Buffer -> Limits(..limits, buffer: maximum)
    failure.EndpointMemory -> Limits(..limits, endpoint_memory: maximum)
    failure.Queue -> Limits(..limits, queue: maximum)
    failure.Frame -> Limits(..limits, frame: maximum)
    failure.Datagram -> Limits(..limits, datagram: maximum)
    failure.QpackTable -> Limits(..limits, qpack_table: maximum)
    failure.QpackBlockedStreams ->
      Limits(..limits, qpack_blocked_streams: maximum)
    failure.AcceptWaiters -> Limits(..limits, accept_waiters: maximum)
    failure.Telemetry -> Limits(..limits, telemetry: maximum)
  })
}

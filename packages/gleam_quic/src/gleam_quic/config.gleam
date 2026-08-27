//// Finite operating policy shared by generic QUIC clients and servers.
////
//// Defaults are immediately usable. Every custom value is validated before
//// it can be attached to an endpoint; there is deliberately no unlimited
//// deadline, queue, stream, Datagram, or buffer setting.

import gleam/bool
import gleam_quic/failure

const maximum_milliseconds = 3_600_000

const maximum_limit = 2_147_483_647

/// Finite DNS, connection, handshake, operation, idle, drain, and total
/// deadlines in milliseconds.
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

/// Finite endpoint, stream, buffer, queue, Datagram, and telemetry limits.
///
/// `EndpointMemory` is the aggregate byte budget for one endpoint. What "one
/// endpoint" means, and whether the budget is enforced, differs by role:
///
///   * server: the whole listener, and it is enforced. Every connection the
///     listener admits is charged 48 KiB on its first valid Initial packet,
///     before any per-connection state is built: a 16 KiB handshake working
///     set, plus the 32 KiB of connection-level receive credit the server
///     advertises to that peer in the handshake. Charging for the advertised
///     credit is what makes this a bound rather than an aspiration, because a
///     transport parameter cannot be retracted once the peer has read it. A
///     connection the budget cannot cover is refused with CONNECTION_REFUSED
///     rather than admitted. After that a connection asks the listener for
///     room, in whole 16 KiB quanta and 256 KiB steps, before it advertises
///     any further receive credit or takes an application's write into its
///     send buffers. Growth the budget cannot fund is refused, and a refused
///     connection stops raising the credit it advertises instead of growing
///     anyway.
///   * client: one connection, because a client endpoint is one connection --
///     and the client role does not enforce this limit yet. Nothing on the
///     client path reads it. What bounds a client connection today is the
///     per-connection ceilings: `Buffer` for each stream direction, `Queue`
///     for backlogs, and `Datagram` for RFC 9221 queueing.
///
/// Sizing rule for a server. `EndpointMemory` should cover
/// `Connections * (48 KiB + Buffer)` for the load you actually expect to
/// carry at once: the admission charge every connection pays, plus the buffer
/// a connection whose owner has stopped reading comes to hold. The defaults
/// deliberately do not satisfy that product -- 1024 connections at a 256 KiB
/// `Buffer` would want 304 MiB, and the default budget is 64 MiB -- because
/// refusing to grow is the intended behaviour beyond it, not a failure of it:
/// connections past the budget keep the credit they were already advertised
/// and stop being offered more, and new connections are refused rather than
/// admitted into memory the endpoint does not have. Raise `EndpointMemory` to
/// the product above if you would rather spend the memory than throttle, and
/// lower it to cap what a peer population can make this endpoint hold.
/// `Buffer` wants to be at least one 256 KiB growth step wide alongside it: a
/// per-stream buffer narrower than the room a connection rests on makes that
/// stream's own reassembly bound, rather than this budget, the first thing a
/// flood meets.
///
/// How tight the bound is. It is exact at admission and soft afterwards, and
/// the slack has exactly two sources. Credit already advertised is never
/// retracted, so a connection whose grant has shrunk may still have
/// outstanding receive credit sized for the grant it held a moment ago: at
/// most one 256 KiB growth step per connection. And measurement is coarse on
/// purpose -- a connection re-measures what it holds once per 16 KiB of
/// traffic rather than once per datagram -- so the hold it is working against
/// can be a quantum out of date, and no more than one of its own turns out of
/// date. There is no third source: an application's write is admitted only as
/// far as the grant reaches past what the connection holds, on every write
/// rather than only after a refusal, and what it holds is counted
/// conservatively, so the send side leaves no `Buffer`-sized hole. Treat the
/// value as a bound with a per-connection margin of one growth step plus one
/// quantum rather than as a byte-exact cap.
///
/// The value is a byte count, so it bounds memory rather than connections;
/// `Connections` and `Handshakes` bound those separately, and the listener's
/// per-connection delivery window bounds mailbox occupancy separately again:
/// per connection by that window, and in aggregate by `Connections` times it.
pub opaque type Limits {
  Limits(
    connections: Int,
    handshakes: Int,
    bidirectional_streams: Int,
    unidirectional_streams: Int,
    buffer: Int,
    endpoint_memory: Int,
    queue: Int,
    datagram: Int,
    accept_waiters: Int,
    telemetry: Int,
  )
}

/// Invalid finite policy input.
pub type Error {
  InvalidDeadline(phase: failure.TimeoutPhase, milliseconds: Int)
  InvalidLimit(resource: failure.Resource, maximum: Int)
}

/// Secure finite deadlines for a new endpoint.
pub fn default_deadlines() -> Deadlines {
  Deadlines(
    dns: 5000,
    connect: 10_000,
    handshake: 10_000,
    operation: 30_000,
    idle: 30_000,
    drain: 3000,
    total: 30_000,
  )
}

/// Conservative bounded resource limits for a new endpoint.
pub fn default_limits() -> Limits {
  Limits(
    connections: 1024,
    handshakes: 128,
    bidirectional_streams: 100,
    unidirectional_streams: 100,
    buffer: 262_144,
    endpoint_memory: 67_108_864,
    queue: 1024,
    datagram: 65_527,
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

/// Construct a legacy single-timeout policy without permitting infinity.
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
    failure.Buffer -> limits.buffer
    failure.EndpointMemory -> limits.endpoint_memory
    failure.Queue -> limits.queue
    failure.Datagram -> limits.datagram
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
    failure.Buffer -> Limits(..limits, buffer: maximum)
    failure.EndpointMemory -> Limits(..limits, endpoint_memory: maximum)
    failure.Queue -> Limits(..limits, queue: maximum)
    failure.Datagram -> Limits(..limits, datagram: maximum)
    failure.AcceptWaiters -> Limits(..limits, accept_waiters: maximum)
    failure.Telemetry -> Limits(..limits, telemetry: maximum)
  })
}

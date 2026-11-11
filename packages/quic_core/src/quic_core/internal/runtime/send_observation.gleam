//// One bounded, owner-scoped send observation shared with its connection actor.
//// The atomic park cause survives a delayed actor reply.
//// Terminal transitions are one-shot, and the owner's reply alias rejects all later publication.

import gleam/erlang/process.{type Pid}

pub type Observation(value)

pub type Awaited(value) {
  Replied(value)
  DeadlineExpired(held_by_grant: Bool)
  WorkerExited
  OwnerExited
  /// The fixed observation, reply alias, or required monitor could not be allocated.
  /// No command result can be observed through this capability.
  Unavailable
}

@external(erlang, "quic_core_send_observation_ffi", "new")
pub fn new() -> Observation(value)

/// Whether the fixed observation and reply alias were allocated.
/// Callers use this before dispatch so a local resource failure has no remote side effect.
@external(erlang, "quic_core_send_observation_ffi", "available")
pub fn available(observation: Observation(value)) -> Bool

@external(erlang, "quic_core_send_observation_ffi", "park")
pub fn park(observation: Observation(value), held_by_grant: Bool) -> Bool

@external(erlang, "quic_core_send_observation_ffi", "publish")
pub fn publish(observation: Observation(value), result: value) -> Bool

@external(erlang, "quic_core_send_observation_ffi", "await")
pub fn await(
  observation: Observation(value),
  worker: Pid,
  timeout_milliseconds: Int,
) -> Awaited(value)

/// Await a reply while also treating an enclosing owner's exit as terminal.
/// This lets a connection-scoped observer stop promptly without periodic polling, while the connection worker still monitors the observer itself.
@external(erlang, "quic_core_send_observation_ffi", "await_with_owner")
pub fn await_with_owner(
  observation: Observation(value),
  worker: Pid,
  owner: Pid,
  timeout_milliseconds: Int,
) -> Awaited(value)

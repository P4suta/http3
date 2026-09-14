//// Applied peer SETTINGS with RFC 9113 initial values.

import gleam/option.{type Option, None, Some}
import gleam/result
import http/internal/http2/settings

/// The local endpoint role receiving a SETTINGS frame.
pub type Role {
  Client
  Server
}

/// Peer policy that controls locally generated frames and streams.
pub opaque type State {
  State(
    header_table_size: Int,
    push_enabled: Bool,
    maximum_concurrent_streams: Option(Int),
    initial_window_size: Int,
    maximum_frame_size: Int,
    maximum_header_list_size: Option(Int),
    extended_connect_enabled: Bool,
    rfc7540_priorities_disabled: Bool,
  )
}

/// The next state and the net per-stream outbound-window delta.
pub type Applied {
  Applied(settings: State, initial_window_delta: Int)
}

/// A role-specific or malformed setting failure.
pub type Error {
  EnablePushForbidden
  InvalidSetting(settings.Error)
}

/// RFC 9113 defaults before any peer SETTINGS are received.
pub fn defaults() -> State {
  State(
    header_table_size: 4096,
    push_enabled: True,
    maximum_concurrent_streams: None,
    initial_window_size: 65_535,
    maximum_frame_size: 16_384,
    maximum_header_list_size: None,
    extended_connect_enabled: False,
    rfc7540_priorities_disabled: False,
  )
}

/// Apply an ordered SETTINGS payload transactionally; duplicate identifiers
/// use their last value and unknown identifiers are ignored.
pub fn apply(
  state: State,
  values: List(settings.Setting),
  role: Role,
) -> Result(Applied, Error) {
  let previous_initial_window = state.initial_window_size
  use _ <- result.try(validate_values(values))
  use state <- result.try(apply_values(state, values, role))
  Ok(Applied(state, state.initial_window_size - previous_initial_window))
}

/// Advertised HPACK table capacity.
pub fn header_table_size(state: State) -> Int {
  state.header_table_size
}

/// Whether the peer accepts server push.
pub fn push_enabled(state: State) -> Bool {
  state.push_enabled
}

/// Peer-advertised concurrent stream limit, or no explicit limit.
pub fn maximum_concurrent_streams(state: State) -> Option(Int) {
  state.maximum_concurrent_streams
}

/// Initial outbound stream flow-control window.
pub fn initial_window_size(state: State) -> Int {
  state.initial_window_size
}

/// Largest frame payload the peer accepts.
pub fn maximum_frame_size(state: State) -> Int {
  state.maximum_frame_size
}

/// Advisory decoded header-list limit, when supplied.
pub fn maximum_header_list_size(state: State) -> Option(Int) {
  state.maximum_header_list_size
}

/// Whether RFC 8441 Extended CONNECT was enabled by the peer.
pub fn extended_connect_enabled(state: State) -> Bool {
  state.extended_connect_enabled
}

/// Whether RFC 7540 priority signaling was disabled by the peer.
pub fn rfc7540_priorities_disabled(state: State) -> Bool {
  state.rfc7540_priorities_disabled
}

fn apply_values(
  state: State,
  values: List(settings.Setting),
  role: Role,
) -> Result(State, Error) {
  case values {
    [] -> Ok(state)
    [value, ..rest] -> {
      use state <- result.try(apply_one(state, value, role))
      apply_values(state, rest, role)
    }
  }
}

fn apply_one(
  state: State,
  value: settings.Setting,
  role: Role,
) -> Result(State, Error) {
  case value {
    settings.HeaderTableSize(value) ->
      Ok(State(..state, header_table_size: value))
    settings.EnablePush(_) if role == Client -> Error(EnablePushForbidden)
    settings.EnablePush(value) -> Ok(State(..state, push_enabled: value))
    settings.MaxConcurrentStreams(value) ->
      Ok(State(..state, maximum_concurrent_streams: Some(value)))
    settings.InitialWindowSize(value) ->
      Ok(State(..state, initial_window_size: value))
    settings.MaxFrameSize(value) ->
      Ok(State(..state, maximum_frame_size: value))
    settings.MaxHeaderListSize(value) ->
      Ok(State(..state, maximum_header_list_size: Some(value)))
    settings.EnableConnectProtocol(False) if state.extended_connect_enabled ->
      Error(InvalidSetting(settings.InvalidValue(8)))
    settings.EnableConnectProtocol(value) ->
      Ok(State(..state, extended_connect_enabled: value))
    settings.NoRfc7540Priorities(value) ->
      Ok(State(..state, rfc7540_priorities_disabled: value))
    settings.Unknown(_, _) -> Ok(state)
  }
}

fn validate_values(values: List(settings.Setting)) -> Result(Nil, Error) {
  case settings.encode(values) {
    Ok(_) -> Ok(Nil)
    Error(failure) -> Error(InvalidSetting(failure))
  }
}

//// RFC 9114 control-stream state and negotiated SETTINGS validation.

import gleam/list
import gleam/option.{type Option, None, Some}
import gleam/result
import gleam_quic/internal/http3/frame
import gleam_quic/varint

/// Endpoint that owns the peer control stream being processed.
pub type PeerRole {
  Client
  Server
}

/// Validated peer HTTP/3 settings with unknown extensions retained.
pub type Settings {
  Settings(
    qpack_max_table_capacity: Int,
    maximum_field_section_size: Int,
    qpack_blocked_streams: Int,
    enable_connect_protocol: Bool,
    h3_datagram: Bool,
    unknown: List(frame.Setting),
  )
}

/// Observable state change from one accepted control frame.
pub type Event {
  SettingsReceived(Settings)
  GoAwayReceived(Int)
  PushCancelled(Int)
  MaximumPushIdReceived(Int)
  ExtensionIgnored(frame_type: Int)
}

/// One peer control stream. Exactly one such stream exists per connection.
pub opaque type State {
  State(
    peer_role: PeerRole,
    settings: Option(Settings),
    goaway_identifier: Option(Int),
    maximum_push_id: Option(Int),
  )
}

/// HTTP/3 control-stream or SETTINGS semantic failure.
pub type Error {
  MissingSettings
  DuplicateSettings
  FrameUnexpected
  InvalidSetting(Int)
  DatagramTransportNotNegotiated
  InvalidGoAwayIdentifier(Int)
  IncreasingGoAwayIdentifier
  PushControlFromServer
  PushIdDecreased
}

/// Start a control stream that must receive SETTINGS first.
pub fn new(peer_role: PeerRole) -> State {
  State(peer_role, None, None, None)
}

/// Apply one already decoded control-stream frame.
pub fn receive(
  state: State,
  incoming: frame.Frame,
  quic_datagram_negotiated: Bool,
) -> Result(#(State, Event), Error) {
  case state.settings, incoming {
    None, frame.Settings(settings) ->
      receive_settings(state, settings, quic_datagram_negotiated)
    None, _ -> Error(MissingSettings)
    Some(_), frame.Settings(_) -> Error(DuplicateSettings)
    Some(_), frame.GoAway(identifier) -> receive_goaway(state, identifier)
    Some(_), frame.CancelPush(push_id) -> receive_cancel_push(state, push_id)
    Some(_), frame.MaxPushId(push_id) -> receive_max_push_id(state, push_id)
    Some(_), frame.Unknown(frame_type, _) ->
      Ok(#(state, ExtensionIgnored(frame_type)))
    Some(_), _ -> Error(FrameUnexpected)
  }
}

/// Return negotiated settings after the mandatory first frame.
pub fn settings(state: State) -> Option(Settings) {
  state.settings
}

fn receive_settings(
  state: State,
  incoming: List(frame.Setting),
  quic_datagram_negotiated: Bool,
) -> Result(#(State, Event), Error) {
  use settings <- result.try(validate_settings(
    incoming,
    quic_datagram_negotiated,
  ))
  Ok(#(State(..state, settings: Some(settings)), SettingsReceived(settings)))
}

fn validate_settings(
  incoming: List(frame.Setting),
  quic_datagram_negotiated: Bool,
) -> Result(Settings, Error) {
  let defaults = Settings(0, varint.maximum, 0, False, False, [])
  use settings <- result.try(apply_settings(incoming, defaults))
  case settings.h3_datagram && !quic_datagram_negotiated {
    True -> Error(DatagramTransportNotNegotiated)
    False -> Ok(settings)
  }
}

fn apply_settings(
  incoming: List(frame.Setting),
  settings: Settings,
) -> Result(Settings, Error) {
  case incoming {
    [] -> Ok(Settings(..settings, unknown: list.reverse(settings.unknown)))
    [frame.Setting(identifier, value) as setting, ..rest] -> {
      use settings <- result.try(apply_setting(
        settings,
        identifier,
        value,
        setting,
      ))
      apply_settings(rest, settings)
    }
  }
}

fn apply_setting(
  settings: Settings,
  identifier: Int,
  value: Int,
  original: frame.Setting,
) -> Result(Settings, Error) {
  case identifier {
    1 -> Ok(Settings(..settings, qpack_max_table_capacity: value))
    6 -> Ok(Settings(..settings, maximum_field_section_size: value))
    7 -> Ok(Settings(..settings, qpack_blocked_streams: value))
    8 ->
      case boolean_setting(value) {
        Error(_) -> Error(InvalidSetting(identifier))
        Ok(enabled) ->
          Ok(Settings(..settings, enable_connect_protocol: enabled))
      }
    0x33 ->
      case boolean_setting(value) {
        Error(_) -> Error(InvalidSetting(identifier))
        Ok(enabled) -> Ok(Settings(..settings, h3_datagram: enabled))
      }
    _ -> Ok(Settings(..settings, unknown: [original, ..settings.unknown]))
  }
}

fn boolean_setting(value: Int) -> Result(Bool, Nil) {
  case value {
    0 -> Ok(False)
    1 -> Ok(True)
    _ -> Error(Nil)
  }
}

fn receive_goaway(
  state: State,
  identifier: Int,
) -> Result(#(State, Event), Error) {
  case valid_goaway_identifier(state.peer_role, identifier) {
    False -> Error(InvalidGoAwayIdentifier(identifier))
    True ->
      case state.goaway_identifier {
        Some(previous) if identifier > previous ->
          Error(IncreasingGoAwayIdentifier)
        _ ->
          Ok(#(
            State(..state, goaway_identifier: Some(identifier)),
            GoAwayReceived(identifier),
          ))
      }
  }
}

fn valid_goaway_identifier(peer_role: PeerRole, identifier: Int) -> Bool {
  case peer_role {
    Client -> identifier >= 0 && identifier <= varint.maximum
    Server ->
      identifier >= 0 && identifier <= varint.maximum && identifier % 4 == 0
  }
}

fn receive_cancel_push(
  state: State,
  push_id: Int,
) -> Result(#(State, Event), Error) {
  case state.peer_role {
    Server -> Error(PushControlFromServer)
    Client -> Ok(#(state, PushCancelled(push_id)))
  }
}

fn receive_max_push_id(
  state: State,
  push_id: Int,
) -> Result(#(State, Event), Error) {
  case state.peer_role, state.maximum_push_id {
    Server, _ -> Error(PushControlFromServer)
    Client, Some(previous) if push_id < previous -> Error(PushIdDecreased)
    Client, _ ->
      Ok(#(
        State(..state, maximum_push_id: Some(push_id)),
        MaximumPushIdReceived(push_id),
      ))
  }
}

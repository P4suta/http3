import gleam/option.{None, Some}
import http3/internal/native/control
import http3/internal/native/frame
import http3/internal/native/origin

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn peer_can_advertise_datagrams_without_local_transport_support_test() -> Nil {
  let assert Ok(#(_, control.SettingsReceived(settings))) =
    control.receive(
      control.new(control.Client),
      frame.Settings([frame.Setting(0x33, 1)]),
    )
  assert settings.h3_datagram
}

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn requires_and_validates_settings_before_control_frames_test() -> Nil {
  let state = control.new(control.Server)
  assert control.receive(state, frame.GoAway(0))
    == Error(control.MissingSettings)
  let settings = [
    frame.Setting(1, 4096),
    frame.Setting(6, 65_536),
    frame.Setting(7, 16),
    frame.Setting(8, 1),
    frame.Setting(0x33, 1),
    frame.Setting(0x21, 9),
  ]
  let assert Ok(#(state, control.SettingsReceived(decoded))) =
    control.receive(state, frame.Settings(settings))
  assert control.settings(state) == Some(decoded)
  assert decoded.qpack_max_table_capacity == 4096
  assert decoded.maximum_field_section_size == 65_536
  assert decoded.qpack_blocked_streams == 16
  assert decoded.enable_connect_protocol
  assert decoded.h3_datagram
  assert decoded.unknown == [frame.Setting(0x21, 9)]
  assert decoded.present == [1, 6, 7, 8, 0x33]
  assert control.receive(state, frame.Settings([]))
    == Error(control.DuplicateSettings)
}

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn validates_goaway_push_and_datagram_constraints_test() -> Nil {
  let server = control.new(control.Server)
  assert control.receive(server, frame.Settings([frame.Setting(0x33, 2)]))
    == Error(control.InvalidSetting(0x33))
  let assert Ok(#(server, _)) = control.receive(server, frame.Settings([]))
  let assert Ok(#(server, control.GoAwayReceived(8))) =
    control.receive(server, frame.GoAway(8))
  assert control.receive(server, frame.GoAway(12))
    == Error(control.IncreasingGoAwayIdentifier)
  assert control.receive(server, frame.GoAway(7))
    == Error(control.InvalidGoAwayIdentifier(7))
  assert control.receive(server, frame.CancelPush(0))
    == Error(control.PushControlFromServer)

  let client = control.new(control.Client)
  let assert Ok(#(client, _)) = control.receive(client, frame.Settings([]))
  let assert Ok(#(client, control.MaximumPushIdReceived(10))) =
    control.receive(client, frame.MaxPushId(10))
  assert control.receive(client, frame.MaxPushId(9))
    == Error(control.PushIdDecreased)
}

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn origin_is_typed_only_on_a_server_control_stream_after_settings_test() -> Nil {
  let origins = [origin.Origin("https", "example.com", None)]
  let server_peer = control.new(control.Server)
  assert control.receive(server_peer, frame.Origin(origins))
    == Error(control.MissingSettings)
  let assert Ok(#(server_peer, _)) =
    control.receive(server_peer, frame.Settings([]))
  let assert Ok(#(_, control.OriginsReceived(received))) =
    control.receive(server_peer, frame.Origin(origins))
  assert received == origins

  let client_peer = control.new(control.Client)
  let assert Ok(#(client_peer, _)) =
    control.receive(client_peer, frame.Settings([]))
  assert control.receive(client_peer, frame.Origin(origins))
    == Error(control.FrameUnexpected)
}

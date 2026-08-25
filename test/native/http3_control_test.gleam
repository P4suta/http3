import gleam/option.{Some}
import http3/internal/native/control
import http3/internal/native/frame

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn requires_and_validates_settings_before_control_frames_test() -> Nil {
  let state = control.new(control.Server)
  assert control.receive(state, frame.GoAway(0), True)
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
    control.receive(state, frame.Settings(settings), True)
  assert control.settings(state) == Some(decoded)
  assert decoded.qpack_max_table_capacity == 4096
  assert decoded.maximum_field_section_size == 65_536
  assert decoded.qpack_blocked_streams == 16
  assert decoded.enable_connect_protocol
  assert decoded.h3_datagram
  assert decoded.unknown == [frame.Setting(0x21, 9)]
  assert control.receive(state, frame.Settings([]), True)
    == Error(control.DuplicateSettings)
}

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn validates_goaway_push_and_datagram_constraints_test() -> Nil {
  let server = control.new(control.Server)
  assert control.receive(
      server,
      frame.Settings([frame.Setting(0x33, 1)]),
      False,
    )
    == Error(control.DatagramTransportNotNegotiated)
  let assert Ok(#(server, _)) =
    control.receive(server, frame.Settings([]), False)
  let assert Ok(#(server, control.GoAwayReceived(8))) =
    control.receive(server, frame.GoAway(8), False)
  assert control.receive(server, frame.GoAway(12), False)
    == Error(control.IncreasingGoAwayIdentifier)
  assert control.receive(server, frame.GoAway(7), False)
    == Error(control.InvalidGoAwayIdentifier(7))
  assert control.receive(server, frame.CancelPush(0), False)
    == Error(control.PushControlFromServer)

  let client = control.new(control.Client)
  let assert Ok(#(client, _)) =
    control.receive(client, frame.Settings([]), False)
  let assert Ok(#(client, control.MaximumPushIdReceived(10))) =
    control.receive(client, frame.MaxPushId(10), False)
  assert control.receive(client, frame.MaxPushId(9), False)
    == Error(control.PushIdDecreased)
}

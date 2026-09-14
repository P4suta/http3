import gleeunit
import http/internal/http2/control
import http/internal/http2/frame
import http/internal/http2/settings

pub fn main() -> Nil {
  gleeunit.main()
}

pub fn settings_and_ping_flags_are_decoded_without_losing_payload_test() -> Nil {
  let settings_payload = <<0, 2, 0, 0, 0, 0, 0, 99, 0, 0, 0, 7>>
  assert control.decode(
      frame.Header(12, frame.Settings, 0, 0),
      settings_payload,
      32,
    )
    == Ok(
      control.SettingsFrame([
        settings.EnablePush(False),
        settings.Unknown(99, 7),
      ]),
    )
  assert control.decode(frame.Header(0, frame.Settings, 1, 0), <<>>, 32)
    == Ok(control.SettingsAcknowledgement)
  assert control.decode(
      frame.Header(8, frame.Ping, 1, 0),
      <<"12345678":utf8>>,
      32,
    )
    == Ok(control.PingFrame(acknowledgement: True, data: <<"12345678":utf8>>))
}

pub fn goaway_and_reserved_last_stream_bit_are_bounded_test() -> Nil {
  let payload = <<1:size(1), 7:size(31), 0x0b, 0xad, 0xca, 0xfe, "bye":utf8>>
  assert control.decode(frame.Header(11, frame.GoAway, 0, 0), payload, 3)
    == Ok(
      control.GoAwayFrame(
        last_stream_id: 7,
        error_code: 0x0bad_cafe,
        debug_data: <<"bye":utf8>>,
      ),
    )
  assert control.decode(frame.Header(11, frame.GoAway, 0, 0), payload, 2)
    == Error(control.DebugDataTooLarge(maximum: 2))
}

pub fn priority_reset_and_window_update_are_typed_test() -> Nil {
  assert control.decode(
      frame.Header(5, frame.Priority, 0, 3),
      <<1:size(1), 1:size(31), 255>>,
      0,
    )
    == Ok(control.PriorityFrame(exclusive: True, dependency: 1, weight: 256))
  assert control.decode(
      frame.Header(4, frame.RstStream, 0, 3),
      <<0, 0, 0, 8>>,
      0,
    )
    == Ok(control.ResetFrame(error_code: 8))
  assert control.decode(
      frame.Header(4, frame.WindowUpdate, 0, 0),
      <<1:size(1), 5:size(31)>>,
      0,
    )
    == Ok(control.WindowUpdateFrame(increment: 5))
}

pub fn malformed_control_payloads_are_rejected_test() -> Nil {
  assert control.decode(
      frame.Header(4, frame.WindowUpdate, 0, 0),
      <<0:size(1), 0:size(31)>>,
      0,
    )
    == Error(control.ZeroWindowIncrement)
  assert control.decode(
      frame.Header(5, frame.Priority, 0, 3),
      <<0:size(1), 3:size(31), 0>>,
      0,
    )
    == Error(control.SelfDependency)
  assert control.decode(frame.Header(8, frame.Ping, 0, 0), <<1:size(1)>>, 0)
    == Error(control.NonByteAligned)
  assert control.decode(frame.Header(8, frame.Ping, 0, 0), <<"short":utf8>>, 0)
    == Error(control.InvalidPayloadLength)
  assert control.decode(frame.Header(0, frame.Data, 0, 1), <<>>, 0)
    == Error(control.UnexpectedFrameType)
}

pub fn typed_control_events_encode_to_validated_frame_envelopes_test() -> Nil {
  let event = control.WindowUpdateFrame(increment: 5)
  let assert Ok(encoded) = control.encode(event, 3, 16_384)
  assert encoded == <<0, 0, 4, 8, 0, 0, 0, 0, 3, 0, 0, 0, 5>>

  let event =
    control.PingFrame(acknowledgement: True, data: <<"12345678":utf8>>)
  let assert Ok(encoded) = control.encode(event, 0, 16_384)
  assert encoded == <<0, 0, 8, 6, 1, 0, 0, 0, 0, "12345678":utf8>>
}

pub fn control_encoder_rejects_invalid_stream_and_value_combinations_test() -> Nil {
  assert control.encode(control.ResetFrame(8), 0, 16_384)
    == Error(control.InvalidStreamIdentifier)
  assert control.encode(control.SettingsAcknowledgement, 1, 16_384)
    == Error(control.InvalidStreamIdentifier)
  assert control.encode(control.WindowUpdateFrame(0), 0, 16_384)
    == Error(control.ZeroWindowIncrement)
  assert control.encode(control.PriorityFrame(False, 3, 1), 3, 16_384)
    == Error(control.SelfDependency)
  assert control.encode(control.PriorityFrame(False, 1, 0), 3, 16_384)
    == Error(control.InvalidWeight)
}

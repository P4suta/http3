import gleeunit
import http/internal/http2/settings

pub fn main() -> Nil {
  gleeunit.main()
}

pub fn known_and_unknown_settings_decode_without_loss_test() -> Nil {
  let payload = <<
    0, 1, 0, 0, 16, 0, 0, 2, 0, 0, 0, 1, 0, 4, 127, 255, 255, 255, 0, 5, 0, 0,
    64, 0, 0, 8, 0, 0, 0, 1, 250, 206, 222, 173, 190, 239,
  >>

  assert settings.decode(payload)
    == Ok([
      settings.HeaderTableSize(4096),
      settings.EnablePush(True),
      settings.InitialWindowSize(2_147_483_647),
      settings.MaxFrameSize(16_384),
      settings.EnableConnectProtocol(True),
      settings.Unknown(0xface, 0xdead_beef),
    ])
}

pub fn setting_sequence_round_trips_in_order_test() -> Nil {
  let values = [
    settings.MaxConcurrentStreams(100),
    settings.MaxHeaderListSize(65_536),
    settings.NoRfc7540Priorities(False),
    settings.Unknown(42, 99),
  ]

  let assert Ok(encoded) = settings.encode(values)
  assert settings.decode(encoded) == Ok(values)
}

pub fn constrained_setting_values_are_rejected_test() -> Nil {
  assert settings.decode(<<0, 2, 0, 0, 0, 2>>)
    == Error(settings.InvalidValue(2))
  assert settings.decode(<<0, 4, 128, 0, 0, 0>>)
    == Error(settings.InvalidValue(4))
  assert settings.decode(<<0, 5, 0, 0, 63, 255>>)
    == Error(settings.InvalidValue(5))
  assert settings.decode(<<0, 5, 1, 0, 0, 0>>)
    == Error(settings.InvalidValue(5))
  assert settings.decode(<<0, 8, 0, 0, 0, 2>>)
    == Error(settings.InvalidValue(8))
  assert settings.decode(<<0, 9, 0, 0, 0, 2>>)
    == Error(settings.InvalidValue(9))
}

pub fn malformed_payload_and_invalid_encode_values_are_typed_test() -> Nil {
  assert settings.decode(<<0, 1, 0>>) == Error(settings.InvalidPayloadLength)
  assert settings.decode(<<1:size(1)>>) == Error(settings.NonByteAligned)
  assert settings.encode([settings.Unknown(65_536, 0)])
    == Error(settings.InvalidIdentifier)
  assert settings.encode([settings.HeaderTableSize(-1)])
    == Error(settings.InvalidValue(1))
}

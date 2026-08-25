import http3/internal/native/frame

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn round_trips_core_extension_and_concatenated_frames_test() -> Nil {
  let limits = frame.default_limits()
  let settings =
    frame.Settings([
      frame.Setting(1, 4096),
      frame.Setting(7, 16),
      frame.Setting(0x33, 1),
    ])
  let assert Ok(encoded_settings) = frame.encode(settings)
  let assert Ok(encoded_headers) = frame.encode(frame.Headers(<<1, 2, 3>>))
  let assert Ok(encoded_unknown) = frame.encode(frame.Unknown(0x21, <<9>>))
  let bytes = <<
    encoded_settings:bits,
    encoded_headers:bits,
    encoded_unknown:bits,
  >>

  let assert Ok(#(decoded_settings, rest)) = frame.decode(bytes, limits)
  assert decoded_settings == settings
  let assert Ok(#(frame.Headers(<<1, 2, 3>>), rest)) =
    frame.decode(rest, limits)
  assert frame.decode(rest, limits) == Ok(#(frame.Unknown(0x21, <<9>>), <<>>))
}

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn matches_rfc_wire_shapes_test() -> Nil {
  assert frame.encode(frame.Data(<<"hello">>)) == Ok(<<0, 5, "hello">>)
  assert frame.encode(frame.Settings([frame.Setting(1, 4096)]))
    == Ok(<<4, 3, 1, 0x50, 0>>)
  assert frame.encode(frame.CancelPush(63)) == Ok(<<3, 1, 63>>)
  assert frame.encode(frame.PushPromise(1, <<2, 3>>)) == Ok(<<5, 3, 1, 2, 3>>)
}

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn rejects_http2_duplicates_truncation_and_resource_exhaustion_test() -> Nil {
  let limits = frame.Limits(8, 4, 2)
  assert frame.decode(<<2, 0>>, limits)
    == Error(frame.ProhibitedHttp2FrameType(2))
  assert frame.decode(<<4, 4, 1, 0, 1, 1>>, limits)
    == Error(frame.DuplicateSetting(1))
  assert frame.decode(<<4, 2, 2, 0>>, limits)
    == Error(frame.ProhibitedSetting(2))
  assert frame.decode(<<1, 5, 1, 2, 3, 4, 5>>, limits)
    == Error(frame.FieldSectionLimitExceeded(4))
  assert frame.decode(<<0, 9, 0, 0, 0, 0, 0, 0, 0, 0, 0>>, limits)
    == Error(frame.PayloadLimitExceeded(8))
  assert frame.decode(<<0, 2, 1>>, limits) == Error(frame.Truncated)
  assert frame.decode(<<4, 6, 1, 0, 6, 0, 7, 0>>, limits)
    == Error(frame.SettingsLimitExceeded(2))
}

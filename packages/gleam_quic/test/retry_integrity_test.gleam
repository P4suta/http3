import gleam_quic/internal/retry_integrity
import gleam_quic/version

const original_destination_connection_id = <<
  0x83,
  0x94,
  0xc8,
  0xf0,
  0x3e,
  0x51,
  0x57,
  0x08,
>>

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn matches_rfc9001_v1_retry_integrity_test() -> Nil {
  let retry_without_tag = <<
    0xff, 0x00, 0x00, 0x00, 0x01, 0x00, 0x08, 0xf0, 0x67, 0xa5, 0x50, 0x2a, 0x42,
    0x62, 0xb5, 0x74, 0x6f, 0x6b, 0x65, 0x6e,
  >>
  let expected = <<
    0x04, 0xa2, 0x65, 0xba, 0x2e, 0xff, 0x4d, 0x82, 0x90, 0x58, 0xfb, 0x3f, 0x0f,
    0x24, 0x96, 0xba,
  >>
  assert retry_integrity.tag(
      version.Version1,
      original_destination_connection_id,
      retry_without_tag,
    )
    == Ok(expected)
  assert retry_integrity.verify(
      version.Version1,
      original_destination_connection_id,
      retry_without_tag,
      expected,
    )
    == Ok(Nil)
}

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn matches_rfc9369_v2_retry_integrity_test() -> Nil {
  let retry_without_tag = <<
    0xcf, 0x6b, 0x33, 0x43, 0xcf, 0x00, 0x08, 0xf0, 0x67, 0xa5, 0x50, 0x2a, 0x42,
    0x62, 0xb5, 0x74, 0x6f, 0x6b, 0x65, 0x6e,
  >>
  let expected = <<
    0xc8, 0x64, 0x6c, 0xe8, 0xbf, 0xe3, 0x39, 0x52, 0xd9, 0x55, 0x54, 0x36, 0x65,
    0xdc, 0xc7, 0xb6,
  >>
  assert retry_integrity.tag(
      version.Version2,
      original_destination_connection_id,
      retry_without_tag,
    )
    == Ok(expected)
  assert retry_integrity.verify(
      version.Version2,
      original_destination_connection_id,
      retry_without_tag,
      expected,
    )
    == Ok(Nil)

  let tampered = <<
    0xc9, 0x64, 0x6c, 0xe8, 0xbf, 0xe3, 0x39, 0x52, 0xd9, 0x55, 0x54, 0x36, 0x65,
    0xdc, 0xc7, 0xb6,
  >>
  assert retry_integrity.verify(
      version.Version2,
      original_destination_connection_id,
      retry_without_tag,
      tampered,
    )
    == Error(retry_integrity.AuthenticationFailed)
}

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn rejects_invalid_retry_integrity_inputs_test() -> Nil {
  let unaligned = <<1:size(1)>>
  assert retry_integrity.tag(version.Negotiation, <<>>, <<>>)
    == Error(retry_integrity.UnsupportedVersion(version.Negotiation))
  assert retry_integrity.tag(version.Version1, unaligned, <<>>)
    == Error(retry_integrity.NonByteAligned)
  assert retry_integrity.tag(version.Version1, <<0:168>>, <<0:64>>)
    == Error(retry_integrity.InvalidInput)
  assert retry_integrity.verify(version.Version1, <<>>, <<0:64>>, <<0:120>>)
    == Error(retry_integrity.InvalidInput)
}

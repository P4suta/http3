import gleam_quic/version

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn recognizes_standard_and_reserved_versions_test() -> Nil {
  assert version.from_wire(0x0000_0001) == Ok(version.Version1)
  assert version.from_wire(0x6b33_43cf) == Ok(version.Version2)
  assert version.from_wire(0x1a2a_3a4a) == Ok(version.Unknown(0x1a2a_3a4a))
  assert version.is_reserved(version.Unknown(0x1a2a_3a4a))
  assert !version.is_reserved(version.Version1)
  assert version.from_wire(-1) == Error(version.OutOfRange)
  assert version.from_wire(0x1_0000_0000) == Error(version.OutOfRange)
}

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn maps_v1_and_v2_long_packet_types_test() -> Nil {
  assert version.long_packet_type(version.Version1, 0) == Ok(version.Initial)
  assert version.long_packet_type(version.Version1, 1) == Ok(version.ZeroRtt)
  assert version.long_packet_type(version.Version1, 2) == Ok(version.Handshake)
  assert version.long_packet_type(version.Version1, 3) == Ok(version.Retry)

  assert version.long_packet_type(version.Version2, 0) == Ok(version.Retry)
  assert version.long_packet_type(version.Version2, 1) == Ok(version.Initial)
  assert version.long_packet_type(version.Version2, 2) == Ok(version.ZeroRtt)
  assert version.long_packet_type(version.Version2, 3) == Ok(version.Handshake)
  assert version.long_packet_type_bits(version.Version1, version.Retry) == Ok(3)
  assert version.long_packet_type_bits(version.Version2, version.Retry) == Ok(0)

  assert version.long_packet_type(version.Unknown(7), 0)
    == Error(version.UnsupportedVersion(7))
  assert version.long_packet_type(version.Version1, 4)
    == Error(version.InvalidPacketType)
}

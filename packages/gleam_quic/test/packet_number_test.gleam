import gleam_quic/packet_number

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn reconstructs_rfc_9000_appendix_a_vector_test() -> Nil {
  assert packet_number.reconstruct(
      truncated: 0x9b32,
      encoded_bits: 16,
      expected: 0xa82f30eb,
    )
    == Ok(0xa82f9b32)
}

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn chooses_packet_number_nearest_expected_test() -> Nil {
  assert packet_number.reconstruct(0, 8, 0xff) == Ok(0x100)
  assert packet_number.reconstruct(0xff, 8, 0x100) == Ok(0xff)
  assert packet_number.reconstruct(0x7f, 8, 0x100) == Ok(0x17f)
}

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn rejects_invalid_input_test() -> Nil {
  assert packet_number.reconstruct(-1, 8, 0) == Error(packet_number.OutOfRange)
  assert packet_number.reconstruct(256, 8, 0) == Error(packet_number.OutOfRange)
  assert packet_number.reconstruct(0, 7, 0) == Error(packet_number.InvalidWidth)
  assert packet_number.reconstruct(0, 8, -1) == Error(packet_number.OutOfRange)
}

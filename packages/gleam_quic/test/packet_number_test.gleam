import gleam/option.{None, Some}
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

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn encodes_shortest_reconstructable_packet_number_test() -> Nil {
  assert packet_number.encode(0, None) == Ok(<<0>>)
  assert packet_number.encode(127, None) == Ok(<<127>>)
  assert packet_number.encode(128, None) == Ok(<<0, 128>>)
  assert packet_number.encode(0xabe8_bc, Some(0xabe8_50)) == Ok(<<0xbc>>)
  assert packet_number.encode(0x1234_5678, Some(0x1233_ffff))
    == Ok(<<0x56, 0x78>>)
  assert packet_number.encode(2_147_483_648, Some(0))
    == Ok(<<0x80, 0x00, 0x00, 0x00>>)
}

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn rejects_ambiguous_packet_number_encoding_test() -> Nil {
  assert packet_number.encode(-1, None) == Error(packet_number.OutOfRange)
  assert packet_number.encode(0, Some(0)) == Error(packet_number.OutOfRange)
  assert packet_number.encode(2, Some(-1)) == Error(packet_number.OutOfRange)
  assert packet_number.encode(4_611_686_018_427_387_904, None)
    == Error(packet_number.OutOfRange)
  assert packet_number.encode(2_147_483_648, None)
    == Error(packet_number.EncodingRangeTooLarge)
}

import gleam/bit_array
import gleam/list
import gleam_quic/varint

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn rfc_9000_encoding_vectors_test() -> Nil {
  assert varint.encode(37) == Ok(<<0x25>>)
  assert varint.encode(15_293) == Ok(<<0x7b, 0xbd>>)
  assert varint.encode(494_878_333) == Ok(<<0x9d, 0x7f, 0x3e, 0x7d>>)
  assert varint.encode(151_288_809_941_952_652)
    == Ok(<<0xc2, 0x19, 0x7c, 0x5e, 0xff, 0x14, 0xe8, 0x8c>>)
}

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn round_trip_boundaries_test() -> Nil {
  [
    0,
    63,
    64,
    16_383,
    16_384,
    1_073_741_823,
    1_073_741_824,
    varint.maximum,
  ]
  |> list.each(fn(value) {
    let assert Ok(encoded) = varint.encode(value)
    assert varint.decode(encoded) == Ok(#(value, <<>>))
    assert varint.encoded_size(value) == Ok(bit_array.byte_size(encoded))
  })
}

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn decoder_accepts_non_minimal_wire_encoding_test() -> Nil {
  assert varint.decode(<<0x40, 0x25, 0xff>>) == Ok(#(37, <<0xff>>))
}

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn invalid_values_and_truncation_are_typed_test() -> Nil {
  assert varint.encode(-1) == Error(varint.OutOfRange)
  assert varint.encode(varint.maximum + 1) == Error(varint.OutOfRange)
  assert varint.decode(<<>>) == Error(varint.Truncated)
  assert varint.decode(<<0x40>>) == Error(varint.Truncated)
  assert varint.decode(<<0x80, 0, 0>>) == Error(varint.Truncated)
  assert varint.decode(<<0xc0, 0, 0, 0, 0, 0, 0>>) == Error(varint.Truncated)
}

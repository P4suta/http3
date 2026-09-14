import http3/internal/varint

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn rfc_9000_appendix_a1_encoding_vectors_test() -> Nil {
  assert varint.encode(37) == Ok(<<0x25>>)
  assert varint.encode(15_293) == Ok(<<0x7b, 0xbd>>)
  assert varint.encode(494_878_333) == Ok(<<0x9d, 0x7f, 0x3e, 0x7d>>)
  assert varint.encode(151_288_809_941_952_652)
    == Ok(<<0xc2, 0x19, 0x7c, 0x5e, 0xff, 0x14, 0xe8, 0x8c>>)
}

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn rfc_9000_appendix_a1_decoding_vectors_test() -> Nil {
  assert varint.decode(<<0x25>>) == Ok(#(37, <<>>))
  assert varint.decode(<<0x7b, 0xbd>>) == Ok(#(15_293, <<>>))
  assert varint.decode(<<0x9d, 0x7f, 0x3e, 0x7d>>) == Ok(#(494_878_333, <<>>))
  assert varint.decode(<<0xc2, 0x19, 0x7c, 0x5e, 0xff, 0x14, 0xe8, 0x8c>>)
    == Ok(#(151_288_809_941_952_652, <<>>))
  assert varint.decode(<<0x25, 0xff>>) == Ok(#(37, <<0xff>>))
}

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn truncated_input_is_typed_test() -> Nil {
  assert varint.decode(<<>>) == Error(varint.Truncated)
  assert varint.decode(<<0x40>>) == Error(varint.Truncated)
  assert varint.decode(<<0x80, 0, 0>>) == Error(varint.Truncated)
  assert varint.decode(<<0xc0, 0, 0, 0, 0, 0, 0>>) == Error(varint.Truncated)
}

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn out_of_range_values_are_typed_test() -> Nil {
  assert varint.maximum == 4_611_686_018_427_387_903
  assert varint.encode(varint.maximum + 1) == Error(varint.OutOfRange)
  assert varint.encode(-1) == Error(varint.OutOfRange)
  assert varint.encoded_size(varint.maximum + 1) == Error(varint.OutOfRange)
  assert varint.encoded_size(-1) == Error(varint.OutOfRange)
}

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn encoded_size_boundaries_test() -> Nil {
  assert varint.encoded_size(0) == Ok(1)
  assert varint.encoded_size(63) == Ok(1)
  assert varint.encoded_size(64) == Ok(2)
  assert varint.encoded_size(16_383) == Ok(2)
  assert varint.encoded_size(16_384) == Ok(4)
  assert varint.encoded_size(1_073_741_823) == Ok(4)
  assert varint.encoded_size(1_073_741_824) == Ok(8)
  assert varint.encoded_size(varint.maximum) == Ok(8)
}

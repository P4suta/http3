//// The HTTP/3-side copy of the QUIC variable-length integer codec defined by
//// RFC 9000 section 16.
////
//// HTTP/3 and QPACK encode stream types, frame lengths, settings, push IDs and
//// field-section prefixes as QUIC varints, so the root package needs the codec
//// too. It is duplicated here rather than imported so that no root module
//// depends on `gleam_quic/varint`, which the core package declares internal.
//// Semantics are identical to the core module and must stay that way.
////
//// The two most significant bits of the first byte select a 1, 2, 4, or 8 byte
//// encoding; the remaining 6, 14, 30, or 62 bits carry the value.

/// The largest value representable by a QUIC variable-length integer.
pub const maximum = 4_611_686_018_427_387_903

/// A variable-length integer codec failure.
pub type Error {
  OutOfRange
  Truncated
}

/// Encode an integer using its shortest valid QUIC wire representation.
pub fn encode(value: Int) -> Result(BitArray, Error) {
  case value {
    value if value < 0 -> Error(OutOfRange)
    value if value <= 63 -> Ok(<<0:size(2), value:size(6)>>)
    value if value <= 16_383 -> Ok(<<1:size(2), value:size(14)>>)
    value if value <= 1_073_741_823 -> Ok(<<2:size(2), value:size(30)>>)
    value if value <= maximum -> Ok(<<3:size(2), value:size(62)>>)
    _ -> Error(OutOfRange)
  }
}

/// Decode one QUIC variable-length integer and return the unconsumed bytes.
///
/// RFC 9000 permits a value to be encoded in more bytes than its shortest
/// representation, so non-minimal encodings are accepted here.
pub fn decode(bytes: BitArray) -> Result(#(Int, BitArray), Error) {
  case bytes {
    <<0:size(2), value:size(6), rest:bits>> -> Ok(#(value, rest))
    <<1:size(2), value:size(14), rest:bits>> -> Ok(#(value, rest))
    <<2:size(2), value:size(30), rest:bits>> -> Ok(#(value, rest))
    <<3:size(2), value:size(62), rest:bits>> -> Ok(#(value, rest))
    _ -> Error(Truncated)
  }
}

/// Return the number of bytes used by the shortest encoding of a value.
pub fn encoded_size(value: Int) -> Result(Int, Error) {
  case value {
    value if value < 0 -> Error(OutOfRange)
    value if value <= 63 -> Ok(1)
    value if value <= 16_383 -> Ok(2)
    value if value <= 1_073_741_823 -> Ok(4)
    value if value <= maximum -> Ok(8)
    _ -> Error(OutOfRange)
  }
}

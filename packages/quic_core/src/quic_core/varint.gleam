//// QUIC variable-length integer codec from RFC 9000 section 16.

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
    value if value <= 63 -> Ok(<<value:size(8)>>)
    value if value <= 16_383 -> Ok(<<1:size(2), value:size(14)>>)
    value if value <= 1_073_741_823 -> Ok(<<2:size(2), value:size(30)>>)
    value if value <= maximum -> Ok(<<3:size(2), value:size(62)>>)
    _ -> Error(OutOfRange)
  }
}

/// Decode one QUIC variable-length integer and return the unconsumed bytes.
///
/// RFC 9000 permits a value to use more bytes than its shortest encoding, so
/// this decoder deliberately accepts non-minimal wire representations.
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

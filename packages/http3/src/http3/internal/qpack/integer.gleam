//// QPACK/HPACK prefixed integer codec with overflow and truncation bounds.

import gleam/bit_array
import gleam/int
import gleam/result
import http3/internal/varint

/// A decoded value and the bytes following its representation.
pub type Decoded {
  Decoded(value: Int, rest: BitArray)
}

/// Invalid prefix, high bits, value, continuation, or alignment.
pub type Error {
  NonByteAligned
  InvalidPrefix
  InvalidHighBits
  ValueOutOfRange
  Truncated
  IntegerTooLong
}

/// Encode `value` in the low `prefix_bits` of the first byte while preserving
/// caller-supplied representation bits above the prefix.
pub fn encode(
  value: Int,
  prefix_bits: Int,
  high_bits: Int,
) -> Result(BitArray, Error) {
  use prefix_maximum <- result.try(validate_encoding(
    value,
    prefix_bits,
    high_bits,
  ))
  case value < prefix_maximum {
    True -> Ok(<<int.bitwise_or(high_bits, value)>>)
    False ->
      encode_continuation(value - prefix_maximum, <<
        int.bitwise_or(high_bits, prefix_maximum),
      >>)
  }
}

/// Decode a prefixed integer from the first byte.
pub fn decode(bytes: BitArray, prefix_bits: Int) -> Result(Decoded, Error) {
  case bit_array.bit_size(bytes) % 8 {
    remainder if remainder != 0 -> Error(NonByteAligned)
    _ -> decode_aligned(bytes, prefix_bits)
  }
}

fn validate_encoding(
  value: Int,
  prefix_bits: Int,
  high_bits: Int,
) -> Result(Int, Error) {
  case prefix_bits >= 1 && prefix_bits <= 8 {
    False -> Error(InvalidPrefix)
    True -> {
      let prefix_maximum = int.bitwise_shift_left(1, prefix_bits) - 1
      let overlaps_prefix = int.bitwise_and(high_bits, prefix_maximum) != 0
      case
        value >= 0
        && value <= varint.maximum
        && high_bits >= 0
        && high_bits <= 255,
        overlaps_prefix
      {
        False, _ -> Error(ValueOutOfRange)
        True, True -> Error(InvalidHighBits)
        True, False -> Ok(prefix_maximum)
      }
    }
  }
}

fn encode_continuation(
  remaining: Int,
  accumulator: BitArray,
) -> Result(BitArray, Error) {
  case remaining >= 128 {
    True ->
      encode_continuation(remaining / 128, <<
        accumulator:bits,
        int.bitwise_or(remaining % 128, 0x80),
      >>)
    False -> Ok(<<accumulator:bits, remaining>>)
  }
}

fn decode_aligned(bytes: BitArray, prefix_bits: Int) -> Result(Decoded, Error) {
  case prefix_bits >= 1 && prefix_bits <= 8, bytes {
    False, _ -> Error(InvalidPrefix)
    _, <<>> -> Error(Truncated)
    True, <<first, rest:bits>> -> {
      let prefix_maximum = int.bitwise_shift_left(1, prefix_bits) - 1
      let prefix = int.bitwise_and(first, prefix_maximum)
      case prefix < prefix_maximum {
        True -> Ok(Decoded(prefix, rest))
        False -> decode_continuation(rest, prefix_maximum, 0, 0)
      }
    }
    True, _ -> Error(Truncated)
  }
}

fn decode_continuation(
  bytes: BitArray,
  value: Int,
  shift: Int,
  octets: Int,
) -> Result(Decoded, Error) {
  case bytes, octets >= 10 || shift >= 63 {
    _, True -> Error(IntegerTooLong)
    <<>>, False -> Error(Truncated)
    <<byte, rest:bits>>, False ->
      decode_continuation_byte(rest, byte, value, shift, octets)
    _, False -> Error(Truncated)
  }
}

fn decode_continuation_byte(
  rest: BitArray,
  byte: Int,
  value: Int,
  shift: Int,
  octets: Int,
) -> Result(Decoded, Error) {
  let contribution =
    int.bitwise_and(byte, 0x7f) * int.bitwise_shift_left(1, shift)
  case contribution > varint.maximum - value {
    True -> Error(ValueOutOfRange)
    False -> {
      let value = value + contribution
      case int.bitwise_and(byte, 0x80) == 0 {
        True -> Ok(Decoded(value, rest))
        False -> decode_continuation(rest, value, shift + 7, octets + 1)
      }
    }
  }
}

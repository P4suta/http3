//// Bounded HPACK prefixed-integer encoding and decoding.

import gleam/bit_array
import gleam/int
import gleam/result

const maximum_supported_value = 0xffff_ffff

const maximum_supported_bytes = 6

/// Per-use bounds for an HPACK integer representation.
pub opaque type Limits {
  Limits(maximum_value: Int, maximum_bytes: Int)
}

/// A decoded integer and the bytes following its representation.
pub type Decoded {
  Decoded(value: Int, rest: BitArray)
}

/// Invalid configuration, representation, or finite-resource failure.
pub type Error {
  NonByteAligned
  InvalidLimits
  InvalidPrefix
  InvalidHighBits
  ValueOutOfRange(maximum: Int)
  Truncated
  IntegerTooLong(maximum_bytes: Int)
}

/// Construct finite limits for one semantic use of an HPACK integer.
///
/// HTTP/2's wire settings and all locally admitted sizes fit in an unsigned
/// 32-bit value. Six bytes are sufficient to encode that range with any
/// valid HPACK prefix.
pub fn limits(maximum_value: Int, maximum_bytes: Int) -> Result(Limits, Error) {
  case
    maximum_value >= 0
    && maximum_value <= maximum_supported_value
    && maximum_bytes >= 1
    && maximum_bytes <= maximum_supported_bytes
  {
    True -> Ok(Limits(maximum_value:, maximum_bytes:))
    False -> Error(InvalidLimits)
  }
}

/// Encode `value` in the low `prefix_bits` of the first byte.
///
/// `high_bits` supplies the HPACK representation bits outside that prefix;
/// overlap with the value prefix is rejected instead of silently discarded.
pub fn encode(
  value: Int,
  prefix_bits: Int,
  high_bits: Int,
  limits: Limits,
) -> Result(BitArray, Error) {
  use prefix_maximum <- result.try(validate_prefix(prefix_bits))
  use _ <- result.try(validate_high_bits(high_bits, prefix_maximum))
  use _ <- result.try(require_value(value, limits))
  case value < prefix_maximum {
    True -> Ok(<<int.bitwise_or(high_bits, value)>>)
    False ->
      encode_continuation(
        value - prefix_maximum,
        <<int.bitwise_or(high_bits, prefix_maximum)>>,
        1,
        limits,
      )
  }
}

/// Decode one bounded HPACK integer from the start of `bytes`.
pub fn decode(
  bytes: BitArray,
  prefix_bits: Int,
  limits: Limits,
) -> Result(Decoded, Error) {
  case bit_array.bit_size(bytes) % 8 {
    remainder if remainder != 0 -> Error(NonByteAligned)
    _ -> decode_aligned(bytes, prefix_bits, limits)
  }
}

fn decode_aligned(
  bytes: BitArray,
  prefix_bits: Int,
  limits: Limits,
) -> Result(Decoded, Error) {
  use prefix_maximum <- result.try(validate_prefix(prefix_bits))
  case bytes {
    <<>> -> Error(Truncated)
    <<first, rest:bytes>> -> {
      let prefix = int.bitwise_and(first, prefix_maximum)
      case prefix < prefix_maximum {
        True -> {
          use _ <- result.try(require_value(prefix, limits))
          Ok(Decoded(prefix, rest))
        }
        False -> decode_continuation(rest, prefix_maximum, 1, 1, limits)
      }
    }
    _ -> Error(NonByteAligned)
  }
}

fn encode_continuation(
  remaining: Int,
  encoded: BitArray,
  used_bytes: Int,
  limits: Limits,
) -> Result(BitArray, Error) {
  case used_bytes >= limits.maximum_bytes {
    True -> Error(IntegerTooLong(limits.maximum_bytes))
    False ->
      case remaining >= 128 {
        True ->
          encode_continuation(
            remaining / 128,
            <<
              encoded:bits,
              int.bitwise_or(remaining % 128, 0x80),
            >>,
            used_bytes + 1,
            limits,
          )
        False -> Ok(<<encoded:bits, remaining>>)
      }
  }
}

fn decode_continuation(
  bytes: BitArray,
  value: Int,
  multiplier: Int,
  used_bytes: Int,
  limits: Limits,
) -> Result(Decoded, Error) {
  case used_bytes >= limits.maximum_bytes, bytes {
    True, _ -> Error(IntegerTooLong(limits.maximum_bytes))
    False, <<>> -> Error(Truncated)
    False, <<byte, rest:bytes>> -> {
      let low_bits = int.bitwise_and(byte, 0x7f)
      use next_value <- result.try(add_contribution(
        value,
        low_bits,
        multiplier,
        limits.maximum_value,
      ))
      case int.bitwise_and(byte, 0x80) == 0 {
        True -> Ok(Decoded(next_value, rest))
        False ->
          decode_continuation(
            rest,
            next_value,
            multiplier * 128,
            used_bytes + 1,
            limits,
          )
      }
    }
    False, _ -> Error(NonByteAligned)
  }
}

fn add_contribution(
  value: Int,
  low_bits: Int,
  multiplier: Int,
  maximum: Int,
) -> Result(Int, Error) {
  case low_bits > { maximum - value } / multiplier {
    True -> Error(ValueOutOfRange(maximum))
    False -> Ok(value + low_bits * multiplier)
  }
}

fn validate_prefix(prefix_bits: Int) -> Result(Int, Error) {
  case prefix_bits >= 1 && prefix_bits <= 8 {
    True -> Ok(int.bitwise_shift_left(1, prefix_bits) - 1)
    False -> Error(InvalidPrefix)
  }
}

fn validate_high_bits(
  high_bits: Int,
  prefix_maximum: Int,
) -> Result(Nil, Error) {
  case
    high_bits >= 0
    && high_bits <= 0xff
    && int.bitwise_and(high_bits, prefix_maximum) == 0
  {
    True -> Ok(Nil)
    False -> Error(InvalidHighBits)
  }
}

fn require_value(value: Int, limits: Limits) -> Result(Nil, Error) {
  case value >= 0 && value <= limits.maximum_value {
    True -> Ok(Nil)
    False -> Error(ValueOutOfRange(limits.maximum_value))
  }
}

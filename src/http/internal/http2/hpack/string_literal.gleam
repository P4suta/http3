//// Bounded HPACK string-literal envelope encoding and decoding.

import gleam/bit_array
import gleam/result
import http/internal/http2/hpack/huffman
import http/internal/http2/hpack/integer

const maximum_encoded_bytes = 0xffff_ffff

/// Encoded string octets, remaining input, and the wire Huffman flag.
///
/// This layer deliberately preserves encoded bytes. Strict Huffman expansion
/// is performed by the bounded Huffman layer after this envelope is parsed.
pub type Decoded {
  Decoded(value: BitArray, rest: BitArray, huffman: Bool)
}

/// Alignment, length, or prefixed-integer failure.
pub type Error {
  NonByteAligned
  InvalidLimit
  Truncated
  EncodedLengthLimitExceeded(maximum: Int)
  DecodedLengthLimitExceeded(maximum: Int)
  IntegerFailure(integer.Error)
  HuffmanFailure(huffman.Error)
}

/// Wrap already-selected string octets in an HPACK 7-bit length envelope.
pub fn encode(value: BitArray, huffman: Bool) -> Result(BitArray, Error) {
  case bit_array.bit_size(value) % 8 {
    remainder if remainder != 0 -> Error(NonByteAligned)
    _ -> {
      use limits <- result.try(
        integer.limits(maximum_encoded_bytes, 6)
        |> map_limits_result,
      )
      let high_bits = case huffman {
        True -> 0x80
        False -> 0
      }
      use length <- result.try(
        integer.encode(bit_array.byte_size(value), 7, high_bits, limits)
        |> map_integer_result,
      )
      Ok(<<length:bits, value:bits>>)
    }
  }
}

/// Encode a value, selecting RFC 7541 Huffman coding only when requested and
/// strictly smaller than the original octets.
pub fn encode_value(
  value: BitArray,
  prefer_huffman: Bool,
) -> Result(BitArray, Error) {
  case prefer_huffman {
    False -> encode(value, False)
    True -> {
      use encoded_size <- result.try(
        huffman.encoded_size(value)
        |> map_huffman_result,
      )
      case encoded_size < bit_array.byte_size(value) {
        False -> encode(value, False)
        True -> {
          use encoded <- result.try(
            huffman.encode(value)
            |> map_huffman_result,
          )
          encode(encoded, True)
        }
      }
    }
  }
}

/// Parse one HPACK string envelope without allocating beyond `maximum_bytes`.
pub fn decode(bytes: BitArray, maximum_bytes: Int) -> Result(Decoded, Error) {
  case bit_array.bit_size(bytes) % 8, bytes {
    remainder, _ if remainder != 0 -> Error(NonByteAligned)
    _, <<>> -> Error(Truncated)
    0, <<first, _:bits>> -> {
      use limits <- result.try(
        integer.limits(maximum_bytes, 6)
        |> map_limits_result,
      )
      use integer.Decoded(length, rest) <- result.try(
        integer.decode(bytes, 7, limits)
        |> map_integer_decode(maximum_bytes),
      )
      use #(value, rest) <- result.try(take(rest, length))
      Ok(Decoded(value:, rest:, huffman: first >= 0x80))
    }
    _, _ -> Error(NonByteAligned)
  }
}

/// Decode an HPACK string envelope and strictly expand its value within both
/// encoded and decoded byte limits.
pub fn decode_value(
  bytes: BitArray,
  maximum_encoded_bytes: Int,
  maximum_decoded_bytes: Int,
) -> Result(Decoded, Error) {
  case maximum_decoded_bytes >= 0 {
    False -> Error(DecodedLengthLimitExceeded(maximum_decoded_bytes))
    True -> {
      use Decoded(value, rest, uses_huffman) <- result.try(decode(
        bytes,
        maximum_encoded_bytes,
      ))
      case uses_huffman {
        True -> {
          use decoded <- result.try(
            huffman.decode(value, maximum_decoded_bytes)
            |> map_huffman_result,
          )
          Ok(Decoded(decoded, rest, True))
        }
        False ->
          case bit_array.byte_size(value) > maximum_decoded_bytes {
            True -> Error(DecodedLengthLimitExceeded(maximum_decoded_bytes))
            False -> Ok(Decoded(value, rest, False))
          }
      }
    }
  }
}

fn take(bytes: BitArray, length: Int) -> Result(#(BitArray, BitArray), Error) {
  case bit_array.byte_size(bytes) < length {
    True -> Error(Truncated)
    False -> {
      let bit_length = length * 8
      case bytes {
        <<value:bits-size(bit_length), rest:bits>> -> Ok(#(value, rest))
        _ -> Error(Truncated)
      }
    }
  }
}

fn map_limits_result(
  value: Result(integer.Limits, integer.Error),
) -> Result(integer.Limits, Error) {
  case value {
    Ok(limits) -> Ok(limits)
    Error(_) -> Error(InvalidLimit)
  }
}

fn map_integer_result(
  value: Result(value, integer.Error),
) -> Result(value, Error) {
  case value {
    Ok(decoded) -> Ok(decoded)
    Error(failure) -> Error(IntegerFailure(failure))
  }
}

fn map_integer_decode(
  value: Result(value, integer.Error),
  maximum_bytes: Int,
) -> Result(value, Error) {
  case value {
    Ok(decoded) -> Ok(decoded)
    Error(integer.ValueOutOfRange(_)) ->
      Error(EncodedLengthLimitExceeded(maximum_bytes))
    Error(failure) -> Error(IntegerFailure(failure))
  }
}

fn map_huffman_result(
  value: Result(value, huffman.Error),
) -> Result(value, Error) {
  case value {
    Ok(decoded) -> Ok(decoded)
    Error(failure) -> Error(HuffmanFailure(failure))
  }
}

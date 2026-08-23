//// Bounded QPACK string literals with optional strict Huffman coding.

import gleam/bit_array
import gleam/int
import gleam/result
import gleam_quic/internal/qpack/huffman
import gleam_quic/internal/qpack/integer

/// Decoded bytes, remaining input, and whether Huffman was selected.
pub type Decoded {
  Decoded(value: BitArray, rest: BitArray, huffman: Bool)
}

/// Prefix, alignment, length, Huffman, or allocation failure.
pub type Error {
  NonByteAligned
  InvalidPrefix
  Truncated
  EncodedLengthLimitExceeded(Int)
  DecodedLengthLimitExceeded(Int)
  IntegerFailure(integer.Error)
  HuffmanFailure(huffman.Error)
}

/// Encode a general string literal with a 7-bit length prefix and H=0x80.
pub fn encode(
  value: BitArray,
  prefer_huffman: Bool,
) -> Result(BitArray, Error) {
  encode_prefixed(value, 7, 0x80, 0, prefer_huffman)
}

/// Decode a general string literal.
pub fn decode(
  bytes: BitArray,
  maximum_encoded_bytes: Int,
  maximum_decoded_bytes: Int,
) -> Result(Decoded, Error) {
  decode_prefixed(bytes, 7, 0x80, maximum_encoded_bytes, maximum_decoded_bytes)
}

/// Encode a literal embedded in another representation's first byte.
pub fn encode_prefixed(
  value: BitArray,
  prefix_bits: Int,
  huffman_mask: Int,
  representation_bits: Int,
  prefer_huffman: Bool,
) -> Result(BitArray, Error) {
  use _ <- result.try(validate_prefix(prefix_bits, huffman_mask))
  use #(encoded, use_huffman) <- result.try(select_encoding(
    value,
    prefer_huffman,
  ))
  let high_bits = case use_huffman {
    True -> int.bitwise_or(representation_bits, huffman_mask)
    False -> representation_bits
  }
  use length <- result.try(
    integer.encode(bit_array.byte_size(encoded), prefix_bits, high_bits)
    |> map_integer_result,
  )
  Ok(<<length:bits, encoded:bits>>)
}

/// Decode a string whose H flag and length use caller-selected first-byte bits.
pub fn decode_prefixed(
  bytes: BitArray,
  prefix_bits: Int,
  huffman_mask: Int,
  maximum_encoded_bytes: Int,
  maximum_decoded_bytes: Int,
) -> Result(Decoded, Error) {
  use _ <- result.try(validate_prefix(prefix_bits, huffman_mask))
  case bytes, maximum_encoded_bytes >= 0 && maximum_decoded_bytes >= 0 {
    _, False -> Error(InvalidPrefix)
    <<>>, True -> Error(Truncated)
    <<first, _:bits>>, True -> {
      let uses_huffman = int.bitwise_and(first, huffman_mask) != 0
      use integer.Decoded(length, rest) <- result.try(
        integer.decode(bytes, prefix_bits) |> map_integer_result,
      )
      use #(encoded, rest) <- result.try(take(
        rest,
        length,
        maximum_encoded_bytes,
      ))
      decode_value(encoded, rest, uses_huffman, maximum_decoded_bytes)
    }
    _, True -> Error(NonByteAligned)
  }
}

fn validate_prefix(prefix_bits: Int, huffman_mask: Int) -> Result(Nil, Error) {
  case
    prefix_bits >= 1
    && prefix_bits <= 7
    && huffman_mask == int.bitwise_shift_left(1, prefix_bits)
  {
    True -> Ok(Nil)
    False -> Error(InvalidPrefix)
  }
}

fn select_encoding(
  value: BitArray,
  prefer_huffman: Bool,
) -> Result(#(BitArray, Bool), Error) {
  case bit_array.bit_size(value) % 8 {
    remainder if remainder != 0 -> Error(NonByteAligned)
    _ ->
      case prefer_huffman {
        False -> Ok(#(value, False))
        True -> select_smaller_encoding(value)
      }
  }
}

fn select_smaller_encoding(
  value: BitArray,
) -> Result(#(BitArray, Bool), Error) {
  use encoded_size <- result.try(
    huffman.encoded_size(value) |> map_huffman_result,
  )
  case encoded_size < bit_array.byte_size(value) {
    False -> Ok(#(value, False))
    True -> {
      use encoded <- result.try(huffman.encode(value) |> map_huffman_result)
      Ok(#(encoded, True))
    }
  }
}

fn decode_value(
  encoded: BitArray,
  rest: BitArray,
  uses_huffman: Bool,
  maximum_decoded_bytes: Int,
) -> Result(Decoded, Error) {
  case uses_huffman {
    True -> {
      use decoded <- result.try(
        huffman.decode(encoded, maximum_decoded_bytes) |> map_huffman_result,
      )
      Ok(Decoded(decoded, rest, True))
    }
    False ->
      case bit_array.byte_size(encoded) > maximum_decoded_bytes {
        True -> Error(DecodedLengthLimitExceeded(maximum_decoded_bytes))
        False -> Ok(Decoded(encoded, rest, False))
      }
  }
}

fn take(
  bytes: BitArray,
  length: Int,
  maximum: Int,
) -> Result(#(BitArray, BitArray), Error) {
  case length > maximum, length > bit_array.byte_size(bytes) {
    True, _ -> Error(EncodedLengthLimitExceeded(maximum))
    _, True -> Error(Truncated)
    False, False -> {
      let bit_length = length * 8
      case bytes {
        <<value:bits-size(bit_length), rest:bits>> -> Ok(#(value, rest))
        _ -> Error(Truncated)
      }
    }
  }
}

fn map_integer_result(
  value: Result(value, integer.Error),
) -> Result(value, Error) {
  case value {
    Ok(decoded) -> Ok(decoded)
    Error(error) -> Error(IntegerFailure(error))
  }
}

fn map_huffman_result(
  value: Result(value, huffman.Error),
) -> Result(value, Error) {
  case value {
    Ok(decoded) -> Ok(decoded)
    Error(error) -> Error(HuffmanFailure(error))
  }
}

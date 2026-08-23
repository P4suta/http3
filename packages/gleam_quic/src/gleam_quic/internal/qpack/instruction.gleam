//// RFC 9204 encoder and decoder stream instruction codecs.

import gleam/bit_array
import gleam/int
import gleam/result
import gleam_quic/internal/qpack/integer
import gleam_quic/internal/qpack/string_literal

/// One instruction sent on the QPACK encoder stream.
pub type EncoderInstruction {
  SetDynamicTableCapacity(Int)
  InsertWithNameReference(static: Bool, name_index: Int, value: BitArray)
  InsertWithLiteralName(name: BitArray, value: BitArray)
  Duplicate(relative_index: Int)
}

/// One instruction sent on the QPACK decoder stream.
pub type DecoderInstruction {
  SectionAcknowledgement(stream_id: Int)
  StreamCancellation(stream_id: Int)
  InsertCountIncrement(increment: Int)
}

/// Bounded string allocation policy for incremental instructions.
pub type Limits {
  Limits(maximum_encoded_string_bytes: Int, maximum_decoded_string_bytes: Int)
}

/// Truncated, invalid, or over-limit instruction input.
pub type Error {
  NonByteAligned
  Truncated
  InvalidInstruction
  IntegerFailure(integer.Error)
  StringFailure(string_literal.Error)
}

/// Conservative instruction string bounds.
pub fn default_limits() -> Limits {
  Limits(65_536, 65_536)
}

/// Encode one encoder-stream instruction.
pub fn encode_encoder(
  instruction: EncoderInstruction,
  prefer_huffman: Bool,
) -> Result(BitArray, Error) {
  case instruction {
    SetDynamicTableCapacity(capacity) ->
      integer.encode(capacity, 5, 0x20) |> map_integer_result
    InsertWithNameReference(is_static, name_index, value) -> {
      let high_bits = case is_static {
        True -> 0xc0
        False -> 0x80
      }
      use name <- result.try(
        integer.encode(name_index, 6, high_bits) |> map_integer_result,
      )
      use value <- result.try(
        string_literal.encode(value, prefer_huffman) |> map_string_result,
      )
      Ok(<<name:bits, value:bits>>)
    }
    InsertWithLiteralName(name, value) -> {
      use name <- result.try(
        string_literal.encode_prefixed(name, 5, 0x20, 0x40, prefer_huffman)
        |> map_string_result,
      )
      use value <- result.try(
        string_literal.encode(value, prefer_huffman) |> map_string_result,
      )
      Ok(<<name:bits, value:bits>>)
    }
    Duplicate(relative_index) ->
      integer.encode(relative_index, 5, 0) |> map_integer_result
  }
}

/// Decode one encoder-stream instruction and preserve following bytes.
pub fn decode_encoder(
  bytes: BitArray,
  limits: Limits,
) -> Result(#(EncoderInstruction, BitArray), Error) {
  use first <- result.try(first_byte(bytes))
  case int.bitwise_and(first, 0x80) != 0 {
    True -> decode_insert_name_reference(bytes, limits)
    False -> decode_encoder_without_high_bit(bytes, first, limits)
  }
}

/// Encode one decoder-stream instruction.
pub fn encode_decoder(
  instruction: DecoderInstruction,
) -> Result(BitArray, Error) {
  case instruction {
    SectionAcknowledgement(stream_id) ->
      integer.encode(stream_id, 7, 0x80) |> map_integer_result
    StreamCancellation(stream_id) ->
      integer.encode(stream_id, 6, 0x40) |> map_integer_result
    InsertCountIncrement(increment) ->
      case increment > 0 {
        True -> integer.encode(increment, 6, 0) |> map_integer_result
        False -> Error(InvalidInstruction)
      }
  }
}

/// Decode one decoder-stream instruction.
pub fn decode_decoder(
  bytes: BitArray,
) -> Result(#(DecoderInstruction, BitArray), Error) {
  use first <- result.try(first_byte(bytes))
  case int.bitwise_and(first, 0x80) != 0, int.bitwise_and(first, 0xc0) == 0x40 {
    True, _ -> {
      use integer.Decoded(stream_id, rest) <- result.try(
        integer.decode(bytes, 7) |> map_integer_result,
      )
      Ok(#(SectionAcknowledgement(stream_id), rest))
    }
    False, True -> {
      use integer.Decoded(stream_id, rest) <- result.try(
        integer.decode(bytes, 6) |> map_integer_result,
      )
      Ok(#(StreamCancellation(stream_id), rest))
    }
    False, False -> {
      use integer.Decoded(increment, rest) <- result.try(
        integer.decode(bytes, 6) |> map_integer_result,
      )
      case increment > 0 {
        True -> Ok(#(InsertCountIncrement(increment), rest))
        False -> Error(InvalidInstruction)
      }
    }
  }
}

fn decode_encoder_without_high_bit(
  bytes: BitArray,
  first: Int,
  limits: Limits,
) -> Result(#(EncoderInstruction, BitArray), Error) {
  case
    int.bitwise_and(first, 0xc0) == 0x40,
    int.bitwise_and(first, 0xe0) == 0x20
  {
    True, _ -> decode_insert_literal_name(bytes, limits)
    False, True -> {
      use integer.Decoded(capacity, rest) <- result.try(
        integer.decode(bytes, 5) |> map_integer_result,
      )
      Ok(#(SetDynamicTableCapacity(capacity), rest))
    }
    False, False -> {
      use integer.Decoded(relative_index, rest) <- result.try(
        integer.decode(bytes, 5) |> map_integer_result,
      )
      Ok(#(Duplicate(relative_index), rest))
    }
  }
}

fn decode_insert_name_reference(
  bytes: BitArray,
  limits: Limits,
) -> Result(#(EncoderInstruction, BitArray), Error) {
  use first <- result.try(first_byte(bytes))
  let is_static = int.bitwise_and(first, 0x40) != 0
  use integer.Decoded(name_index, rest) <- result.try(
    integer.decode(bytes, 6) |> map_integer_result,
  )
  use string_literal.Decoded(value, rest, _) <- result.try(
    string_literal.decode(
      rest,
      limits.maximum_encoded_string_bytes,
      limits.maximum_decoded_string_bytes,
    )
    |> map_string_result,
  )
  Ok(#(InsertWithNameReference(is_static, name_index, value), rest))
}

fn decode_insert_literal_name(
  bytes: BitArray,
  limits: Limits,
) -> Result(#(EncoderInstruction, BitArray), Error) {
  use string_literal.Decoded(name, rest, _) <- result.try(
    string_literal.decode_prefixed(
      bytes,
      5,
      0x20,
      limits.maximum_encoded_string_bytes,
      limits.maximum_decoded_string_bytes,
    )
    |> map_string_result,
  )
  use string_literal.Decoded(value, rest, _) <- result.try(
    string_literal.decode(
      rest,
      limits.maximum_encoded_string_bytes,
      limits.maximum_decoded_string_bytes,
    )
    |> map_string_result,
  )
  Ok(#(InsertWithLiteralName(name, value), rest))
}

fn first_byte(bytes: BitArray) -> Result(Int, Error) {
  case bit_array.bit_size(bytes) % 8, bytes {
    remainder, _ if remainder != 0 -> Error(NonByteAligned)
    _, <<first, _:bits>> -> Ok(first)
    _, _ -> Error(Truncated)
  }
}

fn map_integer_result(
  value: Result(value, integer.Error),
) -> Result(value, Error) {
  case value {
    Ok(decoded) -> Ok(decoded)
    Error(integer.Truncated) -> Error(Truncated)
    Error(error) -> Error(IntegerFailure(error))
  }
}

fn map_string_result(
  value: Result(value, string_literal.Error),
) -> Result(value, Error) {
  case value {
    Ok(decoded) -> Ok(decoded)
    Error(string_literal.Truncated) -> Error(Truncated)
    Error(error) -> Error(StringFailure(error))
  }
}

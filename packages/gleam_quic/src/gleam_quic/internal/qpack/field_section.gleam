//// RFC 9204 encoded field-section prefix and field-line representations.

import gleam/bit_array
import gleam/int
import gleam/list
import gleam/result
import gleam_quic/internal/qpack/integer
import gleam_quic/internal/qpack/string_literal

/// Encoded Field Section Prefix before Required Insert Count reconstruction.
pub type Prefix {
  Prefix(encoded_required_insert_count: Int, sign: Bool, delta_base: Int)
}

/// One QPACK field-line representation.
pub type Representation {
  Indexed(static: Bool, index: Int)
  IndexedPostBase(index: Int)
  LiteralNameReference(
    never_index: Bool,
    static: Bool,
    name_index: Int,
    value: BitArray,
  )
  LiteralPostBaseNameReference(
    never_index: Bool,
    name_index: Int,
    value: BitArray,
  )
  LiteralLiteralName(never_index: Bool, name: BitArray, value: BitArray)
}

/// One complete encoded field section.
pub type Section {
  Section(prefix: Prefix, fields: List(Representation))
}

/// Peer-controlled field/string bounds.
pub type Limits {
  Limits(
    maximum_fields: Int,
    maximum_encoded_string_bytes: Int,
    maximum_decoded_string_bytes: Int,
  )
}

/// Truncated, invalid, or bounded field-section failure.
pub type Error {
  NonByteAligned
  Truncated
  InvalidFieldSection
  FieldLimitExceeded(Int)
  IntegerFailure(integer.Error)
  StringFailure(string_literal.Error)
}

/// Conservative field-section limits.
pub fn default_limits() -> Limits {
  Limits(1024, 1_048_576, 1_048_576)
}

/// Encode a complete field section.
pub fn encode(
  section: Section,
  prefer_huffman: Bool,
) -> Result(BitArray, Error) {
  let Section(Prefix(required, sign, delta), fields) = section
  use required <- result.try(
    integer.encode(required, 8, 0) |> map_integer_result,
  )
  let sign_bit = case sign {
    True -> 0x80
    False -> 0
  }
  use delta <- result.try(
    integer.encode(delta, 7, sign_bit) |> map_integer_result,
  )
  encode_representations(fields, prefer_huffman, <<required:bits, delta:bits>>)
}

/// Decode all representations from one HEADERS/PUSH_PROMISE payload.
pub fn decode(bytes: BitArray, limits: Limits) -> Result(Section, Error) {
  case bit_array.bit_size(bytes) % 8 {
    remainder if remainder != 0 -> Error(NonByteAligned)
    _ -> decode_aligned(bytes, limits)
  }
}

fn decode_aligned(bytes: BitArray, limits: Limits) -> Result(Section, Error) {
  use integer.Decoded(required, rest) <- result.try(
    integer.decode(bytes, 8) |> map_integer_result,
  )
  use first <- result.try(first_byte(rest))
  let sign = int.bitwise_and(first, 0x80) != 0
  use integer.Decoded(delta, rest) <- result.try(
    integer.decode(rest, 7) |> map_integer_result,
  )
  use fields <- result.try(
    decode_representations(rest, limits, limits.maximum_fields, []),
  )
  Ok(Section(Prefix(required, sign, delta), fields))
}

fn encode_representations(
  fields: List(Representation),
  prefer_huffman: Bool,
  accumulator: BitArray,
) -> Result(BitArray, Error) {
  case fields {
    [] -> Ok(accumulator)
    [field, ..rest] -> {
      use encoded <- result.try(encode_representation(field, prefer_huffman))
      encode_representations(rest, prefer_huffman, <<
        accumulator:bits,
        encoded:bits,
      >>)
    }
  }
}

fn encode_representation(
  field: Representation,
  prefer_huffman: Bool,
) -> Result(BitArray, Error) {
  case field {
    Indexed(is_static, index) -> {
      let high_bits = case is_static {
        True -> 0xc0
        False -> 0x80
      }
      integer.encode(index, 6, high_bits) |> map_integer_result
    }
    IndexedPostBase(index) ->
      integer.encode(index, 4, 0x10) |> map_integer_result
    LiteralNameReference(never, is_static, index, value) -> {
      let high_bits =
        0x40
        |> add_flag(never, 0x20)
        |> add_flag(is_static, 0x10)
      use name <- result.try(
        integer.encode(index, 4, high_bits) |> map_integer_result,
      )
      append_value(name, value, prefer_huffman)
    }
    LiteralPostBaseNameReference(never, index, value) -> {
      let high_bits = add_flag(0, never, 0x08)
      use name <- result.try(
        integer.encode(index, 3, high_bits) |> map_integer_result,
      )
      append_value(name, value, prefer_huffman)
    }
    LiteralLiteralName(never, name, value) -> {
      let representation_bits = add_flag(0x20, never, 0x10)
      use name <- result.try(
        string_literal.encode_prefixed(
          name,
          3,
          0x08,
          representation_bits,
          prefer_huffman,
        )
        |> map_string_result,
      )
      append_value(name, value, prefer_huffman)
    }
  }
}

fn append_value(
  prefix: BitArray,
  value: BitArray,
  prefer_huffman: Bool,
) -> Result(BitArray, Error) {
  use value <- result.try(
    string_literal.encode(value, prefer_huffman) |> map_string_result,
  )
  Ok(<<prefix:bits, value:bits>>)
}

fn decode_representations(
  bytes: BitArray,
  limits: Limits,
  remaining_fields: Int,
  reversed: List(Representation),
) -> Result(List(Representation), Error) {
  case bytes, remaining_fields {
    <<>>, _ -> Ok(list.reverse(reversed))
    _, 0 -> Error(FieldLimitExceeded(limits.maximum_fields))
    _, _ -> {
      use #(field, rest) <- result.try(decode_representation(bytes, limits))
      decode_representations(rest, limits, remaining_fields - 1, [
        field,
        ..reversed
      ])
    }
  }
}

fn decode_representation(
  bytes: BitArray,
  limits: Limits,
) -> Result(#(Representation, BitArray), Error) {
  use first <- result.try(first_byte(bytes))
  case
    int.bitwise_and(first, 0x80) != 0,
    int.bitwise_and(first, 0xc0) == 0x40,
    int.bitwise_and(first, 0xf0) == 0x10,
    int.bitwise_and(first, 0xe0) == 0x20
  {
    True, _, _, _ -> decode_indexed(bytes, first)
    False, True, _, _ -> decode_literal_name_reference(bytes, first, limits)
    False, False, True, _ -> decode_indexed_post_base(bytes)
    False, False, False, True ->
      decode_literal_literal_name(bytes, first, limits)
    False, False, False, False ->
      decode_literal_post_base_name_reference(bytes, first, limits)
  }
}

fn decode_indexed(
  bytes: BitArray,
  first: Int,
) -> Result(#(Representation, BitArray), Error) {
  let is_static = int.bitwise_and(first, 0x40) != 0
  use integer.Decoded(index, rest) <- result.try(
    integer.decode(bytes, 6) |> map_integer_result,
  )
  Ok(#(Indexed(is_static, index), rest))
}

fn decode_indexed_post_base(
  bytes: BitArray,
) -> Result(#(Representation, BitArray), Error) {
  use integer.Decoded(index, rest) <- result.try(
    integer.decode(bytes, 4) |> map_integer_result,
  )
  Ok(#(IndexedPostBase(index), rest))
}

fn decode_literal_name_reference(
  bytes: BitArray,
  first: Int,
  limits: Limits,
) -> Result(#(Representation, BitArray), Error) {
  let never = int.bitwise_and(first, 0x20) != 0
  let is_static = int.bitwise_and(first, 0x10) != 0
  use integer.Decoded(index, rest) <- result.try(
    integer.decode(bytes, 4) |> map_integer_result,
  )
  use #(value, rest) <- result.try(decode_value(rest, limits))
  Ok(#(LiteralNameReference(never, is_static, index, value), rest))
}

fn decode_literal_post_base_name_reference(
  bytes: BitArray,
  first: Int,
  limits: Limits,
) -> Result(#(Representation, BitArray), Error) {
  let never = int.bitwise_and(first, 0x08) != 0
  use integer.Decoded(index, rest) <- result.try(
    integer.decode(bytes, 3) |> map_integer_result,
  )
  use #(value, rest) <- result.try(decode_value(rest, limits))
  Ok(#(LiteralPostBaseNameReference(never, index, value), rest))
}

fn decode_literal_literal_name(
  bytes: BitArray,
  first: Int,
  limits: Limits,
) -> Result(#(Representation, BitArray), Error) {
  let never = int.bitwise_and(first, 0x10) != 0
  use string_literal.Decoded(name, rest, _) <- result.try(
    string_literal.decode_prefixed(
      bytes,
      3,
      0x08,
      limits.maximum_encoded_string_bytes,
      limits.maximum_decoded_string_bytes,
    )
    |> map_string_result,
  )
  use #(value, rest) <- result.try(decode_value(rest, limits))
  Ok(#(LiteralLiteralName(never, name, value), rest))
}

fn decode_value(
  bytes: BitArray,
  limits: Limits,
) -> Result(#(BitArray, BitArray), Error) {
  use string_literal.Decoded(value, rest, _) <- result.try(
    string_literal.decode(
      bytes,
      limits.maximum_encoded_string_bytes,
      limits.maximum_decoded_string_bytes,
    )
    |> map_string_result,
  )
  Ok(#(value, rest))
}

fn add_flag(high_bits: Int, enabled: Bool, flag: Int) -> Int {
  case enabled {
    True -> int.bitwise_or(high_bits, flag)
    False -> high_bits
  }
}

fn first_byte(bytes: BitArray) -> Result(Int, Error) {
  case bytes {
    <<first, _:bits>> -> Ok(first)
    _ -> Error(Truncated)
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

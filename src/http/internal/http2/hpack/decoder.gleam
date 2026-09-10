//// Stateful, bounded RFC 7541 header-block decoding.

import gleam/bit_array
import gleam/int
import gleam/list
import gleam/option.{None, Some}
import gleam/result
import http/internal/http2/hpack/dynamic_table
import http/internal/http2/hpack/integer
import http/internal/http2/hpack/static_table
import http/internal/http2/hpack/string_literal

const maximum_wire_integer = 0xffff_ffff

/// One decoded header field. `never_index` preserves the HPACK sensitivity bit.
pub type Header {
  Header(name: BitArray, value: BitArray, never_index: Bool)
}

/// A successful block and the next connection-scoped decoding state.
pub type Decoded {
  Decoded(decoder: Decoder, headers: List(Header))
}

/// Connection-scoped HPACK state with finite table and header-list bounds.
pub opaque type Decoder {
  Decoder(
    table: dynamic_table.State,
    maximum_table_capacity: Int,
    maximum_header_list_bytes: Int,
    wire_integer_limits: integer.Limits,
  )
}

/// Configuration, compression, index, or finite-resource failure.
pub type Error {
  InvalidConfiguration
  NonByteAligned
  Truncated
  InvalidIndex(Int)
  InvalidHeaderName
  LateTableSizeUpdate
  TableSizeExceeded(maximum: Int)
  HeaderListTooLarge(maximum: Int)
  IntegerFailure(integer.Error)
  StringFailure(string_literal.Error)
  TableFailure(dynamic_table.Error)
}

/// Construct a connection-scoped decoder.
pub fn new(
  maximum_table_capacity: Int,
  maximum_header_list_bytes: Int,
) -> Result(Decoder, Error) {
  use table <- result.try(
    dynamic_table.new(maximum_table_capacity)
    |> map_new_table,
  )
  use wire_integer_limits <- result.try(
    integer.limits(maximum_wire_integer, 6)
    |> map_new_integer,
  )
  case
    maximum_header_list_bytes >= 0
    && maximum_header_list_bytes <= maximum_wire_integer
  {
    True ->
      Ok(Decoder(
        table:,
        maximum_table_capacity:,
        maximum_header_list_bytes:,
        wire_integer_limits:,
      ))
    False -> Error(InvalidConfiguration)
  }
}

/// Decode one complete header block transactionally.
///
/// On error, no updated decoder is returned, so callers retain the prior
/// connection state unchanged.
pub fn decode(decoder: Decoder, block: BitArray) -> Result(Decoded, Error) {
  case bit_array.bit_size(block) % 8 {
    remainder if remainder != 0 -> Error(NonByteAligned)
    _ -> decode_fields(decoder, block, [], 0, False)
  }
}

/// Current dynamic-table bytes, for bounded runtime diagnostics.
pub fn dynamic_table_size(decoder: Decoder) -> Int {
  dynamic_table.size(decoder.table)
}

/// Current dynamic-table capacity, for bounded runtime diagnostics.
pub fn dynamic_table_capacity(decoder: Decoder) -> Int {
  dynamic_table.capacity(decoder.table)
}

fn decode_fields(
  decoder: Decoder,
  bytes: BitArray,
  reversed_headers: List(Header),
  header_list_size: Int,
  saw_header: Bool,
) -> Result(Decoded, Error) {
  case bytes {
    <<>> -> Ok(Decoded(decoder, list.reverse(reversed_headers)))
    <<first, _:bits>> ->
      case
        int.bitwise_and(first, 0x80) != 0,
        int.bitwise_and(first, 0x40) != 0,
        int.bitwise_and(first, 0x20) != 0,
        int.bitwise_and(first, 0x10) != 0
      {
        True, _, _, _ ->
          decode_indexed(decoder, bytes, reversed_headers, header_list_size)
        False, True, _, _ ->
          decode_literal(
            decoder,
            bytes,
            6,
            True,
            False,
            reversed_headers,
            header_list_size,
          )
        False, False, True, _ ->
          decode_table_size_update(
            decoder,
            bytes,
            reversed_headers,
            header_list_size,
            saw_header,
          )
        False, False, False, True ->
          decode_literal(
            decoder,
            bytes,
            4,
            False,
            True,
            reversed_headers,
            header_list_size,
          )
        False, False, False, False ->
          decode_literal(
            decoder,
            bytes,
            4,
            False,
            False,
            reversed_headers,
            header_list_size,
          )
      }
    _ -> Error(NonByteAligned)
  }
}

fn decode_indexed(
  decoder: Decoder,
  bytes: BitArray,
  reversed_headers: List(Header),
  header_list_size: Int,
) -> Result(Decoded, Error) {
  use integer.Decoded(index, rest) <- result.try(
    integer.decode(bytes, 7, decoder.wire_integer_limits)
    |> map_integer,
  )
  use #(name, value) <- result.try(resolve_index(decoder, index))
  use next_size <- result.try(add_header_size(
    decoder,
    header_list_size,
    name,
    value,
  ))
  decode_fields(
    decoder,
    rest,
    [Header(name, value, False), ..reversed_headers],
    next_size,
    True,
  )
}

fn decode_literal(
  decoder: Decoder,
  bytes: BitArray,
  prefix_bits: Int,
  insert: Bool,
  never_index: Bool,
  reversed_headers: List(Header),
  header_list_size: Int,
) -> Result(Decoded, Error) {
  use integer.Decoded(name_index, after_name_index) <- result.try(
    integer.decode(bytes, prefix_bits, decoder.wire_integer_limits)
    |> map_integer,
  )
  use #(name, after_name) <- result.try(decode_name(
    decoder,
    name_index,
    after_name_index,
  ))
  use _ <- result.try(validate_name(name))
  use string_literal.Decoded(value, rest, _) <- result.try(
    string_literal.decode_value(
      after_name,
      decoder.maximum_header_list_bytes,
      decoder.maximum_header_list_bytes,
    )
    |> map_string,
  )
  use next_size <- result.try(add_header_size(
    decoder,
    header_list_size,
    name,
    value,
  ))
  let header = Header(name, value, never_index)
  case insert {
    False ->
      decode_fields(
        decoder,
        rest,
        [header, ..reversed_headers],
        next_size,
        True,
      )
    True -> {
      use #(table, _) <- result.try(
        dynamic_table.insert(decoder.table, dynamic_table.Field(name, value))
        |> map_table,
      )
      decode_fields(
        Decoder(..decoder, table: table),
        rest,
        [header, ..reversed_headers],
        next_size,
        True,
      )
    }
  }
}

fn decode_name(
  decoder: Decoder,
  name_index: Int,
  bytes: BitArray,
) -> Result(#(BitArray, BitArray), Error) {
  case name_index {
    0 -> {
      use string_literal.Decoded(name, rest, _) <- result.try(
        string_literal.decode_value(
          bytes,
          decoder.maximum_header_list_bytes,
          decoder.maximum_header_list_bytes,
        )
        |> map_string,
      )
      Ok(#(name, rest))
    }
    index -> {
      use #(name, _) <- result.try(resolve_index(decoder, index))
      Ok(#(name, bytes))
    }
  }
}

fn decode_table_size_update(
  decoder: Decoder,
  bytes: BitArray,
  reversed_headers: List(Header),
  header_list_size: Int,
  saw_header: Bool,
) -> Result(Decoded, Error) {
  case saw_header {
    True -> Error(LateTableSizeUpdate)
    False -> {
      use integer.Decoded(capacity, rest) <- result.try(
        integer.decode(bytes, 5, decoder.wire_integer_limits)
        |> map_integer,
      )
      case capacity > decoder.maximum_table_capacity {
        True -> Error(TableSizeExceeded(decoder.maximum_table_capacity))
        False -> {
          use table <- result.try(
            dynamic_table.set_capacity(decoder.table, capacity)
            |> map_table,
          )
          decode_fields(
            Decoder(..decoder, table: table),
            rest,
            reversed_headers,
            header_list_size,
            False,
          )
        }
      }
    }
  }
}

fn resolve_index(
  decoder: Decoder,
  index: Int,
) -> Result(#(BitArray, BitArray), Error) {
  case index {
    0 -> Error(InvalidIndex(0))
    static_index if static_index <= 61 ->
      case static_table.get(static_index) {
        Some(static_table.Field(name, value)) -> Ok(#(name, value))
        None -> Error(InvalidIndex(index))
      }
    dynamic_index ->
      case dynamic_table.get_relative(decoder.table, dynamic_index - 62) {
        Some(dynamic_table.Field(name, value)) -> Ok(#(name, value))
        None -> Error(InvalidIndex(index))
      }
  }
}

fn validate_name(name: BitArray) -> Result(Nil, Error) {
  case bit_array.byte_size(name) > 0 && bit_array.bit_size(name) % 8 == 0 {
    True -> Ok(Nil)
    False -> Error(InvalidHeaderName)
  }
}

fn add_header_size(
  decoder: Decoder,
  current_size: Int,
  name: BitArray,
  value: BitArray,
) -> Result(Int, Error) {
  let field_size = bit_array.byte_size(name) + bit_array.byte_size(value) + 32
  case field_size > decoder.maximum_header_list_bytes - current_size {
    True -> Error(HeaderListTooLarge(decoder.maximum_header_list_bytes))
    False -> Ok(current_size + field_size)
  }
}

fn map_new_table(
  value: Result(dynamic_table.State, dynamic_table.Error),
) -> Result(dynamic_table.State, Error) {
  case value {
    Ok(table) -> Ok(table)
    Error(_) -> Error(InvalidConfiguration)
  }
}

fn map_new_integer(
  value: Result(integer.Limits, integer.Error),
) -> Result(integer.Limits, Error) {
  case value {
    Ok(limits) -> Ok(limits)
    Error(_) -> Error(InvalidConfiguration)
  }
}

fn map_integer(value: Result(value, integer.Error)) -> Result(value, Error) {
  case value {
    Ok(decoded) -> Ok(decoded)
    Error(integer.Truncated) -> Error(Truncated)
    Error(failure) -> Error(IntegerFailure(failure))
  }
}

fn map_string(
  value: Result(value, string_literal.Error),
) -> Result(value, Error) {
  case value {
    Ok(decoded) -> Ok(decoded)
    Error(string_literal.Truncated) -> Error(Truncated)
    Error(string_literal.IntegerFailure(integer.Truncated)) -> Error(Truncated)
    Error(failure) -> Error(StringFailure(failure))
  }
}

fn map_table(
  value: Result(value, dynamic_table.Error),
) -> Result(value, Error) {
  case value {
    Ok(table) -> Ok(table)
    Error(dynamic_table.CapacityExceeded(maximum)) ->
      Error(TableSizeExceeded(maximum))
    Error(failure) -> Error(TableFailure(failure))
  }
}

//// Stateful, bounded RFC 7541 header-block encoding.

import gleam/bit_array
import gleam/option.{type Option, None, Some}
import gleam/result
import http/internal/http2/hpack/decoder.{type Header, Header}
import http/internal/http2/hpack/dynamic_table
import http/internal/http2/hpack/integer
import http/internal/http2/hpack/static_table
import http/internal/http2/hpack/string_literal

const maximum_wire_integer = 0xffff_ffff

/// A successful block and the next connection-scoped encoding state.
pub type Encoded {
  Encoded(encoder: Encoder, block: BitArray)
}

/// Connection-scoped HPACK state.
pub opaque type Encoder {
  Encoder(
    table: dynamic_table.State,
    maximum_table_capacity: Int,
    maximum_header_list_bytes: Int,
    prefer_huffman: Bool,
    wire_integer_limits: integer.Limits,
    pending_minimum_capacity: Option(Int),
    pending_final_capacity: Option(Int),
  )
}

/// Configuration, field, table, or finite-resource failure.
pub type Error {
  InvalidConfiguration
  InvalidHeaderName
  InvalidHeaderValue
  TableSizeExceeded(maximum: Int)
  HeaderListTooLarge(maximum: Int)
  IntegerFailure(integer.Error)
  StringFailure(string_literal.Error)
  TableFailure(dynamic_table.Error)
}

/// Construct an encoder with finite table and header-list bounds.
pub fn new(
  maximum_table_capacity: Int,
  maximum_header_list_bytes: Int,
  prefer_huffman: Bool,
) -> Result(Encoder, Error) {
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
      Ok(Encoder(
        table:,
        maximum_table_capacity:,
        maximum_header_list_bytes:,
        prefer_huffman:,
        wire_integer_limits:,
        pending_minimum_capacity: None,
        pending_final_capacity: None,
      ))
    False -> Error(InvalidConfiguration)
  }
}

/// Select a new table capacity and queue the required next-block update.
///
/// If the capacity changes more than once between blocks, the smallest value
/// is emitted first and the final value second so the peer performs every
/// required eviction.
pub fn set_capacity(encoder: Encoder, capacity: Int) -> Result(Encoder, Error) {
  case capacity >= 0 && capacity <= encoder.maximum_table_capacity {
    False -> Error(TableSizeExceeded(encoder.maximum_table_capacity))
    True -> {
      use table <- result.try(
        dynamic_table.set_capacity(encoder.table, capacity)
        |> map_table,
      )
      let minimum = case encoder.pending_minimum_capacity {
        None -> capacity
        Some(previous) if capacity < previous -> capacity
        Some(previous) -> previous
      }
      Ok(
        Encoder(
          ..encoder,
          table:,
          pending_minimum_capacity: Some(minimum),
          pending_final_capacity: Some(capacity),
        ),
      )
    }
  }
}

/// Encode one complete header list transactionally.
pub fn encode(
  encoder: Encoder,
  headers: List(Header),
) -> Result(Encoded, Error) {
  use #(prefix, encoder) <- result.try(encode_pending_updates(encoder))
  encode_headers(encoder, headers, prefix, 0)
}

/// Current dynamic-table bytes, for bounded runtime diagnostics.
pub fn dynamic_table_size(encoder: Encoder) -> Int {
  dynamic_table.size(encoder.table)
}

fn encode_pending_updates(
  encoder: Encoder,
) -> Result(#(BitArray, Encoder), Error) {
  let cleared =
    Encoder(
      ..encoder,
      pending_minimum_capacity: None,
      pending_final_capacity: None,
    )
  case encoder.pending_minimum_capacity, encoder.pending_final_capacity {
    None, _ -> Ok(#(<<>>, cleared))
    Some(minimum), Some(final) -> {
      use first <- result.try(encode_capacity(encoder, minimum))
      case minimum == final {
        True -> Ok(#(first, cleared))
        False -> {
          use second <- result.try(encode_capacity(encoder, final))
          Ok(#(<<first:bits, second:bits>>, cleared))
        }
      }
    }
    Some(_), None -> Error(InvalidConfiguration)
  }
}

fn encode_capacity(encoder: Encoder, capacity: Int) -> Result(BitArray, Error) {
  integer.encode(capacity, 5, 0x20, encoder.wire_integer_limits)
  |> map_integer
}

fn encode_headers(
  encoder: Encoder,
  headers: List(Header),
  block: BitArray,
  header_list_size: Int,
) -> Result(Encoded, Error) {
  case headers {
    [] -> Ok(Encoded(encoder, block))
    [Header(name, value, never_index), ..rest] -> {
      use _ <- result.try(validate_field(name, value))
      use next_size <- result.try(add_header_size(
        encoder,
        header_list_size,
        name,
        value,
      ))
      case never_index {
        True -> {
          use encoded <- result.try(encode_literal(
            encoder,
            name,
            value,
            4,
            0x10,
          ))
          encode_headers(encoder, rest, <<block:bits, encoded:bits>>, next_size)
        }
        False ->
          encode_indexed_or_inserted(
            encoder,
            rest,
            block,
            next_size,
            name,
            value,
          )
      }
    }
  }
}

fn encode_indexed_or_inserted(
  encoder: Encoder,
  remaining_headers: List(Header),
  block: BitArray,
  header_list_size: Int,
  name: BitArray,
  value: BitArray,
) -> Result(Encoded, Error) {
  case find_exact_index(encoder, name, value) {
    Some(index) -> {
      use encoded <- result.try(
        integer.encode(index, 7, 0x80, encoder.wire_integer_limits)
        |> map_integer,
      )
      encode_headers(
        encoder,
        remaining_headers,
        <<block:bits, encoded:bits>>,
        header_list_size,
      )
    }
    None -> {
      use encoded <- result.try(encode_literal(encoder, name, value, 6, 0x40))
      use #(table, _) <- result.try(
        dynamic_table.insert(encoder.table, dynamic_table.Field(name, value))
        |> map_table,
      )
      encode_headers(
        Encoder(..encoder, table: table),
        remaining_headers,
        <<block:bits, encoded:bits>>,
        header_list_size,
      )
    }
  }
}

fn encode_literal(
  encoder: Encoder,
  name: BitArray,
  value: BitArray,
  prefix_bits: Int,
  representation_bits: Int,
) -> Result(BitArray, Error) {
  use encoded_name <- result.try(encode_name(
    encoder,
    name,
    prefix_bits,
    representation_bits,
  ))
  use encoded_value <- result.try(
    string_literal.encode_value(value, encoder.prefer_huffman)
    |> map_string,
  )
  Ok(<<encoded_name:bits, encoded_value:bits>>)
}

fn encode_name(
  encoder: Encoder,
  name: BitArray,
  prefix_bits: Int,
  representation_bits: Int,
) -> Result(BitArray, Error) {
  case find_name_index(encoder, name) {
    Some(index) ->
      integer.encode(
        index,
        prefix_bits,
        representation_bits,
        encoder.wire_integer_limits,
      )
      |> map_integer
    None -> {
      use zero <- result.try(
        integer.encode(
          0,
          prefix_bits,
          representation_bits,
          encoder.wire_integer_limits,
        )
        |> map_integer,
      )
      use literal <- result.try(
        string_literal.encode_value(name, encoder.prefer_huffman)
        |> map_string,
      )
      Ok(<<zero:bits, literal:bits>>)
    }
  }
}

fn find_exact_index(
  encoder: Encoder,
  name: BitArray,
  value: BitArray,
) -> Option(Int) {
  case static_table.find(static_table.Field(name, value)) {
    Some(index) -> Some(index)
    None ->
      case dynamic_table.find(encoder.table, dynamic_table.Field(name, value)) {
        Some(relative) -> Some(62 + relative)
        None -> None
      }
  }
}

fn find_name_index(encoder: Encoder, name: BitArray) -> Option(Int) {
  case static_table.find_name(name) {
    Some(index) -> Some(index)
    None ->
      case dynamic_table.find_name(encoder.table, name) {
        Some(relative) -> Some(62 + relative)
        None -> None
      }
  }
}

fn validate_field(name: BitArray, value: BitArray) -> Result(Nil, Error) {
  case bit_array.bit_size(name) % 8, bit_array.byte_size(name) > 0 {
    remainder, _ if remainder != 0 -> Error(InvalidHeaderName)
    _, False -> Error(InvalidHeaderName)
    _, True ->
      case bit_array.bit_size(value) % 8 {
        0 -> Ok(Nil)
        _ -> Error(InvalidHeaderValue)
      }
  }
}

fn add_header_size(
  encoder: Encoder,
  current_size: Int,
  name: BitArray,
  value: BitArray,
) -> Result(Int, Error) {
  let field_size = bit_array.byte_size(name) + bit_array.byte_size(value) + 32
  case field_size > encoder.maximum_header_list_bytes - current_size {
    True -> Error(HeaderListTooLarge(encoder.maximum_header_list_bytes))
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
    Ok(encoded) -> Ok(encoded)
    Error(failure) -> Error(IntegerFailure(failure))
  }
}

fn map_string(
  value: Result(value, string_literal.Error),
) -> Result(value, Error) {
  case value {
    Ok(encoded) -> Ok(encoded)
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

//// Strict, bounded RFC 9651 Structured Field parsing and serialization.

import gleam/bit_array
import gleam/int
import gleam/list
import gleam/option.{type Option, None, Some}
import gleam/result
import gleam/string

const default_maximum_bytes = 1_048_576

const default_maximum_members = 4096

const default_maximum_parameters = 256

const maximum_integer = 999_999_999_999_999

const maximum_decimal_thousandths = 999_999_999_999_999

/// Finite parser ceilings. The member default exceeds RFC 9651's required
/// minimum support for lists containing 1024 members.
pub type Limits {
  Limits(maximum_bytes: Int, maximum_members: Int, maximum_parameters: Int)
}

/// Every RFC 9651 bare item. Decimal values are exact signed thousandths.
pub type BareItem {
  Integer(Int)
  Decimal(thousandths: Int)
  StringValue(String)
  Token(String)
  ByteSequence(BitArray)
  Boolean(Bool)
  Date(unix_seconds: Int)
  /// Use only for values intended for end-user display when an ASCII String
  /// or Token is not adequate; RFC 9651 otherwise does not recommend it.
  DisplayString(String)
}

/// One order-preserving parameter.
pub type Parameter {
  Parameter(key: String, value: BareItem)
}

/// One parameterized item.
pub type Item {
  Item(value: BareItem, parameters: List(Parameter))
}

/// One list or dictionary value.
pub type ListMember {
  ListItem(Item)
  InnerList(items: List(Item), parameters: List(Parameter))
}

/// One order-preserving dictionary member.
pub type DictionaryMember {
  DictionaryMember(key: String, value: ListMember)
}

/// Strict parse or serialization failure.
pub type Error {
  Invalid
  LimitExceeded
}

/// Return one Parameter by its stable wire-order index.
///
/// Negative and out-of-range indexes return `None` without traversing beyond
/// the finite supplied collection.
pub fn parameter_at(
  parameters: List(Parameter),
  index: Int,
) -> Option(Parameter) {
  at(parameters, index)
}

/// Return one Parameter by its case-sensitive Structured Field key.
pub fn parameter_by_key(
  parameters: List(Parameter),
  key: String,
) -> Option(Parameter) {
  case parameters {
    [] -> None
    [Parameter(parameter_key, value), ..rest] ->
      case parameter_key == key {
        True -> Some(Parameter(parameter_key, value))
        False -> parameter_by_key(rest, key)
      }
  }
}

/// Return one Dictionary member by its stable wire-order index.
///
/// Negative and out-of-range indexes return `None`.
pub fn dictionary_member_at(
  members: List(DictionaryMember),
  index: Int,
) -> Option(DictionaryMember) {
  at(members, index)
}

/// Return one Dictionary member by its case-sensitive Structured Field key.
pub fn dictionary_member_by_key(
  members: List(DictionaryMember),
  key: String,
) -> Option(DictionaryMember) {
  case members {
    [] -> None
    [DictionaryMember(member_key, value), ..rest] ->
      case member_key == key {
        True -> Some(DictionaryMember(member_key, value))
        False -> dictionary_member_by_key(rest, key)
      }
  }
}

/// Return the finite general-purpose limits.
pub fn defaults() -> Limits {
  Limits(
    maximum_bytes: default_maximum_bytes,
    maximum_members: default_maximum_members,
    maximum_parameters: default_maximum_parameters,
  )
}

/// Parse a complete Item field.
pub fn parse_item(input: String) -> Result(Item, Error) {
  parse_item_with_limits(input, defaults())
}

/// Parse a complete Item field under explicit finite limits.
pub fn parse_item_with_limits(
  input: String,
  limits: Limits,
) -> Result(Item, Error) {
  use bytes <- result.try(prepare(input, limits))
  use #(item, rest) <- result.try(parse_item_bits(discard_spaces(bytes), limits))
  case discard_spaces(rest) {
    <<>> -> Ok(item)
    _ -> Error(Invalid)
  }
}

/// Parse every matching field line as one Item field value.
///
/// Lines remain in wire order and are combined with comma plus SP exactly
/// once before parsing. Multiple Item lines consequently fail unless their
/// combined representation is itself one valid Item.
pub fn parse_item_field_lines(lines: List(String)) -> Result(Item, Error) {
  parse_item_field_lines_with_limits(lines, defaults())
}

/// Parse matching Item field lines under explicit finite aggregate limits.
pub fn parse_item_field_lines_with_limits(
  lines: List(String),
  limits: Limits,
) -> Result(Item, Error) {
  use combined <- result.try(combine_field_lines(lines, limits))
  parse_item_with_limits(combined, limits)
}

/// Parse a complete List field.
pub fn parse_list(input: String) -> Result(List(ListMember), Error) {
  parse_list_with_limits(input, defaults())
}

/// Parse a complete List field under explicit finite limits.
pub fn parse_list_with_limits(
  input: String,
  limits: Limits,
) -> Result(List(ListMember), Error) {
  use bytes <- result.try(prepare(input, limits))
  let bytes = discard_spaces(bytes)
  case bytes {
    <<>> -> Ok([])
    _ -> parse_list_members(bytes, limits, 0, [])
  }
}

/// Parse all matching field lines as one ordered List field value.
pub fn parse_list_field_lines(
  lines: List(String),
) -> Result(List(ListMember), Error) {
  parse_list_field_lines_with_limits(lines, defaults())
}

/// Parse matching List field lines under explicit finite aggregate limits.
pub fn parse_list_field_lines_with_limits(
  lines: List(String),
  limits: Limits,
) -> Result(List(ListMember), Error) {
  use combined <- result.try(combine_field_lines(lines, limits))
  parse_list_with_limits(combined, limits)
}

/// Parse a complete Dictionary field.
pub fn parse_dictionary(
  input: String,
) -> Result(List(DictionaryMember), Error) {
  parse_dictionary_with_limits(input, defaults())
}

/// Parse a complete Dictionary field under explicit finite limits.
pub fn parse_dictionary_with_limits(
  input: String,
  limits: Limits,
) -> Result(List(DictionaryMember), Error) {
  use bytes <- result.try(prepare(input, limits))
  let bytes = discard_spaces(bytes)
  case bytes {
    <<>> -> Ok([])
    _ -> parse_dictionary_members(bytes, limits, 0, [])
  }
}

/// Parse all matching field lines as one ordered Dictionary field value.
pub fn parse_dictionary_field_lines(
  lines: List(String),
) -> Result(List(DictionaryMember), Error) {
  parse_dictionary_field_lines_with_limits(lines, defaults())
}

/// Parse matching Dictionary lines under explicit finite aggregate limits.
pub fn parse_dictionary_field_lines_with_limits(
  lines: List(String),
  limits: Limits,
) -> Result(List(DictionaryMember), Error) {
  use combined <- result.try(combine_field_lines(lines, limits))
  parse_dictionary_with_limits(combined, limits)
}

/// Serialize one Item using the RFC 9651 canonical textual form.
pub fn serialize_item(item: Item) -> Result(String, Error) {
  use encoded <- result.try(serialize_item_value(item))
  bounded_output(encoded)
}

/// Serialize a List using the RFC 9651 canonical textual form.
pub fn serialize_list(members: List(ListMember)) -> Result(String, Error) {
  use <- require(list.length(members) <= default_maximum_members, LimitExceeded)
  use encoded <- result.try(serialize_members(members, []))
  bounded_output(string.join(list.reverse(encoded), with: ", "))
}

/// Serialize an ordered Dictionary using canonical textual form.
pub fn serialize_dictionary(
  members: List(DictionaryMember),
) -> Result(String, Error) {
  use <- require(list.length(members) <= default_maximum_members, LimitExceeded)
  use <- require(unique_dictionary_keys(members, []), Invalid)
  use encoded <- result.try(serialize_dictionary_members(members, []))
  bounded_output(string.join(list.reverse(encoded), with: ", "))
}

fn prepare(input: String, limits: Limits) -> Result(BitArray, Error) {
  use <- require(valid_limits(limits), LimitExceeded)
  use <- require(string.byte_size(input) <= limits.maximum_bytes, LimitExceeded)
  Ok(bit_array.from_string(input))
}

fn combine_field_lines(
  lines: List(String),
  limits: Limits,
) -> Result(String, Error) {
  use <- require(valid_limits(limits), LimitExceeded)
  combine_field_lines_loop(lines, limits.maximum_bytes, 0, [])
}

fn combine_field_lines_loop(
  lines: List(String),
  maximum_bytes: Int,
  combined_bytes: Int,
  reversed: List(String),
) -> Result(String, Error) {
  case lines {
    [] -> Ok(reversed |> list.reverse |> string.join(with: ", "))
    [line, ..rest] -> {
      let delimiter_bytes = case reversed {
        [] -> 0
        _ -> 2
      }
      let combined_bytes =
        combined_bytes + delimiter_bytes + string.byte_size(line)
      use <- require(combined_bytes <= maximum_bytes, LimitExceeded)
      combine_field_lines_loop(rest, maximum_bytes, combined_bytes, [
        line,
        ..reversed
      ])
    }
  }
}

fn at(values: List(value), index: Int) -> Option(value) {
  case index < 0, values {
    True, _ | _, [] -> None
    False, [value, ..] if index == 0 -> Some(value)
    False, [_, ..rest] -> at(rest, index - 1)
  }
}

fn parse_list_members(
  input: BitArray,
  limits: Limits,
  count: Int,
  reversed: List(ListMember),
) -> Result(List(ListMember), Error) {
  use <- require(count < limits.maximum_members, LimitExceeded)
  use #(member, rest) <- result.try(parse_member(input, limits))
  let reversed = [member, ..reversed]
  case discard_optional_whitespace(rest) {
    <<>> -> Ok(list.reverse(reversed))
    <<0x2c, after_comma:bits>> -> {
      let after_comma = discard_optional_whitespace(after_comma)
      case after_comma {
        <<>> -> Error(Invalid)
        _ -> parse_list_members(after_comma, limits, count + 1, reversed)
      }
    }
    _ -> Error(Invalid)
  }
}

fn parse_dictionary_members(
  input: BitArray,
  limits: Limits,
  count: Int,
  members: List(DictionaryMember),
) -> Result(List(DictionaryMember), Error) {
  use <- require(count < limits.maximum_members, LimitExceeded)
  use #(key, rest) <- result.try(parse_key(input))
  use #(value, rest) <- result.try(case rest {
    <<0x3d, value:bits>> -> parse_member(value, limits)
    _ -> {
      use #(parameters, rest) <- result.try(parse_parameters(rest, limits))
      Ok(#(ListItem(Item(Boolean(True), parameters)), rest))
    }
  })
  let members = upsert_dictionary(members, DictionaryMember(key, value), [])
  case discard_optional_whitespace(rest) {
    <<>> -> Ok(members)
    <<0x2c, after_comma:bits>> -> {
      let after_comma = discard_optional_whitespace(after_comma)
      case after_comma {
        <<>> -> Error(Invalid)
        _ -> parse_dictionary_members(after_comma, limits, count + 1, members)
      }
    }
    _ -> Error(Invalid)
  }
}

fn parse_member(
  input: BitArray,
  limits: Limits,
) -> Result(#(ListMember, BitArray), Error) {
  case input {
    <<0x28, rest:bits>> -> parse_inner_list(rest, limits, 0, [])
    _ -> {
      use #(item, rest) <- result.try(parse_item_bits(input, limits))
      Ok(#(ListItem(item), rest))
    }
  }
}

fn parse_inner_list(
  input: BitArray,
  limits: Limits,
  count: Int,
  reversed: List(Item),
) -> Result(#(ListMember, BitArray), Error) {
  let input = discard_spaces(input)
  case input {
    <<0x29, rest:bits>> -> {
      use #(parameters, rest) <- result.try(parse_parameters(rest, limits))
      Ok(#(InnerList(list.reverse(reversed), parameters), rest))
    }
    <<>> -> Error(Invalid)
    _ -> {
      use <- require(count < limits.maximum_members, LimitExceeded)
      use #(item, rest) <- result.try(parse_item_bits(input, limits))
      case rest {
        <<0x29, _:bits>> ->
          parse_inner_list(rest, limits, count + 1, [item, ..reversed])
        <<0x20, _:bits>> ->
          parse_inner_list(rest, limits, count + 1, [item, ..reversed])
        _ -> Error(Invalid)
      }
    }
  }
}

fn parse_item_bits(
  input: BitArray,
  limits: Limits,
) -> Result(#(Item, BitArray), Error) {
  use #(value, rest) <- result.try(parse_bare_item(input))
  use #(parameters, rest) <- result.try(parse_parameters(rest, limits))
  Ok(#(Item(value, parameters), rest))
}

fn parse_parameters(
  input: BitArray,
  limits: Limits,
) -> Result(#(List(Parameter), BitArray), Error) {
  parse_parameters_loop(input, limits, 0, [])
}

fn parse_parameters_loop(
  input: BitArray,
  limits: Limits,
  count: Int,
  parameters: List(Parameter),
) -> Result(#(List(Parameter), BitArray), Error) {
  case input {
    <<0x3b, rest:bits>> -> {
      use <- require(count < limits.maximum_parameters, LimitExceeded)
      let rest = discard_spaces(rest)
      use #(key, rest) <- result.try(parse_key(rest))
      use #(value, rest) <- result.try(case rest {
        <<0x3d, value:bits>> -> parse_bare_item(value)
        _ -> Ok(#(Boolean(True), rest))
      })
      parse_parameters_loop(
        rest,
        limits,
        count + 1,
        upsert_parameter(parameters, Parameter(key, value), []),
      )
    }
    _ -> Ok(#(parameters, input))
  }
}

fn parse_bare_item(input: BitArray) -> Result(#(BareItem, BitArray), Error) {
  case input {
    <<first, _:bits>> if first == 0x2d || { first >= 0x30 && first <= 0x39 } ->
      parse_number(input)
    <<0x22, rest:bits>> -> parse_string_bytes(rest, [])
    <<first, _:bits>>
      if { first >= 0x61 && first <= 0x7a }
      || { first >= 0x41 && first <= 0x5a }
      || first == 0x2a
    -> parse_token(input)
    <<0x3a, rest:bits>> -> parse_byte_sequence_bytes(rest, [])
    <<0x3f, 0x31, rest:bits>> -> Ok(#(Boolean(True), rest))
    <<0x3f, 0x30, rest:bits>> -> Ok(#(Boolean(False), rest))
    <<0x40, rest:bits>> -> {
      use #(value, rest) <- result.try(parse_number(rest))
      case value {
        Integer(seconds) -> Ok(#(Date(seconds), rest))
        _ -> Error(Invalid)
      }
    }
    <<0x25, 0x22, rest:bits>> -> parse_display_string_bytes(rest, [])
    _ -> Error(Invalid)
  }
}

fn parse_number(input: BitArray) -> Result(#(BareItem, BitArray), Error) {
  let #(negative, input) = case input {
    <<0x2d, rest:bits>> -> #(True, rest)
    _ -> #(False, input)
  }
  let #(whole_digits, whole, rest) = consume_digits(input, 0, 0)
  case whole_digits, rest {
    0, _ -> Error(Invalid)
    count, <<0x2e, fraction:bits>> if count <= 12 -> {
      let #(fraction_digits, fraction, rest) = consume_digits(fraction, 0, 0)
      case fraction_digits >= 1 && fraction_digits <= 3 {
        False -> Error(Invalid)
        True -> {
          let scaled_fraction = case fraction_digits {
            1 -> fraction * 100
            2 -> fraction * 10
            _ -> fraction
          }
          let value = whole * 1000 + scaled_fraction
          let value = case negative {
            True -> 0 - value
            False -> value
          }
          Ok(#(Decimal(value), rest))
        }
      }
    }
    count, _ if count <= 15 -> {
      let value = case negative {
        True -> 0 - whole
        False -> whole
      }
      Ok(#(Integer(value), rest))
    }
    _, _ -> Error(Invalid)
  }
}

fn consume_digits(
  input: BitArray,
  count: Int,
  value: Int,
) -> #(Int, Int, BitArray) {
  case input {
    <<byte, rest:bits>> if byte >= 0x30 && byte <= 0x39 ->
      consume_digits(rest, count + 1, value * 10 + byte - 0x30)
    _ -> #(count, value, input)
  }
}

fn parse_string_bytes(
  input: BitArray,
  reversed: List(BitArray),
) -> Result(#(BareItem, BitArray), Error) {
  case input {
    <<0x22, rest:bits>> -> {
      use value <- result.try(bytes_to_string(reversed))
      Ok(#(StringValue(value), rest))
    }
    <<0x5c, escaped, rest:bits>> if escaped == 0x22 || escaped == 0x5c ->
      parse_string_bytes(rest, [<<escaped>>, ..reversed])
    <<0x5c, _:bits>> -> Error(Invalid)
    <<byte, rest:bits>> if byte >= 0x20 && byte <= 0x7e ->
      parse_string_bytes(rest, [<<byte>>, ..reversed])
    _ -> Error(Invalid)
  }
}

fn parse_token(input: BitArray) -> Result(#(BareItem, BitArray), Error) {
  case input {
    <<first, rest:bits>>
      if { first >= 0x61 && first <= 0x7a }
      || { first >= 0x41 && first <= 0x5a }
      || first == 0x2a
    -> parse_token_bytes(rest, [<<first>>])
    _ -> Error(Invalid)
  }
}

fn parse_token_bytes(
  input: BitArray,
  reversed: List(BitArray),
) -> Result(#(BareItem, BitArray), Error) {
  case input {
    <<byte, rest:bits>> ->
      case is_token_character(byte) {
        True -> parse_token_bytes(rest, [<<byte>>, ..reversed])
        False -> {
          use value <- result.try(bytes_to_string(reversed))
          Ok(#(Token(value), input))
        }
      }
    _ -> {
      use value <- result.try(bytes_to_string(reversed))
      Ok(#(Token(value), input))
    }
  }
}

fn parse_byte_sequence_bytes(
  input: BitArray,
  reversed: List(BitArray),
) -> Result(#(BareItem, BitArray), Error) {
  case input {
    <<0x3a, rest:bits>> -> {
      use encoded <- result.try(bytes_to_string(reversed))
      use decoded <- result.try(decode_canonical_base64(encoded))
      Ok(#(ByteSequence(decoded), rest))
    }
    <<byte, rest:bits>> ->
      case is_base64_character(byte) {
        True -> parse_byte_sequence_bytes(rest, [<<byte>>, ..reversed])
        False -> Error(Invalid)
      }
    _ -> Error(Invalid)
  }
}

fn decode_canonical_base64(encoded: String) -> Result(BitArray, Error) {
  use decoded <- result.try(
    bit_array.base64_decode(encoded) |> result.map_error(fn(_) { Invalid }),
  )
  case bit_array.base64_encode(decoded, True) == encoded {
    True -> Ok(decoded)
    False -> Error(Invalid)
  }
}

fn parse_display_string_bytes(
  input: BitArray,
  reversed: List(BitArray),
) -> Result(#(BareItem, BitArray), Error) {
  case input {
    <<0x22, rest:bits>> -> {
      let bytes = reversed |> list.reverse() |> bit_array.concat()
      use value <- result.try(
        bit_array.to_string(bytes) |> result.map_error(fn(_) { Invalid }),
      )
      Ok(#(DisplayString(value), rest))
    }
    <<0x25, high, low, rest:bits>>
      if { { high >= 0x30 && high <= 0x39 } || { high >= 0x61 && high <= 0x66 } }
      && { { low >= 0x30 && low <= 0x39 } || { low >= 0x61 && low <= 0x66 } }
    -> {
      let decoded = hex_value(high) * 16 + hex_value(low)
      parse_display_string_bytes(rest, [<<decoded>>, ..reversed])
    }
    <<0x25, _:bits>> -> Error(Invalid)
    <<byte, rest:bits>> if byte >= 0x20 && byte <= 0x7e ->
      parse_display_string_bytes(rest, [<<byte>>, ..reversed])
    _ -> Error(Invalid)
  }
}

fn parse_key(input: BitArray) -> Result(#(String, BitArray), Error) {
  case input {
    <<first, rest:bits>>
      if { first >= 0x61 && first <= 0x7a } || first == 0x2a
    -> parse_key_bytes(rest, [<<first>>])
    _ -> Error(Invalid)
  }
}

fn parse_key_bytes(
  input: BitArray,
  reversed: List(BitArray),
) -> Result(#(String, BitArray), Error) {
  case input {
    <<byte, rest:bits>> ->
      case is_key_character(byte) {
        True -> parse_key_bytes(rest, [<<byte>>, ..reversed])
        False -> {
          use key <- result.try(bytes_to_string(reversed))
          Ok(#(key, input))
        }
      }
    _ -> {
      use key <- result.try(bytes_to_string(reversed))
      Ok(#(key, input))
    }
  }
}

fn bytes_to_string(reversed: List(BitArray)) -> Result(String, Error) {
  reversed
  |> list.reverse()
  |> bit_array.concat()
  |> bit_array.to_string()
  |> result.map_error(fn(_) { Invalid })
}

fn upsert_dictionary(
  members: List(DictionaryMember),
  replacement: DictionaryMember,
  earlier: List(DictionaryMember),
) -> List(DictionaryMember) {
  case members {
    [] -> list.reverse([replacement, ..earlier])
    [DictionaryMember(key, _), ..rest] if key == replacement.key ->
      list.append(list.reverse(earlier), [replacement, ..rest])
    [member, ..rest] ->
      upsert_dictionary(rest, replacement, [member, ..earlier])
  }
}

fn upsert_parameter(
  parameters: List(Parameter),
  replacement: Parameter,
  earlier: List(Parameter),
) -> List(Parameter) {
  case parameters {
    [] -> list.reverse([replacement, ..earlier])
    [Parameter(key, _), ..rest] if key == replacement.key ->
      list.append(list.reverse(earlier), [replacement, ..rest])
    [parameter, ..rest] ->
      upsert_parameter(rest, replacement, [parameter, ..earlier])
  }
}

fn serialize_dictionary_members(
  members: List(DictionaryMember),
  reversed: List(String),
) -> Result(List(String), Error) {
  case members {
    [] -> Ok(reversed)
    [DictionaryMember(key, value), ..rest] -> {
      use <- require(valid_key(key), Invalid)
      use encoded <- result.try(case value {
        ListItem(Item(Boolean(True), parameters)) -> {
          use parameters <- result.try(serialize_parameters(parameters))
          Ok(key <> parameters)
        }
        _ -> {
          use member <- result.try(serialize_member(value))
          Ok(key <> "=" <> member)
        }
      })
      serialize_dictionary_members(rest, [encoded, ..reversed])
    }
  }
}

fn serialize_members(
  members: List(ListMember),
  reversed: List(String),
) -> Result(List(String), Error) {
  case members {
    [] -> Ok(reversed)
    [member, ..rest] -> {
      use encoded <- result.try(serialize_member(member))
      serialize_members(rest, [encoded, ..reversed])
    }
  }
}

fn serialize_member(member: ListMember) -> Result(String, Error) {
  case member {
    ListItem(item) -> serialize_item_value(item)
    InnerList(items, parameters) -> {
      use <- require(
        list.length(items) <= default_maximum_members,
        LimitExceeded,
      )
      use items <- result.try(serialize_items(items, []))
      use parameters <- result.try(serialize_parameters(parameters))
      Ok(
        "(" <> string.join(list.reverse(items), with: " ") <> ")" <> parameters,
      )
    }
  }
}

fn serialize_items(
  items: List(Item),
  reversed: List(String),
) -> Result(List(String), Error) {
  case items {
    [] -> Ok(reversed)
    [item, ..rest] -> {
      use encoded <- result.try(serialize_item_value(item))
      serialize_items(rest, [encoded, ..reversed])
    }
  }
}

fn serialize_item_value(item: Item) -> Result(String, Error) {
  use bare <- result.try(serialize_bare_item(item.value))
  use parameters <- result.try(serialize_parameters(item.parameters))
  Ok(bare <> parameters)
}

fn serialize_parameters(parameters: List(Parameter)) -> Result(String, Error) {
  use <- require(
    list.length(parameters) <= default_maximum_parameters,
    LimitExceeded,
  )
  use <- require(unique_parameter_keys(parameters, []), Invalid)
  serialize_parameter_values(parameters, [])
}

fn serialize_parameter_values(
  parameters: List(Parameter),
  reversed: List(String),
) -> Result(String, Error) {
  case parameters {
    [] -> Ok(string.concat(list.reverse(reversed)))
    [Parameter(key, value), ..rest] -> {
      use <- require(valid_key(key), Invalid)
      use encoded <- result.try(case value {
        Boolean(True) -> Ok(";" <> key)
        _ -> {
          use bare <- result.try(serialize_bare_item(value))
          Ok(";" <> key <> "=" <> bare)
        }
      })
      serialize_parameter_values(rest, [encoded, ..reversed])
    }
  }
}

fn serialize_bare_item(value: BareItem) -> Result(String, Error) {
  case value {
    Integer(value) -> serialize_integer(value)
    Decimal(value) -> serialize_decimal(value)
    StringValue(value) -> serialize_string(value)
    Token(value) ->
      case valid_token(value) {
        True -> Ok(value)
        False -> Error(Invalid)
      }
    ByteSequence(value) ->
      Ok(":" <> bit_array.base64_encode(value, True) <> ":")
    Boolean(True) -> Ok("?1")
    Boolean(False) -> Ok("?0")
    Date(seconds) -> {
      use value <- result.try(serialize_integer(seconds))
      Ok("@" <> value)
    }
    DisplayString(value) -> serialize_display_string(value)
  }
}

fn serialize_integer(value: Int) -> Result(String, Error) {
  case absolute(value) <= maximum_integer {
    True -> Ok(int.to_string(value))
    False -> Error(Invalid)
  }
}

fn serialize_decimal(value: Int) -> Result(String, Error) {
  use <- require(absolute(value) <= maximum_decimal_thousandths, Invalid)
  let sign = case value < 0 {
    True -> "-"
    False -> ""
  }
  let value = absolute(value)
  let whole = value / 1000
  let fraction = value % 1000
  let padded = string.drop_start(int.to_string(fraction + 1000), 1)
  Ok(sign <> int.to_string(whole) <> "." <> trim_decimal_zeroes(padded))
}

fn trim_decimal_zeroes(value: String) -> String {
  case string.length(value) > 1 && string.ends_with(value, "0") {
    True ->
      trim_decimal_zeroes(string.slice(
        value,
        at_index: 0,
        length: string.length(value) - 1,
      ))
    False -> value
  }
}

fn serialize_string(value: String) -> Result(String, Error) {
  serialize_string_bytes(bit_array.from_string(value), [])
}

fn serialize_string_bytes(
  input: BitArray,
  reversed: List(BitArray),
) -> Result(String, Error) {
  case input {
    <<>> -> {
      use value <- result.try(bytes_to_string(reversed))
      Ok("\"" <> value <> "\"")
    }
    <<byte, rest:bits>> if byte == 0x22 || byte == 0x5c ->
      serialize_string_bytes(rest, [<<0x5c, byte>>, ..reversed])
    <<byte, rest:bits>> if byte >= 0x20 && byte <= 0x7e ->
      serialize_string_bytes(rest, [<<byte>>, ..reversed])
    _ -> Error(Invalid)
  }
}

fn serialize_display_string(value: String) -> Result(String, Error) {
  use encoded <- result.try(
    serialize_display_bytes(bit_array.from_string(value), []),
  )
  Ok("%\"" <> encoded <> "\"")
}

fn serialize_display_bytes(
  input: BitArray,
  reversed: List(BitArray),
) -> Result(String, Error) {
  case input {
    <<>> -> bytes_to_string(reversed)
    <<byte, rest:bits>>
      if byte >= 0x20 && byte <= 0x7e && byte != 0x22 && byte != 0x25
    -> serialize_display_bytes(rest, [<<byte>>, ..reversed])
    <<byte, rest:bits>> -> {
      let high = lower_hex(byte / 16)
      let low = lower_hex(byte % 16)
      serialize_display_bytes(rest, [<<0x25, high, low>>, ..reversed])
    }
    _ -> Error(Invalid)
  }
}

fn unique_dictionary_keys(
  members: List(DictionaryMember),
  keys: List(String),
) -> Bool {
  case members {
    [] -> True
    [DictionaryMember(key, _), ..rest] ->
      !list.contains(keys, key) && unique_dictionary_keys(rest, [key, ..keys])
  }
}

fn unique_parameter_keys(
  parameters: List(Parameter),
  keys: List(String),
) -> Bool {
  case parameters {
    [] -> True
    [Parameter(key, _), ..rest] ->
      !list.contains(keys, key) && unique_parameter_keys(rest, [key, ..keys])
  }
}

fn valid_key(key: String) -> Bool {
  case bit_array.from_string(key) {
    <<first, rest:bits>>
      if { first >= 0x61 && first <= 0x7a } || first == 0x2a
    -> all_key_bytes(rest)
    _ -> False
  }
}

fn all_key_bytes(input: BitArray) -> Bool {
  case input {
    <<>> -> True
    <<byte, rest:bits>> -> is_key_character(byte) && all_key_bytes(rest)
    _ -> False
  }
}

fn valid_token(token: String) -> Bool {
  case bit_array.from_string(token) {
    <<first, rest:bits>>
      if { first >= 0x61 && first <= 0x7a }
      || { first >= 0x41 && first <= 0x5a }
      || first == 0x2a
    -> all_token_bytes(rest)
    _ -> False
  }
}

fn all_token_bytes(input: BitArray) -> Bool {
  case input {
    <<>> -> True
    <<byte, rest:bits>> -> is_token_character(byte) && all_token_bytes(rest)
    _ -> False
  }
}

fn bounded_output(value: String) -> Result(String, Error) {
  case string.byte_size(value) <= default_maximum_bytes {
    True -> Ok(value)
    False -> Error(LimitExceeded)
  }
}

fn valid_limits(limits: Limits) -> Bool {
  limits.maximum_bytes > 0
  && limits.maximum_bytes <= 67_108_864
  && limits.maximum_members > 0
  && limits.maximum_members <= 65_536
  && limits.maximum_parameters > 0
  && limits.maximum_parameters <= 4096
}

fn discard_spaces(input: BitArray) -> BitArray {
  case input {
    <<0x20, rest:bits>> -> discard_spaces(rest)
    _ -> input
  }
}

fn discard_optional_whitespace(input: BitArray) -> BitArray {
  case input {
    <<byte, rest:bits>> if byte == 0x20 || byte == 0x09 ->
      discard_optional_whitespace(rest)
    _ -> input
  }
}

fn is_lower_alpha(byte: Int) -> Bool {
  byte >= 0x61 && byte <= 0x7a
}

fn is_alpha(byte: Int) -> Bool {
  is_lower_alpha(byte) || { byte >= 0x41 && byte <= 0x5a }
}

fn is_digit(byte: Int) -> Bool {
  byte >= 0x30 && byte <= 0x39
}

fn is_key_character(byte: Int) -> Bool {
  is_lower_alpha(byte)
  || is_digit(byte)
  || byte == 0x5f
  || byte == 0x2d
  || byte == 0x2e
  || byte == 0x2a
}

fn is_token_character(byte: Int) -> Bool {
  is_alpha(byte)
  || is_digit(byte)
  || byte == 0x21
  || byte == 0x23
  || byte == 0x24
  || byte == 0x25
  || byte == 0x26
  || byte == 0x27
  || byte == 0x2a
  || byte == 0x2b
  || byte == 0x2d
  || byte == 0x2e
  || byte == 0x3a
  || byte == 0x2f
  || byte == 0x5e
  || byte == 0x5f
  || byte == 0x60
  || byte == 0x7c
  || byte == 0x7e
}

fn is_base64_character(byte: Int) -> Bool {
  is_alpha(byte)
  || is_digit(byte)
  || byte == 0x2b
  || byte == 0x2f
  || byte == 0x3d
}

fn hex_value(byte: Int) -> Int {
  case is_digit(byte) {
    True -> byte - 0x30
    False -> byte - 0x61 + 10
  }
}

fn lower_hex(value: Int) -> Int {
  case value < 10 {
    True -> 0x30 + value
    False -> 0x61 + value - 10
  }
}

fn absolute(value: Int) -> Int {
  case value < 0 {
    True -> 0 - value
    False -> value
  }
}

fn require(
  condition: Bool,
  failure: Error,
  continue: fn() -> Result(value, Error),
) -> Result(value, Error) {
  case condition {
    True -> continue()
    False -> Error(failure)
  }
}

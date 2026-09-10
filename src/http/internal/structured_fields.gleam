//// Strict RFC 9651 Structured Field parsing used by HTTP field consumers.

import gleam/bit_array
import gleam/list
import gleam/result

/// The bare-item variants needed by consumers that inspect selected members.
pub type BareItem {
  Integer(Int)
  Boolean(Bool)
  Other
}

/// A dictionary value is either one item or one inner list.
pub type Value {
  Item(BareItem)
  InnerList
}

/// One dictionary member in wire order.
pub type Member {
  Member(key: String, value: Value)
}

/// The complete field value is not valid RFC 9651 dictionary syntax.
pub type Error {
  Invalid
}

/// Parse and validate an RFC 9651 Dictionary while retaining the item types
/// needed by field-specific consumers. Duplicate members remain in wire order
/// so consumers can apply the required last-value-wins semantics.
pub fn parse_dictionary(input: BitArray) -> Result(List(Member), Error) {
  let input = discard_spaces(input)
  case input {
    <<>> -> Ok([])
    _ -> parse_dictionary_members(input, [])
  }
}

fn parse_dictionary_members(
  input: BitArray,
  members: List(Member),
) -> Result(List(Member), Error) {
  use #(key, rest) <- result.try(parse_key(input))
  use #(value, rest) <- result.try(parse_dictionary_value(rest))
  let members = [Member(key, value), ..members]
  let rest = discard_optional_whitespace(rest)
  case rest {
    <<>> -> Ok(list.reverse(members))
    <<0x2c, after_comma:bits>> -> {
      let after_comma = discard_optional_whitespace(after_comma)
      case after_comma {
        <<>> -> Error(Invalid)
        _ -> parse_dictionary_members(after_comma, members)
      }
    }
    _ -> Error(Invalid)
  }
}

fn parse_dictionary_value(
  input: BitArray,
) -> Result(#(Value, BitArray), Error) {
  case input {
    <<0x3d, rest:bits>> -> parse_item_or_inner_list(rest)
    _ -> {
      use rest <- result.try(parse_parameters(input))
      Ok(#(Item(Boolean(True)), rest))
    }
  }
}

fn parse_item_or_inner_list(
  input: BitArray,
) -> Result(#(Value, BitArray), Error) {
  case input {
    <<0x28, _:bits>> -> parse_inner_list(input)
    _ -> parse_item(input)
  }
}

fn parse_item(input: BitArray) -> Result(#(Value, BitArray), Error) {
  use #(item, rest) <- result.try(parse_bare_item(input))
  use rest <- result.try(parse_parameters(rest))
  Ok(#(Item(item), rest))
}

fn parse_inner_list(input: BitArray) -> Result(#(Value, BitArray), Error) {
  case input {
    <<0x28, rest:bits>> -> parse_inner_list_members(rest)
    _ -> Error(Invalid)
  }
}

fn parse_inner_list_members(
  input: BitArray,
) -> Result(#(Value, BitArray), Error) {
  let input = discard_spaces(input)
  case input {
    <<0x29, rest:bits>> -> {
      use rest <- result.try(parse_parameters(rest))
      Ok(#(InnerList, rest))
    }
    <<>> -> Error(Invalid)
    _ -> {
      use #(_, rest) <- result.try(parse_item(input))
      case rest {
        <<0x20, _:bits>> | <<0x29, _:bits>> -> parse_inner_list_members(rest)
        _ -> Error(Invalid)
      }
    }
  }
}

fn parse_parameters(input: BitArray) -> Result(BitArray, Error) {
  case input {
    <<0x3b, rest:bits>> -> {
      let rest = discard_spaces(rest)
      use #(_, rest) <- result.try(parse_key(rest))
      use rest <- result.try(case rest {
        <<0x3d, value:bits>> -> {
          use #(_, rest) <- result.try(parse_bare_item(value))
          Ok(rest)
        }
        _ -> Ok(rest)
      })
      parse_parameters(rest)
    }
    _ -> Ok(input)
  }
}

fn parse_bare_item(input: BitArray) -> Result(#(BareItem, BitArray), Error) {
  case input {
    <<first, _:bits>> if first == 0x2d || { first >= 0x30 && first <= 0x39 } ->
      parse_number(input)
    <<0x22, _:bits>> -> parse_string(input)
    <<first, _:bits>>
      if { first >= 0x61 && first <= 0x7a }
      || { first >= 0x41 && first <= 0x5a }
      || first == 0x2a
    -> parse_token(input)
    <<0x3a, _:bits>> -> parse_byte_sequence(input)
    <<0x3f, _:bits>> -> parse_boolean(input)
    <<0x40, rest:bits>> -> {
      use #(value, rest) <- result.try(parse_number(rest))
      case value {
        Integer(_) -> Ok(#(Other, rest))
        _ -> Error(Invalid)
      }
    }
    <<0x25, _:bits>> -> parse_display_string(input)
    _ -> Error(Invalid)
  }
}

fn parse_number(input: BitArray) -> Result(#(BareItem, BitArray), Error) {
  let #(negative, input) = case input {
    <<0x2d, rest:bits>> -> #(True, rest)
    _ -> #(False, input)
  }
  let #(whole_digits, integer, rest) =
    consume_digits(input: input, count: 0, value: 0)
  case whole_digits, rest {
    0, _ -> Error(Invalid)
    count, <<0x2e, fraction:bits>> if count <= 12 -> {
      let #(fraction_digits, _, rest) =
        consume_digits(input: fraction, count: 0, value: 0)
      case
        fraction_digits >= 1
        && fraction_digits <= 3
        && whole_digits + fraction_digits + 1 <= 16
      {
        True -> Ok(#(Other, rest))
        False -> Error(Invalid)
      }
    }
    count, _ if count <= 15 -> {
      let integer = case negative {
        True -> 0 - integer
        False -> integer
      }
      Ok(#(Integer(integer), rest))
    }
    _, _ -> Error(Invalid)
  }
}

fn consume_digits(
  input input: BitArray,
  count count: Int,
  value value: Int,
) -> #(Int, Int, BitArray) {
  case input {
    <<byte, rest:bits>> if byte >= 0x30 && byte <= 0x39 ->
      consume_digits(
        input: rest,
        count: count + 1,
        value: value * 10 + byte - 0x30,
      )
    _ -> #(count, value, input)
  }
}

fn parse_string(input: BitArray) -> Result(#(BareItem, BitArray), Error) {
  case input {
    <<0x22, rest:bits>> -> parse_string_bytes(rest)
    _ -> Error(Invalid)
  }
}

fn parse_string_bytes(input: BitArray) -> Result(#(BareItem, BitArray), Error) {
  case input {
    <<0x22, rest:bits>> -> Ok(#(Other, rest))
    <<0x5c, escaped, rest:bits>> if escaped == 0x22 || escaped == 0x5c ->
      parse_string_bytes(rest)
    <<0x5c, _:bits>> -> Error(Invalid)
    <<byte, rest:bits>> if byte >= 0x20 && byte <= 0x7e ->
      parse_string_bytes(rest)
    _ -> Error(Invalid)
  }
}

fn parse_token(input: BitArray) -> Result(#(BareItem, BitArray), Error) {
  case input {
    <<first, rest:bits>>
      if { first >= 0x61 && first <= 0x7a }
      || { first >= 0x41 && first <= 0x5a }
      || first == 0x2a
    -> Ok(#(Other, consume_token_bytes(rest)))
    _ -> Error(Invalid)
  }
}

fn consume_token_bytes(input: BitArray) -> BitArray {
  case input {
    <<byte, rest:bits>> ->
      case is_token_character(byte) {
        True -> consume_token_bytes(rest)
        False -> input
      }
    _ -> input
  }
}

fn parse_byte_sequence(
  input: BitArray,
) -> Result(#(BareItem, BitArray), Error) {
  case input {
    <<0x3a, rest:bits>> -> parse_byte_sequence_bytes(rest, [])
    _ -> Error(Invalid)
  }
}

fn parse_byte_sequence_bytes(
  input: BitArray,
  encoded: List(BitArray),
) -> Result(#(BareItem, BitArray), Error) {
  case input {
    <<0x3a, rest:bits>> -> {
      let encoded = encoded |> list.reverse() |> bit_array.concat()
      use encoded <- result.try(bit_array.to_string(encoded) |> map_nil_error)
      case bit_array.base64_decode(encoded) {
        Ok(_) -> Ok(#(Other, rest))
        Error(_) -> Error(Invalid)
      }
    }
    <<byte, rest:bits>> ->
      case is_base64_character(byte) {
        True -> parse_byte_sequence_bytes(rest, [<<byte>>, ..encoded])
        False -> Error(Invalid)
      }
    _ -> Error(Invalid)
  }
}

fn parse_boolean(input: BitArray) -> Result(#(BareItem, BitArray), Error) {
  case input {
    <<0x3f, 0x31, rest:bits>> -> Ok(#(Boolean(True), rest))
    <<0x3f, 0x30, rest:bits>> -> Ok(#(Boolean(False), rest))
    _ -> Error(Invalid)
  }
}

fn parse_display_string(
  input: BitArray,
) -> Result(#(BareItem, BitArray), Error) {
  case input {
    <<0x25, 0x22, rest:bits>> -> parse_display_string_bytes(rest, [])
    _ -> Error(Invalid)
  }
}

fn parse_display_string_bytes(
  input: BitArray,
  decoded: List(BitArray),
) -> Result(#(BareItem, BitArray), Error) {
  case input {
    <<0x22, rest:bits>> -> {
      let decoded = decoded |> list.reverse() |> bit_array.concat()
      case bit_array.is_utf8(decoded) {
        True -> Ok(#(Other, rest))
        False -> Error(Invalid)
      }
    }
    <<0x25, high, low, rest:bits>> ->
      case is_lower_hex(high) && is_lower_hex(low) {
        True -> {
          let decoded_byte = hex_value(high) * 16 + hex_value(low)
          parse_display_string_bytes(rest, [<<decoded_byte>>, ..decoded])
        }
        False -> Error(Invalid)
      }
    <<0x25, _:bits>> -> Error(Invalid)
    <<byte, rest:bits>> if byte >= 0x20 && byte <= 0x7e ->
      parse_display_string_bytes(rest, [<<byte>>, ..decoded])
    _ -> Error(Invalid)
  }
}

fn parse_key(input: BitArray) -> Result(#(String, BitArray), Error) {
  case input {
    <<first, rest:bits>>
      if { first >= 0x61 && first <= 0x7a } || first == 0x2a
    -> parse_key_tail(rest, [<<first>>])
    _ -> Error(Invalid)
  }
}

fn parse_key_tail(
  input: BitArray,
  reversed: List(BitArray),
) -> Result(#(String, BitArray), Error) {
  case input {
    <<byte, rest:bits>> ->
      case is_key_character(byte) {
        True -> parse_key_tail(rest, [<<byte>>, ..reversed])
        False -> finish_key(input, reversed)
      }
    _ -> finish_key(input, reversed)
  }
}

fn finish_key(
  input: BitArray,
  reversed: List(BitArray),
) -> Result(#(String, BitArray), Error) {
  let key = reversed |> list.reverse() |> bit_array.concat()
  use key <- result.try(bit_array.to_string(key) |> map_nil_error)
  Ok(#(key, input))
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

fn is_lower_hex(byte: Int) -> Bool {
  is_digit(byte) || { byte >= 0x61 && byte <= 0x66 }
}

fn hex_value(byte: Int) -> Int {
  case is_digit(byte) {
    True -> byte - 0x30
    False -> byte - 0x61 + 10
  }
}

fn map_nil_error(value: Result(value, Nil)) -> Result(value, Error) {
  case value {
    Ok(value) -> Ok(value)
    Error(_) -> Error(Invalid)
  }
}

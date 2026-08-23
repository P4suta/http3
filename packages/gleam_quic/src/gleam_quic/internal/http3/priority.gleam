//// RFC 9218 priority fields and HTTP/3 PRIORITY_UPDATE frames.

import gleam/bit_array
import gleam/int
import gleam/list
import gleam/option.{type Option, None, Some}
import gleam/result
import gleam/string
import gleam_quic/internal/http3/frame
import gleam_quic/varint

const request_update_type = 0xf0700

const push_update_type = 0xf0701

/// Effective RFC 9218 priority parameters.
pub type Priority {
  Priority(urgency: Int, incremental: Bool)
}

/// Target and complete priority value carried by PRIORITY_UPDATE.
pub type Update {
  RequestUpdate(stream_id: Int, priority: Priority)
  PushUpdate(push_id: Int, priority: Priority)
}

/// Invalid Structured Field, frame payload, identifier, or configured bound.
pub type Error {
  NonByteAligned
  NonAscii
  InvalidLimit
  FieldValueTooLarge(Int)
  InvalidDictionary
  DuplicateParameter(String)
  InvalidElementId(Int)
  NotPriorityUpdate
  Truncated
  FrameFailure(frame.Error)
  IntegerFailure(varint.Error)
}

/// RFC defaults: urgency 3 and non-incremental delivery.
pub fn default() -> Priority {
  Priority(3, False)
}

/// Parse a bounded Priority Structured Field dictionary. Unknown or
/// wrong-typed priority parameters are ignored as required by RFC 9218.
pub fn parse(value: BitArray, maximum_bytes: Int) -> Result(Priority, Error) {
  use _ <- result.try(validate_field_input(value, maximum_bytes))
  case bit_array.to_string(value) {
    Error(_) -> Error(NonAscii)
    Ok(text) -> parse_members(string.split(text, ","), [], default())
  }
}

/// Encode the effective priority as a deterministic Structured Field value.
pub fn encode(priority: Priority) -> Result(BitArray, Error) {
  use _ <- result.try(validate_priority(priority))
  let Priority(urgency, incremental) = priority
  let encoded = case incremental {
    True -> "u=" <> int.to_string(urgency) <> ", i"
    False -> "u=" <> int.to_string(urgency)
  }
  Ok(<<encoded:utf8>>)
}

/// Construct an HTTP/3 extension frame carrying a priority update.
pub fn to_frame(update: Update) -> Result(frame.Frame, Error) {
  let #(frame_type, identifier, priority) = case update {
    RequestUpdate(identifier, priority) -> #(
      request_update_type,
      identifier,
      priority,
    )
    PushUpdate(identifier, priority) -> #(
      push_update_type,
      identifier,
      priority,
    )
  }
  use _ <- result.try(validate_element_id(frame_type, identifier))
  use identifier <- result.try(varint.encode(identifier) |> map_integer_result)
  use priority <- result.try(encode(priority))
  Ok(frame.Unknown(frame_type, <<identifier:bits, priority:bits>>))
}

/// Encode a complete PRIORITY_UPDATE frame for the control stream.
pub fn encode_update(update: Update) -> Result(BitArray, Error) {
  use outgoing <- result.try(to_frame(update))
  frame.encode(outgoing) |> map_frame_result
}

/// Decode one already parsed HTTP/3 extension frame.
pub fn from_frame(
  incoming: frame.Frame,
  maximum_field_value_bytes: Int,
) -> Result(Update, Error) {
  case incoming {
    frame.Unknown(frame_type, payload)
      if frame_type == request_update_type || frame_type == push_update_type
    -> {
      use #(identifier, priority_value) <- result.try(decode_integer(payload))
      use _ <- result.try(validate_element_id(frame_type, identifier))
      use priority <- result.try(parse(
        priority_value,
        maximum_field_value_bytes,
      ))
      case frame_type {
        value if value == request_update_type ->
          Ok(RequestUpdate(identifier, priority))
        _ -> Ok(PushUpdate(identifier, priority))
      }
    }
    _ -> Error(NotPriorityUpdate)
  }
}

fn parse_members(
  members: List(String),
  seen: List(String),
  priority: Priority,
) -> Result(Priority, Error) {
  case members {
    [] -> Ok(priority)
    [member, ..rest] -> {
      let member = string.trim(member)
      use #(key, value) <- result.try(parse_member(member))
      use _ <- result.try(case list.contains(seen, key) {
        True -> Error(DuplicateParameter(key))
        False -> Ok(Nil)
      })
      use priority <- result.try(apply_member(priority, key, value))
      parse_members(rest, [key, ..seen], priority)
    }
  }
}

// nolint: deep_nesting -- one bounded member validates its item and parameters in wire order.
fn parse_member(member: String) -> Result(#(String, Option(String)), Error) {
  case member {
    "" -> Error(InvalidDictionary)
    _ -> {
      let item_and_parameters = string.split(member, ";")
      use item <- result.try(first(item_and_parameters))
      use _ <- result.try(validate_parameters(drop_first(item_and_parameters)))
      case
        string.split_once(string.trim(item), on: "=")
        |> result.map(Some)
        |> result.unwrap(None)
      {
        None -> {
          let key = string.trim(item)
          use _ <- result.try(validate_key(key))
          Ok(#(key, None))
        }
        Some(#(key, value)) -> {
          let key = string.trim(key)
          let value = string.trim(value)
          use _ <- result.try(validate_key(key))
          case value {
            "" -> Error(InvalidDictionary)
            _ -> Ok(#(key, Some(value)))
          }
        }
      }
    }
  }
}

// nolint: deep_nesting -- every parameter is validated before recursive continuation.
fn validate_parameters(parameters: List(String)) -> Result(Nil, Error) {
  case parameters {
    [] -> Ok(Nil)
    [parameter, ..rest] -> {
      let parameter = string.trim(parameter)
      let split =
        string.split_once(parameter, on: "=")
        |> result.map(Some)
        |> result.unwrap(None)
      use _ <- result.try(case split {
        None -> validate_key(parameter)
        Some(#(key, value)) -> {
          use _ <- result.try(validate_key(string.trim(key)))
          case string.trim(value) {
            "" -> Error(InvalidDictionary)
            _ -> Ok(Nil)
          }
        }
      })
      validate_parameters(rest)
    }
  }
}

fn apply_member(
  priority: Priority,
  key: String,
  value: Option(String),
) -> Result(Priority, Error) {
  case key, value {
    "u", Some(encoded) ->
      case decimal_integer(encoded) {
        Some(urgency) if urgency >= 0 && urgency <= 7 ->
          Ok(Priority(..priority, urgency: urgency))
        _ -> Ok(priority)
      }
    "u", None -> Ok(priority)
    "i", None -> Ok(Priority(..priority, incremental: True))
    "i", Some("?1") -> Ok(Priority(..priority, incremental: True))
    "i", Some("?0") -> Ok(Priority(..priority, incremental: False))
    "i", Some(_) -> Ok(priority)
    _, _ -> Ok(priority)
  }
}

fn decimal_integer(encoded: String) -> Option(Int) {
  let bytes = <<encoded:utf8>>
  case valid_integer_bytes(bytes, True), int.parse(encoded) {
    True, Ok(value) -> Some(value)
    _, _ -> None
  }
}

fn valid_integer_bytes(value: BitArray, first: Bool) -> Bool {
  case value, first {
    <<>>, _ -> False
    <<0x2d, rest:bits>>, True -> all_digits(rest, False)
    _, _ -> all_digits(value, False)
  }
}

fn all_digits(value: BitArray, seen: Bool) -> Bool {
  case value {
    <<>> -> seen
    <<byte, rest:bits>> if byte >= 48 && byte <= 57 -> all_digits(rest, True)
    _ -> False
  }
}

fn validate_key(key: String) -> Result(Nil, Error) {
  case <<key:utf8>> {
    <<first, rest:bits>> if { first >= 97 && first <= 122 } || first == 0x2a ->
      validate_key_tail(rest)
    _ -> Error(InvalidDictionary)
  }
}

fn validate_key_tail(value: BitArray) -> Result(Nil, Error) {
  case value {
    <<>> -> Ok(Nil)
    <<byte, rest:bits>>
      if { byte >= 97 && byte <= 122 }
      || { byte >= 48 && byte <= 57 }
      || byte == 0x5f
      || byte == 0x2d
      || byte == 0x2e
      || byte == 0x2a
    -> validate_key_tail(rest)
    _ -> Error(InvalidDictionary)
  }
}

fn validate_field_input(
  value: BitArray,
  maximum_bytes: Int,
) -> Result(Nil, Error) {
  case maximum_bytes >= 0, bit_array.bit_size(value) % 8 {
    False, _ -> Error(InvalidLimit)
    _, remainder if remainder != 0 -> Error(NonByteAligned)
    True, _ ->
      case bit_array.byte_size(value) > maximum_bytes {
        True -> Error(FieldValueTooLarge(maximum_bytes))
        False -> validate_ascii(value)
      }
  }
}

fn validate_ascii(value: BitArray) -> Result(Nil, Error) {
  case value {
    <<>> -> Ok(Nil)
    <<byte, rest:bits>> if byte <= 0x7f -> validate_ascii(rest)
    _ -> Error(NonAscii)
  }
}

fn validate_priority(priority: Priority) -> Result(Nil, Error) {
  case priority.urgency >= 0 && priority.urgency <= 7 {
    True -> Ok(Nil)
    False -> Error(InvalidDictionary)
  }
}

fn validate_element_id(frame_type: Int, identifier: Int) -> Result(Nil, Error) {
  case
    identifier >= 0 && identifier <= varint.maximum,
    frame_type == request_update_type
  {
    False, _ -> Error(InvalidElementId(identifier))
    True, True if identifier % 4 != 0 -> Error(InvalidElementId(identifier))
    True, _ -> Ok(Nil)
  }
}

fn first(values: List(value)) -> Result(value, Error) {
  case values {
    [value, ..] -> Ok(value)
    [] -> Error(InvalidDictionary)
  }
}

fn drop_first(values: List(value)) -> List(value) {
  case values {
    [_, ..rest] -> rest
    [] -> []
  }
}

fn decode_integer(bytes: BitArray) -> Result(#(Int, BitArray), Error) {
  case varint.decode(bytes) {
    Ok(decoded) -> Ok(decoded)
    Error(varint.Truncated) -> Error(Truncated)
    Error(error) -> Error(IntegerFailure(error))
  }
}

fn map_integer_result(
  encoded: Result(BitArray, varint.Error),
) -> Result(BitArray, Error) {
  case encoded {
    Ok(value) -> Ok(value)
    Error(error) -> Error(IntegerFailure(error))
  }
}

fn map_frame_result(value: Result(value, frame.Error)) -> Result(value, Error) {
  case value {
    Ok(encoded) -> Ok(encoded)
    Error(error) -> Error(FrameFailure(error))
  }
}

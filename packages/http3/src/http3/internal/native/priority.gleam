//// RFC 9218 priority fields and HTTP/3 PRIORITY_UPDATE frames.

import gleam/bit_array
import gleam/int
import gleam/result
import http3/internal/native/frame
import http3/internal/structured_fields
import http3/internal/varint

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

/// Whether an extension frame type is one of the two PRIORITY_UPDATE types.
pub fn is_update_frame_type(frame_type: Int) -> Bool {
  frame_type == request_update_type || frame_type == push_update_type
}

/// Parse a bounded Priority Structured Field dictionary. Unknown or
/// wrong-typed priority parameters are ignored as required by RFC 9218.
pub fn parse(value: BitArray, maximum_bytes: Int) -> Result(Priority, Error) {
  use _ <- result.try(validate_field_input(value, maximum_bytes))
  case structured_fields.parse_dictionary(value) {
    Ok(members) -> apply_members(members, default())
    Error(_) -> Error(InvalidDictionary)
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

fn apply_members(
  members: List(structured_fields.Member),
  priority: Priority,
) -> Result(Priority, Error) {
  case members {
    [] -> Ok(priority)
    [member, ..rest] -> {
      let priority = case member {
        structured_fields.Member(
          "u",
          structured_fields.Item(structured_fields.Integer(urgency)),
        )
          if urgency >= 0 && urgency <= 7
        -> Priority(..priority, urgency: urgency)
        structured_fields.Member("u", _) -> Priority(..priority, urgency: 3)
        structured_fields.Member(
          "i",
          structured_fields.Item(structured_fields.Boolean(incremental)),
        ) -> Priority(..priority, incremental: incremental)
        structured_fields.Member("i", _) ->
          Priority(..priority, incremental: False)
        _ -> priority
      }
      apply_members(rest, priority)
    }
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

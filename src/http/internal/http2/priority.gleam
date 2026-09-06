//// RFC 9218 priority fields and bounded HTTP/2 PRIORITY_UPDATE frames.

import gleam/bit_array
import gleam/bool
import gleam/int
import gleam/result
import http/internal/http2/frame
import http/internal/structured_fields

const maximum_stream_id = 0x7fff_ffff

/// Effective RFC 9218 priority parameters.
pub type Priority {
  Priority(urgency: Int, incremental: Bool)
}

/// Target stream and complete priority value carried by PRIORITY_UPDATE.
pub type Update {
  Update(stream_id: Int, priority: Priority)
}

/// Invalid Structured Field, frame envelope, target, or configured bound.
pub type Error {
  NonByteAligned
  NonAscii
  InvalidLimit
  FieldValueTooLarge(maximum: Int)
  InvalidDictionary
  InvalidFrameType
  InvalidStreamIdentifier
  InvalidPrioritizedStream
  InvalidPayloadLength
  FrameFailure(frame.Error)
}

/// RFC defaults: urgency 3 and non-incremental delivery.
pub fn default() -> Priority {
  Priority(3, False)
}

/// Parse a bounded Priority Structured Field dictionary. Unknown or
/// wrong-typed parameters are ignored, and duplicate keys use their last value.
pub fn parse(
  value value: BitArray,
  maximum_bytes maximum_bytes: Int,
) -> Result(Priority, Error) {
  use _ <- result.try(validate_field_input(value, maximum_bytes))
  case structured_fields.parse_dictionary(value) {
    Ok(members) -> apply_members(members, default())
    Error(_) -> Error(InvalidDictionary)
  }
}

/// Encode effective priority values deterministically.
pub fn encode(priority priority: Priority) -> Result(BitArray, Error) {
  use _ <- result.try(validate_priority(priority))
  let Priority(urgency, incremental) = priority
  let encoded = case incremental {
    True -> "u=" <> int.to_string(urgency) <> ", i"
    False -> "u=" <> int.to_string(urgency)
  }
  Ok(<<encoded:utf8>>)
}

/// Decode one HTTP/2 PRIORITY_UPDATE frame payload.
pub fn decode(
  header header: frame.Header,
  payload payload: BitArray,
  maximum_field_value_bytes maximum_field_value_bytes: Int,
) -> Result(Update, Error) {
  let frame.Header(length, frame_type, _, stream_id) = header
  use _ <- result.try(case frame_type {
    frame.PriorityUpdate -> Ok(Nil)
    _ -> Error(InvalidFrameType)
  })
  use _ <- result.try(case stream_id {
    0 -> Ok(Nil)
    _ -> Error(InvalidStreamIdentifier)
  })
  use _ <- result.try(validate_payload(payload, length))
  case payload {
    <<_reserved:size(1), prioritized_stream_id:size(31), value:bits>> -> {
      use _ <- result.try(validate_prioritized_stream(prioritized_stream_id))
      use priority <- result.try(parse(
        value: value,
        maximum_bytes: maximum_field_value_bytes,
      ))
      Ok(Update(prioritized_stream_id, priority))
    }
    _ -> Error(InvalidPayloadLength)
  }
}

/// Encode one complete PRIORITY_UPDATE frame on stream zero.
pub fn encode_update(
  update update: Update,
  maximum_frame_bytes maximum_frame_bytes: Int,
) -> Result(BitArray, Error) {
  let Update(stream_id, priority) = update
  use _ <- result.try(validate_prioritized_stream(stream_id))
  use encoded <- result.try(encode(priority: priority))
  frame.encode(
    frame.PriorityUpdate,
    0,
    0,
    <<0:size(1), stream_id:size(31), encoded:bits>>,
    maximum_frame_bytes,
  )
  |> result.map_error(FrameFailure)
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
        True -> Error(FieldValueTooLarge(maximum: maximum_bytes))
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
  use <- bool.guard(
    when: priority.urgency < 0 || priority.urgency > 7,
    return: Error(InvalidDictionary),
  )
  Ok(Nil)
}

fn validate_prioritized_stream(stream_id: Int) -> Result(Nil, Error) {
  use <- bool.guard(
    when: stream_id <= 0 || stream_id > maximum_stream_id,
    return: Error(InvalidPrioritizedStream),
  )
  Ok(Nil)
}

fn validate_payload(
  payload: BitArray,
  expected_length: Int,
) -> Result(Nil, Error) {
  case
    bit_array.bit_size(payload) % 8,
    bit_array.byte_size(payload) == expected_length,
    bit_array.byte_size(payload) >= 4
  {
    remainder, _, _ if remainder != 0 -> Error(NonByteAligned)
    _, False, _ | _, _, False -> Error(InvalidPayloadLength)
    _, True, True -> Ok(Nil)
  }
}

//// Bounded RFC 9114 HTTP/3 frame and SETTINGS codec.

import gleam/bit_array
import gleam/list
import gleam/option.{type Option, None, Some}
import gleam/result
import gleam_quic/varint

/// One SETTINGS identifier/value pair. Unknown identifiers are preserved.
pub type Setting {
  Setting(identifier: Int, value: Int)
}

/// HTTP/3 frames, including extension frames unknown to this implementation.
pub type Frame {
  Data(BitArray)
  Headers(BitArray)
  CancelPush(push_id: Int)
  Settings(List(Setting))
  PushPromise(push_id: Int, field_section: BitArray)
  GoAway(identifier: Int)
  MaxPushId(push_id: Int)
  Unknown(frame_type: Int, payload: BitArray)
}

/// Peer-controlled allocation and iteration bounds.
pub type Limits {
  Limits(
    maximum_payload_bytes: Int,
    maximum_field_section_bytes: Int,
    maximum_settings: Int,
  )
}

/// Invalid, truncated, prohibited, duplicated, or over-limit frame input.
pub type Error {
  NonByteAligned
  InvalidLimits
  Truncated
  InvalidFrame
  ProhibitedHttp2FrameType(Int)
  DuplicateSetting(Int)
  ProhibitedSetting(Int)
  PayloadLimitExceeded(Int)
  FieldSectionLimitExceeded(Int)
  SettingsLimitExceeded(Int)
  IntegerFailure(varint.Error)
}

/// Conservative defaults for one HTTP/3 stream parser.
pub fn default_limits() -> Limits {
  Limits(
    maximum_payload_bytes: 16_777_216,
    maximum_field_section_bytes: 1_048_576,
    maximum_settings: 256,
  )
}

/// Decode one complete frame while preserving following stream bytes.
pub fn decode(
  bytes: BitArray,
  limits: Limits,
) -> Result(#(Frame, BitArray), Error) {
  use _ <- result.try(validate_input(bytes, limits))
  use #(frame_type, rest) <- result.try(decode_integer(bytes))
  use #(length, payload_and_rest) <- result.try(decode_integer(rest))
  use #(payload, remaining) <- result.try(take_payload(
    payload_and_rest,
    length,
    limits.maximum_payload_bytes,
  ))
  use decoded <- result.try(decode_payload(frame_type, payload, limits))
  Ok(#(decoded, remaining))
}

/// Encode one deterministic HTTP/3 frame.
pub fn encode(value: Frame) -> Result(BitArray, Error) {
  use #(frame_type, payload) <- result.try(encode_payload(value))
  use encoded_type <- result.try(encode_integer(frame_type))
  use encoded_length <- result.try(encode_integer(bit_array.byte_size(payload)))
  Ok(<<encoded_type:bits, encoded_length:bits, payload:bits>>)
}

fn validate_input(bytes: BitArray, limits: Limits) -> Result(Nil, Error) {
  case bit_array.bit_size(bytes) % 8 {
    remainder if remainder != 0 -> Error(NonByteAligned)
    _ ->
      case
        limits.maximum_payload_bytes >= 0
        && limits.maximum_field_section_bytes >= 0
        && limits.maximum_field_section_bytes <= limits.maximum_payload_bytes
        && limits.maximum_settings > 0
      {
        True -> Ok(Nil)
        False -> Error(InvalidLimits)
      }
  }
}

fn decode_payload(
  frame_type: Int,
  payload: BitArray,
  limits: Limits,
) -> Result(Frame, Error) {
  case frame_type {
    0 -> Ok(Data(payload))
    1 -> decode_field_section(payload, limits, Headers)
    2 | 6 | 8 | 9 -> Error(ProhibitedHttp2FrameType(frame_type))
    3 -> decode_single_integer(payload, CancelPush)
    4 -> decode_settings(payload, limits)
    5 -> decode_push_promise(payload, limits)
    7 -> decode_single_integer(payload, GoAway)
    13 -> decode_single_integer(payload, MaxPushId)
    _ -> Ok(Unknown(frame_type, payload))
  }
}

fn decode_field_section(
  payload: BitArray,
  limits: Limits,
  constructor: fn(BitArray) -> Frame,
) -> Result(Frame, Error) {
  case bit_array.byte_size(payload) > limits.maximum_field_section_bytes {
    True -> Error(FieldSectionLimitExceeded(limits.maximum_field_section_bytes))
    False -> Ok(constructor(payload))
  }
}

fn decode_single_integer(
  payload: BitArray,
  constructor: fn(Int) -> Frame,
) -> Result(Frame, Error) {
  use #(value, rest) <- result.try(decode_integer(payload))
  case rest {
    <<>> -> Ok(constructor(value))
    _ -> Error(InvalidFrame)
  }
}

fn decode_push_promise(
  payload: BitArray,
  limits: Limits,
) -> Result(Frame, Error) {
  use #(push_id, field_section) <- result.try(decode_integer(payload))
  case bit_array.byte_size(field_section) > limits.maximum_field_section_bytes {
    True -> Error(FieldSectionLimitExceeded(limits.maximum_field_section_bytes))
    False -> Ok(PushPromise(push_id, field_section))
  }
}

fn decode_settings(payload: BitArray, limits: Limits) -> Result(Frame, Error) {
  use settings <- result.try(
    decode_setting_entries(payload, limits.maximum_settings, []),
  )
  Ok(Settings(settings))
}

fn decode_setting_entries(
  payload: BitArray,
  remaining_entries: Int,
  reversed: List(Setting),
) -> Result(List(Setting), Error) {
  case payload, remaining_entries {
    <<>>, _ -> Ok(list.reverse(reversed))
    _, 0 -> Error(SettingsLimitExceeded(list.length(reversed)))
    _, _ -> {
      use #(identifier, rest) <- result.try(decode_integer(payload))
      use #(value, rest) <- result.try(decode_integer(rest))
      use _ <- result.try(validate_setting(identifier, reversed))
      decode_setting_entries(rest, remaining_entries - 1, [
        Setting(identifier, value),
        ..reversed
      ])
    }
  }
}

fn validate_setting(
  identifier: Int,
  existing: List(Setting),
) -> Result(Nil, Error) {
  case identifier {
    2 | 3 | 4 | 5 -> Error(ProhibitedSetting(identifier))
    _ ->
      case find_setting(existing, identifier) {
        Some(_) -> Error(DuplicateSetting(identifier))
        None -> Ok(Nil)
      }
  }
}

fn find_setting(settings: List(Setting), identifier: Int) -> Option(Int) {
  case settings {
    [] -> None
    [Setting(current, value), ..rest] ->
      case current == identifier {
        True -> Some(value)
        False -> find_setting(rest, identifier)
      }
  }
}

fn encode_payload(value: Frame) -> Result(#(Int, BitArray), Error) {
  case value {
    Data(payload) -> aligned_payload(0, payload)
    Headers(field_section) -> aligned_payload(1, field_section)
    CancelPush(push_id) -> encode_integer_payload(3, push_id)
    Settings(settings) -> {
      use payload <- result.try(encode_settings(settings, [], <<>>))
      Ok(#(4, payload))
    }
    PushPromise(push_id, field_section) -> {
      use push_id <- result.try(encode_integer(push_id))
      use #(_, field_section) <- result.try(aligned_payload(1, field_section))
      Ok(#(5, <<push_id:bits, field_section:bits>>))
    }
    GoAway(identifier) -> encode_integer_payload(7, identifier)
    MaxPushId(push_id) -> encode_integer_payload(13, push_id)
    Unknown(frame_type, payload) ->
      case frame_type >= 0 && frame_type <= varint.maximum {
        False -> Error(InvalidFrame)
        True -> aligned_payload(frame_type, payload)
      }
  }
}

fn aligned_payload(
  frame_type: Int,
  payload: BitArray,
) -> Result(#(Int, BitArray), Error) {
  case bit_array.bit_size(payload) % 8 {
    0 -> Ok(#(frame_type, payload))
    _ -> Error(NonByteAligned)
  }
}

fn encode_integer_payload(
  frame_type: Int,
  value: Int,
) -> Result(#(Int, BitArray), Error) {
  use payload <- result.try(encode_integer(value))
  Ok(#(frame_type, payload))
}

fn encode_settings(
  settings: List(Setting),
  encoded_identifiers: List(Setting),
  accumulator: BitArray,
) -> Result(BitArray, Error) {
  case settings {
    [] -> Ok(accumulator)
    [Setting(identifier, value) as setting, ..rest] -> {
      use _ <- result.try(validate_setting(identifier, encoded_identifiers))
      use identifier <- result.try(encode_integer(identifier))
      use value <- result.try(encode_integer(value))
      encode_settings(rest, [setting, ..encoded_identifiers], <<
        accumulator:bits,
        identifier:bits,
        value:bits,
      >>)
    }
  }
}

fn take_payload(
  bytes: BitArray,
  length: Int,
  maximum: Int,
) -> Result(#(BitArray, BitArray), Error) {
  case length > maximum, length > bit_array.byte_size(bytes) {
    True, _ -> Error(PayloadLimitExceeded(maximum))
    _, True -> Error(Truncated)
    False, False -> {
      let bit_length = length * 8
      case bytes {
        <<payload:bits-size(bit_length), rest:bits>> -> Ok(#(payload, rest))
        _ -> Error(Truncated)
      }
    }
  }
}

fn decode_integer(bytes: BitArray) -> Result(#(Int, BitArray), Error) {
  case varint.decode(bytes) {
    Ok(decoded) -> Ok(decoded)
    Error(varint.Truncated) -> Error(Truncated)
    Error(error) -> Error(IntegerFailure(error))
  }
}

fn encode_integer(value: Int) -> Result(BitArray, Error) {
  case varint.encode(value) {
    Ok(encoded) -> Ok(encoded)
    Error(error) -> Error(IntegerFailure(error))
  }
}

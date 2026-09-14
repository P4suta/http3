//// Lossless HTTP/2 SETTINGS payload encoding and decoding.

import gleam/bit_array
import gleam/list
import gleam/result

const maximum_uint32 = 0xffff_ffff

const maximum_initial_window_size = 0x7fff_ffff

const minimum_frame_size = 0x4000

const maximum_frame_size = 0xff_ffff

/// One typed HTTP/2 setting, including unregistered identifiers.
pub type Setting {
  HeaderTableSize(Int)
  EnablePush(Bool)
  MaxConcurrentStreams(Int)
  InitialWindowSize(Int)
  MaxFrameSize(Int)
  MaxHeaderListSize(Int)
  EnableConnectProtocol(Bool)
  NoRfc7540Priorities(Bool)
  Unknown(identifier: Int, value: Int)
}

/// A SETTINGS payload failure.
pub type Error {
  NonByteAligned
  InvalidPayloadLength
  InvalidIdentifier
  InvalidValue(identifier: Int)
}

/// Decode an ordered SETTINGS payload without discarding unknown parameters.
pub fn decode(payload: BitArray) -> Result(List(Setting), Error) {
  case bit_array.bit_size(payload) % 8, bit_array.byte_size(payload) % 6 {
    remainder, _ if remainder != 0 -> Error(NonByteAligned)
    _, remainder if remainder != 0 -> Error(InvalidPayloadLength)
    _, _ -> decode_entries(payload, [])
  }
}

/// Encode an ordered SETTINGS payload after validating every value.
pub fn encode(values: List(Setting)) -> Result(BitArray, Error) {
  use chunks <- result.try(list.try_map(values, encode_one))
  Ok(bit_array.concat(chunks))
}

fn decode_entries(
  payload: BitArray,
  reversed: List(Setting),
) -> Result(List(Setting), Error) {
  case payload {
    <<>> -> Ok(list.reverse(reversed))
    <<identifier:size(16), value:size(32), rest:bytes>> -> {
      use setting <- result.try(from_wire(identifier, value))
      decode_entries(rest, [setting, ..reversed])
    }
    _ -> Error(InvalidPayloadLength)
  }
}

fn from_wire(identifier: Int, value: Int) -> Result(Setting, Error) {
  case identifier {
    1 -> bounded_value(identifier, value, maximum_uint32, HeaderTableSize)
    2 -> boolean_value(identifier, value, EnablePush)
    3 -> bounded_value(identifier, value, maximum_uint32, MaxConcurrentStreams)
    4 ->
      bounded_value(
        identifier,
        value,
        maximum_initial_window_size,
        InitialWindowSize,
      )
    5 ->
      case value >= minimum_frame_size && value <= maximum_frame_size {
        True -> Ok(MaxFrameSize(value))
        False -> Error(InvalidValue(identifier))
      }
    6 -> bounded_value(identifier, value, maximum_uint32, MaxHeaderListSize)
    8 -> boolean_value(identifier, value, EnableConnectProtocol)
    9 -> boolean_value(identifier, value, NoRfc7540Priorities)
    _ -> Ok(Unknown(identifier, value))
  }
}

fn encode_one(setting: Setting) -> Result(BitArray, Error) {
  use #(identifier, value) <- result.try(to_wire(setting))
  Ok(<<identifier:size(16), value:size(32)>>)
}

fn to_wire(setting: Setting) -> Result(#(Int, Int), Error) {
  case setting {
    HeaderTableSize(value) -> numeric_wire(1, value, maximum_uint32)
    EnablePush(enabled) -> Ok(#(2, boolean_integer(enabled)))
    MaxConcurrentStreams(value) -> numeric_wire(3, value, maximum_uint32)
    InitialWindowSize(value) ->
      numeric_wire(4, value, maximum_initial_window_size)
    MaxFrameSize(value) ->
      case value >= minimum_frame_size && value <= maximum_frame_size {
        True -> Ok(#(5, value))
        False -> Error(InvalidValue(5))
      }
    MaxHeaderListSize(value) -> numeric_wire(6, value, maximum_uint32)
    EnableConnectProtocol(enabled) -> Ok(#(8, boolean_integer(enabled)))
    NoRfc7540Priorities(enabled) -> Ok(#(9, boolean_integer(enabled)))
    Unknown(identifier, value) ->
      case
        identifier >= 0 && identifier <= 0xffff && !known_identifier(identifier)
      {
        False -> Error(InvalidIdentifier)
        True -> numeric_wire(identifier, value, maximum_uint32)
      }
  }
}

fn bounded_value(
  identifier: Int,
  value: Int,
  maximum: Int,
  construct: fn(Int) -> Setting,
) -> Result(Setting, Error) {
  case value >= 0 && value <= maximum {
    True -> Ok(construct(value))
    False -> Error(InvalidValue(identifier))
  }
}

fn boolean_value(
  identifier: Int,
  value: Int,
  construct: fn(Bool) -> Setting,
) -> Result(Setting, Error) {
  case value {
    0 -> Ok(construct(False))
    1 -> Ok(construct(True))
    _ -> Error(InvalidValue(identifier))
  }
}

fn numeric_wire(
  identifier: Int,
  value: Int,
  maximum: Int,
) -> Result(#(Int, Int), Error) {
  case value >= 0 && value <= maximum {
    True -> Ok(#(identifier, value))
    False -> Error(InvalidValue(identifier))
  }
}

fn boolean_integer(value: Bool) -> Int {
  case value {
    True -> 1
    False -> 0
  }
}

fn known_identifier(identifier: Int) -> Bool {
  case identifier {
    1 | 2 | 3 | 4 | 5 | 6 | 8 | 9 -> True
    _ -> False
  }
}

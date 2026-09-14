//// Incremental RFC 6455 framing for RFC 9220 WebSockets over HTTP/3.

import gleam/bit_array
import gleam/bool
import gleam/option.{type Option, None, Some}
import gleam/result

/// Which endpoint owns a frame encoder or decoder.
pub type Role {
  Client
  Server
}

/// An RFC 6455 frame opcode supported without extensions.
pub type Opcode {
  Continuation
  Text
  Binary
  Close
  Ping
  Pong
}

/// One decoded or to-be-encoded WebSocket frame.
pub type Frame {
  Frame(fin: Bool, opcode: Opcode, payload: BitArray)
}

/// A finite incremental frame decoder.
pub opaque type Decoder {
  Decoder(
    role: Role,
    maximum_payload_bytes: Int,
    maximum_buffered_bytes: Int,
    buffered: BitArray,
  )
}

/// Outcome of pulling one frame from an incremental decoder.
pub type Outcome {
  Ready(Decoder, Frame)
  NeedMore(Decoder)
}

/// Invalid framing, masking, length, or finite-buffer use.
pub type Error {
  InvalidLimit
  NonByteAligned
  BufferLimitExceeded(Int)
  PayloadLimitExceeded(Int)
  ReservedBits
  ReservedOpcode(Int)
  MaskRequired
  MaskForbidden
  InvalidLength
  FragmentedControl
  ControlPayloadTooLarge
  InvalidMask
}

type LengthOutcome {
  LengthReady(Int, BitArray)
  LengthNeedMore
  LengthError
}

@external(erlang, "http3_websocket_ffi", "mask")
fn apply_mask(payload: BitArray, key: BitArray) -> Result(BitArray, Nil)

@external(erlang, "http3_websocket_ffi", "random_mask")
fn random_mask() -> Result(BitArray, Nil)

/// Construct a decoder with finite payload and retained-buffer limits.
pub fn decoder(
  role: Role,
  maximum_payload_bytes: Int,
  maximum_buffered_bytes: Int,
) -> Result(Decoder, Error) {
  case
    maximum_payload_bytes > 0
    && maximum_buffered_bytes > 0
    && maximum_payload_bytes <= maximum_buffered_bytes
  {
    True ->
      Ok(Decoder(role, maximum_payload_bytes, maximum_buffered_bytes, <<>>))
    False -> Error(InvalidLimit)
  }
}

/// Append one byte-aligned transport chunk without exceeding retained memory.
pub fn push(decoder: Decoder, bytes: BitArray) -> Result(Decoder, Error) {
  use <- bool.guard(
    when: bit_array.bit_size(bytes) % 8 != 0,
    return: Error(NonByteAligned),
  )
  let total = bit_array.byte_size(decoder.buffered) + bit_array.byte_size(bytes)
  use <- bool.guard(
    when: total > decoder.maximum_buffered_bytes,
    return: Error(BufferLimitExceeded(decoder.maximum_buffered_bytes)),
  )
  Ok(Decoder(..decoder, buffered: <<decoder.buffered:bits, bytes:bits>>))
}

/// Return the number of bytes retained between transport reads.
pub fn buffered_bytes(decoder: Decoder) -> Int {
  bit_array.byte_size(decoder.buffered)
}

/// Pull one complete frame, retaining an incomplete suffix.
pub fn next(decoder: Decoder) -> Result(Outcome, Error) {
  case decoder.buffered {
    <<fin:1, reserved:3, opcode_value:4, masked:1, marker:7, rest:bits>> -> {
      use <- bool.guard(when: reserved != 0, return: Error(ReservedBits))
      use opcode <- result.try(decode_opcode(opcode_value))
      case parse_length(marker, rest) {
        LengthNeedMore -> Ok(NeedMore(decoder))
        LengthError -> Error(InvalidLength)
        LengthReady(length, payload_and_mask) ->
          decode_payload(decoder, fin, opcode, masked, length, payload_and_mask)
      }
    }
    _ -> Ok(NeedMore(decoder))
  }
}

fn decode_payload(
  decoder: Decoder,
  fin: Int,
  opcode: Opcode,
  masked: Int,
  length: Int,
  payload_and_mask: BitArray,
) -> Result(Outcome, Error) {
  use <- bool.guard(
    when: length > decoder.maximum_payload_bytes,
    return: Error(PayloadLimitExceeded(decoder.maximum_payload_bytes)),
  )
  use _ <- result.try(validate_control(opcode, fin == 1, length))
  use _ <- result.try(validate_mask(decoder.role, masked == 1))
  let mask_bytes = case masked {
    1 -> 4
    _ -> 0
  }
  case take(payload_and_mask, mask_bytes + length) {
    None -> Ok(NeedMore(decoder))
    Some(#(encoded, remaining)) -> {
      use payload <- result.try(case masked {
        0 -> Ok(encoded)
        _ -> unmask(encoded, length)
      })
      Ok(Ready(
        Decoder(..decoder, buffered: remaining),
        Frame(fin == 1, opcode, payload),
      ))
    }
  }
}

fn unmask(encoded: BitArray, length: Int) -> Result(BitArray, Error) {
  case encoded {
    <<key:bits-size(32), payload:bits>> ->
      case bit_array.byte_size(payload) == length {
        True -> apply_mask(payload, key) |> result.replace_error(InvalidMask)
        False -> Error(InvalidMask)
      }
    _ -> Error(InvalidMask)
  }
}

fn validate_mask(role: Role, masked: Bool) -> Result(Nil, Error) {
  case role, masked {
    Server, False -> Error(MaskRequired)
    Client, True -> Error(MaskForbidden)
    _, _ -> Ok(Nil)
  }
}

fn validate_control(
  opcode: Opcode,
  fin: Bool,
  length: Int,
) -> Result(Nil, Error) {
  case is_control(opcode), fin, length > 125 {
    True, False, _ -> Error(FragmentedControl)
    True, _, True -> Error(ControlPayloadTooLarge)
    _, _, _ -> Ok(Nil)
  }
}

fn parse_length(marker: Int, bytes: BitArray) -> LengthOutcome {
  case marker {
    126 ->
      case bytes {
        <<length:size(16), rest:bits>> if length >= 126 ->
          LengthReady(length, rest)
        <<_:size(16), _rest:bits>> -> LengthError
        _ -> LengthNeedMore
      }
    127 ->
      case bytes {
        <<0:1, length:size(63), rest:bits>> if length >= 65_536 ->
          LengthReady(length, rest)
        <<_:size(64), _rest:bits>> -> LengthError
        _ -> LengthNeedMore
      }
    length -> LengthReady(length, bytes)
  }
}

fn decode_opcode(value: Int) -> Result(Opcode, Error) {
  case value {
    0 -> Ok(Continuation)
    1 -> Ok(Text)
    2 -> Ok(Binary)
    8 -> Ok(Close)
    9 -> Ok(Ping)
    10 -> Ok(Pong)
    value -> Error(ReservedOpcode(value))
  }
}

fn opcode_value(opcode: Opcode) -> Int {
  case opcode {
    Continuation -> 0
    Text -> 1
    Binary -> 2
    Close -> 8
    Ping -> 9
    Pong -> 10
  }
}

fn is_control(opcode: Opcode) -> Bool {
  case opcode {
    Close | Ping | Pong -> True
    Continuation | Text | Binary -> False
  }
}

/// Encode one frame, using a cryptographically random mask for a client.
pub fn encode(role: Role, frame: Frame) -> Result(BitArray, Error) {
  case role {
    Server -> encode_with_mask(frame, None)
    Client -> {
      use mask <- result.try(random_mask() |> result.replace_error(InvalidMask))
      encode_with_mask(frame, Some(mask))
    }
  }
}

/// Encode one frame with an explicit mask, primarily for deterministic tests.
pub fn encode_with_mask(
  frame: Frame,
  mask: Option(BitArray),
) -> Result(BitArray, Error) {
  let Frame(fin, opcode, payload) = frame
  use <- bool.guard(
    when: bit_array.bit_size(payload) % 8 != 0,
    return: Error(NonByteAligned),
  )
  use _ <- result.try(validate_control(
    opcode,
    fin,
    bit_array.byte_size(payload),
  ))
  use <- bool.guard(
    when: case mask {
      Some(value) -> bit_array.byte_size(value) != 4
      None -> False
    },
    return: Error(InvalidMask),
  )
  let first = case fin {
    True -> 128 + opcode_value(opcode)
    False -> opcode_value(opcode)
  }
  let length = bit_array.byte_size(payload)
  let #(marker, extended) = encoded_length(length)
  case mask {
    None -> Ok(<<first, marker, extended:bits, payload:bits>>)
    Some(key) -> {
      use masked <- result.try(
        apply_mask(payload, key) |> result.replace_error(InvalidMask),
      )
      let second = 128 + marker
      Ok(<<first, second, extended:bits, key:bits, masked:bits>>)
    }
  }
}

fn encoded_length(length: Int) -> #(Int, BitArray) {
  case length {
    value if value <= 125 -> #(value, <<>>)
    value if value <= 65_535 -> #(126, <<value:size(16)>>)
    value -> #(127, <<value:size(64)>>)
  }
}

fn take(bytes: BitArray, length: Int) -> Option(#(BitArray, BitArray)) {
  case length < 0 || length > bit_array.byte_size(bytes) {
    True -> None
    False -> {
      let bit_length = length * 8
      case bytes {
        <<value:bits-size(bit_length), rest:bits>> -> Some(#(value, rest))
        _ -> None
      }
    }
  }
}

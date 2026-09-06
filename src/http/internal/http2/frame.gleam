//// Bounded incremental HTTP/2 frame-envelope decoding.

import gleam/bit_array
import gleam/int
import gleam/result

const maximum_wire_frame_bytes = 0xff_ffff

/// The frame types registered by the HTTP/2 core protocol.
pub type FrameType {
  Data
  Headers
  Priority
  RstStream
  Settings
  PushPromise
  Ping
  GoAway
  WindowUpdate
  Continuation
  Origin
  PriorityUpdate
  Unknown(Int)
}

/// One validated HTTP/2 frame header.
pub type Header {
  Header(length: Int, frame_type: FrameType, flags: Int, stream_id: Int)
}

/// An opaque decoder retaining at most one bounded incomplete frame.
pub opaque type Decoder {
  Decoder(maximum_frame_bytes: Int, buffered: BitArray)
}

/// Incremental decoding progress for exactly one frame.
pub type Outcome {
  NeedMore(Decoder)
  FrameReady(Header, payload: BitArray, remaining: BitArray)
}

/// A frame-envelope or finite-resource failure.
pub type Error {
  InvalidLimit
  NonByteAligned
  FrameTooLarge(maximum: Int)
  InvalidFrameType
  InvalidFlags
  InvalidStreamIdentifier
  InvalidPayloadLength
}

/// Construct an empty decoder with a finite inbound frame-size limit.
pub fn decoder(maximum_frame_bytes: Int) -> Result(Decoder, Error) {
  case
    maximum_frame_bytes > 0 && maximum_frame_bytes <= maximum_wire_frame_bytes
  {
    True -> Ok(Decoder(maximum_frame_bytes, <<>>))
    False -> Error(InvalidLimit)
  }
}

/// Append bytes and decode at most one HTTP/2 frame.
///
/// The reserved stream bit is deliberately ignored on receipt, as required by
/// HTTP/2. Bytes following a complete frame are returned untouched.
pub fn feed(decoder: Decoder, bytes: BitArray) -> Result(Outcome, Error) {
  case bit_array.bit_size(bytes) % 8 {
    remainder if remainder != 0 -> Error(NonByteAligned)
    _ ->
      decode(
        Decoder(..decoder, buffered: <<decoder.buffered:bits, bytes:bits>>),
      )
  }
}

/// Encode one frame after applying the same envelope validation as decoding.
pub fn encode(
  frame_type: FrameType,
  flags: Int,
  stream_id: Int,
  payload: BitArray,
  maximum_frame_bytes: Int,
) -> Result(BitArray, Error) {
  use _ <- result.try(decoder(maximum_frame_bytes))
  use _ <- result.try(require(
    bit_array.bit_size(payload) % 8 == 0,
    NonByteAligned,
  ))
  use _ <- result.try(require(flags >= 0 && flags <= 0xff, InvalidFlags))
  use raw_type <- result.try(wire_frame_type(frame_type))
  let length = bit_array.byte_size(payload)
  use _ <- result.try(validate_header(
    length,
    frame_type,
    flags,
    stream_id,
    maximum_frame_bytes,
  ))
  Ok(<<
    length:size(24),
    raw_type,
    flags,
    0:size(1),
    stream_id:size(31),
    payload:bits,
  >>)
}

fn decode(decoder: Decoder) -> Result(Outcome, Error) {
  case decoder.buffered {
    <<
      length:size(24),
      raw_type,
      flags,
      _reserved:size(1),
      stream_id:size(31),
      after_header:bytes,
    >> -> {
      let frame_type = frame_type(raw_type)
      use _ <- result.try(validate_header(
        length,
        frame_type,
        flags,
        stream_id,
        decoder.maximum_frame_bytes,
      ))
      decode_payload(
        decoder,
        length,
        frame_type,
        flags,
        stream_id,
        after_header,
      )
    }
    _ -> Ok(NeedMore(decoder))
  }
}

fn decode_payload(
  decoder: Decoder,
  length: Int,
  frame_type: FrameType,
  flags: Int,
  stream_id: Int,
  bytes: BitArray,
) -> Result(Outcome, Error) {
  case bit_array.byte_size(bytes) < length {
    True -> Ok(NeedMore(decoder))
    False -> {
      use payload <- result.try(
        bit_array.slice(bytes, at: 0, take: length)
        |> result.replace_error(InvalidPayloadLength),
      )
      use remaining <- result.try(
        bit_array.slice(
          bytes,
          at: length,
          take: bit_array.byte_size(bytes) - length,
        )
        |> result.replace_error(InvalidPayloadLength),
      )
      Ok(FrameReady(
        Header(length:, frame_type:, flags:, stream_id:),
        payload,
        remaining,
      ))
    }
  }
}

fn validate_header(
  length: Int,
  frame_type: FrameType,
  flags: Int,
  stream_id: Int,
  maximum_frame_bytes: Int,
) -> Result(Nil, Error) {
  use _ <- result.try(require(
    stream_id >= 0 && stream_id <= 0x7fff_ffff,
    InvalidStreamIdentifier,
  ))
  use _ <- result.try(require(
    length <= maximum_frame_bytes,
    FrameTooLarge(maximum_frame_bytes),
  ))
  use _ <- result.try(valid_stream_identifier(frame_type, stream_id))
  valid_payload_length(frame_type, flags, length)
}

fn valid_stream_identifier(
  frame_type: FrameType,
  stream_id: Int,
) -> Result(Nil, Error) {
  let valid = case frame_type {
    Data | Headers | Priority | RstStream | PushPromise | Continuation ->
      stream_id != 0
    Settings | Ping | GoAway | PriorityUpdate -> stream_id == 0
    WindowUpdate | Origin | Unknown(_) -> True
  }
  require(valid, InvalidStreamIdentifier)
}

fn valid_payload_length(
  frame_type: FrameType,
  flags: Int,
  length: Int,
) -> Result(Nil, Error) {
  let valid = case frame_type {
    Priority -> length == 5
    RstStream | WindowUpdate -> length == 4
    Settings ->
      case int.bitwise_and(flags, 0x1) == 0 {
        True -> length % 6 == 0
        False -> length == 0
      }
    Ping -> length == 8
    GoAway -> length >= 8
    PushPromise -> length >= 4
    PriorityUpdate -> length >= 4
    Data | Headers | Continuation | Origin | Unknown(_) -> True
  }
  require(valid, InvalidPayloadLength)
}

fn frame_type(raw: Int) -> FrameType {
  case raw {
    0 -> Data
    1 -> Headers
    2 -> Priority
    3 -> RstStream
    4 -> Settings
    5 -> PushPromise
    6 -> Ping
    7 -> GoAway
    8 -> WindowUpdate
    9 -> Continuation
    0x0c -> Origin
    0x10 -> PriorityUpdate
    value -> Unknown(value)
  }
}

fn wire_frame_type(frame_type: FrameType) -> Result(Int, Error) {
  case frame_type {
    Data -> Ok(0)
    Headers -> Ok(1)
    Priority -> Ok(2)
    RstStream -> Ok(3)
    Settings -> Ok(4)
    PushPromise -> Ok(5)
    Ping -> Ok(6)
    GoAway -> Ok(7)
    WindowUpdate -> Ok(8)
    Continuation -> Ok(9)
    Origin -> Ok(0x0c)
    PriorityUpdate -> Ok(0x10)
    Unknown(value)
      if value >= 10 && value <= 0xff && value != 0x0c && value != 0x10
    -> Ok(value)
    Unknown(_) -> Error(InvalidFrameType)
  }
}

fn require(condition: Bool, failure: Error) -> Result(Nil, Error) {
  case condition {
    True -> Ok(Nil)
    False -> Error(failure)
  }
}

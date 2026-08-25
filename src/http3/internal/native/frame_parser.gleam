//// Bounded incremental parser for HTTP/3 framed streams.

import gleam/bit_array
import http3/internal/native/frame

/// Unread stream bytes and fixed frame/parser limits.
pub opaque type State {
  State(
    buffered: BitArray,
    frame_limits: frame.Limits,
    maximum_buffered_bytes: Int,
  )
}

/// Parser needs another chunk or produced one complete frame.
pub type Outcome {
  NeedMore(State)
  FrameReady(State, frame.Frame)
}

/// Configuration, buffer, framing, or truncated clean-end failure.
pub type Error {
  InvalidConfiguration
  NonByteAligned
  BufferLimitExceeded(Int)
  TruncatedFrame
  FrameFailure(frame.Error)
}

/// Start one parser. The buffer bound includes the largest permitted frame
/// header as well as its payload and any following bytes in the same chunk.
pub fn new(
  frame_limits: frame.Limits,
  maximum_buffered_bytes: Int,
) -> Result(State, Error) {
  case frame_limits, maximum_buffered_bytes {
    frame.Limits(maximum_payload, maximum_fields, maximum_settings), maximum
      if maximum_payload >= 0
      && maximum_fields >= 0
      && maximum_fields <= maximum_payload
      && maximum_settings > 0
      && maximum >= maximum_payload + 16
    -> Ok(State(<<>>, frame_limits, maximum))
    _, _ -> Error(InvalidConfiguration)
  }
}

/// Append in-order stream bytes.
pub fn push(state: State, bytes: BitArray) -> Result(State, Error) {
  case bit_array.bit_size(bytes) % 8 {
    remainder if remainder != 0 -> Error(NonByteAligned)
    _ -> {
      let size =
        bit_array.byte_size(state.buffered) + bit_array.byte_size(bytes)
      case size > state.maximum_buffered_bytes {
        True -> Error(BufferLimitExceeded(state.maximum_buffered_bytes))
        False ->
          Ok(State(..state, buffered: <<state.buffered:bits, bytes:bits>>))
      }
    }
  }
}

/// Parse at most one complete frame.
pub fn next(state: State) -> Result(Outcome, Error) {
  case state.buffered {
    <<>> -> Ok(NeedMore(state))
    _ ->
      case frame.decode(state.buffered, state.frame_limits) {
        Ok(#(decoded, rest)) ->
          Ok(FrameReady(State(..state, buffered: rest), decoded))
        Error(frame.Truncated) -> Ok(NeedMore(state))
        Error(error) -> Error(FrameFailure(error))
      }
  }
}

/// A clean stream end cannot bisect a frame.
pub fn finish(state: State) -> Result(Nil, Error) {
  case state.buffered {
    <<>> -> Ok(Nil)
    _ -> Error(TruncatedFrame)
  }
}

/// Bytes retained across incremental calls.
pub fn buffered_bytes(state: State) -> Int {
  bit_array.byte_size(state.buffered)
}

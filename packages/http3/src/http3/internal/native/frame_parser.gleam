//// Bounded incremental parser for HTTP/3 framed streams.

import gleam/bit_array
import gleam/int
import gleam/option.{type Option, None, Some}
import gleam/result
import http3/internal/native/frame
import http3/internal/varint

type Delivery {
  WholeFrames
  StreamingData(maximum_chunk_bytes: Int)
}

/// Unread stream bytes and fixed frame/parser limits.
pub opaque type State {
  State(
    buffered: BitArray,
    frame_limits: frame.Limits,
    maximum_buffered_bytes: Int,
    delivery: Delivery,
    remaining_data_bytes: Int,
    declared_data_bytes: Int,
    completed_data_frame: Option(Int),
  )
}

/// Parser needs another chunk, produced a complete frame, or delivered a bounded portion of DATA when constructed with `new_streaming`.
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

/// Start one parser.
/// The buffer bound includes the largest permitted frame header as well as its payload and any following bytes in the same chunk.
pub fn new(
  frame_limits: frame.Limits,
  maximum_buffered_bytes: Int,
) -> Result(State, Error) {
  case frame_limits, maximum_buffered_bytes {
    frame.Limits(
      maximum_payload,
      maximum_fields,
      maximum_settings,
      maximum_origins,
    ),
      maximum
      if maximum_payload >= 0
      && maximum_fields >= 0
      && maximum_fields <= maximum_payload
      && maximum_settings > 0
      && maximum_origins > 0
      && maximum >= maximum_payload + 16
    -> Ok(State(<<>>, frame_limits, maximum, WholeFrames, 0, 0, None))
    _, _ -> Error(InvalidConfiguration)
  }
}

/// Stream DATA independently of its declared frame length.
/// Only received bytes count toward the buffer bound; the remaining length is one QUIC varint.
/// Every DATA delivery is bounded by `maximum_data_chunk_bytes`.
/// Other frames retain the complete-frame limits supplied to `new`.
pub fn new_streaming(
  frame_limits: frame.Limits,
  maximum_buffered_bytes: Int,
  maximum_data_chunk_bytes: Int,
) -> Result(State, Error) {
  use state <- result.try(new(frame_limits, maximum_buffered_bytes))
  case maximum_data_chunk_bytes {
    maximum if maximum > 0 && maximum <= maximum_buffered_bytes ->
      Ok(State(..state, delivery: StreamingData(maximum)))
    _ -> Error(InvalidConfiguration)
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

/// Parse at most one complete frame or bounded DATA portion.
/// A caller can consume each DATA delivery and return transport credit before frame FIN.
pub fn next(state: State) -> Result(Outcome, Error) {
  let state = State(..state, completed_data_frame: None)
  case state.delivery, state.remaining_data_bytes {
    StreamingData(maximum), remaining if remaining > 0 ->
      next_data(state, maximum)
    StreamingData(maximum), _ -> next_streaming_frame(state, maximum)
    WholeFrames, _ -> next_whole_frame(state)
  }
}

fn next_streaming_frame(state: State, maximum: Int) -> Result(Outcome, Error) {
  case varint.decode(state.buffered) {
    Error(varint.Truncated) -> Ok(NeedMore(state))
    Error(error) -> Error(FrameFailure(frame.IntegerFailure(error)))
    Ok(#(0, after_type)) ->
      case varint.decode(after_type) {
        Error(varint.Truncated) -> Ok(NeedMore(state))
        Error(error) -> Error(FrameFailure(frame.IntegerFailure(error)))
        Ok(#(0, rest)) ->
          Ok(FrameReady(
            State(..state, buffered: rest, completed_data_frame: Some(0)),
            frame.Data(<<>>),
          ))
        Ok(#(length, rest)) ->
          next_data(
            State(
              ..state,
              buffered: rest,
              remaining_data_bytes: length,
              declared_data_bytes: length,
            ),
            maximum,
          )
      }
    Ok(_) -> next_whole_frame(state)
  }
}

fn next_data(state: State, maximum: Int) -> Result(Outcome, Error) {
  let length =
    int.min(state.remaining_data_bytes, bit_array.byte_size(state.buffered))
    |> int.min(maximum)
  case state.buffered, length {
    _, 0 -> Ok(NeedMore(state))
    <<chunk:bytes-size(length), rest:bits>>, _ ->
      Ok(FrameReady(
        State(
          ..state,
          buffered: rest,
          remaining_data_bytes: state.remaining_data_bytes - length,
          completed_data_frame: case state.remaining_data_bytes == length {
            True -> Some(state.declared_data_bytes)
            False -> None
          },
        ),
        frame.Data(chunk),
      ))
    _, _ -> Error(TruncatedFrame)
  }
}

fn next_whole_frame(state: State) -> Result(Outcome, Error) {
  case state.buffered {
    <<>> -> Ok(NeedMore(state))
    _ ->
      case frame.decode(state.buffered, state.frame_limits) {
        Ok(#(decoded, rest)) ->
          Ok(FrameReady(State(..state, buffered: rest), decoded))
        Error(frame.Truncated) ->
          case complete_frame_is_buffered(state.buffered) {
            True -> Error(FrameFailure(frame.Truncated))
            False -> Ok(NeedMore(state))
          }
        Error(error) -> Error(FrameFailure(error))
      }
  }
}

fn complete_frame_is_buffered(bytes: BitArray) -> Bool {
  let complete = {
    use #(_, after_type) <- result.try(varint.decode(bytes))
    use #(length, payload) <- result.try(varint.decode(after_type))
    Ok(bit_array.byte_size(payload) >= length)
  }
  result.unwrap(complete, False)
}

/// A clean stream end cannot bisect a frame.
pub fn finish(state: State) -> Result(Nil, Error) {
  case state.buffered, state.remaining_data_bytes {
    <<>>, 0 -> Ok(Nil)
    _, _ -> Error(TruncatedFrame)
  }
}

/// Bytes retained across incremental calls.
pub fn buffered_bytes(state: State) -> Int {
  bit_array.byte_size(state.buffered)
}

/// Payload length of the original wire DATA frame completed by the most recent `next` delivery.
/// Partial deliveries never count as additional wire frames.
pub fn completed_data_frame(state: State) -> Option(Int) {
  state.completed_data_frame
}

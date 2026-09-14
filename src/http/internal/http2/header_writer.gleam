//// Stateful HPACK encoding and bounded HEADERS/CONTINUATION framing.

import gleam/bit_array
import gleam/list
import gleam/result
import http/internal/http2/frame
import http/internal/http2/hpack/decoder.{type Header}
import http/internal/http2/hpack/encoder

const maximum_wire_frame_bytes = 0xff_ffff

const maximum_wire_integer = 0xffff_ffff

/// A successful field section and the next connection-scoped writer state.
pub type Encoded {
  Encoded(state: State, frames: List(BitArray))
}

/// Configuration, compression, envelope, or bounded slicing failure.
pub type Error {
  InvalidConfiguration
  InvalidFrameLimit
  InvalidStreamIdentifier
  CompressionFailure(encoder.Error)
  FrameFailure(frame.Error)
  SliceFailure
}

/// Opaque connection-scoped HPACK writer state.
pub opaque type State {
  State(encoder: encoder.Encoder)
}

/// Construct a finite writer.
pub fn new(
  maximum_table_capacity maximum_table_capacity: Int,
  maximum_header_list_bytes maximum_header_list_bytes: Int,
  prefer_huffman prefer_huffman: Bool,
) -> Result(State, Error) {
  case
    maximum_table_capacity >= 0
    && maximum_table_capacity <= maximum_wire_integer
    && maximum_header_list_bytes >= 0
    && maximum_header_list_bytes <= maximum_wire_integer
  {
    False -> Error(InvalidConfiguration)
    True ->
      encoder.new(
        maximum_table_capacity,
        maximum_header_list_bytes,
        prefer_huffman,
      )
      |> result.map(State)
      |> result.map_error(CompressionFailure)
  }
}

/// Apply a peer-advertised HPACK table capacity for the next block.
pub fn set_capacity(state: State, capacity: Int) -> Result(State, Error) {
  encoder.set_capacity(state.encoder, capacity)
  |> result.map(State)
  |> result.map_error(CompressionFailure)
}

/// Encode and split one field section into ordered wire frames.
pub fn encode(
  state: State,
  stream_id stream_id: Int,
  headers headers: List(Header),
  end_stream end_stream: Bool,
  maximum_frame_bytes maximum_frame_bytes: Int,
) -> Result(Encoded, Error) {
  use _ <- result.try(validate_envelope(stream_id, maximum_frame_bytes))
  use compressed <- result.try(
    encoder.encode(state.encoder, headers)
    |> result.map_error(CompressionFailure),
  )
  let encoder.Encoded(next_encoder, block) = compressed
  use frames <- result.try(
    encode_fragments(
      block,
      stream_id,
      end_stream,
      maximum_frame_bytes,
      True,
      [],
    ),
  )
  Ok(Encoded(State(next_encoder), frames))
}

fn encode_fragments(
  remaining: BitArray,
  stream_id: Int,
  end_stream: Bool,
  maximum_frame_bytes: Int,
  first: Bool,
  reversed_frames: List(BitArray),
) -> Result(List(BitArray), Error) {
  let remaining_bytes = bit_array.byte_size(remaining)
  case remaining_bytes <= maximum_frame_bytes {
    True -> {
      use encoded <- result.try(encode_fragment(
        remaining,
        stream_id,
        end_stream,
        maximum_frame_bytes,
        first,
        True,
      ))
      Ok(list.reverse([encoded, ..reversed_frames]))
    }
    False -> {
      use fragment <- result.try(slice(remaining, 0, maximum_frame_bytes))
      use rest <- result.try(slice(
        remaining,
        maximum_frame_bytes,
        remaining_bytes - maximum_frame_bytes,
      ))
      use encoded <- result.try(encode_fragment(
        fragment,
        stream_id,
        end_stream,
        maximum_frame_bytes,
        first,
        False,
      ))
      encode_fragments(rest, stream_id, end_stream, maximum_frame_bytes, False, [
        encoded,
        ..reversed_frames
      ])
    }
  }
}

fn encode_fragment(
  fragment: BitArray,
  stream_id: Int,
  end_stream: Bool,
  maximum_frame_bytes: Int,
  first: Bool,
  last: Bool,
) -> Result(BitArray, Error) {
  let frame_type = case first {
    True -> frame.Headers
    False -> frame.Continuation
  }
  let flags = end_stream_flag(first, end_stream) + end_headers_flag(last)
  frame.encode(frame_type, flags, stream_id, fragment, maximum_frame_bytes)
  |> result.map_error(FrameFailure)
}

fn validate_envelope(
  stream_id: Int,
  maximum_frame_bytes: Int,
) -> Result(Nil, Error) {
  case
    stream_id > 0 && stream_id <= 0x7fff_ffff,
    maximum_frame_bytes > 0 && maximum_frame_bytes <= maximum_wire_frame_bytes
  {
    False, _ -> Error(InvalidStreamIdentifier)
    _, False -> Error(InvalidFrameLimit)
    True, True -> Ok(Nil)
  }
}

fn slice(bytes: BitArray, at: Int, take: Int) -> Result(BitArray, Error) {
  bit_array.slice(bytes, at: at, take: take)
  |> result.replace_error(SliceFailure)
}

fn end_stream_flag(first: Bool, end_stream: Bool) -> Int {
  case first && end_stream {
    True -> 0x1
    False -> 0
  }
}

fn end_headers_flag(last: Bool) -> Int {
  case last {
    True -> 0x4
    False -> 0
  }
}

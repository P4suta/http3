//// Bounded HTTP/2 DATA framing under dual flow-control windows.

import gleam/bit_array
import gleam/list
import gleam/result
import http/internal/http2/frame

const maximum_wire_frame_bytes = 0xff_ffff

/// Progress after attempting to frame one application chunk.
pub type Outcome {
  Blocked
  Written(
    frames: List(BitArray),
    consumed: Int,
    remaining: BitArray,
    end_stream_sent: Bool,
  )
}

/// Input, envelope, or bounded slicing failure.
pub type Error {
  NonByteAligned
  InvalidStreamIdentifier
  InvalidFrameLimit
  InvalidCredit
  FrameFailure(frame.Error)
  SliceFailure
}

/// Frame as much data as both connection and stream credit permit.
pub fn encode(
  bytes: BitArray,
  stream_id stream_id: Int,
  end_stream end_stream: Bool,
  maximum_frame_bytes maximum_frame_bytes: Int,
  connection_credit connection_credit: Int,
  stream_credit stream_credit: Int,
) -> Result(Outcome, Error) {
  use _ <- result.try(validate(
    bytes,
    stream_id,
    maximum_frame_bytes,
    connection_credit,
    stream_credit,
  ))
  let byte_count = bit_array.byte_size(bytes)
  case byte_count {
    0 -> encode_empty(stream_id, end_stream, maximum_frame_bytes)
    _ -> {
      let permitted =
        smallest(byte_count, smallest(connection_credit, stream_credit))
      case permitted {
        0 -> Ok(Blocked)
        _ -> {
          use sendable <- result.try(slice(bytes, 0, permitted))
          use remaining <- result.try(slice(
            bytes,
            permitted,
            byte_count - permitted,
          ))
          let end_stream_sent = end_stream && permitted == byte_count
          use frames <- result.try(
            encode_fragments(
              sendable,
              stream_id,
              maximum_frame_bytes,
              end_stream_sent,
              [],
            ),
          )
          Ok(Written(frames, permitted, remaining, end_stream_sent))
        }
      }
    }
  }
}

fn encode_empty(
  stream_id: Int,
  end_stream: Bool,
  maximum_frame_bytes: Int,
) -> Result(Outcome, Error) {
  case end_stream {
    False -> Ok(Written([], 0, <<>>, False))
    True -> {
      use encoded <- result.try(encode_frame(
        stream_id,
        <<>>,
        True,
        maximum_frame_bytes,
      ))
      Ok(Written([encoded], 0, <<>>, True))
    }
  }
}

fn encode_fragments(
  remaining: BitArray,
  stream_id: Int,
  maximum_frame_bytes: Int,
  end_stream: Bool,
  reversed_frames: List(BitArray),
) -> Result(List(BitArray), Error) {
  let remaining_bytes = bit_array.byte_size(remaining)
  let take = smallest(remaining_bytes, maximum_frame_bytes)
  use fragment <- result.try(slice(remaining, 0, take))
  use rest <- result.try(slice(remaining, take, remaining_bytes - take))
  let last = take == remaining_bytes
  use encoded <- result.try(encode_frame(
    stream_id,
    fragment,
    last && end_stream,
    maximum_frame_bytes,
  ))
  case last {
    True -> Ok(list.reverse([encoded, ..reversed_frames]))
    False ->
      encode_fragments(rest, stream_id, maximum_frame_bytes, end_stream, [
        encoded,
        ..reversed_frames
      ])
  }
}

fn encode_frame(
  stream_id: Int,
  payload: BitArray,
  end_stream: Bool,
  maximum_frame_bytes: Int,
) -> Result(BitArray, Error) {
  let flags = case end_stream {
    True -> 0x1
    False -> 0
  }
  frame.encode(frame.Data, flags, stream_id, payload, maximum_frame_bytes)
  |> result.map_error(FrameFailure)
}

fn validate(
  bytes: BitArray,
  stream_id: Int,
  maximum_frame_bytes: Int,
  connection_credit: Int,
  stream_credit: Int,
) -> Result(Nil, Error) {
  case
    bit_array.bit_size(bytes) % 8,
    stream_id > 0 && stream_id <= 0x7fff_ffff,
    maximum_frame_bytes > 0 && maximum_frame_bytes <= maximum_wire_frame_bytes,
    connection_credit >= 0 && stream_credit >= 0
  {
    remainder, _, _, _ if remainder != 0 -> Error(NonByteAligned)
    _, False, _, _ -> Error(InvalidStreamIdentifier)
    _, _, False, _ -> Error(InvalidFrameLimit)
    _, _, _, False -> Error(InvalidCredit)
    0, True, True, True -> Ok(Nil)
    _, True, True, True -> Error(NonByteAligned)
  }
}

fn slice(bytes: BitArray, at: Int, take: Int) -> Result(BitArray, Error) {
  bit_array.slice(bytes, at: at, take: take)
  |> result.replace_error(SliceFailure)
}

fn smallest(first: Int, second: Int) -> Int {
  case first < second {
    True -> first
    False -> second
  }
}

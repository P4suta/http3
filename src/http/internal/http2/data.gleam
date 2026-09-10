//// HTTP/2 DATA payload parsing with exact flow-control accounting.

import gleam/bit_array
import gleam/int
import gleam/result
import http/internal/http2/frame

/// Application bytes and their distinct wire-level window consumption.
pub type Data {
  Data(bytes: BitArray, end_stream: Bool, flow_controlled_bytes: Int)
}

/// Envelope or padding failure.
pub type Error {
  NonByteAligned
  InvalidPayloadLength
  UnexpectedFrameType
  InvalidPadding
}

/// Decode one DATA payload. Padding and its length byte consume flow-control
/// window even though they are not returned as application bytes.
pub fn decode(header: frame.Header, payload: BitArray) -> Result(Data, Error) {
  use _ <- result.try(validate_payload(header, payload))
  let frame.Header(length, frame_type, flags, _) = header
  case frame_type {
    frame.Data -> {
      use bytes <- result.try(remove_padding(
        payload,
        int.bitwise_and(flags, 0x8) != 0,
      ))
      Ok(Data(
        bytes:,
        end_stream: int.bitwise_and(flags, 0x1) != 0,
        flow_controlled_bytes: length,
      ))
    }
    _ -> Error(UnexpectedFrameType)
  }
}

fn remove_padding(payload: BitArray, padded: Bool) -> Result(BitArray, Error) {
  case padded, payload {
    False, _ -> Ok(payload)
    True, <<padding, rest:bytes>> -> {
      let rest_bytes = bit_array.byte_size(rest)
      case padding > rest_bytes {
        True -> Error(InvalidPadding)
        False -> {
          let data_bytes = rest_bytes - padding
          case rest {
            <<data:bytes-size(data_bytes), _:bytes-size(padding)>> -> Ok(data)
            _ -> Error(InvalidPadding)
          }
        }
      }
    }
    True, _ -> Error(InvalidPadding)
  }
}

fn validate_payload(
  header: frame.Header,
  payload: BitArray,
) -> Result(Nil, Error) {
  let frame.Header(length, _, _, _) = header
  case bit_array.bit_size(payload) % 8 {
    remainder if remainder != 0 -> Error(NonByteAligned)
    _ ->
      case bit_array.byte_size(payload) == length {
        True -> Ok(Nil)
        False -> Error(InvalidPayloadLength)
      }
  }
}

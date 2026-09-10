//// Incremental HTTP/2 connection-preface validation and generation.

import gleam/bit_array
import gleam/result
import http/internal/http2/frame
import http/internal/http2/settings

const magic_bytes = <<"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n":utf8>>

/// An opaque server-side preface decoder retaining at most 23 bytes.
pub opaque type Decoder {
  Decoder(buffered: BitArray)
}

/// Incremental preface progress.
pub type Outcome {
  NeedMore(Decoder)
  Ready(remaining: BitArray)
}

/// Preface, settings, or frame-envelope failure.
pub type Error {
  NonByteAligned
  InvalidPreface
  SettingsFailure(settings.Error)
  FrameFailure(frame.Error)
}

/// Exact 24-byte client connection preface.
pub fn client_magic() -> BitArray {
  magic_bytes
}

/// Construct an empty server-side decoder.
pub fn server_decoder() -> Decoder {
  Decoder(<<>>)
}

/// Validate a server's incoming client magic incrementally and return any
/// bytes following it without consuming the first frame.
pub fn feed(decoder: Decoder, bytes: BitArray) -> Result(Outcome, Error) {
  case bit_array.bit_size(bytes) % 8 {
    remainder if remainder != 0 -> Error(NonByteAligned)
    _ -> validate_prefix(<<decoder.buffered:bits, bytes:bits>>)
  }
}

/// Generate the client magic immediately followed by initial SETTINGS.
pub fn client_initial_bytes(
  values: List(settings.Setting),
  maximum_frame_bytes: Int,
) -> Result(BitArray, Error) {
  case server_initial_bytes(values, maximum_frame_bytes) {
    Ok(initial_settings) -> Ok(<<magic_bytes:bits, initial_settings:bits>>)
    Error(failure) -> Error(failure)
  }
}

/// Generate a server's initial SETTINGS frame.
pub fn server_initial_bytes(
  values: List(settings.Setting),
  maximum_frame_bytes: Int,
) -> Result(BitArray, Error) {
  use payload <- result.try(map_settings(settings.encode(values)))
  frame.encode(frame.Settings, 0, 0, payload, maximum_frame_bytes)
  |> map_frame
}

fn validate_prefix(buffered: BitArray) -> Result(Outcome, Error) {
  let available = bit_array.byte_size(buffered)
  case available < 24 {
    True -> {
      let prefix_bits = available * 8
      case magic_bytes {
        <<expected:bits-size(prefix_bits), _:bits>> ->
          case buffered == expected {
            True -> Ok(NeedMore(Decoder(buffered)))
            False -> Error(InvalidPreface)
          }
        _ -> Error(InvalidPreface)
      }
    }
    False ->
      case buffered {
        <<candidate:bytes-size(24), rest:bits>> ->
          case candidate == magic_bytes {
            True -> Ok(Ready(rest))
            False -> Error(InvalidPreface)
          }
        _ -> Error(InvalidPreface)
      }
  }
}

fn map_settings(value: Result(value, settings.Error)) -> Result(value, Error) {
  case value {
    Ok(payload) -> Ok(payload)
    Error(failure) -> Error(SettingsFailure(failure))
  }
}

fn map_frame(value: Result(value, frame.Error)) -> Result(value, Error) {
  case value {
    Ok(encoded) -> Ok(encoded)
    Error(failure) -> Error(FrameFailure(failure))
  }
}

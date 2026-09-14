//// Typed HTTP/2 control-frame payload decoding.

import gleam/bit_array
import gleam/int
import gleam/result
import http/internal/http2/frame
import http/internal/http2/settings

/// One validated control-frame event.
pub type Event {
  SettingsFrame(List(settings.Setting))
  SettingsAcknowledgement
  PingFrame(acknowledgement: Bool, data: BitArray)
  GoAwayFrame(last_stream_id: Int, error_code: Int, debug_data: BitArray)
  PriorityFrame(exclusive: Bool, dependency: Int, weight: Int)
  ResetFrame(error_code: Int)
  WindowUpdateFrame(increment: Int)
}

/// Envelope, semantic, or finite-resource failure.
pub type Error {
  InvalidLimit
  NonByteAligned
  InvalidPayloadLength
  UnexpectedFrameType
  InvalidStreamIdentifier
  InvalidWeight
  InvalidErrorCode
  InvalidWindowIncrement
  DebugDataTooLarge(maximum: Int)
  ZeroWindowIncrement
  SelfDependency
  SettingsFailure(settings.Error)
  FrameFailure(frame.Error)
}

/// Decode one control payload after validating it against its frame envelope.
pub fn decode(
  header: frame.Header,
  payload: BitArray,
  maximum_debug_bytes: Int,
) -> Result(Event, Error) {
  use _ <- result.try(validate_payload(header, payload, maximum_debug_bytes))
  let frame.Header(_, frame_type, flags, stream_id) = header
  case frame_type {
    frame.Settings -> decode_settings(payload, flags)
    frame.Ping ->
      Ok(PingFrame(
        acknowledgement: int.bitwise_and(flags, 0x1) != 0,
        data: payload,
      ))
    frame.GoAway -> decode_goaway(payload, maximum_debug_bytes)
    frame.Priority -> decode_priority(payload, stream_id)
    frame.RstStream -> decode_reset(payload)
    frame.WindowUpdate -> decode_window_update(payload)
    _ -> Error(UnexpectedFrameType)
  }
}

/// Encode one typed control event in a validated HTTP/2 frame envelope.
pub fn encode(
  event: Event,
  stream_id: Int,
  maximum_frame_bytes: Int,
) -> Result(BitArray, Error) {
  case event {
    SettingsFrame(values) -> {
      use _ <- result.try(require_connection_stream(stream_id))
      use payload <- result.try(
        settings.encode(values)
        |> map_settings,
      )
      encode_frame(frame.Settings, 0, 0, payload, maximum_frame_bytes)
    }
    SettingsAcknowledgement -> {
      use _ <- result.try(require_connection_stream(stream_id))
      encode_frame(frame.Settings, 1, 0, <<>>, maximum_frame_bytes)
    }
    PingFrame(acknowledgement, data) -> {
      use _ <- result.try(require_connection_stream(stream_id))
      encode_frame(
        frame.Ping,
        bool_flag(acknowledgement),
        0,
        data,
        maximum_frame_bytes,
      )
    }
    GoAwayFrame(last_stream_id, error_code, debug_data) -> {
      use _ <- result.try(require_connection_stream(stream_id))
      use _ <- result.try(require_stream_range(last_stream_id))
      use _ <- result.try(require_error_code(error_code))
      encode_frame(
        frame.GoAway,
        0,
        0,
        <<
          0:size(1),
          last_stream_id:size(31),
          error_code:size(32),
          debug_data:bits,
        >>,
        maximum_frame_bytes,
      )
    }
    PriorityFrame(exclusive, dependency, weight) -> {
      use _ <- result.try(require_application_stream(stream_id))
      use _ <- result.try(require_stream_range(dependency))
      use _ <- result.try(require_priority(stream_id, dependency, weight))
      let exclusive_bit = bool_flag(exclusive)
      let wire_weight = weight - 1
      encode_frame(
        frame.Priority,
        0,
        stream_id,
        <<exclusive_bit:size(1), dependency:size(31), wire_weight>>,
        maximum_frame_bytes,
      )
    }
    ResetFrame(error_code) -> {
      use _ <- result.try(require_application_stream(stream_id))
      use _ <- result.try(require_error_code(error_code))
      encode_frame(
        frame.RstStream,
        0,
        stream_id,
        <<error_code:size(32)>>,
        maximum_frame_bytes,
      )
    }
    WindowUpdateFrame(increment) -> {
      use _ <- result.try(require_stream_range(stream_id))
      use _ <- result.try(require_window_increment(increment))
      encode_frame(
        frame.WindowUpdate,
        0,
        stream_id,
        <<0:size(1), increment:size(31)>>,
        maximum_frame_bytes,
      )
    }
  }
}

fn decode_settings(payload: BitArray, flags: Int) -> Result(Event, Error) {
  case int.bitwise_and(flags, 0x1) != 0 {
    True -> Ok(SettingsAcknowledgement)
    False ->
      case settings.decode(payload) {
        Ok(values) -> Ok(SettingsFrame(values))
        Error(failure) -> Error(SettingsFailure(failure))
      }
  }
}

fn decode_goaway(
  payload: BitArray,
  maximum_debug_bytes: Int,
) -> Result(Event, Error) {
  case payload {
    <<
      _reserved:size(1),
      last_stream_id:size(31),
      error_code:size(32),
      debug:bytes,
    >> ->
      case bit_array.byte_size(debug) > maximum_debug_bytes {
        True -> Error(DebugDataTooLarge(maximum_debug_bytes))
        False -> Ok(GoAwayFrame(last_stream_id, error_code, debug))
      }
    _ -> Error(InvalidPayloadLength)
  }
}

fn decode_priority(payload: BitArray, stream_id: Int) -> Result(Event, Error) {
  case payload {
    <<exclusive:size(1), dependency:size(31), weight>> ->
      case dependency == stream_id {
        True -> Error(SelfDependency)
        False -> Ok(PriorityFrame(exclusive == 1, dependency, weight + 1))
      }
    _ -> Error(InvalidPayloadLength)
  }
}

fn decode_reset(payload: BitArray) -> Result(Event, Error) {
  case payload {
    <<error_code:size(32)>> -> Ok(ResetFrame(error_code))
    _ -> Error(InvalidPayloadLength)
  }
}

fn decode_window_update(payload: BitArray) -> Result(Event, Error) {
  case payload {
    <<_reserved:size(1), increment:size(31)>> ->
      case increment {
        0 -> Error(ZeroWindowIncrement)
        _ -> Ok(WindowUpdateFrame(increment))
      }
    _ -> Error(InvalidPayloadLength)
  }
}

fn validate_payload(
  header: frame.Header,
  payload: BitArray,
  maximum_debug_bytes: Int,
) -> Result(Nil, Error) {
  let frame.Header(length, _, _, _) = header
  case
    bit_array.bit_size(payload) % 8,
    maximum_debug_bytes >= 0,
    bit_array.byte_size(payload) == length
  {
    remainder, _, _ if remainder != 0 -> Error(NonByteAligned)
    _, False, _ -> Error(InvalidLimit)
    _, _, False -> Error(InvalidPayloadLength)
    0, True, True -> Ok(Nil)
    _, True, True -> Error(NonByteAligned)
  }
}

fn encode_frame(
  frame_type: frame.FrameType,
  flags: Int,
  stream_id: Int,
  payload: BitArray,
  maximum_frame_bytes: Int,
) -> Result(BitArray, Error) {
  case
    frame.encode(frame_type, flags, stream_id, payload, maximum_frame_bytes)
  {
    Ok(encoded) -> Ok(encoded)
    Error(failure) -> Error(FrameFailure(failure))
  }
}

fn require_connection_stream(stream_id: Int) -> Result(Nil, Error) {
  case stream_id {
    0 -> Ok(Nil)
    _ -> Error(InvalidStreamIdentifier)
  }
}

fn require_application_stream(stream_id: Int) -> Result(Nil, Error) {
  case stream_id > 0 && stream_id <= 0x7fff_ffff {
    True -> Ok(Nil)
    False -> Error(InvalidStreamIdentifier)
  }
}

fn require_stream_range(stream_id: Int) -> Result(Nil, Error) {
  case stream_id >= 0 && stream_id <= 0x7fff_ffff {
    True -> Ok(Nil)
    False -> Error(InvalidStreamIdentifier)
  }
}

fn require_priority(
  stream_id: Int,
  dependency: Int,
  weight: Int,
) -> Result(Nil, Error) {
  case dependency == stream_id, weight >= 1 && weight <= 256 {
    True, _ -> Error(SelfDependency)
    _, False -> Error(InvalidWeight)
    False, True -> Ok(Nil)
  }
}

fn require_error_code(error_code: Int) -> Result(Nil, Error) {
  case error_code >= 0 && error_code <= 0xffff_ffff {
    True -> Ok(Nil)
    False -> Error(InvalidErrorCode)
  }
}

fn require_window_increment(increment: Int) -> Result(Nil, Error) {
  case increment {
    0 -> Error(ZeroWindowIncrement)
    value if value > 0 && value <= 0x7fff_ffff -> Ok(Nil)
    _ -> Error(InvalidWindowIncrement)
  }
}

fn map_settings(value: Result(value, settings.Error)) -> Result(value, Error) {
  case value {
    Ok(payload) -> Ok(payload)
    Error(failure) -> Error(SettingsFailure(failure))
  }
}

fn bool_flag(value: Bool) -> Int {
  case value {
    True -> 1
    False -> 0
  }
}

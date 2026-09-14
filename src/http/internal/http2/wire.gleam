//// Finite incremental HTTP/2 preface, frame, and connection driver.

import gleam/bit_array
import gleam/http/request.{type Request}
import gleam/http/response.{type Response}
import gleam/list
import gleam/option.{type Option, None, Some}
import gleam/result
import http/internal/http2/connection
import http/internal/http2/control
import http/internal/http2/frame
import http/internal/http2/origin
import http/internal/http2/preface
import http/internal/http2/settings

const maximum_wire_frame_bytes = 0xff_ffff

const maximum_feed_limit = 67_108_864

/// Per-call and retained wire parsing bounds.
pub type Limits {
  Limits(
    maximum_frame_bytes: Int,
    maximum_feed_bytes: Int,
    maximum_frames_per_feed: Int,
  )
}

/// Incremental input progress and all ordered connection actions it produced.
pub type Fed {
  Fed(state: State, actions: List(connection.Action))
}

/// Initial connection bytes and state carrying one SETTINGS acknowledgement debt.
pub type Started {
  Started(state: State, bytes: BitArray)
}

/// Outbound request frames and the same wire driver with advanced state.
pub type HeadersWritten {
  HeadersWritten(state: State, stream_id: Int, frames: List(BitArray))
}

/// Outbound DATA progress and the same wire driver with advanced state.
pub type DataWrite {
  DataBlocked(state: State)
  DataWritten(
    state: State,
    frames: List(BitArray),
    remaining: BitArray,
    end_stream_sent: Bool,
  )
}

/// WINDOW_UPDATE frames and the same wire driver with restored receive credit.
pub type ReceiveCreditReleased {
  ReceiveCreditReleased(state: State, frames: List(BitArray))
}

/// Encoded connection-control frames and the advanced wire state.
pub type ControlWritten {
  ControlWritten(state: State, frames: List(BitArray))
}

/// Configuration, preface, envelope, connection, or finite-work failure.
pub type Error {
  InvalidLimits
  AlreadyStarted
  ChunkTooLarge(maximum: Int)
  TooManyFrames(maximum: Int)
  PrefaceFailure(preface.Error)
  FrameFailure(frame.Error)
  ControlFailure(control.Error)
  ConnectionFailure(connection.Error)
}

/// Opaque pure state retaining one bounded preface or frame fragment.
pub opaque type State {
  State(
    role: connection.Role,
    limits: Limits,
    connection: connection.State,
    decoder: frame.Decoder,
    server_preface: Option(preface.Decoder),
    initial_bytes_sent: Bool,
  )
}

/// Construct a wire driver without sending bytes or owning a socket.
pub fn new(
  role: connection.Role,
  connection_limits: connection.Limits,
  limits: Limits,
) -> Result(State, Error) {
  new_with_capabilities(
    role,
    connection_limits,
    connection.Capabilities(extended_connect_enabled: False),
    limits,
  )
}

/// Construct a wire driver with explicit opt-in protocol capabilities.
pub fn new_with_capabilities(
  role: connection.Role,
  connection_limits: connection.Limits,
  capabilities: connection.Capabilities,
  limits: Limits,
) -> Result(State, Error) {
  use _ <- result.try(validate_limits(limits))
  let Limits(maximum_frame_bytes, _, _) = limits
  use decoder <- result.try(
    frame.decoder(maximum_frame_bytes)
    |> result.map_error(FrameFailure),
  )
  use connection <- result.try(
    connection.new_with_capabilities(role, connection_limits, capabilities)
    |> result.map_error(ConnectionFailure),
  )
  Ok(State(
    role: role,
    limits: limits,
    connection: connection,
    decoder: decoder,
    server_preface: case role {
      connection.Client -> None
      connection.Server -> Some(preface.server_decoder())
    },
    initial_bytes_sent: False,
  ))
}

/// Generate the role-specific preface and initial SETTINGS exactly once.
pub fn initial_bytes(
  state: State,
  values: List(settings.Setting),
) -> Result(Started, Error) {
  case state.initial_bytes_sent {
    True -> Error(AlreadyStarted)
    False -> {
      let Limits(maximum_frame_bytes, _, _) = state.limits
      use bytes <- result.try(
        case state.role {
          connection.Client ->
            preface.client_initial_bytes(values, maximum_frame_bytes)
          connection.Server ->
            preface.server_initial_bytes(values, maximum_frame_bytes)
        }
        |> result.map_error(PrefaceFailure),
      )
      use connection <- result.try(
        connection.record_settings_sent(state.connection)
        |> result.map_error(ConnectionFailure),
      )
      Ok(Started(
        State(..state, connection: connection, initial_bytes_sent: True),
        bytes,
      ))
    }
  }
}

/// Feed one bounded byte chunk and process at most the configured frame count.
pub fn feed(state: State, bytes: BitArray) -> Result(Fed, Error) {
  let Limits(_, maximum_feed_bytes, _) = state.limits
  case bit_array.byte_size(bytes) > maximum_feed_bytes {
    True -> Error(ChunkTooLarge(maximum: maximum_feed_bytes))
    False -> feed_preface(state, bytes)
  }
}

/// Inspect the pure protocol state without exposing a socket or backend term.
pub fn connection_state(state: State) -> connection.State {
  state.connection
}

/// Encode a standard request while retaining the advanced connection state.
pub fn send_request_headers(
  state: State,
  outgoing: Request(body),
  end_stream end_stream: Bool,
) -> Result(HeadersWritten, Error) {
  use written <- result.try(
    connection.send_request_headers(
      state.connection,
      outgoing,
      end_stream: end_stream,
    )
    |> result.map_error(ConnectionFailure),
  )
  let connection.HeadersWritten(connection, stream_id, frames) = written
  Ok(HeadersWritten(State(..state, connection: connection), stream_id, frames))
}

/// Encode an RFC 8441 Extended CONNECT after peer capability negotiation.
pub fn send_extended_connect_headers(
  state: State,
  outgoing: Request(body),
  protocol protocol: String,
) -> Result(HeadersWritten, Error) {
  use written <- result.try(
    connection.send_extended_connect_headers(
      state.connection,
      outgoing,
      protocol: protocol,
    )
    |> result.map_error(ConnectionFailure),
  )
  let connection.HeadersWritten(connection, stream_id, frames) = written
  Ok(HeadersWritten(State(..state, connection: connection), stream_id, frames))
}

/// Encode a standard response while retaining the advanced connection state.
pub fn send_response_headers(
  state: State,
  stream_id: Int,
  outgoing: Response(body),
  end_stream end_stream: Bool,
) -> Result(HeadersWritten, Error) {
  use written <- result.try(
    connection.send_response_headers(
      state.connection,
      stream_id,
      outgoing,
      end_stream: end_stream,
    )
    |> result.map_error(ConnectionFailure),
  )
  let connection.HeadersWritten(connection, stream_id, frames) = written
  Ok(HeadersWritten(State(..state, connection: connection), stream_id, frames))
}

/// Encode trailers on an existing stream while retaining advanced state.
pub fn send_trailers(
  state: State,
  stream_id: Int,
  trailers: List(#(String, String)),
) -> Result(HeadersWritten, Error) {
  use written <- result.try(
    connection.send_trailers(state.connection, stream_id, trailers)
    |> result.map_error(ConnectionFailure),
  )
  let connection.HeadersWritten(connection, stream_id, frames) = written
  Ok(HeadersWritten(State(..state, connection: connection), stream_id, frames))
}

/// Encode as much DATA as the current connection and stream credit permit.
pub fn send_data(
  state: State,
  stream_id stream_id: Int,
  bytes bytes: BitArray,
  end_stream end_stream: Bool,
) -> Result(DataWrite, Error) {
  use outcome <- result.try(
    connection.send_data(
      state.connection,
      stream_id: stream_id,
      bytes: bytes,
      end_stream: end_stream,
    )
    |> result.map_error(ConnectionFailure),
  )
  case outcome {
    connection.DataBlocked(connection) ->
      Ok(DataBlocked(State(..state, connection: connection)))
    connection.DataWritten(connection, frames, remaining, end_stream_sent) ->
      Ok(DataWritten(
        State(..state, connection: connection),
        frames,
        remaining,
        end_stream_sent,
      ))
  }
}

/// Return credit after the application has consumed inbound DATA.
pub fn release_receive_credit(
  state: State,
  stream_id stream_id: Int,
  octets octets: Int,
) -> Result(ReceiveCreditReleased, Error) {
  use released <- result.try(
    connection.release_receive_credit(
      state.connection,
      stream_id: stream_id,
      octets: octets,
    )
    |> result.map_error(ConnectionFailure),
  )
  let connection.ReceiveCreditReleased(connection, frames) = released
  Ok(ReceiveCreditReleased(State(..state, connection: connection), frames))
}

/// Reset one stream without disturbing any other active stream.
pub fn reset_stream(
  state: State,
  stream_id stream_id: Int,
  error_code error_code: Int,
) -> Result(ControlWritten, Error) {
  use written <- result.try(
    connection.reset_stream(state.connection, stream_id:, error_code:)
    |> result.map_error(ConnectionFailure),
  )
  let connection.ControlWritten(connection, frames) = written
  Ok(ControlWritten(State(..state, connection: connection), frames))
}

/// Encode a server ORIGIN advertisement through the typed connection state.
pub fn send_origins(
  state: State,
  origins: List(origin.Origin),
) -> Result(ControlWritten, Error) {
  use written <- result.try(
    connection.send_origins(state.connection, origins)
    |> result.map_error(ConnectionFailure),
  )
  let connection.ControlWritten(connection, frames) = written
  Ok(ControlWritten(State(..state, connection: connection), frames))
}

/// Begin graceful connection drain with GOAWAY and no error.
pub fn begin_drain(state: State) -> Result(ControlWritten, Error) {
  use written <- result.try(
    connection.begin_drain(state.connection, error_code: 0, debug_data: <<>>)
    |> result.map_error(ConnectionFailure),
  )
  let connection.ControlWritten(connection, frames) = written
  Ok(ControlWritten(State(..state, connection: connection), frames))
}

/// Encode mandatory SETTINGS and PING acknowledgements from ordered actions.
/// Application events deliberately produce no bytes.
pub fn automatic_writes(
  actions: List(connection.Action),
  maximum_frame_bytes: Int,
) -> Result(List(BitArray), Error) {
  automatic_writes_loop(actions, maximum_frame_bytes, [])
}

fn feed_preface(state: State, bytes: BitArray) -> Result(Fed, Error) {
  case state.server_preface {
    None -> feed_frames(state, state.decoder, bytes, 0, [])
    Some(decoder) -> {
      use outcome <- result.try(
        preface.feed(decoder, bytes)
        |> result.map_error(PrefaceFailure),
      )
      case outcome {
        preface.NeedMore(decoder) ->
          Ok(Fed(State(..state, server_preface: Some(decoder)), []))
        preface.Ready(remaining) ->
          feed_frames(
            State(..state, server_preface: None),
            state.decoder,
            remaining,
            0,
            [],
          )
      }
    }
  }
}

fn feed_frames(
  state: State,
  decoder: frame.Decoder,
  bytes: BitArray,
  processed: Int,
  reversed_actions: List(connection.Action),
) -> Result(Fed, Error) {
  use outcome <- result.try(
    frame.feed(decoder, bytes)
    |> result.map_error(FrameFailure),
  )
  case outcome {
    frame.NeedMore(decoder) ->
      Ok(Fed(State(..state, decoder: decoder), list.reverse(reversed_actions)))
    frame.FrameReady(header, payload, remaining) -> {
      let Limits(_, _, maximum_frames) = state.limits
      case processed >= maximum_frames {
        True -> Error(TooManyFrames(maximum: maximum_frames))
        False -> {
          use transition <- result.try(
            connection.receive_frame(state.connection, header, payload)
            |> result.map_error(ConnectionFailure),
          )
          let connection.Transition(connection, actions) = transition
          use next_decoder <- result.try(new_decoder(state.limits))
          feed_frames(
            State(..state, connection: connection, decoder: next_decoder),
            next_decoder,
            remaining,
            processed + 1,
            prepend_reversed(actions, reversed_actions),
          )
        }
      }
    }
  }
}

fn new_decoder(limits: Limits) -> Result(frame.Decoder, Error) {
  let Limits(maximum_frame_bytes, _, _) = limits
  frame.decoder(maximum_frame_bytes)
  |> result.map_error(FrameFailure)
}

fn validate_limits(limits: Limits) -> Result(Nil, Error) {
  let Limits(maximum_frame_bytes, maximum_feed_bytes, maximum_frames_per_feed) =
    limits
  case
    maximum_frame_bytes > 0
    && maximum_frame_bytes <= maximum_wire_frame_bytes
    && maximum_feed_bytes > 0
    && maximum_feed_bytes <= maximum_feed_limit
    && maximum_frames_per_feed > 0
  {
    True -> Ok(Nil)
    False -> Error(InvalidLimits)
  }
}

fn prepend_reversed(values: List(value), reversed: List(value)) -> List(value) {
  case values {
    [] -> reversed
    [value, ..rest] -> prepend_reversed(rest, [value, ..reversed])
  }
}

fn automatic_writes_loop(
  actions: List(connection.Action),
  maximum_frame_bytes: Int,
  reversed: List(BitArray),
) -> Result(List(BitArray), Error) {
  case actions {
    [] -> Ok(list.reverse(reversed))
    [connection.SendSettingsAcknowledgement, ..rest] -> {
      use encoded <- result.try(
        control.encode(control.SettingsAcknowledgement, 0, maximum_frame_bytes)
        |> result.map_error(ControlFailure),
      )
      automatic_writes_loop(rest, maximum_frame_bytes, [encoded, ..reversed])
    }
    [connection.SendPingAcknowledgement(data), ..rest] -> {
      use encoded <- result.try(
        control.encode(control.PingFrame(True, data), 0, maximum_frame_bytes)
        |> result.map_error(ControlFailure),
      )
      automatic_writes_loop(rest, maximum_frame_bytes, [encoded, ..reversed])
    }
    [_, ..rest] -> automatic_writes_loop(rest, maximum_frame_bytes, reversed)
  }
}

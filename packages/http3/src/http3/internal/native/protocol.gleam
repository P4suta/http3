//// Role-neutral HTTP/3 orchestration over an opaque QUIC resource adapter.
////
//// This module owns HTTP/3, QPACK, and incremental parsing only.
//// The caller supplies closures over its public `quic_core/client` or `quic_core/server` connection and stream values.
//// No socket, packet, TLS,
//// recovery, or QUIC actor type crosses this boundary.

import gleam/bit_array
import gleam/dict.{type Dict}
import gleam/int
import gleam/list
import gleam/option.{type Option, None, Some}
import gleam/result
import http3/failure as runtime_failure
import http3/internal/native/connection_state as http3_state
import http3/internal/native/control
import http3/internal/native/datagram
import http3/internal/native/drain
import http3/internal/native/frame
import http3/internal/native/frame_parser
import http3/internal/native/message_stream
import http3/internal/native/origin
import http3/internal/native/priority
import http3/internal/native/push
import http3/internal/native/settings_memory
import http3/internal/native/stream_registry
import http3/internal/qpack/header.{type Header}
import http3/internal/qpack/instruction
import http3/internal/qpack/instruction_stream
import http3/internal/stream_id
import http3/internal/varint

const maximum_stream_read_bytes = 65_536

const maximum_preface_bytes = 16

const maximum_instruction_parser_bytes = 65_552

type FrameKind {
  ControlFrames
  RequestFrames
  PushFrames(push_id: Int)
}

type Input {
  AwaitingPreface(BitArray)
  Framed(FrameKind, frame_parser.State)
  Instructions(instruction_stream.State)
  Ignored
  /// A locally aborted stream can still have bytes already pulled by its public-core reader.
  /// Retain a bounded tombstone until FIN/reset so those ordered deliveries remain stream-local instead of becoming a connection `MissingInput` failure.
  Discarded
}

/// Stable failures produced by a role-specific opaque resource adapter.
pub type ResourceError {
  InvalidResourceOperation
  ResourceClosed
  ResourceStreamFinished
  ResourceSendLimited(maximum: Int)
  ResourceDatagramsNotNegotiated
  ResourceDatagramTooLarge(maximum: Int)
}

/// The only QUIC operations HTTP/3 is permitted to perform.
///
/// `connection` is chosen by the role-specific adapter and may contain only public opaque QUIC handles plus its bounded stream registry.
pub type Resource(connection) {
  Resource(
    open_bidirectional: fn(connection) ->
      Result(#(connection, Int), ResourceError),
    open_unidirectional: fn(connection) ->
      Result(#(connection, Int), ResourceError),
    write: fn(connection, Int, BitArray, Bool) ->
      Result(connection, ResourceError),
    abort: fn(connection, Int, Int) -> Result(connection, ResourceError),
    send_datagram: fn(connection, BitArray) -> Result(connection, ResourceError),
    maximum_datagram_size: fn(connection) -> Result(Int, ResourceError),
    guaranteed_datagram_size: fn(connection) -> Result(Int, ResourceError),
  )
}

/// Semantic events emitted after QPACK and HTTP validation.
pub type Event {
  Http3Event(http3_state.Event)
  DataFrameParsed(stream_id: Int, payload_bytes: Int)
  MessageStreamWasRejected(
    target: MessageStreamTarget,
    stream_id: Int,
    application_error_code: Int,
  )
}

/// The application object which owns one peer message stream.
///
/// Request streams use their QUIC stream ID.
/// Push streams are exposed to the client by Push ID, so retain both identities while the protocol state still has the authenticated preface available.
pub type MessageStreamTarget {
  RequestStream
  PushStream(push_id: Int)
}

/// Result of applying one active peer-stream delivery.
///
/// A malformed or incomplete HTTP message is a successful connection transition which has aborted only its owning stream.
/// All other peer protocol failures remain an `Error` so the connection owner can apply their connection-level code.
pub type ActiveStreamReceive(connection) {
  StreamReceived(State(connection))
  MessageStreamAborted(
    state: State(connection),
    target: MessageStreamTarget,
    application_error_code: Int,
  )
}

/// Resource, HTTP/3, or bounded incremental-parser failure.
pub type Error {
  InvalidPeerStream(Int)
  MissingInput(Int)
  PrefaceLimitExceeded
  ResourceFailure(ResourceError)
  Http3Failure(http3_state.Error)
  FrameParserFailure(frame_parser.Error)
  InstructionParserFailure(instruction_stream.Kind, instruction_stream.Error)
}

/// Map connection-scoped failures caused by authenticated peer bytes to registered HTTP/3 or QPACK application close codes.
///
/// H3_MESSAGE_ERROR and H3_REQUEST_INCOMPLETE are deliberately excluded: RFC 9114 section 4.1 makes both stream errors.
/// `receive_active_stream` owns those transitions before a role adapter can close the connection.
pub fn peer_application_error_code(error: Error) -> Option(Int) {
  case error {
    ResourceFailure(_) -> None
    FrameParserFailure(error) -> frame_parser_application_error_code(error)
    InstructionParserFailure(instruction_stream.EncoderStream, _) -> Some(0x201)
    InstructionParserFailure(instruction_stream.DecoderStream, _) -> Some(0x202)
    Http3Failure(http3_state.QpackDecompressionFailure(_)) -> Some(0x200)
    Http3Failure(http3_state.QpackEncoderStreamFailure(_)) -> Some(0x201)
    Http3Failure(http3_state.QpackDecoderStreamFailure(_)) -> Some(0x202)
    Http3Failure(http3_state.ControlFailure(error)) ->
      Some(control_application_error_code(error))
    Http3Failure(http3_state.ZeroRttSettingsIncompatible)
    | Http3Failure(http3_state.SettingsMemoryFailure(_)) -> Some(0x109)
    Http3Failure(http3_state.InvalidStreamId(_)) -> Some(0x108)
    Http3Failure(http3_state.RequestRejected(_)) -> Some(0x10b)
    Http3Failure(http3_state.InvalidMessageFraming)
    | Http3Failure(http3_state.HeaderFailure(_)) -> None
    Http3Failure(http3_state.MessageFailure(error)) ->
      case message_stream_application_error_code(error) {
        0x10d | 0x10e -> None
        code -> Some(code)
      }
    Http3Failure(http3_state.PushFailure(error)) ->
      case push_application_error_code(error) {
        0x10e -> None
        code -> Some(code)
      }
    Http3Failure(http3_state.DrainFailure(drain.InvalidRequestId(_)))
    | Http3Failure(http3_state.DrainFailure(drain.InvalidPushId(_)))
    | Http3Failure(http3_state.DrainFailure(drain.IncreasingGoAwayIdentifier))
    | Http3Failure(http3_state.DrainFailure(drain.DuplicateIdentifier(_))) ->
      Some(0x108)
    Http3Failure(http3_state.FrameUnexpected) -> Some(0x105)
    Http3Failure(http3_state.PriorityFailure(priority.InvalidElementId(_))) ->
      Some(0x108)
    Http3Failure(http3_state.DatagramFailure(datagram.Truncated))
    | Http3Failure(http3_state.DatagramFailure(datagram.InvalidQuarterStreamId(
        _,
      )))
    | Http3Failure(http3_state.DatagramFailure(datagram.IntegerFailure(_))) ->
      Some(0x33)
    Http3Failure(http3_state.StreamRegistryFailure(error)) ->
      case error {
        stream_registry.PushIdNotAllowed(_)
        | stream_registry.DuplicatePushId(_) -> Some(0x108)
        stream_registry.DuplicateControlStream
        | stream_registry.DuplicateQpackEncoderStream
        | stream_registry.DuplicateQpackDecoderStream -> Some(0x103)
        stream_registry.ClosedCriticalStream(_) -> Some(0x104)
        _ -> Some(0x103)
      }
    InvalidPeerStream(_) | PrefaceLimitExceeded -> Some(0x103)
    MissingInput(_) | Http3Failure(_) -> Some(0x101)
  }
}

/// Return the stream-level code for malformed or incomplete peer messages.
///
/// Frame placement errors such as DATA before final HEADERS are intentionally absent and continue through `peer_application_error_code` as connection H3_FRAME_UNEXPECTED failures.
/// Missing final HEADERS is also absent because its code depends on the receiving role: an incomplete request received by a server is H3_REQUEST_INCOMPLETE, while an incomplete response received by a client is H3_MESSAGE_ERROR.
pub fn peer_stream_application_error_code(error: Error) -> Option(Int) {
  case error {
    Http3Failure(http3_state.InvalidMessageFraming)
    | Http3Failure(http3_state.HeaderFailure(_)) -> Some(0x10e)
    Http3Failure(http3_state.MessageFailure(error)) ->
      case error {
        message_stream.MissingFinalHeaders -> None
        message_stream.InformationalRequestHeaders
        | message_stream.DuplicateFinalHeaders
        | message_stream.TrailersBeforeFinalHeaders
        | message_stream.ContentLengthExceeded(_, _)
        | message_stream.ContentLengthMismatch(_, _) -> Some(0x10e)
        _ -> None
      }
    Http3Failure(http3_state.PushFailure(error)) ->
      case error {
        push.InvalidPromisedRequest(_)
        | push.UnsafePromisedRequest
        | push.PromisedRequestRejected(_) -> Some(0x10e)
        _ -> None
      }
    _ -> None
  }
}

fn control_application_error_code(error: control.Error) -> Int {
  case error {
    control.MissingSettings -> 0x10a
    control.DuplicateSettings | control.FrameUnexpected -> 0x105
    control.InvalidSetting(_) -> 0x109
    control.InvalidGoAwayIdentifier(_)
    | control.IncreasingGoAwayIdentifier
    | control.PushControlFromServer
    | control.PushIdDecreased -> 0x108
  }
}

fn message_stream_application_error_code(error: message_stream.Error) -> Int {
  case error {
    message_stream.DataBeforeFinalHeaders
    | message_stream.DuplicateTrailers
    | message_stream.HeadersAfterTrailers
    | message_stream.DataAfterTrailers
    | message_stream.HeadersAfterConnect -> 0x105
    message_stream.MissingFinalHeaders -> 0x10d
    message_stream.BodyLimitExceeded(_) -> 0x107
    message_stream.InformationalRequestHeaders
    | message_stream.DuplicateFinalHeaders
    | message_stream.TrailersBeforeFinalHeaders
    | message_stream.ContentLengthExceeded(_, _)
    | message_stream.ContentLengthMismatch(_, _) -> 0x10e
    message_stream.FrameAfterFinished
    | message_stream.ConnectBeforeFinalHeaders
    | message_stream.NonByteAligned -> 0x101
  }
}

fn push_application_error_code(error: push.Error) -> Int {
  case error {
    push.InvalidPromisedRequest(_)
    | push.UnsafePromisedRequest
    | push.PromisedRequestRejected(_) -> 0x10e
    push.PushIdDecreased
    | push.PushIdNotAllowed(_)
    | push.InvalidRequestStream(_)
    | push.InvalidPushStream(_)
    | push.DuplicatePushStream(_) -> 0x108
    push.InconsistentDuplicatePromise(_) -> 0x101
    push.InvalidConfiguration
    | push.PushLimitExceeded(_)
    | push.MissingPush(_)
    | push.AlreadyTerminal(_)
    | push.InvalidTime -> 0x101
  }
}

fn frame_parser_application_error_code(
  error: frame_parser.Error,
) -> Option(Int) {
  case error {
    frame_parser.InvalidConfiguration
    | frame_parser.NonByteAligned
    | frame_parser.FrameFailure(frame.InvalidLimits)
    | frame_parser.FrameFailure(frame.NonByteAligned)
    | frame_parser.FrameFailure(frame.OriginFailure(origin.InvalidLimit))
    | frame_parser.FrameFailure(frame.OriginFailure(origin.NonByteAligned)) ->
      None
    frame_parser.BufferLimitExceeded(_)
    | frame_parser.FrameFailure(frame.PayloadLimitExceeded(_))
    | frame_parser.FrameFailure(frame.FieldSectionLimitExceeded(_))
    | frame_parser.FrameFailure(frame.SettingsLimitExceeded(_))
    | frame_parser.FrameFailure(frame.OriginFailure(origin.TooManyOrigins(_)))
    | frame_parser.FrameFailure(frame.OriginFailure(origin.OriginTooLong(_))) ->
      Some(0x107)
    frame_parser.FrameFailure(frame.ProhibitedHttp2FrameType(_)) -> Some(0x105)
    frame_parser.FrameFailure(frame.DuplicateSetting(_))
    | frame_parser.FrameFailure(frame.ProhibitedSetting(_)) -> Some(0x109)
    frame_parser.TruncatedFrame
    | frame_parser.FrameFailure(frame.Truncated)
    | frame_parser.FrameFailure(frame.InvalidFrame)
    | frame_parser.FrameFailure(frame.IntegerFailure(_))
    | frame_parser.FrameFailure(frame.OriginFailure(_)) -> Some(0x106)
  }
}

/// Preserve the configured resource and its bound independently of the wire close code.
/// Malformed peer bytes and local parser misuse remain distinct.
pub fn frame_parser_runtime_failure(
  error: frame_parser.Error,
) -> runtime_failure.Failure {
  case error {
    frame_parser.BufferLimitExceeded(maximum) ->
      runtime_failure.Limit(runtime_failure.Buffer, maximum)
    frame_parser.FrameFailure(frame.PayloadLimitExceeded(maximum))
    | frame_parser.FrameFailure(frame.FieldSectionLimitExceeded(maximum))
    | frame_parser.FrameFailure(frame.OriginFailure(origin.OriginTooLong(
        maximum,
      ))) -> runtime_failure.Limit(runtime_failure.Frame, maximum)
    frame_parser.FrameFailure(frame.SettingsLimitExceeded(maximum))
    | frame_parser.FrameFailure(frame.OriginFailure(origin.TooManyOrigins(
        maximum,
      ))) -> runtime_failure.Limit(runtime_failure.Queue, maximum)
    _ ->
      case frame_parser_application_error_code(error) {
        None -> runtime_failure.Http3(runtime_failure.Local, None)
        Some(code) -> runtime_failure.Http3(runtime_failure.Peer, Some(code))
      }
  }
}

/// HTTP/3 state above a role-specific opaque public QUIC resource.
pub opaque type State(connection) {
  State(
    resource: Resource(connection),
    connection: connection,
    http3: http3_state.State,
    inputs: Dict(Int, Input),
    events: List(Event),
    maximum_frame_payload_bytes: Int,
    maximum_field_section_bytes: Int,
  )
}

/// Bootstrap the mandatory control and QPACK streams.
pub fn start(
  resource: Resource(connection),
  connection: connection,
  config: http3_state.Config,
  quic_datagram_negotiated: Bool,
) -> Result(State(connection), Error) {
  use http3 <- result.try(
    http3_state.new(config, quic_datagram_negotiated) |> map_http3_result,
  )
  let Resource(open_bidirectional: _, open_unidirectional:, ..) = resource
  use #(connection, control_id) <- result.try(
    open_unidirectional(connection) |> map_resource_result,
  )
  use #(connection, encoder_id) <- result.try(
    open_unidirectional(connection) |> map_resource_result,
  )
  use #(connection, decoder_id) <- result.try(
    open_unidirectional(connection) |> map_resource_result,
  )
  use #(http3, bootstrap) <- result.try(
    http3_state.bootstrap(http3, control_id, encoder_id, decoder_id)
    |> map_http3_result,
  )
  let state =
    State(
      resource,
      connection,
      http3,
      dict.new(),
      [],
      config.maximum_frame_payload_bytes,
      int.min(
        config.maximum_frame_payload_bytes,
        config.settings.maximum_field_section_size,
      ),
    )
  use state <- result.try(queue_stream_bytes(state, bootstrap))
  Ok(state)
}

/// Return the role adapter's opaque connection value.
pub fn connection(state: State(connection)) -> connection {
  state.connection
}

/// Replace the adapter connection after registering an accepted stream.
pub fn with_connection(
  state: State(connection),
  connection: connection,
) -> State(connection) {
  State(..state, connection: connection)
}

/// Payload-free cardinalities for parsers and HTTP/3 per-stream state.
pub fn resource_counts(state: State(connection)) -> #(Int, Int, Int, Int) {
  let #(transactions, push_transactions, blocked_streams) =
    http3_state.resource_counts(state.http3)
  #(dict.size(state.inputs), transactions, push_transactions, blocked_streams)
}

/// Pull and clear ordered semantic events.
pub fn take_events(
  state: State(connection),
) -> #(State(connection), List(Event)) {
  #(State(..state, events: []), state.events)
}

/// Open a client request stream and queue its initial HEADERS frame.
pub fn open_request(
  state: State(connection),
  fields: List(Header),
  allow_qpack_blocking: Bool,
) -> Result(#(State(connection), Int), Error) {
  let Resource(open_bidirectional:, ..) = state.resource
  use #(connection, identifier) <- result.try(
    open_bidirectional(state.connection) |> map_resource_result,
  )
  use #(http3, bytes) <- result.try(
    http3_state.open_request(
      state.http3,
      identifier,
      fields,
      allow_qpack_blocking,
    )
    |> map_http3_result,
  )
  use parser <- result.try(new_frame_parser(state))
  use state <- result.try(queue_bytes(
    State(
      ..state,
      connection: connection,
      http3: http3,
      inputs: dict.insert(
        state.inputs,
        identifier,
        Framed(RequestFrames, parser),
      ),
    ),
    identifier,
    bytes,
    False,
  ))
  flush_qpack(state)
  |> result.map(fn(state) { #(state, identifier) })
}

/// Queue server response HEADERS on an existing request stream.
pub fn send_response_headers(
  state: State(connection),
  stream_id: Int,
  fields: List(Header),
  allow_qpack_blocking: Bool,
) -> Result(State(connection), Error) {
  use #(http3, bytes) <- result.try(
    http3_state.send_response_headers(
      state.http3,
      stream_id,
      fields,
      allow_qpack_blocking,
    )
    |> map_http3_result,
  )
  use state <- result.try(queue_bytes(
    State(..state, http3: http3),
    stream_id,
    bytes,
    False,
  ))
  flush_qpack(state)
}

/// Queue one bounded HTTP DATA frame.
pub fn send_data(
  state: State(connection),
  stream_id: Int,
  bytes: BitArray,
) -> Result(State(connection), Error) {
  use #(http3, encoded) <- result.try(
    http3_state.send_data(state.http3, stream_id, bytes) |> map_http3_result,
  )
  queue_bytes(State(..state, http3: http3), stream_id, encoded, False)
}

/// Queue one HTTP trailer section.
pub fn send_trailers(
  state: State(connection),
  stream_id: Int,
  fields: List(Header),
  allow_qpack_blocking: Bool,
) -> Result(State(connection), Error) {
  use #(http3, encoded) <- result.try(
    http3_state.send_trailers(
      state.http3,
      stream_id,
      fields,
      allow_qpack_blocking,
    )
    |> map_http3_result,
  )
  use state <- result.try(queue_bytes(
    State(..state, http3: http3),
    stream_id,
    encoded,
    False,
  ))
  flush_qpack(state)
}

/// Validate message framing and queue a stream FIN.
pub fn finish_stream(
  state: State(connection),
  stream_id: Int,
) -> Result(State(connection), Error) {
  use http3 <- result.try(
    http3_state.finish_send(state.http3, stream_id) |> map_http3_result,
  )
  queue_bytes(State(..state, http3: http3), stream_id, <<>>, True)
}

/// Grant the peer a bounded inclusive server Push ID.
pub fn permit_pushes(
  state: State(connection),
  maximum_push_id: Int,
) -> Result(State(connection), Error) {
  use #(http3, bytes) <- result.try(
    http3_state.permit_pushes(state.http3, maximum_push_id)
    |> map_http3_result,
  )
  use control_stream <- result.try(
    http3_state.control_stream_id(http3) |> map_http3_result,
  )
  queue_bytes(State(..state, http3: http3), control_stream, bytes, False)
}

/// Promise a push and open its server-initiated unidirectional stream.
pub fn promise_push(
  state: State(connection),
  request_stream_id: Int,
  fields: List(Header),
  now_ms: Int,
) -> Result(#(State(connection), Int, Int), Error) {
  use #(http3, push_id, promise_bytes) <- result.try(
    http3_state.promise_push(state.http3, request_stream_id, fields, False)
    |> map_http3_result,
  )
  use state <- result.try(queue_bytes(
    State(..state, http3: http3),
    request_stream_id,
    promise_bytes,
    False,
  ))
  let Resource(open_unidirectional:, ..) = state.resource
  use #(connection, push_stream_id) <- result.try(
    open_unidirectional(state.connection) |> map_resource_result,
  )
  use #(http3, preface) <- result.try(
    http3_state.open_push_stream(state.http3, push_stream_id, push_id, now_ms)
    |> map_http3_result,
  )
  use state <- result.try(queue_bytes(
    State(..state, connection: connection, http3: http3),
    push_stream_id,
    preface,
    False,
  ))
  flush_qpack(state)
  |> result.map(fn(state) { #(state, push_id, push_stream_id) })
}

/// Queue pushed response HEADERS.
pub fn send_push_response_headers(
  state: State(connection),
  stream_id: Int,
  fields: List(Header),
) -> Result(State(connection), Error) {
  use #(http3, bytes) <- result.try(
    http3_state.send_push_response_headers(
      state.http3,
      stream_id,
      fields,
      False,
    )
    |> map_http3_result,
  )
  use state <- result.try(queue_bytes(
    State(..state, http3: http3),
    stream_id,
    bytes,
    False,
  ))
  flush_qpack(state)
}

/// Queue pushed response DATA.
pub fn send_push_data(
  state: State(connection),
  stream_id: Int,
  bytes: BitArray,
) -> Result(State(connection), Error) {
  use #(http3, encoded) <- result.try(
    http3_state.send_push_data(state.http3, stream_id, bytes)
    |> map_http3_result,
  )
  queue_bytes(State(..state, http3: http3), stream_id, encoded, False)
}

/// Queue pushed response trailers.
pub fn send_push_trailers(
  state: State(connection),
  stream_id: Int,
  fields: List(Header),
) -> Result(State(connection), Error) {
  use #(http3, encoded) <- result.try(
    http3_state.send_push_trailers(state.http3, stream_id, fields, False)
    |> map_http3_result,
  )
  use state <- result.try(queue_bytes(
    State(..state, http3: http3),
    stream_id,
    encoded,
    False,
  ))
  flush_qpack(state)
}

/// Finish one pushed response stream.
pub fn finish_push(
  state: State(connection),
  stream_id: Int,
) -> Result(State(connection), Error) {
  use http3 <- result.try(
    http3_state.finish_push_send(state.http3, stream_id) |> map_http3_result,
  )
  queue_bytes(State(..state, http3: http3), stream_id, <<>>, True)
}

/// Cancel one promised push and abort its stream when already opened.
pub fn cancel_push(
  state: State(connection),
  push_id: Int,
) -> Result(State(connection), Error) {
  use #(http3, bytes, push_stream_id) <- result.try(
    http3_state.cancel_push(state.http3, push_id) |> map_http3_result,
  )
  use control_stream <- result.try(
    http3_state.control_stream_id(http3) |> map_http3_result,
  )
  use state <- result.try(queue_bytes(
    State(..state, http3: http3),
    control_stream,
    bytes,
    False,
  ))
  case push_stream_id {
    None -> Ok(state)
    Some(identifier) -> abort_stream(state, identifier, 0x10c)
  }
}

/// Abort both usable directions of one HTTP stream.
pub fn abort_stream(
  state: State(connection),
  stream_id: Int,
  application_error_code: Int,
) -> Result(State(connection), Error) {
  let Resource(abort:, ..) = state.resource
  use connection <- result.try(
    abort(state.connection, stream_id, application_error_code)
    |> map_resource_result,
  )
  retire_aborted_stream(State(..state, connection: connection), stream_id)
}

/// Abort only the local send direction after peer STOP_SENDING.
///
/// This deliberately leaves the peer-to-local direction registered so bytes already authorized by the peer, and its terminal FIN or reset, retain their ordered HTTP/3 meaning.
pub fn observe_send_stopped(
  state: State(connection),
  stream_id: Int,
) -> Result(State(connection), Error) {
  use http3 <- result.try(
    http3_state.observe_send_stopped(state.http3, stream_id)
    |> map_http3_result,
  )
  Ok(State(..state, http3: http3))
}

/// Complete local HTTP/3 cancellation after both QUIC directions are terminal.
pub fn retire_aborted_stream(
  state: State(connection),
  stream_id: Int,
) -> Result(State(connection), Error) {
  use http3 <- result.try(
    http3_state.abort_stream(state.http3, stream_id) |> map_http3_result,
  )
  flush_qpack(
    State(
      ..state,
      http3: http3,
      inputs: case dict.has_key(state.inputs, stream_id) {
        True -> dict.insert(state.inputs, stream_id, Discarded)
        False -> state.inputs
      },
    ),
  )
}

/// Return whether both QUIC and HTTP/3 Datagram settings were negotiated.
pub fn datagrams_available(state: State(connection)) -> Bool {
  http3_state.datagrams_available(state.http3)
}

/// Return whether the peer's mandatory SETTINGS frame has arrived.
pub fn peer_settings_received(state: State(connection)) -> Bool {
  http3_state.peer_settings_received(state.http3)
}

/// Return only authenticated peer settings, excluding ticket memory.
pub fn peer_settings_snapshot(
  state: State(connection),
) -> Result(Option(settings_memory.Snapshot), Error) {
  http3_state.peer_settings_snapshot(state.http3) |> map_http3_result
}

/// Mark this connection's attempted 0-RTT as authenticated and accepted.
pub fn accept_zero_rtt(
  state: State(connection),
) -> Result(State(connection), Error) {
  http3_state.accept_zero_rtt(state.http3)
  |> map_http3_result
  |> result.map(fn(http3) { State(..state, http3: http3) })
}

/// Return the largest HTTP Datagram application payload for a request stream.
pub fn maximum_http_datagram_size(
  state: State(connection),
  stream_id: Int,
) -> Result(Int, Error) {
  use _ <- result.try(
    http3_state.send_datagram(state.http3, stream_id, <<>>)
    |> map_http3_result,
  )
  let Resource(maximum_datagram_size:, ..) = state.resource
  http_datagram_payload_size(state, stream_id, maximum_datagram_size)
}

/// Return the payload ceiling that survives ACK debt and path fallback for an active HTTP Datagram association.
pub fn guaranteed_http_datagram_size(
  state: State(connection),
  stream_id: Int,
) -> Result(Int, Error) {
  use _ <- result.try(
    http3_state.send_datagram(state.http3, stream_id, <<>>)
    |> map_http3_result,
  )
  let Resource(guaranteed_datagram_size:, ..) = state.resource
  http_datagram_payload_size(state, stream_id, guaranteed_datagram_size)
}

/// Return the lifetime-stable payload ceiling for an admitted Extended CONNECT request before its successful response makes the association active.
pub fn prospective_guaranteed_http_datagram_size(
  state: State(connection),
  stream_id: Int,
) -> Result(Int, Error) {
  use _ <- result.try(case http3_state.datagrams_available(state.http3) {
    True -> Ok(Nil)
    False -> Error(ResourceFailure(ResourceDatagramsNotNegotiated))
  })
  let Resource(guaranteed_datagram_size:, ..) = state.resource
  http_datagram_payload_size(state, stream_id, guaranteed_datagram_size)
}

fn http_datagram_payload_size(
  state: State(connection),
  stream_id: Int,
  capacity: fn(connection) -> Result(Int, ResourceError),
) -> Result(Int, Error) {
  use raw_limit <- result.try(capacity(state.connection) |> map_resource_result)
  use quarter_bytes <- result.try(
    varint.encoded_size(stream_id / 4)
    |> result.replace_error(
      Http3Failure(http3_state.InvalidStreamId(stream_id)),
    ),
  )
  let maximum = raw_limit - quarter_bytes
  case stream_id >= 0 && stream_id % 4 == 0 && maximum >= 0 {
    True -> Ok(maximum)
    False -> Error(Http3Failure(http3_state.InvalidStreamId(stream_id)))
  }
}

/// Queue one RFC 9297 quarter-stream-prefixed QUIC Datagram.
pub fn send_http_datagram(
  state: State(connection),
  stream_id: Int,
  payload: BitArray,
) -> Result(State(connection), Error) {
  use _ <- result.try(maximum_http_datagram_size(state, stream_id))
  use encoded <- result.try(
    http3_state.send_datagram(state.http3, stream_id, payload)
    |> map_http3_result,
  )
  let Resource(send_datagram:, ..) = state.resource
  use connection <- result.try(
    send_datagram(state.connection, encoded) |> map_resource_result,
  )
  Ok(State(..state, connection: connection))
}

/// Consume one received RFC 9221 QUIC Datagram.
pub fn receive_datagram(
  state: State(connection),
  encoded: BitArray,
) -> Result(State(connection), Error) {
  use receipt <- result.try(
    http3_state.receive_datagram(state.http3, encoded) |> map_http3_result,
  )
  case receipt {
    http3_state.DatagramDelivered(datagram.Received(identifier, _, payload)) ->
      Ok(
        add_events(state, [
          Http3Event(http3_state.HttpDatagram(identifier, payload)),
        ]),
      )
    http3_state.DatagramDropped -> Ok(state)
    http3_state.DatagramRequestRejected(identifier) ->
      abort_stream(state, identifier, 0x33)
  }
}

/// Queue a request PRIORITY_UPDATE on the local control stream.
pub fn set_request_priority(
  state: State(connection),
  stream_id: Int,
  urgency: Int,
  incremental: Bool,
) -> Result(State(connection), Error) {
  use http3_state.StreamBytes(identifier, bytes) <- result.try(
    http3_state.request_priority_update(
      state.http3,
      stream_id,
      urgency,
      incremental,
    )
    |> map_http3_result,
  )
  queue_bytes(state, identifier, bytes, False)
}

/// Begin two-stage graceful drain and queue the initial GOAWAY.
pub fn start_drain(
  state: State(connection),
  now_ms: Int,
) -> Result(State(connection), Error) {
  use #(http3, http3_state.StreamBytes(identifier, bytes)) <- result.try(
    http3_state.start_drain(state.http3, now_ms) |> map_http3_result,
  )
  queue_bytes(State(..state, http3: http3), identifier, bytes, False)
}

/// Queue the final GOAWAY cutoff and return rejected request identifiers.
pub fn refine_drain(
  state: State(connection),
  identifier: Int,
) -> Result(#(State(connection), List(Int)), Error) {
  use #(http3, http3_state.StreamBytes(control_stream, bytes), rejected) <- result.try(
    http3_state.refine_drain(state.http3, identifier) |> map_http3_result,
  )
  use state <- result.try(queue_bytes(
    State(..state, http3: http3),
    control_stream,
    bytes,
    False,
  ))
  Ok(#(state, rejected))
}

/// Return the HTTP/3 graceful-drain phase.
pub fn drain_phase(state: State(connection)) -> drain.Phase {
  http3_state.drain_phase(state.http3)
}

/// Mark graceful drain closed after QUIC close is queued.
pub fn close_drained(
  state: State(connection),
) -> Result(State(connection), Error) {
  use http3 <- result.try(
    http3_state.close_drained(state.http3) |> map_http3_result,
  )
  Ok(State(..state, http3: http3))
}

/// Register one peer-initiated public QUIC stream before reading it.
/// Repeated registration keeps the stream's parser state.
pub fn register_peer_stream(
  state: State(connection),
  identifier: Int,
) -> Result(State(connection), Error) {
  register_input(state, identifier)
}

/// Feed one bounded public QUIC stream read into HTTP/3.
pub fn receive_stream(
  state: State(connection),
  identifier: Int,
  bytes: BitArray,
  finished: Bool,
  now_ms: Int,
) -> Result(State(connection), Error) {
  use input <- result.try(
    dict.get(state.inputs, identifier)
    |> result.replace_error(MissingInput(identifier)),
  )
  use state <- result.try(feed_input(state, identifier, input, bytes, now_ms))
  case finished {
    True -> finish_current_input(state, identifier)
    False -> Ok(state)
  }
}

/// Apply a public-core stream delivery with RFC 9114 message-error scope.
///
/// Malformed request, response, trailer, PUSH_PROMISE, and pushed-response semantics abort their usable directions with H3_MESSAGE_ERROR.
/// A server receiving a request that ends before final HEADERS uses H3_REQUEST_INCOMPLETE; incomplete responses received by a client use H3_MESSAGE_ERROR.
/// The connection state is returned as usable.
/// A terminal delivery removes the discard tombstone because no later FIN can arrive.
pub fn receive_active_stream(
  state: State(connection),
  identifier: Int,
  bytes: BitArray,
  finished: Bool,
  now_ms: Int,
) -> Result(ActiveStreamReceive(connection), Error) {
  use input <- result.try(
    dict.get(state.inputs, identifier)
    |> result.replace_error(MissingInput(identifier)),
  )
  let target = message_stream_target(input, bytes)
  case receive_stream(state, identifier, bytes, finished, now_ms) {
    Ok(state) -> Ok(StreamReceived(state))
    Error(error) ->
      case peer_message_stream_error_code(state, target, error) {
        None -> Error(error)
        Some(code) -> {
          use state <- result.try(abort_stream(state, identifier, code))
          let state = case finished {
            True ->
              State(..state, inputs: dict.delete(state.inputs, identifier))
            False -> state
          }
          Ok(MessageStreamAborted(state, target, code))
        }
      }
  }
}

fn peer_message_stream_error_code(
  state: State(connection),
  target: MessageStreamTarget,
  error: Error,
) -> Option(Int) {
  case error {
    Http3Failure(http3_state.MessageFailure(message_stream.MissingFinalHeaders)) ->
      case http3_state.role(state.http3), target {
        http3_state.Server, RequestStream -> Some(0x10d)
        _, _ -> Some(0x10e)
      }
    _ -> peer_stream_application_error_code(error)
  }
}

fn message_stream_target(input: Input, bytes: BitArray) -> MessageStreamTarget {
  case input {
    Framed(PushFrames(push_id), _) -> PushStream(push_id)
    AwaitingPreface(buffered) ->
      case stream_registry.decode_preface(<<buffered:bits, bytes:bits>>) {
        Ok(stream_registry.Preface(stream_registry.Push(push_id), _)) ->
          PushStream(push_id)
        _ -> RequestStream
      }
    _ -> RequestStream
  }
}

/// Forget a reset input; the role adapter retains the authoritative code.
pub fn receive_reset(
  state: State(connection),
  identifier: Int,
) -> Result(State(connection), Error) {
  let input =
    dict.get(state.inputs, identifier)
    |> result.map(Some)
    |> result.unwrap(None)
  case input {
    None -> Ok(state)
    Some(AwaitingPreface(_)) | Some(Discarded) ->
      Ok(State(..state, inputs: dict.delete(state.inputs, identifier)))
    Some(Ignored) | Some(Instructions(_)) | Some(Framed(ControlFrames, _)) ->
      close_unidirectional(state, identifier)
    Some(Framed(RequestFrames, _)) | Some(Framed(PushFrames(_), _)) -> {
      use http3 <- result.try(
        http3_state.receive_stream_reset(state.http3, identifier)
        |> map_http3_result,
      )
      flush_qpack(
        State(
          ..state,
          http3: http3,
          inputs: dict.delete(state.inputs, identifier),
        ),
      )
    }
  }
}

fn queue_stream_bytes(
  state: State(connection),
  outputs: List(http3_state.StreamBytes),
) -> Result(State(connection), Error) {
  case outputs {
    [] -> Ok(state)
    [http3_state.StreamBytes(identifier, bytes), ..rest] -> {
      use state <- result.try(queue_bytes(state, identifier, bytes, False))
      queue_stream_bytes(state, rest)
    }
  }
}

fn queue_bytes(
  state: State(connection),
  identifier: Int,
  bytes: BitArray,
  finish: Bool,
) -> Result(State(connection), Error) {
  let Resource(write:, ..) = state.resource
  use connection <- result.try(
    write(state.connection, identifier, bytes, finish)
    |> map_resource_result,
  )
  Ok(State(..state, connection: connection))
}

fn flush_qpack(state: State(connection)) -> Result(State(connection), Error) {
  use #(http3, encoder_output) <- result.try(
    http3_state.take_qpack_encoder_bytes(state.http3) |> map_http3_result,
  )
  use #(http3, decoder_output) <- result.try(
    http3_state.take_qpack_decoder_bytes(http3) |> map_http3_result,
  )
  use state <- result.try(queue_optional_stream_bytes(
    State(..state, http3: http3),
    encoder_output,
  ))
  queue_optional_stream_bytes(state, decoder_output)
}

fn queue_optional_stream_bytes(
  state: State(connection),
  output: Option(http3_state.StreamBytes),
) -> Result(State(connection), Error) {
  case output {
    None -> Ok(state)
    Some(http3_state.StreamBytes(identifier, bytes)) ->
      queue_bytes(state, identifier, bytes, False)
  }
}

fn register_input(
  state: State(connection),
  identifier: Int,
) -> Result(State(connection), Error) {
  case stream_id.decode(identifier) {
    Error(_) -> Error(InvalidPeerStream(identifier))
    Ok(stream_id.StreamId(_, initiator, direction)) ->
      register_decoded_input(state, identifier, initiator, direction)
  }
}

fn register_decoded_input(
  state: State(connection),
  identifier: Int,
  initiator: stream_id.Initiator,
  direction: stream_id.Direction,
) -> Result(State(connection), Error) {
  let local = case http3_state.role(state.http3) {
    http3_state.Client -> stream_id.Client
    http3_state.Server -> stream_id.Server
  }
  case initiator == local, direction, dict.has_key(state.inputs, identifier) {
    True, _, _ | False, _, True -> Ok(state)
    False, stream_id.Unidirectional, False ->
      Ok(put_input(state, identifier, AwaitingPreface(<<>>)))
    False, stream_id.Bidirectional, False ->
      case http3_state.role(state.http3), initiator {
        http3_state.Server, stream_id.Client -> {
          use parser <- result.try(new_frame_parser(state))
          Ok(put_input(state, identifier, Framed(RequestFrames, parser)))
        }
        _, _ -> Error(InvalidPeerStream(identifier))
      }
  }
}

fn feed_input(
  state: State(connection),
  identifier: Int,
  input: Input,
  bytes: BitArray,
  now_ms: Int,
) -> Result(State(connection), Error) {
  case input {
    AwaitingPreface(buffered) ->
      feed_preface(state, identifier, buffered, bytes, now_ms)
    Framed(kind, parser) -> feed_frames(state, identifier, kind, parser, bytes)
    Instructions(parser) -> feed_instructions(state, identifier, parser, bytes)
    Ignored | Discarded -> Ok(state)
  }
}

fn feed_preface(
  state: State(connection),
  identifier: Int,
  buffered: BitArray,
  bytes: BitArray,
  now_ms: Int,
) -> Result(State(connection), Error) {
  let combined = <<buffered:bits, bytes:bits>>
  case
    http3_state.open_peer_unidirectional_stream(
      state.http3,
      identifier,
      combined,
      now_ms,
    )
  {
    Error(http3_state.StreamRegistryFailure(stream_registry.TruncatedPreface)) ->
      case bit_array.byte_size(combined) > maximum_preface_bytes {
        True -> Error(PrefaceLimitExceeded)
        False -> Ok(put_input(state, identifier, AwaitingPreface(combined)))
      }
    Error(error) -> Error(Http3Failure(error))
    Ok(#(http3, kind, remaining)) -> {
      let state = State(..state, http3: http3)
      let cancelled = case kind {
        stream_registry.Push(push_id) ->
          http3_state.push_cancelled(http3, push_id)
        _ -> False
      }
      case cancelled {
        True -> {
          let state = put_input(state, identifier, Discarded)
          use state <- result.try(abort_stream(state, identifier, 0x10c))
          feed_input(state, identifier, Discarded, remaining, now_ms)
        }
        False -> {
          use input <- result.try(input_for_kind(state, kind))
          feed_input(
            put_input(state, identifier, input),
            identifier,
            input,
            remaining,
            now_ms,
          )
        }
      }
    }
  }
}

fn input_for_kind(
  state: State(connection),
  kind: stream_registry.Kind,
) -> Result(Input, Error) {
  case kind {
    stream_registry.Control ->
      new_frame_parser(state)
      |> result.map(fn(parser) { Framed(ControlFrames, parser) })
    stream_registry.Push(push_id) ->
      new_frame_parser(state)
      |> result.map(fn(parser) { Framed(PushFrames(push_id), parser) })
    stream_registry.QpackEncoder ->
      new_instruction_parser(instruction_stream.EncoderStream)
      |> result.map(Instructions)
    stream_registry.QpackDecoder ->
      new_instruction_parser(instruction_stream.DecoderStream)
      |> result.map(Instructions)
    stream_registry.Unknown(_) -> Ok(Ignored)
  }
}

fn feed_frames(
  state: State(connection),
  identifier: Int,
  kind: FrameKind,
  parser: frame_parser.State,
  bytes: BitArray,
) -> Result(State(connection), Error) {
  use parser <- result.try(
    frame_parser.push(parser, bytes) |> map_frame_parser_result,
  )
  parse_frames(state, identifier, kind, parser)
}

fn parse_frames(
  state: State(connection),
  identifier: Int,
  kind: FrameKind,
  parser: frame_parser.State,
) -> Result(State(connection), Error) {
  case frame_parser.next(parser) {
    Error(error) -> Error(FrameParserFailure(error))
    Ok(frame_parser.NeedMore(parser)) ->
      Ok(put_input(state, identifier, Framed(kind, parser)))
    Ok(frame_parser.FrameReady(parser, incoming)) -> {
      use #(http3, events) <- result.try(receive_http3_frame(
        state.http3,
        identifier,
        kind,
        incoming,
      ))
      use state <- result.try(add_http3_events(
        State(..state, http3: http3),
        events,
      ))
      use state <- result.try(flush_qpack(state))
      let state = case frame_parser.completed_data_frame(parser) {
        None -> state
        Some(bytes) ->
          State(
            ..state,
            events: list.append(state.events, [
              DataFrameParsed(identifier, bytes),
            ]),
          )
      }
      parse_frames(state, identifier, kind, parser)
    }
  }
}

fn receive_http3_frame(
  state: http3_state.State,
  identifier: Int,
  kind: FrameKind,
  incoming: frame.Frame,
) -> Result(#(http3_state.State, List(http3_state.Event)), Error) {
  case kind {
    ControlFrames ->
      http3_state.receive_control_frame(state, incoming) |> map_http3_result
    RequestFrames ->
      http3_state.receive_request_frame(state, identifier, incoming)
      |> map_http3_result
    PushFrames(_) ->
      http3_state.receive_push_stream_frame(state, identifier, incoming)
      |> map_http3_result
  }
}

fn feed_instructions(
  state: State(connection),
  identifier: Int,
  parser: instruction_stream.State,
  bytes: BitArray,
) -> Result(State(connection), Error) {
  use parser <- result.try(
    instruction_stream.push(parser, bytes)
    |> map_instruction_parser_result(instruction_stream.kind(parser)),
  )
  parse_instructions(state, identifier, parser)
}

fn parse_instructions(
  state: State(connection),
  identifier: Int,
  parser: instruction_stream.State,
) -> Result(State(connection), Error) {
  case instruction_stream.next(parser) {
    Error(error) ->
      Error(InstructionParserFailure(instruction_stream.kind(parser), error))
    Ok(instruction_stream.NeedMore(parser)) ->
      Ok(put_input(state, identifier, Instructions(parser)))
    Ok(instruction_stream.InstructionReady(parser, decoded)) -> {
      use state <- result.try(apply_instruction(state, decoded))
      parse_instructions(state, identifier, parser)
    }
  }
}

fn apply_instruction(
  state: State(connection),
  decoded: instruction_stream.Decoded,
) -> Result(State(connection), Error) {
  case decoded {
    instruction_stream.EncoderInstruction(incoming) -> {
      use #(http3, events) <- result.try(
        http3_state.receive_qpack_encoder_instruction(state.http3, incoming)
        |> map_http3_result,
      )
      use state <- result.try(add_http3_events(
        State(..state, http3: http3),
        events,
      ))
      flush_qpack(state)
    }
    instruction_stream.DecoderInstruction(incoming) -> {
      use http3 <- result.try(
        http3_state.receive_qpack_decoder_instruction(state.http3, incoming)
        |> map_http3_result,
      )
      Ok(State(..state, http3: http3))
    }
  }
}

fn finish_current_input(
  state: State(connection),
  identifier: Int,
) -> Result(State(connection), Error) {
  use input <- result.try(
    dict.get(state.inputs, identifier)
    |> result.replace_error(MissingInput(identifier)),
  )
  finish_input(state, identifier, input)
}

fn finish_input(
  state: State(connection),
  identifier: Int,
  input: Input,
) -> Result(State(connection), Error) {
  case input {
    // A peer is allowed to open an otherwise unused unidirectional stream and finish it without sending a stream-type varint.
    // Once any preface byte has arrived, however, FIN leaves a truncated type and remains a connection error.
    // Keep reset handling separate: receive_reset/2 owns that contract.
    AwaitingPreface(<<>>) ->
      Ok(State(..state, inputs: dict.delete(state.inputs, identifier)))
    AwaitingPreface(_) -> Error(PrefaceLimitExceeded)
    Instructions(parser) ->
      instruction_stream.finish(parser)
      |> map_instruction_parser_result(instruction_stream.kind(parser))
      |> result.map(fn(_) {
        State(..state, inputs: dict.delete(state.inputs, identifier))
      })
    Ignored -> close_unidirectional(state, identifier)
    Discarded ->
      Ok(State(..state, inputs: dict.delete(state.inputs, identifier)))
    Framed(kind, parser) -> {
      use Nil <- result.try(
        frame_parser.finish(parser) |> map_frame_parser_result,
      )
      finish_framed(state, identifier, kind)
    }
  }
}

fn finish_framed(
  state: State(connection),
  identifier: Int,
  kind: FrameKind,
) -> Result(State(connection), Error) {
  case kind {
    RequestFrames -> {
      use #(http3, events) <- result.try(
        case http3_state.receive_request_finish(state.http3, identifier) {
          Error(http3_state.MissingTransaction(missing))
            if missing == identifier
          ->
            Error(
              Http3Failure(http3_state.MessageFailure(
                message_stream.MissingFinalHeaders,
              )),
            )
          outcome -> outcome |> map_http3_result
        },
      )
      use state <- result.try(add_http3_events(
        State(
          ..state,
          http3: http3,
          inputs: dict.delete(state.inputs, identifier),
        ),
        events,
      ))
      flush_qpack(state)
    }
    ControlFrames | PushFrames(_) -> close_unidirectional(state, identifier)
  }
}

fn close_unidirectional(
  state: State(connection),
  identifier: Int,
) -> Result(State(connection), Error) {
  use #(http3, events) <- result.try(
    http3_state.close_peer_unidirectional_stream(state.http3, identifier)
    |> map_http3_result,
  )
  add_http3_events(
    State(..state, http3: http3, inputs: dict.delete(state.inputs, identifier)),
    events,
  )
}

fn new_frame_parser(
  state: State(connection),
) -> Result(frame_parser.State, Error) {
  frame_parser.new_streaming(
    frame.Limits(
      maximum_payload_bytes: state.maximum_frame_payload_bytes,
      maximum_field_section_bytes: state.maximum_field_section_bytes,
      maximum_settings: 256,
      maximum_origin_entries: 256,
    ),
    state.maximum_frame_payload_bytes + maximum_stream_read_bytes + 16,
    maximum_stream_read_bytes,
  )
  |> map_frame_parser_result
}

fn new_instruction_parser(
  kind: instruction_stream.Kind,
) -> Result(instruction_stream.State, Error) {
  instruction_stream.new(
    kind,
    instruction.default_limits(),
    maximum_instruction_parser_bytes,
  )
  |> map_instruction_parser_result(kind)
}

fn put_input(
  state: State(connection),
  identifier: Int,
  input: Input,
) -> State(connection) {
  State(..state, inputs: dict.insert(state.inputs, identifier, input))
}

fn add_http3_events(
  state: State(connection),
  events: List(http3_state.Event),
) -> Result(State(connection), Error) {
  use state <- result.try(apply_push_rejection_advisories(state, events))
  use #(state, converted) <- result.try(convert_http3_events(state, events, []))
  Ok(add_events(state, converted))
}

fn convert_http3_events(
  state: State(connection),
  events: List(http3_state.Event),
  converted_reversed: List(Event),
) -> Result(#(State(connection), List(Event)), Error) {
  case events {
    [] -> Ok(#(state, list.reverse(converted_reversed)))
    [http3_state.MessageStreamRejected(stream_id, target, code), ..rest] -> {
      let Resource(abort:, ..) = state.resource
      use connection <- result.try(
        abort(state.connection, stream_id, code) |> map_resource_result,
      )
      let inputs = case dict.has_key(state.inputs, stream_id) {
        True -> dict.insert(state.inputs, stream_id, Discarded)
        False -> state.inputs
      }
      let target = case target {
        http3_state.RequestMessage -> RequestStream
        http3_state.PushMessage(push_id) -> PushStream(push_id)
      }
      convert_http3_events(
        State(..state, connection: connection, inputs: inputs),
        rest,
        [
          MessageStreamWasRejected(target, stream_id, code),
          ..converted_reversed
        ],
      )
    }
    [event, ..rest] ->
      convert_http3_events(state, rest, [
        Http3Event(event),
        ..converted_reversed
      ])
  }
}

fn apply_push_rejection_advisories(
  state: State(connection),
  events: List(http3_state.Event),
) -> Result(State(connection), Error) {
  case events {
    [] -> Ok(state)
    [http3_state.PushPromiseRejected(push_id, _), ..rest] -> {
      use state <- result.try(
        case http3_state.push_cancelled(state.http3, push_id) {
          True -> Ok(state)
          False -> cancel_push(state, push_id)
        },
      )
      apply_push_rejection_advisories(state, rest)
    }
    [_, ..rest] -> apply_push_rejection_advisories(state, rest)
  }
}

fn add_events(
  state: State(connection),
  events: List(Event),
) -> State(connection) {
  State(..state, events: list.append(state.events, events))
}

fn map_resource_result(
  value: Result(value, ResourceError),
) -> Result(value, Error) {
  value |> result.map_error(ResourceFailure)
}

fn map_http3_result(
  value: Result(value, http3_state.Error),
) -> Result(value, Error) {
  value |> result.map_error(Http3Failure)
}

fn map_frame_parser_result(
  value: Result(value, frame_parser.Error),
) -> Result(value, Error) {
  value |> result.map_error(FrameParserFailure)
}

fn map_instruction_parser_result(
  value: Result(value, instruction_stream.Error),
  kind: instruction_stream.Kind,
) -> Result(value, Error) {
  value |> result.map_error(fn(error) { InstructionParserFailure(kind, error) })
}

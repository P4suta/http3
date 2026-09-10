//// Pure, bounded HTTP/2 connection and stream state.

import gleam/bit_array
import gleam/dict.{type Dict}
import gleam/http as gleam_http
import gleam/http/request.{type Request}
import gleam/http/response.{type Response}
import gleam/int
import gleam/option.{type Option, None, Some}
import gleam/result
import http/internal/http2/body_length
import http/internal/http2/control
import http/internal/http2/data
import http/internal/http2/data_writer
import http/internal/http2/flow_control
import http/internal/http2/frame
import http/internal/http2/header_codec
import http/internal/http2/header_semantics
import http/internal/http2/header_writer
import http/internal/http2/hpack/decoder as hpack_decoder
import http/internal/http2/message
import http/internal/http2/origin
import http/internal/http2/peer_settings
import http/internal/http2/priority
import http/internal/http2/settings
import http/internal/http2/stream_registry
import http/internal/http2/stream_state

const maximum_origin_entries = 1024

const maximum_priority_field_value_bytes = 4096

/// The local endpoint role.
pub type Role {
  Client
  Server
}

/// Finite limits for connection metadata, streams, and field sections.
pub type Limits {
  Limits(
    maximum_outstanding_settings: Int,
    maximum_debug_bytes: Int,
    maximum_active_streams: Int,
    header_limits: header_codec.Limits,
  )
}

/// Explicit protocol capabilities that remain disabled by default.
pub type Capabilities {
  Capabilities(extended_connect_enabled: Bool)
}

/// A locally allocated stream and the next pure connection state.
pub type StreamOpened {
  StreamOpened(state: State, stream_id: Int)
}

/// Encoded HEADERS/CONTINUATION frames and the next connection state.
pub type HeadersWritten {
  HeadersWritten(state: State, stream_id: Int, frames: List(BitArray))
}

/// DATA write progress under the current dual flow-control windows.
pub type DataWrite {
  DataBlocked(state: State)
  DataWritten(
    state: State,
    frames: List(BitArray),
    remaining: BitArray,
    end_stream_sent: Bool,
  )
}

/// Encoded connection-control frames and the state advanced by that write.
pub type ControlWritten {
  ControlWritten(state: State, frames: List(BitArray))
}

/// WINDOW_UPDATE frames and state after the application consumes inbound DATA.
pub type ReceiveCreditReleased {
  ReceiveCreditReleased(state: State, frames: List(BitArray))
}

/// One side effect requested by a successful pure transition.
pub type Action {
  SendSettingsAcknowledgement
  PeerSettingsChanged(initial_window_delta: Int)
  SettingsAcknowledged
  SendPingAcknowledgement(data: BitArray)
  PingAcknowledged(data: BitArray)
  ConnectionWindowIncreased(available: Int)
  StreamWindowIncreased(stream_id: Int, available: Int)
  StreamReset(stream_id: Int, error_code: Int)
  LegacyPriorityReceived(
    stream_id: Int,
    exclusive: Bool,
    dependency: Int,
    weight: Int,
  )
  OriginsReceived(origins: List(origin.Origin))
  PriorityUpdated(stream_id: Int, priority: priority.Priority)
  PeerGoAway(last_stream_id: Int, error_code: Int, debug_data: BitArray)
  HeadersReceived(header_codec.HeaderSection)
  DataReceived(
    stream_id: Int,
    bytes: BitArray,
    end_stream: Bool,
    flow_controlled_bytes: Int,
  )
  IgnoredUnknownFrame(frame_type: Int)
}

/// A successful state transition and its ordered side effects.
pub type Transition {
  Transition(state: State, actions: List(Action))
}

/// An HTTP/2 connection, stream, or finite-resource failure.
pub type Error {
  InvalidLimits
  ExpectedInitialSettings
  UnexpectedSettingsAcknowledgement
  TooManyOutstandingSettings(maximum: Int)
  PeerConcurrentStreamLimit(maximum: Int)
  MissingRequestMetadata(stream_id: Int)
  InformationalResponseMustNotEnd(status: Int)
  ResponseMustEndStream(status: Int)
  ExtendedConnectNotEnabled
  ConnectionDraining
  WrongRole
  UnsupportedFrame(frame.FrameType)
  FrameFailure(frame.Error)
  ControlFailure(control.Error)
  DataFailure(data.Error)
  DataWriterFailure(data_writer.Error)
  HeaderFailure(header_codec.Error)
  HeaderWriterFailure(header_writer.Error)
  BodyLengthFailure(body_length.Error)
  MessageFailure(message.Error)
  OriginFailure(origin.Error)
  PriorityFailure(priority.Error)
  PriorityUpdateForbidden
  InvalidPriorityTarget(stream_id: Int)
  TooManyPrioritizedStreams(maximum: Int)
  NoRfc7540PrioritiesNotInitial
  NoRfc7540PrioritiesChanged(previous: Bool, received: Bool)
  PeerSettingsFailure(peer_settings.Error)
  FlowControlFailure(flow_control.Error)
  StreamFailure(stream_registry.Error)
  IncreasingGoAwayLastStreamId(previous: Int, received: Int)
}

/// Opaque state. It owns no process, socket, PID, or backend terms.
pub opaque type State {
  State(
    role: Role,
    limits: Limits,
    peer: peer_settings.State,
    received_initial_settings: Bool,
    initial_no_rfc7540_priorities: Option(Bool),
    outstanding_settings: Int,
    connection_send_window: flow_control.Window,
    connection_receive_window: flow_control.Window,
    peer_last_stream_id: Option(Int),
    streams: stream_registry.State,
    body_lengths: body_length.State,
    outbound_body_lengths: body_length.State,
    local_methods: Dict(Int, gleam_http.Method),
    remote_methods: Dict(Int, BitArray),
    priorities: Dict(Int, priority.Priority),
    headers: header_codec.State,
    writer: header_writer.State,
  )
}

/// Construct an empty connection state with explicit finite limits.
pub fn new(role: Role, limits: Limits) -> Result(State, Error) {
  new_with_capabilities(
    role,
    limits,
    Capabilities(extended_connect_enabled: False),
  )
}

/// Construct a connection with explicit opt-in protocol capabilities.
pub fn new_with_capabilities(
  role: Role,
  limits: Limits,
  capabilities: Capabilities,
) -> Result(State, Error) {
  let Limits(
    maximum_outstanding_settings,
    maximum_debug_bytes,
    maximum_active_streams,
    header_limits,
  ) = limits
  let Capabilities(extended_connect_enabled) = capabilities
  case
    maximum_outstanding_settings > 0
    && maximum_debug_bytes >= 0
    && maximum_active_streams > 0
  {
    False -> Error(InvalidLimits)
    True -> {
      use connection_send_window <- result.try(new_connection_window())
      use connection_receive_window <- result.try(new_connection_window())
      use streams <- result.try(
        stream_registry.new(stream_role(role), maximum_active_streams)
        |> result.map_error(StreamFailure),
      )
      use body_lengths <- result.try(
        body_length.new(maximum_active_streams)
        |> result.map_error(BodyLengthFailure),
      )
      use outbound_body_lengths <- result.try(
        body_length.new(maximum_active_streams)
        |> result.map_error(BodyLengthFailure),
      )
      use headers <- result.try(
        header_codec.new(
          header_role(role),
          header_limits,
          extended_connect_enabled: extended_connect_enabled,
        )
        |> result.map_error(HeaderFailure),
      )
      let header_codec.Limits(
        _,
        maximum_header_list_bytes,
        maximum_table_capacity,
        _,
      ) = header_limits
      use writer <- result.try(
        header_writer.new(
          maximum_table_capacity: maximum_table_capacity,
          maximum_header_list_bytes: maximum_header_list_bytes,
          prefer_huffman: True,
        )
        |> result.map_error(HeaderWriterFailure),
      )
      Ok(State(
        role:,
        limits:,
        peer: peer_settings.defaults(),
        received_initial_settings: False,
        initial_no_rfc7540_priorities: None,
        outstanding_settings: 0,
        connection_send_window:,
        connection_receive_window:,
        peer_last_stream_id: None,
        streams:,
        body_lengths:,
        outbound_body_lengths:,
        local_methods: dict.new(),
        remote_methods: dict.new(),
        priorities: dict.new(),
        headers:,
        writer:,
      ))
    }
  }
}

/// Allocate a locally initiated stream unless peer GOAWAY forbids new work.
pub fn open_local_stream(
  state: State,
  end_stream end_stream: Bool,
) -> Result(StreamOpened, Error) {
  case state.peer_last_stream_id {
    Some(_) -> Error(ConnectionDraining)
    None -> {
      use _ <- result.try(require_peer_stream_capacity(state))
      use opened <- result.try(
        stream_registry.open_local(state.streams, end_stream)
        |> result.map_error(StreamFailure),
      )
      let stream_registry.Opened(streams, stream_id) = opened
      Ok(StreamOpened(State(..state, streams: streams), stream_id))
    }
  }
}

/// Encode a standard request on the next client-initiated stream.
pub fn send_request_headers(
  state: State,
  outgoing: Request(body),
  end_stream end_stream: Bool,
) -> Result(HeadersWritten, Error) {
  case state.role {
    Server -> Error(WrongRole)
    Client -> {
      use fields <- result.try(
        message.request_headers(outgoing)
        |> result.map_error(MessageFailure),
      )
      use expected <- result.try(
        message.request_content_length(outgoing)
        |> result.map_error(MessageFailure),
      )
      write_request_field_section(
        state,
        fields,
        outgoing.method,
        expected,
        end_stream,
      )
    }
  }
}

/// Encode an RFC 8441 Extended CONNECT request on a new open stream.
///
/// This transition is unavailable until the peer has explicitly advertised
/// SETTINGS_ENABLE_CONNECT_PROTOCOL=1. It never sends END_STREAM because
/// successful tunnel bytes flow in both directions after the response.
pub fn send_extended_connect_headers(
  state: State,
  outgoing: Request(body),
  protocol protocol: String,
) -> Result(HeadersWritten, Error) {
  case state.role {
    Server -> Error(WrongRole)
    Client -> {
      use _ <- result.try(
        case peer_settings.extended_connect_enabled(state.peer) {
          True -> Ok(Nil)
          False -> Error(ExtendedConnectNotEnabled)
        },
      )
      use fields <- result.try(
        message.extended_connect_headers(outgoing, protocol)
        |> result.map_error(MessageFailure),
      )
      write_request_field_section(
        state,
        fields,
        gleam_http.Connect,
        None,
        False,
      )
    }
  }
}

fn write_request_field_section(
  state: State,
  fields: List(hpack_decoder.Header),
  method: gleam_http.Method,
  expected: Option(Int),
  end_stream: Bool,
) -> Result(HeadersWritten, Error) {
  use opened <- result.try(open_local_stream(state, end_stream: end_stream))
  let StreamOpened(state, stream_id) = opened
  use outbound_body_lengths <- result.try(
    body_length.start(
      state.outbound_body_lengths,
      stream_id: stream_id,
      expected: expected,
      end_stream: end_stream,
    )
    |> result.map_error(BodyLengthFailure),
  )
  use encoded <- result.try(
    header_writer.encode(
      state.writer,
      stream_id: stream_id,
      headers: fields,
      end_stream: end_stream,
      maximum_frame_bytes: peer_settings.maximum_frame_size(state.peer),
    )
    |> result.map_error(HeaderWriterFailure),
  )
  let header_writer.Encoded(writer, frames) = encoded
  let local_methods = dict.insert(state.local_methods, stream_id, method)
  Ok(HeadersWritten(
    State(
      ..state,
      outbound_body_lengths: outbound_body_lengths,
      local_methods: local_methods,
      writer: writer,
    ),
    stream_id,
    frames,
  ))
}

/// Encode a standard response on an existing server-side request stream.
pub fn send_response_headers(
  state: State,
  stream_id: Int,
  outgoing: Response(body),
  end_stream end_stream: Bool,
) -> Result(HeadersWritten, Error) {
  case state.role {
    Client -> Error(WrongRole)
    Server -> {
      use fields <- result.try(
        message.response_headers(outgoing)
        |> result.map_error(MessageFailure),
      )
      use body_tracking <- result.try(prepare_outbound_response(
        state,
        stream_id,
        outgoing,
        end_stream,
      ))
      let #(outbound_body_lengths, remote_methods) = body_tracking
      use updated <- result.try(
        stream_registry.send_headers(state.streams, stream_id, end_stream)
        |> result.map_error(StreamFailure),
      )
      let stream_registry.Updated(streams, _) = updated
      use encoded <- result.try(
        header_writer.encode(
          state.writer,
          stream_id: stream_id,
          headers: fields,
          end_stream: end_stream,
          maximum_frame_bytes: peer_settings.maximum_frame_size(state.peer),
        )
        |> result.map_error(HeaderWriterFailure),
      )
      let header_writer.Encoded(writer, frames) = encoded
      let headers = release_closed_headers(state.headers, streams, stream_id)
      let priorities = release_sent_priority(state, streams, stream_id)
      Ok(HeadersWritten(
        State(
          ..state,
          streams: streams,
          outbound_body_lengths: outbound_body_lengths,
          remote_methods: remote_methods,
          priorities: priorities,
          headers: headers,
          writer: writer,
        ),
        stream_id,
        frames,
      ))
    }
  }
}

fn prepare_outbound_response(
  state: State,
  stream_id: Int,
  outgoing: Response(body),
  end_stream: Bool,
) -> Result(#(body_length.State, Dict(Int, BitArray)), Error) {
  use expected <- result.try(
    message.response_content_length(outgoing)
    |> result.map_error(MessageFailure),
  )
  case header_semantics.is_informational_status(outgoing.status), end_stream {
    True, True ->
      Error(InformationalResponseMustNotEnd(status: outgoing.status))
    True, False -> Ok(#(state.outbound_body_lengths, state.remote_methods))
    False, _ -> {
      use method <- result.try(remote_method(state, stream_id))
      prepare_final_outbound_response(
        state,
        stream_id,
        method,
        outgoing.status,
        expected,
        end_stream,
      )
    }
  }
}

fn prepare_final_outbound_response(
  state: State,
  stream_id: Int,
  method: BitArray,
  status: Int,
  expected: Option(Int),
  end_stream: Bool,
) -> Result(#(body_length.State, Dict(Int, BitArray)), Error) {
  case outbound_response_has_no_body(method, status), end_stream {
    True, False -> Error(ResponseMustEndStream(status: status))
    True, True ->
      Ok(#(
        state.outbound_body_lengths,
        dict.delete(state.remote_methods, stream_id),
      ))
    False, _ -> {
      let expected = case method, status {
        <<"CONNECT">>, status if status >= 200 && status < 300 -> None
        _, _ -> expected
      }
      use outbound_body_lengths <- result.try(
        body_length.start(
          state.outbound_body_lengths,
          stream_id: stream_id,
          expected: expected,
          end_stream: end_stream,
        )
        |> result.map_error(BodyLengthFailure),
      )
      let remote_methods = case end_stream {
        True -> dict.delete(state.remote_methods, stream_id)
        False -> state.remote_methods
      }
      Ok(#(outbound_body_lengths, remote_methods))
    }
  }
}

/// Encode trailers on an existing locally writable stream and end it.
pub fn send_trailers(
  state: State,
  stream_id: Int,
  trailers: List(#(String, String)),
) -> Result(HeadersWritten, Error) {
  use fields <- result.try(
    message.trailer_headers(trailers)
    |> result.map_error(MessageFailure),
  )
  use outbound_body_lengths <- result.try(finish_outbound_body(state, stream_id))
  let remote_methods = release_remote_method(state, stream_id, True)
  use updated <- result.try(
    stream_registry.send_headers(state.streams, stream_id, True)
    |> result.map_error(StreamFailure),
  )
  let stream_registry.Updated(streams, _) = updated
  use encoded <- result.try(
    header_writer.encode(
      state.writer,
      stream_id: stream_id,
      headers: fields,
      end_stream: True,
      maximum_frame_bytes: peer_settings.maximum_frame_size(state.peer),
    )
    |> result.map_error(HeaderWriterFailure),
  )
  let header_writer.Encoded(writer, frames) = encoded
  let headers = release_closed_headers(state.headers, streams, stream_id)
  let priorities = release_sent_priority(state, streams, stream_id)
  Ok(HeadersWritten(
    State(
      ..state,
      streams: streams,
      outbound_body_lengths: outbound_body_lengths,
      remote_methods: remote_methods,
      priorities: priorities,
      headers: headers,
      writer: writer,
    ),
    stream_id,
    frames,
  ))
}

/// Encode as much DATA as current connection and stream credit permit.
pub fn send_data(
  state: State,
  stream_id stream_id: Int,
  bytes bytes: BitArray,
  end_stream end_stream: Bool,
) -> Result(DataWrite, Error) {
  use stream_credit <- result.try(
    stream_registry.send_window(state.streams, stream_id)
    |> result.map_error(StreamFailure),
  )
  use outcome <- result.try(
    data_writer.encode(
      bytes,
      stream_id: stream_id,
      end_stream: end_stream,
      maximum_frame_bytes: peer_settings.maximum_frame_size(state.peer),
      connection_credit: nonnegative(connection_send_window(state)),
      stream_credit: nonnegative(stream_credit),
    )
    |> result.map_error(DataWriterFailure),
  )
  case outcome {
    data_writer.Blocked -> Ok(DataBlocked(state))
    data_writer.Written(frames, consumed, remaining, end_stream_sent) -> {
      use outbound_body_lengths <- result.try(track_outbound_data(
        state,
        stream_id,
        consumed,
        end_stream_sent,
      ))
      let remote_methods =
        release_remote_method(state, stream_id, end_stream_sent)
      use connection_send_window <- result.try(
        flow_control.consume(state.connection_send_window, consumed)
        |> result.map_error(FlowControlFailure),
      )
      use updated <- result.try(
        stream_registry.consume_send_data(
          state.streams,
          stream_id,
          consumed,
          end_stream_sent,
        )
        |> result.map_error(StreamFailure),
      )
      let stream_registry.Updated(streams, _) = updated
      let headers = release_closed_headers(state.headers, streams, stream_id)
      let priorities = release_sent_priority(state, streams, stream_id)
      Ok(DataWritten(
        State(
          ..state,
          streams: streams,
          headers: headers,
          connection_send_window: connection_send_window,
          outbound_body_lengths: outbound_body_lengths,
          remote_methods: remote_methods,
          priorities: priorities,
        ),
        frames,
        remaining,
        end_stream_sent,
      ))
    }
  }
}

/// Encode RST_STREAM and release only the selected stream's retained state.
pub fn reset_stream(
  state: State,
  stream_id stream_id: Int,
  error_code error_code: Int,
) -> Result(ControlWritten, Error) {
  use encoded <- result.try(
    control.encode(
      control.ResetFrame(error_code),
      stream_id,
      peer_settings.maximum_frame_size(state.peer),
    )
    |> result.map_error(ControlFailure),
  )
  use updated <- result.try(
    stream_registry.send_reset(state.streams, stream_id)
    |> result.map_error(StreamFailure),
  )
  let stream_registry.Updated(streams, _) = updated
  let body_lengths = body_length.reset(state.body_lengths, stream_id: stream_id)
  let outbound_body_lengths =
    body_length.reset(state.outbound_body_lengths, stream_id: stream_id)
  let local_methods = dict.delete(state.local_methods, stream_id)
  let remote_methods = dict.delete(state.remote_methods, stream_id)
  let priorities = dict.delete(state.priorities, stream_id)
  let headers = release_closed_headers(state.headers, streams, stream_id)
  Ok(
    ControlWritten(
      State(
        ..state,
        streams:,
        body_lengths:,
        outbound_body_lengths:,
        local_methods:,
        remote_methods:,
        priorities:,
        headers:,
      ),
      [encoded],
    ),
  )
}

/// Encode one bounded RFC 8336 ORIGIN frame. Only a server can advertise
/// authority, and the envelope is fixed to stream 0 with no flags.
pub fn send_origins(
  state: State,
  origins: List(origin.Origin),
) -> Result(ControlWritten, Error) {
  case state.role {
    Client -> Error(WrongRole)
    Server -> {
      use payload <- result.try(
        origin.encode(origins, maximum_entries: maximum_origin_entries)
        |> result.map_error(OriginFailure),
      )
      use encoded <- result.try(
        frame.encode(
          frame.Origin,
          0,
          0,
          payload,
          peer_settings.maximum_frame_size(state.peer),
        )
        |> result.map_error(FrameFailure),
      )
      Ok(ControlWritten(state, [encoded]))
    }
  }
}

/// Encode GOAWAY at the highest peer-initiated stream observed so far.
/// Existing streams remain usable; callers reject later work while draining.
pub fn begin_drain(
  state: State,
  error_code error_code: Int,
  debug_data debug_data: BitArray,
) -> Result(ControlWritten, Error) {
  let last_stream_id = case
    stream_registry.highest_peer_stream_id(state.streams)
  {
    Some(stream_id) -> stream_id
    None -> 0
  }
  use encoded <- result.try(
    control.encode(
      control.GoAwayFrame(last_stream_id, error_code, debug_data),
      0,
      peer_settings.maximum_frame_size(state.peer),
    )
    |> result.map_error(ControlFailure),
  )
  Ok(ControlWritten(state, [encoded]))
}

fn track_outbound_data(
  state: State,
  stream_id: Int,
  octets: Int,
  end_stream: Bool,
) -> Result(body_length.State, Error) {
  use updated <- result.try(
    body_length.receive_data(
      state.outbound_body_lengths,
      stream_id: stream_id,
      octets: octets,
      end_stream: end_stream,
    )
    |> result.map_error(BodyLengthFailure),
  )
  let body_length.Updated(lengths, _) = updated
  Ok(lengths)
}

fn finish_outbound_body(
  state: State,
  stream_id: Int,
) -> Result(body_length.State, Error) {
  body_length.receive_trailers(
    state.outbound_body_lengths,
    stream_id: stream_id,
  )
  |> result.map_error(BodyLengthFailure)
}

fn release_remote_method(
  state: State,
  stream_id: Int,
  end_stream: Bool,
) -> Dict(Int, BitArray) {
  case state.role, end_stream {
    Server, True -> dict.delete(state.remote_methods, stream_id)
    _, _ -> state.remote_methods
  }
}

/// Restore exactly the connection and live-stream credit consumed by DATA.
///
/// A remotely closed stream needs no further stream-level credit, but its
/// flow-controlled bytes must still be returned to the connection window.
pub fn release_receive_credit(
  state: State,
  stream_id stream_id: Int,
  octets octets: Int,
) -> Result(ReceiveCreditReleased, Error) {
  use connection_receive_window <- result.try(
    flow_control.increase(state.connection_receive_window, octets)
    |> result.map_error(FlowControlFailure),
  )
  use connection_frame <- result.try(encode_window_update(state, 0, octets))
  case stream_registry.stream_state(state.streams, stream_id) {
    stream_state.Open | stream_state.HalfClosedLocal -> {
      use streams <- result.try(
        stream_registry.restore_receive_window(state.streams, stream_id, octets)
        |> result.map_error(StreamFailure),
      )
      use stream_frame <- result.try(encode_window_update(
        state,
        stream_id,
        octets,
      ))
      Ok(
        ReceiveCreditReleased(
          State(
            ..state,
            streams: streams,
            connection_receive_window: connection_receive_window,
          ),
          [connection_frame, stream_frame],
        ),
      )
    }
    stream_state.HalfClosedRemote | stream_state.Closed ->
      Ok(
        ReceiveCreditReleased(
          State(..state, connection_receive_window: connection_receive_window),
          [connection_frame],
        ),
      )
    stream_state.Idle
    | stream_state.ReservedLocal
    | stream_state.ReservedRemote ->
      Error(StreamFailure(stream_registry.UnknownStream(stream_id: stream_id)))
  }
}

/// Record that one locally generated non-ACK SETTINGS frame was sent.
pub fn record_settings_sent(state: State) -> Result(State, Error) {
  let Limits(maximum, _, _, _) = state.limits
  case state.outstanding_settings < maximum {
    True ->
      Ok(State(..state, outstanding_settings: state.outstanding_settings + 1))
    False -> Error(TooManyOutstandingSettings(maximum: maximum))
  }
}

/// Apply one already envelope-validated peer frame transactionally.
pub fn receive_frame(
  state: State,
  header: frame.Header,
  payload: BitArray,
) -> Result(Transition, Error) {
  case state.received_initial_settings {
    False -> receive_initial_settings(state, header, payload)
    True -> receive_after_settings(state, header, payload)
  }
}

/// Whether the mandatory first peer SETTINGS frame has been accepted.
pub fn received_initial_settings(state: State) -> Bool {
  state.received_initial_settings
}

/// The latest transactionally applied peer SETTINGS.
pub fn peer_settings(state: State) -> peer_settings.State {
  state.peer
}

/// Number of locally sent SETTINGS frames awaiting acknowledgements.
pub fn outstanding_settings(state: State) -> Int {
  state.outstanding_settings
}

/// Current connection-level credit for outbound DATA.
pub fn connection_send_window(state: State) -> Int {
  flow_control.available(state.connection_send_window)
}

/// Current connection-level credit for inbound DATA.
pub fn connection_receive_window(state: State) -> Int {
  flow_control.available(state.connection_receive_window)
}

/// Current outbound credit for one active stream.
pub fn stream_send_window(state: State, stream_id: Int) -> Result(Int, Error) {
  stream_registry.send_window(state.streams, stream_id)
  |> result.map_error(StreamFailure)
}

/// Current inbound credit for one active stream.
pub fn stream_receive_window(
  state: State,
  stream_id: Int,
) -> Result(Int, Error) {
  stream_registry.receive_window(state.streams, stream_id)
  |> result.map_error(StreamFailure)
}

/// Lifecycle state for a known, skipped, closed, or idle stream identifier.
pub fn stream_state(state: State, stream_id: Int) -> stream_state.State {
  stream_registry.stream_state(state.streams, stream_id)
}

/// Latest effective priority retained for a request or push response.
pub fn stream_priority(
  state: State,
  stream_id: Int,
) -> Option(priority.Priority) {
  case dict.get(state.priorities, stream_id) {
    Ok(priority) -> Some(priority)
    Error(Nil) -> None
  }
}

/// Whether the peer has sent a valid GOAWAY frame.
pub fn draining(state: State) -> Bool {
  state.peer_last_stream_id != None
}

/// Most restrictive last-stream identifier received from GOAWAY.
pub fn peer_last_stream_id(state: State) -> Option(Int) {
  state.peer_last_stream_id
}

fn receive_initial_settings(
  state: State,
  header: frame.Header,
  payload: BitArray,
) -> Result(Transition, Error) {
  let frame.Header(_, frame_type, flags, _) = header
  case frame_type == frame.Settings && int.bitwise_and(flags, 0x1) == 0 {
    False -> Error(ExpectedInitialSettings)
    True -> {
      use event <- result.try(decode_control(state, header, payload))
      case event {
        control.SettingsFrame(values) ->
          apply_peer_settings(state, values, True)
        _ -> Error(ExpectedInitialSettings)
      }
    }
  }
}

fn receive_after_settings(
  state: State,
  header: frame.Header,
  payload: BitArray,
) -> Result(Transition, Error) {
  let frame.Header(_, frame_type, _, _) = header
  case header_codec.is_idle(state.headers) {
    False -> receive_headers(state, header, payload)
    True ->
      case frame_type {
        frame.Headers | frame.Continuation ->
          receive_headers(state, header, payload)
        frame.Data -> receive_data(state, header, payload)
        frame.Origin -> receive_origin(state, header, payload)
        frame.PriorityUpdate -> receive_priority_update(state, header, payload)
        frame.Unknown(raw_type) ->
          ignore_unknown(state, header, payload, raw_type)
        frame.Settings
        | frame.Ping
        | frame.GoAway
        | frame.Priority
        | frame.RstStream
        | frame.WindowUpdate -> receive_control(state, header, payload)
        frame.PushPromise -> Error(UnsupportedFrame(frame.PushPromise))
      }
  }
}

fn receive_origin(
  state: State,
  header: frame.Header,
  payload: BitArray,
) -> Result(Transition, Error) {
  let frame.Header(_, _, flags, stream_id) = header
  case state.role, stream_id, int.bitwise_and(flags, 0x0f) == 0 {
    Client, 0, True -> {
      use origins <- result.try(
        origin.decode(payload, maximum_entries: maximum_origin_entries)
        |> result.map_error(OriginFailure),
      )
      Ok(Transition(state, [OriginsReceived(origins: origins)]))
    }
    _, _, _ -> Ok(Transition(state, []))
  }
}

fn receive_priority_update(
  state: State,
  header: frame.Header,
  payload: BitArray,
) -> Result(Transition, Error) {
  case state.role {
    Client -> Error(PriorityUpdateForbidden)
    Server -> {
      use update <- result.try(
        priority.decode(
          header,
          payload,
          maximum_field_value_bytes: maximum_priority_field_value_bytes,
        )
        |> result.map_error(PriorityFailure),
      )
      let priority.Update(stream_id, value) = update
      store_priority_update(state, stream_id, value)
    }
  }
}

fn store_priority_update(
  state: State,
  stream_id: Int,
  value: priority.Priority,
) -> Result(Transition, Error) {
  case stream_id % 2, stream_state(state, stream_id) {
    1, stream_state.Idle -> store_idle_priority(state, stream_id, value)
    1, stream_state.Open | 1, stream_state.HalfClosedRemote ->
      priority_transition(state, stream_id, value)
    1, stream_state.HalfClosedLocal | 1, stream_state.Closed ->
      Ok(Transition(state, []))
    0, stream_state.ReservedLocal | 0, stream_state.HalfClosedRemote ->
      priority_transition(state, stream_id, value)
    0, stream_state.Closed -> Ok(Transition(state, []))
    _, _ -> Error(InvalidPriorityTarget(stream_id: stream_id))
  }
}

fn store_idle_priority(
  state: State,
  stream_id: Int,
  value: priority.Priority,
) -> Result(Transition, Error) {
  let Limits(_, _, maximum, _) = state.limits
  let already_retained = dict.has_key(state.priorities, stream_id)
  let admitted =
    already_retained
    || stream_registry.active_count(state.streams) + idle_priority_count(state)
    < maximum
  case admitted {
    True -> priority_transition(state, stream_id, value)
    False -> Error(TooManyPrioritizedStreams(maximum: maximum))
  }
}

fn priority_transition(
  state: State,
  stream_id: Int,
  value: priority.Priority,
) -> Result(Transition, Error) {
  let priorities = dict.insert(state.priorities, stream_id, value)
  Ok(
    Transition(State(..state, priorities: priorities), [
      PriorityUpdated(stream_id: stream_id, priority: value),
    ]),
  )
}

fn idle_priority_count(state: State) -> Int {
  count_idle_priorities(state, dict.to_list(state.priorities), 0)
}

fn count_idle_priorities(
  state: State,
  entries: List(#(Int, priority.Priority)),
  count: Int,
) -> Int {
  case entries {
    [] -> count
    [#(stream_id, _), ..rest] ->
      count_idle_priorities(state, rest, case stream_state(state, stream_id) {
        stream_state.Idle -> count + 1
        _ -> count
      })
  }
}

fn receive_headers(
  state: State,
  header: frame.Header,
  payload: BitArray,
) -> Result(Transition, Error) {
  use outcome <- result.try(
    header_codec.accept(state.headers, header, payload)
    |> result.map_error(HeaderFailure),
  )
  case outcome {
    header_codec.Waiting(headers) ->
      Ok(Transition(State(..state, headers: headers), []))
    header_codec.Complete(headers, section) -> {
      let section = ignore_legacy_headers_priority(state, section)
      let header_codec.HeaderSection(stream_id, end_stream, _, _) = section
      let #(priorities, priority_update) =
        receive_request_priority(state, section)
      use body_tracking <- result.try(receive_body_headers(state, section))
      let #(body_lengths, local_methods) = body_tracking
      let remote_methods = retain_remote_request_method(state, section)
      use updated <- result.try(
        stream_registry.receive_headers(state.streams, stream_id, end_stream)
        |> result.map_error(StreamFailure),
      )
      let stream_registry.Updated(streams, _) = updated
      let headers = release_closed_headers(headers, streams, stream_id)
      Ok(
        Transition(
          State(
            ..state,
            streams: streams,
            body_lengths: body_lengths,
            local_methods: local_methods,
            remote_methods: remote_methods,
            priorities: priorities,
            headers: headers,
          ),
          case priority_update {
            Some(value) -> [
              PriorityUpdated(stream_id: stream_id, priority: value),
              HeadersReceived(section),
            ]
            None -> [HeadersReceived(section)]
          },
        ),
      )
    }
  }
}

fn receive_request_priority(
  state: State,
  section: header_codec.HeaderSection,
) -> #(Dict(Int, priority.Priority), Option(priority.Priority)) {
  case state.role, section {
    Server,
      header_codec.HeaderSection(
        stream_id,
        _,
        header_semantics.Validated(
          header_semantics.RequestControlData(_),
          fields,
          _,
        ),
        _,
      )
    ->
      case dict.has_key(state.priorities, stream_id) {
        True -> #(state.priorities, None)
        False -> apply_priority_field(state.priorities, stream_id, fields)
      }
    _, _ -> #(state.priorities, None)
  }
}

fn apply_priority_field(
  priorities: Dict(Int, priority.Priority),
  stream_id: Int,
  fields: List(hpack_decoder.Header),
) -> #(Dict(Int, priority.Priority), Option(priority.Priority)) {
  case priority_field_value(fields, None) {
    None -> #(priorities, None)
    Some(encoded) ->
      case
        priority.parse(
          value: encoded,
          maximum_bytes: maximum_priority_field_value_bytes,
        )
      {
        // nolint: thrown_away_error -- an invalid advisory Priority field is ignored.
        Error(_) -> #(priorities, None)
        Ok(value) -> #(dict.insert(priorities, stream_id, value), Some(value))
      }
  }
}

fn priority_field_value(
  fields: List(hpack_decoder.Header),
  combined: Option(BitArray),
) -> Option(BitArray) {
  case fields {
    [] -> combined
    [hpack_decoder.Header(<<"priority">>, value, _), ..rest] -> {
      let combined = case combined {
        None -> Some(value)
        Some(previous) -> Some(<<previous:bits, ", ":utf8, value:bits>>)
      }
      priority_field_value(rest, combined)
    }
    [_, ..rest] -> priority_field_value(rest, combined)
  }
}

fn receive_data(
  state: State,
  header: frame.Header,
  payload: BitArray,
) -> Result(Transition, Error) {
  use decoded <- result.try(
    data.decode(header, payload)
    |> result.map_error(DataFailure),
  )
  let data.Data(bytes, end_stream, flow_controlled_bytes) = decoded
  let frame.Header(_, _, _, stream_id) = header
  use body_tracking <- result.try(receive_body_data(
    state,
    stream_id,
    bit_array.byte_size(bytes),
    end_stream,
  ))
  let #(body_lengths, local_methods) = body_tracking
  use connection_receive_window <- result.try(
    flow_control.consume(state.connection_receive_window, flow_controlled_bytes)
    |> result.map_error(FlowControlFailure),
  )
  use updated <- result.try(
    stream_registry.consume_receive_data(
      state.streams,
      stream_id,
      flow_controlled_bytes,
      end_stream,
    )
    |> result.map_error(StreamFailure),
  )
  let stream_registry.Updated(streams, _) = updated
  let headers = release_closed_headers(state.headers, streams, stream_id)
  Ok(
    Transition(
      State(
        ..state,
        streams: streams,
        body_lengths: body_lengths,
        local_methods: local_methods,
        headers: headers,
        connection_receive_window: connection_receive_window,
      ),
      [DataReceived(stream_id, bytes, end_stream, flow_controlled_bytes)],
    ),
  )
}

fn receive_control(
  state: State,
  header: frame.Header,
  payload: BitArray,
) -> Result(Transition, Error) {
  use event <- result.try(decode_control(state, header, payload))
  let frame.Header(_, _, _, stream_id) = header
  case event {
    control.SettingsFrame(values) -> apply_peer_settings(state, values, False)
    control.SettingsAcknowledgement -> acknowledge_settings(state)
    control.PingFrame(False, ping_data) ->
      Ok(Transition(state, [SendPingAcknowledgement(ping_data)]))
    control.PingFrame(True, ping_data) ->
      Ok(Transition(state, [PingAcknowledged(ping_data)]))
    control.WindowUpdateFrame(increment) ->
      increase_send_window(state, stream_id, increment)
    control.GoAwayFrame(last_stream_id, error_code, debug_data) ->
      receive_goaway(state, last_stream_id, error_code, debug_data)
    control.PriorityFrame(exclusive, dependency, weight) ->
      case legacy_priorities_disabled(state) {
        True -> Ok(Transition(state, []))
        False ->
          Ok(
            Transition(state, [
              LegacyPriorityReceived(
                stream_id: stream_id,
                exclusive: exclusive,
                dependency: dependency,
                weight: weight,
              ),
            ]),
          )
      }
    control.ResetFrame(error_code) -> {
      use updated <- result.try(
        stream_registry.receive_reset(state.streams, stream_id)
        |> result.map_error(StreamFailure),
      )
      let stream_registry.Updated(streams, _) = updated
      let body_lengths =
        body_length.reset(state.body_lengths, stream_id: stream_id)
      let outbound_body_lengths =
        body_length.reset(state.outbound_body_lengths, stream_id: stream_id)
      let local_methods = dict.delete(state.local_methods, stream_id)
      let remote_methods = dict.delete(state.remote_methods, stream_id)
      let priorities = dict.delete(state.priorities, stream_id)
      let headers = release_closed_headers(state.headers, streams, stream_id)
      Ok(
        Transition(
          State(
            ..state,
            streams: streams,
            body_lengths: body_lengths,
            outbound_body_lengths: outbound_body_lengths,
            local_methods: local_methods,
            remote_methods: remote_methods,
            priorities: priorities,
            headers: headers,
          ),
          [
            StreamReset(stream_id: stream_id, error_code: error_code),
          ],
        ),
      )
    }
  }
}

fn receive_body_headers(
  state: State,
  section: header_codec.HeaderSection,
) -> Result(#(body_length.State, Dict(Int, gleam_http.Method)), Error) {
  let header_codec.HeaderSection(
    stream_id,
    end_stream,
    header_semantics.Validated(control, _, expected),
    _,
  ) = section
  case state.role {
    Client ->
      receive_client_body_headers(
        state,
        stream_id,
        end_stream,
        control,
        expected,
      )
    Server ->
      receive_server_body_headers(
        state,
        stream_id,
        end_stream,
        control,
        expected,
      )
  }
}

fn retain_remote_request_method(
  state: State,
  section: header_codec.HeaderSection,
) -> Dict(Int, BitArray) {
  case state.role, section {
    Server,
      header_codec.HeaderSection(
        stream_id,
        _,
        header_semantics.Validated(
          header_semantics.RequestControlData(header_semantics.RequestControl(
            method,
            _,
            _,
            _,
            _,
          )),
          _,
          _,
        ),
        _,
      )
    -> dict.insert(state.remote_methods, stream_id, method)
    _, _ -> state.remote_methods
  }
}

fn receive_server_body_headers(
  state: State,
  stream_id: Int,
  end_stream: Bool,
  control: header_semantics.Control,
  expected: Option(Int),
) -> Result(#(body_length.State, Dict(Int, gleam_http.Method)), Error) {
  case control {
    header_semantics.RequestControlData(_) -> {
      use body_lengths <- result.try(
        body_length.start(
          state.body_lengths,
          stream_id: stream_id,
          expected: expected,
          end_stream: end_stream,
        )
        |> result.map_error(BodyLengthFailure),
      )
      Ok(#(body_lengths, state.local_methods))
    }
    header_semantics.TrailerControlData -> {
      use body_lengths <- result.try(
        body_length.receive_trailers(state.body_lengths, stream_id: stream_id)
        |> result.map_error(BodyLengthFailure),
      )
      Ok(#(body_lengths, state.local_methods))
    }
    header_semantics.ResponseControlData(_) ->
      Ok(#(state.body_lengths, state.local_methods))
  }
}

fn receive_client_body_headers(
  state: State,
  stream_id: Int,
  end_stream: Bool,
  control: header_semantics.Control,
  expected: Option(Int),
) -> Result(#(body_length.State, Dict(Int, gleam_http.Method)), Error) {
  case control {
    header_semantics.ResponseControlData(status)
      if status >= 100 && status < 200
    ->
      case end_stream {
        True -> Error(InformationalResponseMustNotEnd(status: status))
        False -> Ok(#(state.body_lengths, state.local_methods))
      }
    header_semantics.ResponseControlData(status) -> {
      use method <- result.try(local_method(state, stream_id))
      receive_final_response_headers(
        state,
        stream_id,
        end_stream,
        method,
        status,
        expected,
      )
    }
    header_semantics.TrailerControlData -> {
      use body_lengths <- result.try(
        body_length.receive_trailers(state.body_lengths, stream_id: stream_id)
        |> result.map_error(BodyLengthFailure),
      )
      Ok(#(body_lengths, dict.delete(state.local_methods, stream_id)))
    }
    header_semantics.RequestControlData(_) ->
      Ok(#(state.body_lengths, state.local_methods))
  }
}

fn receive_final_response_headers(
  state: State,
  stream_id: Int,
  end_stream: Bool,
  method: gleam_http.Method,
  status: Int,
  expected: Option(Int),
) -> Result(#(body_length.State, Dict(Int, gleam_http.Method)), Error) {
  case response_has_no_body(method, status), end_stream {
    True, False -> Error(ResponseMustEndStream(status: status))
    True, True ->
      Ok(#(state.body_lengths, dict.delete(state.local_methods, stream_id)))
    False, _ ->
      start_response_body(
        state,
        stream_id,
        end_stream,
        method,
        status,
        expected,
      )
  }
}

fn start_response_body(
  state: State,
  stream_id: Int,
  end_stream: Bool,
  method: gleam_http.Method,
  status: Int,
  expected: Option(Int),
) -> Result(#(body_length.State, Dict(Int, gleam_http.Method)), Error) {
  let expected = case method, status {
    gleam_http.Connect, status if status >= 200 && status < 300 -> None
    _, _ -> expected
  }
  use body_lengths <- result.try(
    body_length.start(
      state.body_lengths,
      stream_id: stream_id,
      expected: expected,
      end_stream: end_stream,
    )
    |> result.map_error(BodyLengthFailure),
  )
  let local_methods = case end_stream {
    True -> dict.delete(state.local_methods, stream_id)
    False -> state.local_methods
  }
  Ok(#(body_lengths, local_methods))
}

fn receive_body_data(
  state: State,
  stream_id: Int,
  octets: Int,
  end_stream: Bool,
) -> Result(#(body_length.State, Dict(Int, gleam_http.Method)), Error) {
  use updated <- result.try(
    body_length.receive_data(
      state.body_lengths,
      stream_id: stream_id,
      octets: octets,
      end_stream: end_stream,
    )
    |> result.map_error(BodyLengthFailure),
  )
  let body_length.Updated(body_lengths, _) = updated
  let local_methods = case state.role, end_stream {
    Client, True -> dict.delete(state.local_methods, stream_id)
    _, _ -> state.local_methods
  }
  Ok(#(body_lengths, local_methods))
}

fn local_method(
  state: State,
  stream_id: Int,
) -> Result(gleam_http.Method, Error) {
  case dict.get(state.local_methods, stream_id) {
    Ok(method) -> Ok(method)
    Error(Nil) -> Error(MissingRequestMetadata(stream_id: stream_id))
  }
}

fn remote_method(state: State, stream_id: Int) -> Result(BitArray, Error) {
  case dict.get(state.remote_methods, stream_id) {
    Ok(method) -> Ok(method)
    Error(Nil) -> Error(MissingRequestMetadata(stream_id: stream_id))
  }
}

fn response_has_no_body(method: gleam_http.Method, status: Int) -> Bool {
  method == gleam_http.Head || status == 204 || status == 304
}

fn outbound_response_has_no_body(method: BitArray, status: Int) -> Bool {
  method == <<"HEAD">> || status == 204 || status == 304
}

fn increase_send_window(
  state: State,
  stream_id: Int,
  increment: Int,
) -> Result(Transition, Error) {
  case stream_id {
    0 -> {
      use window <- result.try(
        flow_control.increase(state.connection_send_window, increment)
        |> result.map_error(FlowControlFailure),
      )
      let available = flow_control.available(window)
      Ok(
        Transition(State(..state, connection_send_window: window), [
          ConnectionWindowIncreased(available: available),
        ]),
      )
    }
    _ ->
      case stream_registry.stream_state(state.streams, stream_id) {
        stream_state.Closed -> Ok(Transition(state, []))
        _ -> {
          use streams <- result.try(
            stream_registry.increase_send_window(
              state.streams,
              stream_id,
              increment,
            )
            |> result.map_error(StreamFailure),
          )
          use available <- result.try(
            stream_registry.send_window(streams, stream_id)
            |> result.map_error(StreamFailure),
          )
          Ok(
            Transition(State(..state, streams: streams), [
              StreamWindowIncreased(stream_id: stream_id, available: available),
            ]),
          )
        }
      }
  }
}

fn encode_window_update(
  state: State,
  stream_id: Int,
  increment: Int,
) -> Result(BitArray, Error) {
  control.encode(
    control.WindowUpdateFrame(increment),
    stream_id,
    peer_settings.maximum_frame_size(state.peer),
  )
  |> result.map_error(ControlFailure)
}

fn receive_goaway(
  state: State,
  last_stream_id: Int,
  error_code: Int,
  debug_data: BitArray,
) -> Result(Transition, Error) {
  case state.peer_last_stream_id {
    Some(previous) if last_stream_id > previous ->
      Error(IncreasingGoAwayLastStreamId(previous:, received: last_stream_id))
    _ ->
      Ok(
        Transition(State(..state, peer_last_stream_id: Some(last_stream_id)), [
          PeerGoAway(last_stream_id:, error_code:, debug_data:),
        ]),
      )
  }
}

fn ignore_unknown(
  state: State,
  header: frame.Header,
  payload: BitArray,
  raw_type: Int,
) -> Result(Transition, Error) {
  let frame.Header(length, _, _, _) = header
  case bit_array.bit_size(payload) % 8, bit_array.byte_size(payload) == length {
    remainder, _ if remainder != 0 ->
      Error(ControlFailure(control.NonByteAligned))
    _, False -> Error(ControlFailure(control.InvalidPayloadLength))
    0, True ->
      Ok(Transition(state, [IgnoredUnknownFrame(frame_type: raw_type)]))
    _, True -> Error(ControlFailure(control.NonByteAligned))
  }
}

fn apply_peer_settings(
  state: State,
  values: List(settings.Setting),
  initial: Bool,
) -> Result(Transition, Error) {
  use initial_no_rfc7540_priorities <- result.try(
    validate_no_rfc7540_priorities(state, values, initial),
  )
  use applied <- result.try(
    peer_settings.apply(state.peer, values, peer_role(state.role))
    |> result.map_error(PeerSettingsFailure),
  )
  let peer_settings.Applied(peer, initial_window_delta) = applied
  use streams <- result.try(
    stream_registry.apply_peer_initial_window_size(
      state.streams,
      peer_settings.initial_window_size(peer),
    )
    |> result.map_error(StreamFailure),
  )
  use writer <- result.try(update_writer_capacity(state, peer))
  Ok(
    Transition(
      State(
        ..state,
        peer: peer,
        initial_no_rfc7540_priorities: initial_no_rfc7540_priorities,
        streams: streams,
        writer: writer,
        received_initial_settings: state.received_initial_settings || initial,
      ),
      [
        SendSettingsAcknowledgement,
        PeerSettingsChanged(initial_window_delta: initial_window_delta),
      ],
    ),
  )
}

fn validate_no_rfc7540_priorities(
  state: State,
  values: List(settings.Setting),
  initial: Bool,
) -> Result(Option(Bool), Error) {
  let received = last_no_rfc7540_priorities(values, None)
  case initial, state.initial_no_rfc7540_priorities, received {
    True, _, value -> Ok(value)
    False, previous, None -> Ok(previous)
    False, None, Some(_) -> Error(NoRfc7540PrioritiesNotInitial)
    False, Some(previous), Some(received) if previous != received ->
      Error(NoRfc7540PrioritiesChanged(previous: previous, received: received))
    False, Some(previous), Some(_) -> Ok(Some(previous))
  }
}

fn last_no_rfc7540_priorities(
  values: List(settings.Setting),
  found: Option(Bool),
) -> Option(Bool) {
  case values {
    [] -> found
    [settings.NoRfc7540Priorities(value), ..rest] ->
      last_no_rfc7540_priorities(rest, Some(value))
    [_, ..rest] -> last_no_rfc7540_priorities(rest, found)
  }
}

fn update_writer_capacity(
  state: State,
  peer: peer_settings.State,
) -> Result(header_writer.State, Error) {
  let previous = effective_writer_capacity(state, state.peer)
  let replacement = effective_writer_capacity(state, peer)
  case previous == replacement {
    True -> Ok(state.writer)
    False ->
      header_writer.set_capacity(state.writer, replacement)
      |> result.map_error(HeaderWriterFailure)
  }
}

fn effective_writer_capacity(state: State, peer: peer_settings.State) -> Int {
  let Limits(_, _, _, header_limits) = state.limits
  let header_codec.Limits(_, _, local_maximum, _) = header_limits
  let peer_maximum = peer_settings.header_table_size(peer)
  case local_maximum < peer_maximum {
    True -> local_maximum
    False -> peer_maximum
  }
}

fn acknowledge_settings(state: State) -> Result(Transition, Error) {
  case state.outstanding_settings {
    0 -> Error(UnexpectedSettingsAcknowledgement)
    count ->
      Ok(
        Transition(State(..state, outstanding_settings: count - 1), [
          SettingsAcknowledged,
        ]),
      )
  }
}

fn decode_control(
  state: State,
  header: frame.Header,
  payload: BitArray,
) -> Result(control.Event, Error) {
  let Limits(_, maximum_debug_bytes, _, _) = state.limits
  control.decode(header, payload, maximum_debug_bytes)
  |> result.map_error(ControlFailure)
}

fn new_connection_window() -> Result(flow_control.Window, Error) {
  flow_control.new(65_535)
  |> result.map_error(FlowControlFailure)
}

fn peer_role(role: Role) -> peer_settings.Role {
  case role {
    Client -> peer_settings.Client
    Server -> peer_settings.Server
  }
}

fn stream_role(role: Role) -> stream_registry.Role {
  case role {
    Client -> stream_registry.Client
    Server -> stream_registry.Server
  }
}

fn header_role(role: Role) -> header_codec.Role {
  case role {
    Client -> header_codec.Client
    Server -> header_codec.Server
  }
}

fn release_closed_headers(
  headers: header_codec.State,
  streams: stream_registry.State,
  stream_id: Int,
) -> header_codec.State {
  case stream_registry.stream_state(streams, stream_id) {
    stream_state.Closed -> header_codec.release(headers, stream_id)
    _ -> headers
  }
}

fn ignore_legacy_headers_priority(
  state: State,
  section: header_codec.HeaderSection,
) -> header_codec.HeaderSection {
  case legacy_priorities_disabled(state), section {
    True, header_codec.HeaderSection(stream_id, end_stream, validated, _) ->
      header_codec.HeaderSection(stream_id, end_stream, validated, None)
    False, _ -> section
  }
}

fn legacy_priorities_disabled(state: State) -> Bool {
  state.role == Server && peer_settings.rfc7540_priorities_disabled(state.peer)
}

fn release_sent_priority(
  state: State,
  streams: stream_registry.State,
  stream_id: Int,
) -> Dict(Int, priority.Priority) {
  case state.role, stream_registry.stream_state(streams, stream_id) {
    Server, stream_state.HalfClosedLocal | Server, stream_state.Closed ->
      dict.delete(state.priorities, stream_id)
    _, _ -> state.priorities
  }
}

fn require_peer_stream_capacity(state: State) -> Result(Nil, Error) {
  let active = stream_registry.local_active_count(state.streams)
  case peer_settings.maximum_concurrent_streams(state.peer) {
    Some(maximum) if active >= maximum ->
      Error(PeerConcurrentStreamLimit(maximum: maximum))
    _ -> Ok(Nil)
  }
}

fn nonnegative(value: Int) -> Int {
  case value {
    value if value < 0 -> 0
    value -> value
  }
}

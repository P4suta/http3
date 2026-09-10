//// Synchronous bounded HTTP/3 requests over the shared opaque connection.

import gleam/bit_array
import gleam/int
import gleam/list
import gleam/option.{type Option, None, Some}
import gleam/result
import http3/internal/native/client_connection
import http3/internal/native/connection_state as http3_state
import http3/internal/native/header_semantics
import http3/internal/qpack/header.{type Header, Header}
import quic_core.{type AddressFamily, type Version}
import quic_core/diagnostics
import quic_core/failure as core_failure

const maximum_request_data_chunk_bytes = 65_535

const default_stream_buffer_bytes = 262_144

const default_frame_limit = 65_536

const default_datagram_limit = 65_527

const default_qpack_table_limit = 4096

const default_qpack_blocked_stream_limit = 16

const default_bidirectional_stream_limit = 100

const default_unidirectional_stream_limit = 100

/// Validated inputs for one native request.
pub type Config {
  Config(
    hostname: String,
    port: Int,
    address_family: AddressFamily,
    connect_address: Option(BitArray),
    dns_timeout_milliseconds: Int,
    connect_timeout_milliseconds: Int,
    handshake_timeout_milliseconds: Int,
    timeout_milliseconds: Int,
    operation_timeout_milliseconds: Int,
    idle_timeout_milliseconds: Int,
    maximum_request_body_bytes: Int,
    maximum_response_body_bytes: Int,
    endpoint_memory_limit: Int,
    telemetry_limit: Int,
    ca_certificates: Option(List(BitArray)),
    quic_version: Version,
    keepalive_milliseconds: Int,
    qlog_directory: String,
  )
}

/// A complete bounded HTTP response.
pub type Response {
  Response(status: Int, headers: List(#(String, String)), body: BitArray)
}

/// Stable failures without leaking protocol-state representations.
pub type Error {
  InvalidInput
  ResolutionFailed
  SocketUnavailable
  DnsTimeout
  ConnectTimeout
  HandshakeTimeout
  OperationTimeout
  TotalTimeout
  TrustStoreFailed
  TlsHandshakeFailed
  QuicTransportFailed
  CoreFailure(core_failure.Failure)
  Http3ProtocolFailed
  Http3OperationFailed
  PeerClosed
  StreamReset(Int)
  InvalidHeaderEncoding
  ResponseBodyTooLarge(Int)
  QlogUnavailable
  VersionNegotiationReceived
  VersionNegotiationFailed
}

type Collector {
  Collector(
    status: Option(Int),
    headers: List(#(String, String)),
    reversed_body: List(BitArray),
    body_size: Int,
    finished: Bool,
  )
}

/// Run one request on one connection and close its socket before return.
pub fn send(
  config: Config,
  fields: List(#(String, String)),
  body: BitArray,
) -> Result(Response, Error) {
  use Nil <- result.try(validate(config, body))
  let total_deadline =
    diagnostics.monotonic_milliseconds() + config.timeout_milliseconds
  use headers <- result.try(encode_headers(fields))
  use connection <- result.try(
    client_connection.connect(connection_config(config, body))
    |> result.map_error(map_connection_error),
  )
  send_connected(config, connection, headers, body, total_deadline)
}

fn send_connected(
  config: Config,
  connection: client_connection.State,
  headers: List(Header),
  body: BitArray,
  total_deadline: Int,
) -> Result(Response, Error) {
  case open_qlog(config.qlog_directory, config.telemetry_limit) {
    Error(_) -> {
      client_connection.close(connection, 0x100, "qlog unavailable")
      Error(QlogUnavailable)
    }
    Ok(writer) ->
      send_with_qlog(config, connection, headers, body, total_deadline, writer)
  }
}

fn send_with_qlog(
  config: Config,
  connection: client_connection.State,
  headers: List(Header),
  body: BitArray,
  total_deadline: Int,
  writer: Option(diagnostics.Writer),
) -> Result(Response, Error) {
  record_qlog_bootstrap(writer, connection)
  let outcome =
    request(
      connection,
      headers,
      body,
      config.maximum_response_body_bytes,
      total_deadline,
      config.operation_timeout_milliseconds,
      config.keepalive_milliseconds,
      writer,
    )
  client_connection.close(connection, 0, "one-shot complete")
  case outcome, close_qlog(writer) {
    outcome, Ok(Nil) -> outcome
    Error(error), Error(_) -> Error(error)
    Ok(_), Error(_) -> Error(QlogUnavailable)
  }
}

fn connection_config(
  config: Config,
  body: BitArray,
) -> client_connection.Config {
  client_connection.Config(
    hostname: config.hostname,
    port: config.port,
    address_family: config.address_family,
    connect_address: config.connect_address,
    dns_timeout_milliseconds: config.dns_timeout_milliseconds,
    connect_timeout_milliseconds: config.connect_timeout_milliseconds,
    handshake_timeout_milliseconds: config.handshake_timeout_milliseconds,
    timeout_milliseconds: config.timeout_milliseconds,
    idle_timeout_milliseconds: config.idle_timeout_milliseconds,
    ca_certificates: config.ca_certificates,
    http_datagrams: False,
    resumption_ticket: None,
    address_token: <<>>,
    maximum_pushes: 0,
    quic_version: config.quic_version,
    stream_buffer_limit: int.max(
      default_stream_buffer_bytes,
      bit_array.byte_size(body) + default_frame_limit,
    ),
    endpoint_memory_limit: config.endpoint_memory_limit,
    bidirectional_stream_limit: default_bidirectional_stream_limit,
    unidirectional_stream_limit: default_unidirectional_stream_limit,
    frame_limit: default_frame_limit,
    datagram_limit: default_datagram_limit,
    qpack_table_limit: default_qpack_table_limit,
    qpack_blocked_stream_limit: default_qpack_blocked_stream_limit,
    telemetry_limit: config.telemetry_limit,
    // The one-shot adapter owns the sole writer so it can add HTTP/3 events
    // to the same trace as its redacted QUIC counter observations.
    qlog_directory: "",
  )
}

fn request(
  connection: client_connection.State,
  headers: List(Header),
  body: BitArray,
  body_limit: Int,
  total_deadline: Int,
  operation_timeout_milliseconds: Int,
  keepalive_milliseconds: Int,
  writer: Option(diagnostics.Writer),
) -> Result(Response, Error) {
  let remaining = remaining_milliseconds(total_deadline)
  case remaining <= 0 {
    True -> Error(TotalTimeout)
    False -> {
      use #(connection, stream_id) <- result.try(
        client_connection.open_request(
          connection,
          headers,
          False,
          int.min(remaining, operation_timeout_milliseconds),
        )
        |> result.map_error(map_connection_error),
      )
      record_http3_stream_type(writer, stream_id, diagnostics.RequestStream)
      record_http3_frame_created(writer, stream_id, diagnostics.HeadersFrame, 0)
      use connection <- result.try(send_request_body(
        connection,
        stream_id,
        body,
        writer,
      ))
      use connection <- result.try(
        client_connection.finish_stream(connection, stream_id)
        |> result.map_error(map_connection_error),
      )
      let #(deadline, timeout_error) =
        operation_deadline(total_deadline, operation_timeout_milliseconds)
      collect_response(
        connection,
        stream_id,
        Collector(None, [], [], 0, False),
        body_limit,
        deadline,
        timeout_error,
        keepalive_milliseconds,
        next_keepalive(keepalive_milliseconds),
        writer,
      )
    }
  }
}

fn send_request_body(
  connection: client_connection.State,
  stream_id: Int,
  body: BitArray,
  writer: Option(diagnostics.Writer),
) -> Result(client_connection.State, Error) {
  let size = bit_array.byte_size(body)
  case size {
    0 -> Ok(connection)
    _ -> {
      let take = int.min(size, maximum_request_data_chunk_bytes)
      use chunk <- result.try(
        bit_array.slice(body, at: 0, take:)
        |> result.replace_error(InvalidInput),
      )
      use rest <- result.try(
        bit_array.slice(body, at: take, take: size - take)
        |> result.replace_error(InvalidInput),
      )
      use connection <- result.try(
        client_connection.send_data(connection, stream_id, chunk)
        |> result.map_error(map_connection_error),
      )
      record_http3_frame_created(
        writer,
        stream_id,
        diagnostics.DataFrame,
        bit_array.byte_size(chunk),
      )
      send_request_body(connection, stream_id, rest, writer)
    }
  }
}

fn collect_response(
  connection: client_connection.State,
  stream_id: Int,
  collector: Collector,
  body_limit: Int,
  deadline: Int,
  timeout_error: Error,
  keepalive_milliseconds: Int,
  next_keepalive_milliseconds: Int,
  writer: Option(diagnostics.Writer),
) -> Result(Response, Error) {
  let #(connection, events) = client_connection.take_events(connection)
  record_response_events(writer, events)
  use collector <- result.try(apply_events(
    events,
    stream_id,
    collector,
    body_limit,
  ))
  case collector.finished, collector.status, remaining_milliseconds(deadline) {
    True, Some(status), _ ->
      Ok(Response(
        status,
        collector.headers,
        collector.reversed_body |> list.reverse() |> bit_array.concat(),
      ))
    True, None, _ -> Error(Http3ProtocolFailed)
    _, _, remaining if remaining <= 0 -> Error(timeout_error)
    _, _, _ -> {
      let now = diagnostics.monotonic_milliseconds()
      use #(connection, next_keepalive_milliseconds) <- result.try(
        maybe_keepalive(
          connection,
          keepalive_milliseconds,
          next_keepalive_milliseconds,
          now,
        ),
      )
      use protocol_deadline <- result.try(
        client_connection.next_deadline(connection, now)
        |> result.map_error(map_connection_error),
      )
      use connection <- result.try(
        client_connection.pump(
          connection,
          wait_milliseconds(
            deadline,
            protocol_deadline,
            keepalive_milliseconds,
            next_keepalive_milliseconds,
            now,
          ),
        )
        |> result.map_error(map_connection_error),
      )
      collect_response(
        connection,
        stream_id,
        collector,
        body_limit,
        deadline,
        timeout_error,
        keepalive_milliseconds,
        next_keepalive_milliseconds,
        writer,
      )
    }
  }
}

fn open_qlog(
  directory: String,
  telemetry_limit: Int,
) -> Result(Option(diagnostics.Writer), diagnostics.Error) {
  case directory {
    "" -> Ok(None)
    _ ->
      diagnostics.open(
        directory,
        diagnostics.Client,
        diagnostics.monotonic_milliseconds(),
        telemetry_limit,
      )
      |> result.map(Some)
  }
}

/// Reconstruct only bounded facts already authenticated before the one-shot
/// writer could be opened. Packet events are representative observations, not
/// byte or identifier-bearing replays of the completed handshake.
fn record_qlog_bootstrap(
  writer: Option(diagnostics.Writer),
  connection: client_connection.State,
) -> Nil {
  case writer {
    None -> Nil
    Some(writer) -> {
      let now = diagnostics.monotonic_milliseconds()
      diagnostics.connection_started(writer, now)
      let client_connection.Stats(received, sent, _, _, _, _, _, _) =
        client_connection.stats(connection)
      case received > 0 {
        True -> {
          diagnostics.datagrams_received(writer, now, 1)
          diagnostics.packet_received(writer, now, diagnostics.UnknownPacket, 0)
        }
        False -> Nil
      }
      case sent > 0 {
        True -> {
          diagnostics.datagrams_sent(writer, now, 1)
          diagnostics.packet_sent(writer, now, diagnostics.UnknownPacket, 0)
        }
        False -> Nil
      }
      diagnostics.key_updated(writer, now, diagnostics.ClientOneRttSecret)
      diagnostics.key_updated(writer, now, diagnostics.ServerOneRttSecret)
      diagnostics.key_discarded(writer, now, diagnostics.ClientHandshakeSecret)
      diagnostics.key_discarded(writer, now, diagnostics.ServerHandshakeSecret)
      diagnostics.recovery_metrics(
        writer,
        now,
        client_connection.path_stats(connection),
      )
      diagnostics.congestion_state_updated(
        writer,
        now,
        diagnostics.ApplicationLimited,
      )
      diagnostics.http3_parameters_set(writer, now, diagnostics.LocalInitiator)
      diagnostics.http3_parameters_set(writer, now, diagnostics.RemoteInitiator)
      diagnostics.http3_stream_type_set(
        writer,
        now,
        2,
        diagnostics.ControlStream,
      )
      diagnostics.http3_stream_type_set(
        writer,
        now,
        6,
        diagnostics.QpackEncoderStream,
      )
      diagnostics.http3_stream_type_set(
        writer,
        now,
        10,
        diagnostics.QpackDecoderStream,
      )
    }
  }
}

fn record_response_events(
  writer: Option(diagnostics.Writer),
  events: List(client_connection.Event),
) -> Nil {
  case events {
    [] -> Nil
    [event, ..rest] -> {
      case event {
        client_connection.Http3Event(http3_state.PeerSettings(_)) -> {
          record_remote_http3_parameters(writer)
          record_http3_frame_parsed(writer, 3, diagnostics.SettingsFrame, 0)
        }
        client_connection.Http3Event(http3_state.InformationalResponse(
          stream_id,
          _,
        ))
        | client_connection.Http3Event(http3_state.ResponseHeaders(stream_id, _))
        | client_connection.Http3Event(http3_state.Trailers(stream_id, _)) ->
          record_http3_frame_parsed(
            writer,
            stream_id,
            diagnostics.HeadersFrame,
            0,
          )
        client_connection.Http3Event(http3_state.Data(stream_id, bytes)) ->
          record_http3_frame_parsed(
            writer,
            stream_id,
            diagnostics.DataFrame,
            bit_array.byte_size(bytes),
          )
        client_connection.Http3Event(http3_state.GoAwayReceived(_, _)) ->
          record_http3_frame_parsed(writer, 3, diagnostics.GoAwayFrame, 0)
        _ -> Nil
      }
      record_response_events(writer, rest)
    }
  }
}

fn record_remote_http3_parameters(writer: Option(diagnostics.Writer)) -> Nil {
  case writer {
    Some(writer) ->
      diagnostics.http3_parameters_set(
        writer,
        diagnostics.monotonic_milliseconds(),
        diagnostics.RemoteInitiator,
      )
    None -> Nil
  }
}

fn record_http3_stream_type(
  writer: Option(diagnostics.Writer),
  stream_id: Int,
  stream_type: diagnostics.Http3StreamType,
) -> Nil {
  case writer {
    Some(writer) ->
      diagnostics.http3_stream_type_set(
        writer,
        diagnostics.monotonic_milliseconds(),
        stream_id,
        stream_type,
      )
    None -> Nil
  }
}

fn record_http3_frame_created(
  writer: Option(diagnostics.Writer),
  stream_id: Int,
  frame_type: diagnostics.Http3FrameType,
  payload_bytes: Int,
) -> Nil {
  case writer {
    Some(writer) ->
      diagnostics.http3_frame_created(
        writer,
        diagnostics.monotonic_milliseconds(),
        stream_id,
        frame_type,
        payload_bytes,
      )
    None -> Nil
  }
}

fn record_http3_frame_parsed(
  writer: Option(diagnostics.Writer),
  stream_id: Int,
  frame_type: diagnostics.Http3FrameType,
  payload_bytes: Int,
) -> Nil {
  case writer {
    Some(writer) ->
      diagnostics.http3_frame_parsed(
        writer,
        diagnostics.monotonic_milliseconds(),
        stream_id,
        frame_type,
        payload_bytes,
      )
    None -> Nil
  }
}

fn close_qlog(
  writer: Option(diagnostics.Writer),
) -> Result(Nil, diagnostics.Error) {
  case writer {
    None -> Ok(Nil)
    Some(writer) -> {
      diagnostics.connection_closed(
        writer,
        diagnostics.monotonic_milliseconds(),
      )
      diagnostics.close(writer)
    }
  }
}

fn apply_events(
  events: List(client_connection.Event),
  stream_id: Int,
  collector: Collector,
  body_limit: Int,
) -> Result(Collector, Error) {
  case events {
    [] -> Ok(collector)
    [event, ..rest] -> {
      use collector <- result.try(apply_event(
        event,
        stream_id,
        collector,
        body_limit,
      ))
      apply_events(rest, stream_id, collector, body_limit)
    }
  }
}

fn apply_event(
  event: client_connection.Event,
  stream_id: Int,
  collector: Collector,
  body_limit: Int,
) -> Result(Collector, Error) {
  case event {
    client_connection.Http3Event(http3_state.ResponseHeaders(
      identifier,
      validated,
    ))
      if identifier == stream_id
    -> {
      let header_semantics.Validated(control, fields, _) = validated
      use status <- result.try(response_status(control))
      use headers <- result.try(decode_headers(fields))
      Ok(Collector(..collector, status: Some(status), headers: headers))
    }
    client_connection.Http3Event(http3_state.Data(identifier, bytes))
      if identifier == stream_id
    -> {
      let size = collector.body_size + bit_array.byte_size(bytes)
      case size > body_limit {
        True -> Error(ResponseBodyTooLarge(body_limit))
        False ->
          Ok(
            Collector(
              ..collector,
              reversed_body: [bytes, ..collector.reversed_body],
              body_size: size,
            ),
          )
      }
    }
    client_connection.Http3Event(http3_state.StreamFinished(identifier))
      if identifier == stream_id
    -> Ok(Collector(..collector, finished: True))
    client_connection.StreamWasReset(identifier, code)
      if identifier == stream_id
    -> Error(StreamReset(code))
    client_connection.ConnectionTerminated -> Error(PeerClosed)
    _ -> Ok(collector)
  }
}

fn response_status(control: header_semantics.Control) -> Result(Int, Error) {
  case control {
    header_semantics.ResponseControlData(status) -> Ok(status)
    _ -> Error(Http3ProtocolFailed)
  }
}

fn encode_headers(
  fields: List(#(String, String)),
) -> Result(List(Header), Error) {
  fields
  |> list.map(fn(field) {
    let #(name, value) = field
    Header(bit_array.from_string(name), bit_array.from_string(value), False)
  })
  |> Ok
}

fn decode_headers(
  fields: List(Header),
) -> Result(List(#(String, String)), Error) {
  case fields {
    [] -> Ok([])
    [Header(name, value, _), ..rest] -> {
      use name <- result.try(
        bit_array.to_string(name) |> result.replace_error(InvalidHeaderEncoding),
      )
      use value <- result.try(
        bit_array.to_string(value)
        |> result.replace_error(InvalidHeaderEncoding),
      )
      use rest <- result.try(decode_headers(rest))
      Ok([#(name, value), ..rest])
    }
  }
}

fn maybe_keepalive(
  connection: client_connection.State,
  interval: Int,
  next: Int,
  now: Int,
) -> Result(#(client_connection.State, Int), Error) {
  case interval > 0 && now >= next {
    False -> Ok(#(connection, next))
    True ->
      client_connection.ping(connection)
      |> result.map(fn(connection) { #(connection, now + interval) })
      |> result.map_error(map_connection_error)
  }
}

fn next_keepalive(interval: Int) -> Int {
  case interval > 0 {
    True -> diagnostics.monotonic_milliseconds() + interval
    False -> 0
  }
}

fn operation_deadline(
  total_deadline: Int,
  operation_timeout_milliseconds: Int,
) -> #(Int, Error) {
  let operation_deadline =
    diagnostics.monotonic_milliseconds() + operation_timeout_milliseconds
  case total_deadline <= operation_deadline {
    True -> #(total_deadline, TotalTimeout)
    False -> #(operation_deadline, OperationTimeout)
  }
}

fn wait_milliseconds(
  deadline: Int,
  protocol_deadline: Option(Int),
  keepalive_milliseconds: Int,
  next_keepalive_milliseconds: Int,
  now: Int,
) -> Int {
  let target = case protocol_deadline {
    Some(protocol) if protocol < deadline -> protocol
    _ -> deadline
  }
  let target = case
    keepalive_milliseconds > 0 && next_keepalive_milliseconds < target
  {
    True -> next_keepalive_milliseconds
    False -> target
  }
  int.max(0, target - now)
}

fn remaining_milliseconds(deadline: Int) -> Int {
  deadline - diagnostics.monotonic_milliseconds()
}

/// Validate a non-empty DER trust set behind the opaque TLS adapter.
pub fn valid_ca_certificates(certificates: List(BitArray)) -> Bool {
  client_connection.valid_ca_certificates(certificates)
}

fn validate(config: Config, body: BitArray) -> Result(Nil, Error) {
  case
    config.hostname != ""
    && config.port > 0
    && config.port <= 65_535
    && config.dns_timeout_milliseconds > 0
    && config.connect_timeout_milliseconds > 0
    && config.handshake_timeout_milliseconds > 0
    && config.timeout_milliseconds > 0
    && config.operation_timeout_milliseconds > 0
    && config.idle_timeout_milliseconds > 0
    && config.maximum_request_body_bytes >= bit_array.byte_size(body)
    && config.maximum_response_body_bytes > 0
    && config.telemetry_limit > 0
    && {
      config.keepalive_milliseconds == 0
      || {
        config.keepalive_milliseconds >= 1000
        && config.keepalive_milliseconds <= 29_000
      }
    }
    && bit_array.bit_size(body) % 8 == 0
  {
    True -> Ok(Nil)
    False -> Error(InvalidInput)
  }
}

fn map_connection_error(error: client_connection.Error) -> Error {
  case error {
    client_connection.InvalidInput -> InvalidInput
    client_connection.ResolutionFailed -> ResolutionFailed
    client_connection.SocketUnavailable -> SocketUnavailable
    client_connection.DnsTimeout -> DnsTimeout
    client_connection.ConnectTimeout -> ConnectTimeout
    client_connection.HandshakeTimeout -> HandshakeTimeout
    client_connection.OperationTimeout -> OperationTimeout
    client_connection.TotalTimeout -> TotalTimeout
    client_connection.TrustStoreFailed -> TrustStoreFailed
    client_connection.TlsHandshakeFailed -> TlsHandshakeFailed
    client_connection.QuicTransportFailed(_) -> QuicTransportFailed
    client_connection.CoreFailure(failure) -> CoreFailure(failure)
    client_connection.Http3OperationFailed(_, _) -> Http3OperationFailed
    client_connection.PeerClosed -> PeerClosed
    client_connection.MigrationUnavailable -> QuicTransportFailed
    client_connection.VersionNegotiationReceived(_) ->
      VersionNegotiationReceived
    client_connection.VersionNegotiationFailed -> VersionNegotiationFailed
  }
}

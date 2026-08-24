//// Typed boundary around the repository-owned reusable HTTP/3 client.

import gleam/result
import gleam_quic/http3/client as native_client
import http3/internal/client_backend
import http3/internal/client_request.{
  type PreparedStreamingRequest, PreparedStreamingRequest,
}

/// Opaque native connection identity.
pub type ConnectionHandle =
  native_client.Connection

/// Opaque native request-stream identity.
pub type StreamHandle =
  native_client.Stream

/// Opaque native server-push identity.
pub type PushHandle =
  native_client.Push

/// Opaque backend-owned TLS resumption material.
pub type ResumptionTicketHandle =
  native_client.ResumptionTicket

/// Primitive event data consumed by the stable parent-package adapter.
pub type RawEvent =
  #(Int, Int, List(#(String, String)), BitArray)

/// Establish one reusable, securely verified HTTP/3 connection.
pub fn connect(
  host host: String,
  port port: Int,
  ca_certificates ca_certificates: List(BitArray),
  timeout_milliseconds timeout_milliseconds: Int,
  stream_buffer_limit stream_buffer_limit: Int,
  http_datagrams http_datagrams: Bool,
  maximum_pushes maximum_pushes: Int,
  quic_v2 quic_v2: Bool,
  qlog_directory qlog_directory: String,
  resumption_tickets resumption_tickets: List(ResumptionTicketHandle),
) -> Result(ConnectionHandle, client_backend.Failure) {
  case resumption_tickets {
    [_, _, ..] ->
      Error(client_backend.BackendFailure(
        "only one native resumption ticket may be attached",
      ))
    _ -> {
      use configured <- result.try(
        native_client.new(host, port) |> map_configuration_result,
      )
      let configured =
        native_client.with_quic_version(configured, case quic_v2 {
          False -> native_client.QuicV1
          True -> native_client.QuicV2
        })
      use configured <- result.try(
        native_client.with_timeout(configured, timeout_milliseconds)
        |> map_configuration_result,
      )
      use configured <- result.try(
        native_client.with_stream_buffer_limit(configured, stream_buffer_limit)
        |> map_configuration_result,
      )
      use configured <- result.try(
        native_client.with_push_limit(configured, maximum_pushes)
        |> map_configuration_result,
      )
      use configured <- result.try(configure_trust(configured, ca_certificates))
      let configured = case http_datagrams {
        True -> native_client.with_http_datagrams(configured)
        False -> configured
      }
      let configured = case qlog_directory {
        "" -> Ok(configured)
        _ -> native_client.with_qlog(configured, qlog_directory)
      }
      use configured <- result.try(configured |> map_configuration_result)
      let configured = case resumption_tickets {
        [ticket] -> native_client.with_resumption_ticket(configured, ticket)
        [] -> configured
        _ -> configured
      }
      native_client.connect(configured) |> map_native_result
    }
  }
}

/// Pull the next validated server push promise.
pub fn next_push(
  connection: ConnectionHandle,
) -> Result(
  #(PushHandle, String, String, List(#(String, String))),
  client_backend.Failure,
) {
  native_client.next_push(connection)
  |> result.map(fn(push) {
    #(
      push,
      native_client.push_method(push),
      native_client.push_path(push),
      native_client.push_headers(push),
    )
  })
  |> map_native_result
}

/// Open a request stream without ending its request body.
pub fn open_stream(
  connection connection: ConnectionHandle,
  request request: PreparedStreamingRequest,
) -> Result(StreamHandle, client_backend.Failure) {
  let PreparedStreamingRequest(host, port, headers, _) = request
  native_client.open_stream(connection, host, port, headers)
  |> map_native_result
}

/// Send one request-body chunk with synchronous flow-control feedback.
pub fn send_chunk(
  stream stream: StreamHandle,
  chunk chunk: BitArray,
) -> Result(Nil, client_backend.Failure) {
  native_client.send_chunk(stream, chunk) |> map_native_result
}

/// Send request trailers and the terminal FIN.
pub fn send_trailers(
  stream stream: StreamHandle,
  headers headers: List(#(String, String)),
) -> Result(Nil, client_backend.Failure) {
  native_client.send_trailers(stream, headers) |> map_native_result
}

/// End a request body.
pub fn finish(stream: StreamHandle) -> Result(Nil, client_backend.Failure) {
  native_client.finish(stream) |> map_native_result
}

/// Pull the next response event.
pub fn next_event(
  stream: StreamHandle,
) -> Result(RawEvent, client_backend.Failure) {
  case native_client.next_event(stream) {
    Ok(native_client.InformationalResponse(status, headers)) ->
      Ok(#(1, status, headers, <<>>))
    Ok(native_client.ResponseHeaders(status, headers)) ->
      Ok(#(2, status, headers, <<>>))
    Ok(native_client.Data(bytes)) -> Ok(#(3, 0, [], bytes))
    Ok(native_client.Trailers(headers)) -> Ok(#(4, 0, headers, <<>>))
    Ok(native_client.End) -> Ok(#(5, 0, [], <<>>))
    Error(error) -> Error(map_native_error(error))
  }
}

/// Pull the next response event for one server push.
pub fn next_push_event(
  push: PushHandle,
) -> Result(RawEvent, client_backend.Failure) {
  case native_client.next_push_event(push) {
    Ok(native_client.InformationalResponse(status, headers)) ->
      Ok(#(1, status, headers, <<>>))
    Ok(native_client.ResponseHeaders(status, headers)) ->
      Ok(#(2, status, headers, <<>>))
    Ok(native_client.Data(bytes)) -> Ok(#(3, 0, [], bytes))
    Ok(native_client.Trailers(headers)) -> Ok(#(4, 0, headers, <<>>))
    Ok(native_client.End) -> Ok(#(5, 0, [], <<>>))
    Error(error) -> Error(map_native_error(error))
  }
}

/// Cancel a request stream and return a primitive idempotence status.
pub fn cancel(stream: StreamHandle) -> Result(Int, client_backend.Failure) {
  case native_client.cancel(stream) {
    Ok(native_client.Cancelled) -> Ok(1)
    Ok(native_client.AlreadyCancelled) -> Ok(2)
    Ok(native_client.AlreadyCompleted) -> Ok(3)
    Error(error) -> Error(map_native_error(error))
  }
}

/// Cancel a server push and return a primitive idempotence status.
pub fn cancel_push(push: PushHandle) -> Result(Int, client_backend.Failure) {
  case native_client.cancel_push(push) {
    Ok(native_client.Cancelled) -> Ok(1)
    Ok(native_client.AlreadyCancelled) -> Ok(2)
    Ok(native_client.AlreadyCompleted) -> Ok(3)
    Error(error) -> Error(map_native_error(error))
  }
}

/// Close a connection and return a primitive idempotence status.
pub fn close(
  connection: ConnectionHandle,
) -> Result(Int, client_backend.Failure) {
  case native_client.close(connection) {
    Ok(native_client.Closed) -> Ok(1)
    Ok(native_client.AlreadyClosed) -> Ok(2)
    Error(error) -> Error(map_native_error(error))
  }
}

fn configure_trust(
  client: native_client.Client,
  certificates: List(BitArray),
) -> Result(native_client.Client, client_backend.Failure) {
  case certificates {
    [] -> Ok(client)
    _ ->
      native_client.with_ca_certificates(client, certificates)
      |> map_configuration_result
  }
}

fn map_configuration_result(
  outcome: Result(value, native_client.ConfigurationError),
) -> Result(value, client_backend.Failure) {
  result.map_error(outcome, fn(error) {
    let detail = case error {
      native_client.InvalidHost -> "host"
      native_client.InvalidPort(_) -> "port"
      native_client.InvalidTimeout -> "timeout"
      native_client.InvalidResponseBodyLimit -> "response body limit"
      native_client.InvalidStreamBufferLimit -> "stream buffer limit"
      native_client.InvalidPushLimit -> "server push limit"
      native_client.InvalidCaCertificate -> "CA certificate"
      native_client.InvalidQlogDirectory -> "qlog directory"
    }
    client_backend.BackendFailure("invalid native client " <> detail)
  })
}

fn map_native_result(
  outcome: Result(value, native_client.Error),
) -> Result(value, client_backend.Failure) {
  result.map_error(outcome, map_native_error)
}

fn map_native_error(error: native_client.Error) -> client_backend.Failure {
  case error {
    native_client.InvalidRequest ->
      client_backend.BackendFailure("invalid native request")
    native_client.ResolutionFailed ->
      client_backend.ConnectFailed("name resolution failed")
    native_client.TrustStoreFailed ->
      client_backend.ConnectFailed("trust store unavailable")
    native_client.ConnectFailed ->
      client_backend.ConnectFailed("UDP connection unavailable")
    native_client.HandshakeFailed ->
      client_backend.ConnectFailed("TLS handshake failed")
    native_client.TransportError(message) ->
      client_backend.BackendFailure(message)
    native_client.Http3Error(message) ->
      client_backend.ProtocolError(0x101, message)
    native_client.Timeout -> client_backend.Timeout
    native_client.ConnectionClosed -> client_backend.ConnectionClosed
    native_client.StreamReset(code) -> client_backend.StreamReset(code)
    native_client.ProtocolError ->
      client_backend.ProtocolError(0x101, "invalid HTTP/3 response")
    native_client.InvalidHeaderEncoding ->
      client_backend.ProtocolError(0x109, "invalid response header encoding")
    native_client.InvalidContentLength -> client_backend.InvalidContentLength
    native_client.ResponseBodyTooLarge(_) -> client_backend.ResponseBodyTooLarge
    native_client.ConsumerTooSlow(limit) ->
      client_backend.ConsumerTooSlow(limit)
    native_client.ConcurrentReceive -> client_backend.ConcurrentReceive
    native_client.RequestAlreadyFinished ->
      client_backend.RequestAlreadyFinished
    native_client.StreamFinished -> client_backend.StreamFinished
    native_client.StreamCancelled -> client_backend.StreamCancelled
    native_client.OriginMismatch -> client_backend.OriginMismatch
    native_client.UnsafeEarlyDataMethod(method) ->
      client_backend.UnsafeEarlyDataMethod(method)
    native_client.ResumptionOriginMismatch ->
      client_backend.ResumptionOriginMismatch
    native_client.DatagramsNotNegotiated ->
      client_backend.BackendFailure("HTTP Datagrams were not negotiated")
    native_client.DatagramNotAssociated ->
      client_backend.BackendFailure("HTTP Datagram stream is not associated")
    native_client.DatagramTooLarge(_) ->
      client_backend.BackendFailure("HTTP Datagram is too large")
    native_client.DatagramBufferExceeded(_) ->
      client_backend.BackendFailure("HTTP Datagram buffer exceeded")
    native_client.ConcurrentDatagramReceive ->
      client_backend.BackendFailure("concurrent HTTP Datagram receive")
    native_client.MigrationUnavailable ->
      client_backend.BackendFailure("active migration unavailable")
    native_client.CongestionLimited ->
      client_backend.BackendFailure("congestion limited")
    native_client.UnsupportedCongestionControl ->
      client_backend.BackendFailure("unsupported congestion control")
    native_client.TicketUnavailable -> client_backend.Timeout
    native_client.QlogUnavailable ->
      client_backend.BackendFailure("qlog output unavailable")
    native_client.VersionNegotiationFailed ->
      client_backend.ConnectFailed("no compatible QUIC version")
  }
}

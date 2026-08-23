//// Bounded and streaming HTTP/3 server powered by the native QUIC stack.

import gleam/bit_array
import gleam/option.{type Option, Some}
import gleam/result
import gleam_quic/internal/http3/server_connection
import gleam_quic/internal/http3/server_worker
import gleam_quic/internal/tls/authentication
import gleam_quic/internal/tls/extension_value

const maximum_timeout_milliseconds = 3_600_000

/// Secure listener configuration with decoded runtime-owned credentials.
pub opaque type Server {
  Server(
    certificate_chain: List(BitArray),
    signing_key: authentication.SigningKey,
    signature_scheme: extension_value.SignatureScheme,
    port: Int,
    timeout_milliseconds: Int,
    request_body_limit: Int,
    response_body_limit: Int,
    stream_buffer_limit: Int,
    http_datagrams: Bool,
    qlog_directory: String,
  )
}

/// A running owner-bound listener.
pub opaque type Listener {
  Listener(handle: server_worker.Listener)
}

/// One accepted request stream.
pub opaque type Request {
  Request(handle: server_worker.Request)
}

/// Primitive accepted request data for the parent HTTP adapter.
pub type Incoming {
  Incoming(
    request: Request,
    method: String,
    path: String,
    headers: List(#(String, String)),
  )
}

/// One pull-based request-body event.
pub type RequestEvent {
  Data(BitArray)
  Trailers(List(#(String, String)))
  End
}

/// Idempotent listener-stop result.
pub type StopResult {
  Stopped
  AlreadyStopped
}

/// State of a request's connection-level early-data attempt.
pub type EarlyDataStatus {
  NotAttempted
  Pending
  Accepted
  Rejected
}

/// Invalid secure server configuration.
pub type ConfigurationError {
  InvalidCertificate
  InvalidPrivateKey
  IncompatiblePrivateKey
  InvalidPort(Int)
  InvalidTimeout
  InvalidRequestBodyLimit
  InvalidResponseBodyLimit
  InvalidStreamBufferLimit
  InvalidQlogDirectory
}

/// Native listener, request, protocol, or resource failure.
pub type Error {
  InvalidInput
  StartFailed
  Timeout
  ListenerClosed
  ConnectionClosed
  StreamReset(Int)
  ProtocolError(Int, String)
  RequestBodyTooLarge(Int)
  ResponseBodyTooLarge(Int)
  ConsumerTooSlow(Int)
  ConcurrentAccept
  ConcurrentReceive
  ResponseAlreadyStarted
  ResponseNotStarted
  ResponseAlreadyFinished
  InvalidContentLength
  InvalidHeaderEncoding
  DatagramsNotNegotiated
  DatagramTooLarge(Int)
  DatagramBufferExceeded(Int)
  ConcurrentDatagramReceive
  StreamFinished
  CongestionLimited
  BackendFailure(String)
}

/// Decode a certificate chain and private signing key.
pub fn new(
  certificate_pem: BitArray,
  private_key_pem: BitArray,
) -> Result(Server, ConfigurationError) {
  use certificate_chain <- result.try(
    authentication.certificate_chain_from_pem(certificate_pem)
    |> result.replace_error(InvalidCertificate),
  )
  use signing_key <- result.try(
    authentication.signing_key_from_pem(private_key_pem)
    |> result.replace_error(InvalidPrivateKey),
  )
  use signature_scheme <- result.try(
    authentication.signing_key_scheme(signing_key)
    |> result.replace_error(IncompatiblePrivateKey),
  )
  Ok(Server(
    certificate_chain,
    signing_key,
    signature_scheme,
    0,
    30_000,
    8_388_608,
    8_388_608,
    262_144,
    False,
    "",
  ))
}

/// Return whether bytes decode as a non-empty PEM certificate chain.
pub fn is_valid_certificate(certificate_pem: BitArray) -> Bool {
  authentication.certificate_chain_from_pem(certificate_pem) |> result.is_ok
}

/// Return whether bytes decode as a supported unencrypted private key.
pub fn is_valid_private_key(private_key_pem: BitArray) -> Bool {
  case authentication.signing_key_from_pem(private_key_pem) {
    Error(_) -> False
    Ok(key) -> authentication.signing_key_scheme(key) |> result.is_ok
  }
}

/// Set the UDP port; zero requests an operating-system-assigned port.
pub fn with_port(
  server: Server,
  port: Int,
) -> Result(Server, ConfigurationError) {
  case port >= 0 && port <= 65_535 {
    True -> Ok(Server(..server, port: port))
    False -> Error(InvalidPort(port))
  }
}

/// Set one fixed operation timeout from one millisecond to one hour.
pub fn with_timeout(
  server: Server,
  milliseconds: Int,
) -> Result(Server, ConfigurationError) {
  case milliseconds > 0 && milliseconds <= maximum_timeout_milliseconds {
    True -> Ok(Server(..server, timeout_milliseconds: milliseconds))
    False -> Error(InvalidTimeout)
  }
}

/// Set the maximum accepted request body size.
pub fn with_request_body_limit(
  server: Server,
  bytes: Int,
) -> Result(Server, ConfigurationError) {
  case bytes > 0 {
    True -> Ok(Server(..server, request_body_limit: bytes))
    False -> Error(InvalidRequestBodyLimit)
  }
}

/// Set the maximum emitted response body size.
pub fn with_response_body_limit(
  server: Server,
  bytes: Int,
) -> Result(Server, ConfigurationError) {
  case bytes > 0 {
    True -> Ok(Server(..server, response_body_limit: bytes))
    False -> Error(InvalidResponseBodyLimit)
  }
}

/// Set the maximum unconsumed body or Datagram bytes per request.
pub fn with_stream_buffer_limit(
  server: Server,
  bytes: Int,
) -> Result(Server, ConfigurationError) {
  case bytes > 0 {
    True -> Ok(Server(..server, stream_buffer_limit: bytes))
    False -> Error(InvalidStreamBufferLimit)
  }
}

/// Negotiate RFC 9221 and RFC 9297 Datagram support.
pub fn with_http_datagrams(server: Server) -> Server {
  Server(..server, http_datagrams: True)
}

/// Write a streaming qlog trace in an explicitly selected directory.
pub fn with_qlog(
  server: Server,
  directory: String,
) -> Result(Server, ConfigurationError) {
  case directory == "" {
    True -> Error(InvalidQlogDirectory)
    False -> Ok(Server(..server, qlog_directory: directory))
  }
}

/// Start the listener actor and bind UDP.
pub fn start(server: Server) -> Result(Listener, Error) {
  server_worker.start(
    server.port,
    server.timeout_milliseconds,
    server.request_body_limit,
    server.response_body_limit,
    server.stream_buffer_limit,
    server.certificate_chain,
    server.signing_key,
    server.signature_scheme,
    server.http_datagrams,
    server.qlog_directory,
  )
  |> result.map(Listener)
  |> result.map_error(map_error)
}

/// Return the concrete bound UDP port.
pub fn port(listener: Listener) -> Result(Int, Error) {
  let Listener(handle) = listener
  server_worker.port(handle) |> result.map_error(map_error)
}

/// Pull the next validated request head.
pub fn accept(listener: Listener) -> Result(Incoming, Error) {
  let Listener(handle) = listener
  case server_worker.accept(handle) {
    Ok(server_worker.Incoming(request, method, path, headers)) ->
      Ok(Incoming(Request(request), method, path, headers))
    Error(error) -> Error(map_error(error))
  }
}

/// Pull one request-body event.
pub fn next_event(request: Request) -> Result(RequestEvent, Error) {
  let Request(handle) = request
  case server_worker.next_event(handle) {
    Ok(server_worker.Data(bytes)) -> Ok(Data(bytes))
    Ok(server_worker.Trailers(headers)) -> Ok(Trailers(headers))
    Ok(server_worker.End) -> Ok(End)
    Error(error) -> Error(map_error(error))
  }
}

/// Send one complete bounded response.
pub fn respond(
  request: Request,
  status: Int,
  headers: List(#(String, String)),
  body: BitArray,
) -> Result(Nil, Error) {
  use Nil <- result.try(send_response(
    request,
    status,
    headers,
    Some(bit_array.byte_size(body)),
  ))
  use Nil <- result.try(send_chunk(request, body))
  finish_response(request)
}

/// Send one final streaming response head.
pub fn send_response(
  request: Request,
  status: Int,
  headers: List(#(String, String)),
  declared_content_length: Option(Int),
) -> Result(Nil, Error) {
  let Request(handle) = request
  server_worker.send_response(handle, status, headers, declared_content_length)
  |> result.map_error(map_error)
}

/// Send one informational response before the final response head.
pub fn send_informational(
  request: Request,
  status: Int,
  headers: List(#(String, String)),
) -> Result(Nil, Error) {
  let Request(handle) = request
  server_worker.send_informational(handle, status, headers)
  |> result.map_error(map_error)
}

/// Send one response-body chunk with producer backpressure.
pub fn send_chunk(request: Request, bytes: BitArray) -> Result(Nil, Error) {
  let Request(handle) = request
  server_worker.send_chunk(handle, bytes) |> result.map_error(map_error)
}

/// Finish the response body.
pub fn finish_response(request: Request) -> Result(Nil, Error) {
  let Request(handle) = request
  server_worker.finish_response(handle) |> result.map_error(map_error)
}

/// Send response trailers and finish the response atomically.
pub fn send_trailers(
  request: Request,
  headers: List(#(String, String)),
) -> Result(Nil, Error) {
  let Request(handle) = request
  server_worker.send_trailers(handle, headers) |> result.map_error(map_error)
}

/// Stop the listener and every owned connection idempotently.
pub fn stop(listener: Listener) -> Result(StopResult, Error) {
  let Listener(handle) = listener
  case server_worker.stop(handle) {
    Ok(server_worker.Stopped) -> Ok(Stopped)
    Ok(server_worker.AlreadyStopped) -> Ok(AlreadyStopped)
    Error(error) -> Error(map_error(error))
  }
}

/// Return advanced capability flags for one request stream.
pub fn capabilities(
  request: Request,
) -> Result(#(Bool, Bool, Bool, Bool), Error) {
  let Request(handle) = request
  server_worker.capabilities(handle) |> result.map_error(map_error)
}

/// Return the largest HTTP Datagram payload for one request.
pub fn maximum_datagram_size(request: Request) -> Result(Int, Error) {
  let Request(handle) = request
  server_worker.maximum_datagram_size(handle) |> result.map_error(map_error)
}

/// Send one unreliable HTTP Datagram.
pub fn send_datagram(
  request: Request,
  payload: BitArray,
) -> Result(Nil, Error) {
  let Request(handle) = request
  server_worker.send_datagram(handle, payload) |> result.map_error(map_error)
}

/// Pull one unreliable HTTP Datagram.
pub fn next_datagram(request: Request) -> Result(BitArray, Error) {
  let Request(handle) = request
  server_worker.next_datagram(handle) |> result.map_error(map_error)
}

/// Set a locally effective response priority.
pub fn set_priority(
  request: Request,
  urgency: Int,
  incremental: Bool,
) -> Result(Nil, Error) {
  let Request(handle) = request
  server_worker.set_priority(handle, urgency, incremental)
  |> result.map_error(map_error)
}

/// Return one request's effective priority.
pub fn get_priority(request: Request) -> Result(#(Int, Bool), Error) {
  let Request(handle) = request
  server_worker.get_priority(handle) |> result.map_error(map_error)
}

/// Return the request connection's early-data outcome.
pub fn early_data_status(request: Request) -> Result(EarlyDataStatus, Error) {
  let Request(handle) = request
  case server_worker.early_data_status(handle) {
    Ok(server_connection.NotAttempted) -> Ok(NotAttempted)
    Ok(server_connection.Pending) -> Ok(Pending)
    Ok(server_connection.Accepted) -> Ok(Accepted)
    Ok(server_connection.Rejected) -> Ok(Rejected)
    Error(error) -> Error(map_error(error))
  }
}

fn map_error(error: server_worker.Error) -> Error {
  case error {
    server_worker.InvalidInput -> InvalidInput
    server_worker.StartFailed -> StartFailed
    server_worker.Timeout -> Timeout
    server_worker.ListenerClosed -> ListenerClosed
    server_worker.ConnectionClosed -> ConnectionClosed
    server_worker.StreamReset(code) -> StreamReset(code)
    server_worker.ProtocolError(code, message) -> ProtocolError(code, message)
    server_worker.RequestBodyTooLarge(limit) -> RequestBodyTooLarge(limit)
    server_worker.ResponseBodyTooLarge(limit) -> ResponseBodyTooLarge(limit)
    server_worker.ConsumerTooSlow(limit) -> ConsumerTooSlow(limit)
    server_worker.ConcurrentAccept -> ConcurrentAccept
    server_worker.ConcurrentReceive -> ConcurrentReceive
    server_worker.ResponseAlreadyStarted -> ResponseAlreadyStarted
    server_worker.ResponseNotStarted -> ResponseNotStarted
    server_worker.ResponseAlreadyFinished -> ResponseAlreadyFinished
    server_worker.InvalidContentLength -> InvalidContentLength
    server_worker.InvalidHeaderEncoding -> InvalidHeaderEncoding
    server_worker.DatagramsNotNegotiated -> DatagramsNotNegotiated
    server_worker.DatagramTooLarge(limit) -> DatagramTooLarge(limit)
    server_worker.DatagramBufferExceeded(limit) -> DatagramBufferExceeded(limit)
    server_worker.ConcurrentDatagramReceive -> ConcurrentDatagramReceive
    server_worker.StreamFinished -> StreamFinished
    server_worker.CongestionLimited -> CongestionLimited
    server_worker.BackendFailure(message) -> BackendFailure(message)
  }
}

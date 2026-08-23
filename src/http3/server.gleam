//// A bounded and streaming HTTP/3 server for the Erlang target.

import gleam/bit_array
import gleam/bool
import gleam/http
import gleam/list
import gleam/option.{None, Some}
import http3/internal/server_backend
import http3/internal/server_response
import http3/transport

const default_timeout_milliseconds = 30_000

const maximum_timeout_milliseconds = 3_600_000

const default_body_limit = 8_388_608

const default_stream_buffer_limit = 262_144

/// Secure listener configuration.
pub opaque type Configuration {
  Configuration(
    certificate: BitArray,
    private_key: BitArray,
    port: Int,
    timeout_milliseconds: Int,
    request_body_limit: Int,
    response_body_limit: Int,
    stream_buffer_limit: Int,
    http_datagrams: Bool,
    qlog_directory: String,
  )
}

/// A running HTTP/3 listener.
pub opaque type Listener {
  Listener(handle: server_backend.ListenerHandle)
}

/// One accepted HTTP/3 request.
pub opaque type Request {
  Request(
    handle: server_backend.RequestHandle,
    method: http.Method,
    path: String,
    headers: List(#(String, String)),
  )
}

/// One streaming request-body event.
pub type RequestEvent {
  Data(BitArray)
  Trailers(List(#(String, String)))
  End
}

/// The result of idempotently stopping a listener.
pub type StopResult {
  Stopped
  AlreadyStopped
}

/// An invalid listener configuration.
pub type ConfigurationError {
  InvalidCertificate
  InvalidPrivateKey
  InvalidPort(Int)
  InvalidTimeout
  InvalidRequestBodyLimit
  InvalidResponseBodyLimit
  InvalidStreamBufferLimit
}

/// A server, request, or response failure.
pub type Error {
  StartFailed(String)
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
  InvalidStatus(Int)
  InvalidHeader(String)
  InvalidContentLength
  InvalidBody
  BackendFailure(String)
}

/// Construct secure server configuration from PEM certificate and key bytes.
pub fn new(
  certificate certificate: BitArray,
  private_key private_key: BitArray,
) -> Result(Configuration, ConfigurationError) {
  use <- bool.guard(
    when: bit_array.bit_size(certificate) == 0
      || bit_array.bit_size(certificate) % 8 != 0
      || !server_backend.valid_certificate(certificate),
    return: Error(InvalidCertificate),
  )
  use <- bool.guard(
    when: bit_array.bit_size(private_key) == 0
      || bit_array.bit_size(private_key) % 8 != 0
      || !server_backend.valid_private_key(private_key),
    return: Error(InvalidPrivateKey),
  )
  Ok(Configuration(
    certificate: certificate,
    private_key: private_key,
    port: 0,
    timeout_milliseconds: default_timeout_milliseconds,
    request_body_limit: default_body_limit,
    response_body_limit: default_body_limit,
    stream_buffer_limit: default_stream_buffer_limit,
    http_datagrams: False,
    qlog_directory: "",
  ))
}

/// Enable RFC 9297 HTTP Datagrams for accepted connections.
pub fn with_http_datagrams(configuration: Configuration) -> Configuration {
  Configuration(..configuration, http_datagrams: True)
}

/// Enable qlog tracing for accepted connections.
///
/// Trace files can contain sensitive connection metadata. qlog remains off
/// unless this function is called explicitly.
pub fn with_qlog(
  configuration configuration: Configuration,
  qlog qlog: transport.Qlog,
) -> Configuration {
  Configuration(..configuration, qlog_directory: transport.qlog_directory(qlog))
}

/// Set the UDP port, using zero for an operating-system-assigned port.
pub fn with_port(
  configuration configuration: Configuration,
  port port: Int,
) -> Result(Configuration, ConfigurationError) {
  use <- bool.guard(
    when: port < 0 || port > 65_535,
    return: Error(InvalidPort(port)),
  )
  Ok(Configuration(..configuration, port: port))
}

/// Set the total timeout for accept, request, and response operations.
pub fn with_timeout(
  configuration configuration: Configuration,
  milliseconds milliseconds: Int,
) -> Result(Configuration, ConfigurationError) {
  use <- bool.guard(
    when: milliseconds <= 0 || milliseconds > maximum_timeout_milliseconds,
    return: Error(InvalidTimeout),
  )
  Ok(Configuration(..configuration, timeout_milliseconds: milliseconds))
}

/// Set the maximum request body size in bytes.
pub fn with_request_body_limit(
  configuration configuration: Configuration,
  bytes bytes: Int,
) -> Result(Configuration, ConfigurationError) {
  use <- bool.guard(when: bytes <= 0, return: Error(InvalidRequestBodyLimit))
  Ok(Configuration(..configuration, request_body_limit: bytes))
}

/// Set the maximum response body size in bytes.
pub fn with_response_body_limit(
  configuration configuration: Configuration,
  bytes bytes: Int,
) -> Result(Configuration, ConfigurationError) {
  use <- bool.guard(when: bytes <= 0, return: Error(InvalidResponseBodyLimit))
  Ok(Configuration(..configuration, response_body_limit: bytes))
}

/// Set the maximum unconsumed request data retained per stream.
pub fn with_stream_buffer_limit(
  configuration configuration: Configuration,
  bytes bytes: Int,
) -> Result(Configuration, ConfigurationError) {
  use <- bool.guard(when: bytes <= 0, return: Error(InvalidStreamBufferLimit))
  Ok(Configuration(..configuration, stream_buffer_limit: bytes))
}

/// Start an HTTP/3 listener owned by the calling process.
pub fn start(configuration: Configuration) -> Result(Listener, Error) {
  let Configuration(
    certificate,
    private_key,
    port,
    timeout,
    request_limit,
    response_limit,
    buffer_limit,
    http_datagrams,
    qlog_directory,
  ) = configuration
  case
    server_backend.start(
      certificate,
      private_key,
      port,
      timeout,
      request_limit,
      response_limit,
      buffer_limit,
      http_datagrams,
      qlog_directory,
    )
  {
    Ok(handle) -> Ok(Listener(handle))
    Error(error) -> Error(from_backend_failure(error))
  }
}

/// Obtain typed advanced controls for an accepted request stream.
pub fn request_transport(request: Request) -> transport.Stream {
  transport.server_stream(request.handle)
}

/// Return the listener's bound UDP port.
pub fn port(listener: Listener) -> Result(Int, Error) {
  let Listener(handle) = listener
  map_backend(server_backend.port(handle))
}

/// Pull the next accepted request head.
pub fn accept(listener: Listener) -> Result(Request, Error) {
  let Listener(handle) = listener
  case server_backend.accept(handle) {
    Ok(#(request_handle, method, path, headers)) -> {
      let method = case http.parse_method(method) {
        Ok(method) -> method
        Error(parse_error) -> {
          let _parse_error = parse_error
          http.Other(method)
        }
      }
      Ok(Request(request_handle, method, path, headers))
    }
    Error(error) -> Error(from_backend_failure(error))
  }
}

/// Return an accepted request's method.
pub fn method(request: Request) -> http.Method {
  request.method
}

/// Return an accepted request's path and query string.
pub fn path(request: Request) -> String {
  request.path
}

/// Return an accepted request's non-pseudo headers.
pub fn headers(request: Request) -> List(#(String, String)) {
  request.headers
}

/// Pull the next request-body event.
pub fn next_event(request: Request) -> Result(RequestEvent, Error) {
  case server_backend.next_event(request.handle) {
    Ok(#(1, _, chunk)) -> Ok(Data(chunk))
    Ok(#(2, trailers, _)) -> Ok(Trailers(trailers))
    Ok(#(3, _, _)) -> Ok(End)
    Ok(_) -> Error(BackendFailure("invalid request event"))
    Error(error) -> Error(from_backend_failure(error))
  }
}

/// Collect a request body within the configured server limit.
pub fn read_body(request: Request) -> Result(BitArray, Error) {
  read_body_loop(request, [])
}

fn read_body_loop(
  request: Request,
  chunks: List(BitArray),
) -> Result(BitArray, Error) {
  case next_event(request) {
    Ok(Data(chunk)) -> read_body_loop(request, [chunk, ..chunks])
    Ok(Trailers(_)) -> read_body_loop(request, chunks)
    Ok(End) -> Ok(bit_array.concat(list.reverse(chunks)))
    Error(error) -> Error(error)
  }
}

/// Send a complete bounded response.
pub fn respond(
  request request: Request,
  status status: Int,
  headers headers: List(#(String, String)),
  body body: BitArray,
) -> Result(Nil, Error) {
  use <- bool.guard(
    when: bit_array.bit_size(body) % 8 != 0,
    return: Error(InvalidBody),
  )
  case
    server_response.prepare_bounded(status, headers, bit_array.byte_size(body))
  {
    Ok(headers) ->
      map_backend(server_backend.respond(request.handle, status, headers, body))
    Error(error) -> Error(from_response_error(error))
  }
}

/// Send a streaming response head.
pub fn send_response(
  request request: Request,
  status status: Int,
  headers headers: List(#(String, String)),
) -> Result(Nil, Error) {
  case server_response.prepare_streaming(status, headers) {
    Ok(#(headers, declared_content_length)) -> {
      let declared_content_length = case declared_content_length {
        Some(length) -> length
        None -> -1
      }
      map_backend(server_backend.send_response(
        request.handle,
        status,
        headers,
        declared_content_length,
      ))
    }
    Error(error) -> Error(from_response_error(error))
  }
}

/// Send one byte-aligned streaming response-body chunk with backpressure.
pub fn send_chunk(
  request request: Request,
  chunk chunk: BitArray,
) -> Result(Nil, Error) {
  use <- bool.guard(
    when: bit_array.bit_size(chunk) % 8 != 0,
    return: Error(InvalidBody),
  )
  map_backend(server_backend.send_chunk(request.handle, chunk))
}

/// Finish a streaming response body.
pub fn finish_response(request: Request) -> Result(Nil, Error) {
  map_backend(server_backend.finish_response(request.handle))
}

/// Stop a listener and all owned connections idempotently.
pub fn stop(listener: Listener) -> Result(StopResult, Error) {
  let Listener(handle) = listener
  case server_backend.stop(handle) {
    Ok(1) -> Ok(Stopped)
    Ok(2) -> Ok(AlreadyStopped)
    Ok(_) -> Error(BackendFailure("invalid stop status"))
    Error(error) -> Error(from_backend_failure(error))
  }
}

fn map_backend(
  result: Result(value, server_backend.Failure),
) -> Result(value, Error) {
  case result {
    Ok(value) -> Ok(value)
    Error(error) -> Error(from_backend_failure(error))
  }
}

fn from_response_error(error: server_response.Error) -> Error {
  case error {
    server_response.InvalidStatus(status) -> InvalidStatus(status)
    server_response.InvalidHeader(name) -> InvalidHeader(name)
    server_response.InvalidContentLength -> InvalidContentLength
  }
}

fn from_backend_failure(failure: server_backend.Failure) -> Error {
  case failure {
    server_backend.StartFailed(message) -> StartFailed(message)
    server_backend.Timeout -> Timeout
    server_backend.ListenerClosed -> ListenerClosed
    server_backend.ConnectionClosed -> ConnectionClosed
    server_backend.StreamReset(code) -> StreamReset(code)
    server_backend.ProtocolError(code, message) -> ProtocolError(code, message)
    server_backend.RequestBodyTooLarge(limit) -> RequestBodyTooLarge(limit)
    server_backend.ResponseBodyTooLarge(limit) -> ResponseBodyTooLarge(limit)
    server_backend.ConsumerTooSlow(limit) -> ConsumerTooSlow(limit)
    server_backend.ConcurrentAccept -> ConcurrentAccept
    server_backend.ConcurrentReceive -> ConcurrentReceive
    server_backend.ResponseAlreadyStarted -> ResponseAlreadyStarted
    server_backend.ResponseNotStarted -> ResponseNotStarted
    server_backend.ResponseAlreadyFinished -> ResponseAlreadyFinished
    server_backend.InvalidContentLength -> InvalidContentLength
    server_backend.BackendFailure(message) -> BackendFailure(message)
  }
}

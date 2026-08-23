//// An HTTP/3 client for the Erlang target.
////
//// `send` owns one connection, collects one response within explicit limits,
//// and closes the connection before returning. `connect` instead creates a
//// reusable connection whose streams use synchronous request-body
//// backpressure and pull-based response events with bounded buffering.
////
//// ```gleam
//// import gleam/http/request
//// import http3/client
////
//// pub fn fetch() {
////   let assert Ok(request) = request.to("https://example.com/")
////   let request = request.set_body(request, <<>>)
////
////   client.send(client.new(), request)
//// }
//// ```

import gleam/bit_array
import gleam/bool
import gleam/http/request.{type Request}
import gleam/http/response.{type Response}
import http3/internal/client_backend
import http3/internal/client_request
import http3/internal/client_stream_backend
import http3/transport

const default_timeout_milliseconds = 30_000

const maximum_timeout_milliseconds = 3_600_000

const default_response_body_limit = 8_388_608

const default_request_body_limit = 8_388_608

const default_stream_buffer_limit = 262_144

/// Configuration for one-shot HTTP/3 requests.
pub opaque type Client {
  Client(
    timeout_milliseconds: Int,
    request_body_limit: Int,
    response_body_limit: Int,
    stream_buffer_limit: Int,
    ca_certificates: List(BitArray),
    http_datagrams: Bool,
    qlog_directory: String,
    resumption_tickets: List(client_stream_backend.ResumptionTicketHandle),
  )
}

/// A reusable secure HTTP/3 connection.
pub opaque type Connection {
  Connection(handle: client_stream_backend.ConnectionHandle)
}

/// One request and response stream on an HTTP/3 connection.
pub opaque type Stream {
  Stream(handle: client_stream_backend.StreamHandle)
}

/// One event from a streaming response.
pub type ResponseEvent {
  /// An informational response from status 100 through 199.
  InformationalResponse(status: Int, headers: List(#(String, String)))

  /// The final response head.
  Response(status: Int, headers: List(#(String, String)))

  /// A non-empty response-body chunk.
  Data(BitArray)

  /// Response trailers.
  Trailers(List(#(String, String)))

  /// The response stream ended successfully.
  End
}

/// The result of an idempotent stream cancellation.
pub type Cancellation {
  Cancelled
  AlreadyCancelled
  AlreadyCompleted
}

/// The result of idempotently closing a connection.
pub type CloseResult {
  Closed
  AlreadyClosed
}

/// An invalid client configuration value.
pub type ConfigurationError {
  /// A timeout must be between one millisecond and one hour.
  InvalidTimeout

  /// A response body limit must be greater than zero bytes.
  InvalidResponseBodyLimit

  /// A request body limit must be greater than zero bytes.
  InvalidRequestBodyLimit

  /// A streaming response buffer limit must be greater than zero bytes.
  InvalidStreamBufferLimit

  /// A CA certificate must be a non-empty, byte-aligned DER certificate.
  InvalidCaCertificate
}

/// A bounded HTTP/3 request failure.
pub type Error {
  /// HTTP/3 requests require the HTTPS scheme.
  InvalidScheme

  /// The request host is empty or contains surrounding whitespace.
  InvalidHost

  /// The request port is outside the UDP port range.
  InvalidPort(Int)

  /// The request body is not byte-aligned.
  InvalidBody

  /// The method is not supported by the bounded client.
  UnsupportedMethod(String)

  /// The request target is not an absolute path.
  InvalidPath(String)

  /// A request header is invalid for HTTP/3.
  InvalidHeader(String)

  /// The declared content length does not match the buffered request body.
  InvalidContentLength

  /// The connection or TLS handshake failed.
  ConnectFailed(String)

  /// The backend rejected the request before receiving a response.
  RequestFailed(String)

  /// The configured total request timeout expired.
  Timeout

  /// The response body exceeded the configured byte limit.
  ResponseBodyTooLarge(limit: Int)

  /// The request body exceeded the configured byte limit.
  RequestBodyTooLarge(limit: Int)

  /// The connection closed before the response completed.
  ConnectionClosed

  /// The peer reset the request stream with an HTTP/3 error code.
  StreamReset(code: Int)

  /// The peer or backend reported an HTTP/3 protocol error.
  ProtocolError(code: Int, message: String)

  /// The backend failed in an unexpected way.
  BackendFailure(String)

  /// A streaming consumer did not pull data before its buffer filled.
  ConsumerTooSlow(limit: Int)

  /// More than one process tried to receive from the same stream.
  ConcurrentReceive

  /// Request data was sent after its stream was finished.
  RequestAlreadyFinished

  /// No more response events are available from this completed stream.
  StreamFinished

  /// The stream was cancelled locally.
  StreamCancelled

  /// A request does not match the connection's host and port.
  OriginMismatch

  /// A resumed 0-RTT connection only permits replay-safe request methods.
  UnsafeEarlyDataMethod(String)

  /// A resumption ticket belongs to a different host or port.
  ResumptionOriginMismatch
}

/// Construct a client with secure TLS verification and bounded defaults.
///
/// The total timeout is 30 seconds. Buffered request and response bodies are
/// each limited to 8 MiB. Certificate chains are checked against the operating
/// system trust store and the request host is verified.
pub fn new() -> Client {
  Client(
    timeout_milliseconds: default_timeout_milliseconds,
    request_body_limit: default_request_body_limit,
    response_body_limit: default_response_body_limit,
    stream_buffer_limit: default_stream_buffer_limit,
    ca_certificates: [],
    http_datagrams: False,
    qlog_directory: "",
    resumption_tickets: [],
  )
}

/// Enable RFC 9297 HTTP Datagrams for reusable connections.
pub fn with_http_datagrams(client: Client) -> Client {
  Client(..client, http_datagrams: True)
}

/// Enable qlog tracing for reusable connections.
///
/// Trace files can contain sensitive connection metadata. qlog remains off
/// unless this function is called explicitly.
pub fn with_qlog(client client: Client, qlog qlog: transport.Qlog) -> Client {
  Client(..client, qlog_directory: transport.qlog_directory(qlog))
}

/// Attach one origin-bound session ticket for an explicit 0-RTT attempt.
///
/// Early requests are restricted to GET, HEAD, and OPTIONS because 0-RTT data
/// can be replayed by the network.
pub fn with_resumption_ticket(
  client client: Client,
  ticket ticket: transport.ResumptionTicket,
) -> Client {
  Client(..client, resumption_tickets: [transport.ticket_handle(ticket)])
}

/// Set the total request timeout from one millisecond through one hour.
pub fn with_timeout(
  client client: Client,
  milliseconds milliseconds: Int,
) -> Result(Client, ConfigurationError) {
  use <- bool.guard(
    when: milliseconds <= 0 || milliseconds > maximum_timeout_milliseconds,
    return: Error(InvalidTimeout),
  )
  Ok(Client(..client, timeout_milliseconds: milliseconds))
}

/// Set the maximum buffered response body size in bytes.
pub fn with_response_body_limit(
  client client: Client,
  bytes bytes: Int,
) -> Result(Client, ConfigurationError) {
  use <- bool.guard(when: bytes <= 0, return: Error(InvalidResponseBodyLimit))
  Ok(Client(..client, response_body_limit: bytes))
}

/// Set the maximum buffered request body size in bytes.
pub fn with_request_body_limit(
  client client: Client,
  bytes bytes: Int,
) -> Result(Client, ConfigurationError) {
  use <- bool.guard(when: bytes <= 0, return: Error(InvalidRequestBodyLimit))
  Ok(Client(..client, request_body_limit: bytes))
}

/// Set the maximum unconsumed response data retained per stream.
pub fn with_stream_buffer_limit(
  client client: Client,
  bytes bytes: Int,
) -> Result(Client, ConfigurationError) {
  use <- bool.guard(when: bytes <= 0, return: Error(InvalidStreamBufferLimit))
  Ok(Client(..client, stream_buffer_limit: bytes))
}

/// Add a DER-encoded CA certificate without disabling TLS verification.
///
/// Once a certificate is added, the configured certificates form an explicit
/// trust set in place of the operating system trust store. This is suitable
/// for private certificate authorities and local test fixtures. Hostname
/// verification remains enabled.
pub fn with_ca_certificate(
  client client: Client,
  certificate certificate: BitArray,
) -> Result(Client, ConfigurationError) {
  use <- bool.guard(
    when: bit_array.bit_size(certificate) == 0
      || bit_array.bit_size(certificate) % 8 != 0
      || !client_backend.is_valid_ca_certificate(certificate),
    return: Error(InvalidCaCertificate),
  )
  Ok(Client(..client, ca_certificates: [certificate, ..client.ca_certificates]))
}

/// Send one bounded, buffered HTTP/3 request.
///
/// The request must use HTTPS and an absolute path. CONNECT and HTTP/3-forbidden
/// connection-specific headers are rejected before a socket is opened. A new
/// connection is always closed before this function returns.
pub fn send(
  client client: Client,
  request request: Request(BitArray),
) -> Result(Response(BitArray), Error) {
  case client_request.prepare(request) {
    Ok(prepared) ->
      case bit_array.byte_size(request.body) > client.request_body_limit {
        True -> Error(RequestBodyTooLarge(client.request_body_limit))
        False -> send_prepared(client, prepared)
      }
    Error(error) -> Error(from_preparation_error(error))
  }
}

fn send_prepared(
  client: Client,
  request: client_request.PreparedRequest,
) -> Result(Response(BitArray), Error) {
  case
    client_backend.send(
      request,
      client.ca_certificates,
      client.timeout_milliseconds,
      client.response_body_limit,
    )
  {
    Ok(#(status, headers, body)) -> Ok(response.Response(status, headers, body))
    Error(error) ->
      Error(from_backend_failure(error, client.response_body_limit))
  }
}

/// Establish a reusable HTTP/3 connection with TLS verification enabled.
///
/// All streams opened on the connection must use the same host and port. The
/// connection is owned by the process that calls this function and is closed
/// automatically if that process exits.
pub fn connect(
  client client: Client,
  host host: String,
  port port: Int,
) -> Result(Connection, Error) {
  case client_request.prepare_origin(host, port) {
    Ok(_) ->
      case
        client_stream_backend.connect(
          host,
          port,
          client.ca_certificates,
          client.timeout_milliseconds,
          client.stream_buffer_limit,
          client.http_datagrams,
          client.qlog_directory,
          client.resumption_tickets,
        )
      {
        Ok(handle) -> Ok(Connection(handle))
        Error(error) ->
          Error(from_backend_failure(error, client.response_body_limit))
      }
    Error(error) -> Error(from_preparation_error(error))
  }
}

/// Obtain typed advanced controls for a reusable connection.
pub fn connection_transport(connection: Connection) -> transport.Connection {
  let Connection(handle) = connection
  transport.client_connection(handle)
}

/// Open a request stream, leaving its request body open for chunks.
pub fn open_stream(
  connection connection: Connection,
  request request: Request(Nil),
) -> Result(Stream, Error) {
  let Connection(handle) = connection
  case client_request.prepare_streaming(request) {
    Ok(prepared) ->
      case client_stream_backend.open_stream(handle, prepared) {
        Ok(stream) -> Ok(Stream(stream))
        Error(error) -> Error(from_backend_failure(error, 0))
      }
    Error(error) -> Error(from_preparation_error(error))
  }
}

/// Obtain typed advanced controls for a request stream.
pub fn stream_transport(stream: Stream) -> transport.Stream {
  let Stream(handle) = stream
  transport.client_stream(handle)
}

/// Send one byte-aligned request-body chunk.
///
/// The call does not return successfully until the backend accepts the chunk,
/// so a producer observes QUIC flow-control pressure.
pub fn send_chunk(
  stream stream: Stream,
  chunk chunk: BitArray,
) -> Result(Nil, Error) {
  use <- bool.guard(
    when: bit_array.bit_size(chunk) % 8 != 0,
    return: Error(InvalidBody),
  )
  let Stream(handle) = stream
  case client_stream_backend.send_chunk(handle, chunk) {
    Ok(value) -> Ok(value)
    Error(error) -> Error(from_backend_failure(error, 0))
  }
}

/// Finish a streaming request body.
pub fn finish(stream: Stream) -> Result(Nil, Error) {
  let Stream(handle) = stream
  case client_stream_backend.finish(handle) {
    Ok(value) -> Ok(value)
    Error(error) -> Error(from_backend_failure(error, 0))
  }
}

/// Pull the next response event, waiting up to the configured stream timeout.
pub fn next_event(stream: Stream) -> Result(ResponseEvent, Error) {
  let Stream(handle) = stream
  case client_stream_backend.next_event(handle) {
    Ok(#(1, status, headers, _)) -> Ok(InformationalResponse(status, headers))
    Ok(#(2, status, headers, _)) -> Ok(Response(status, headers))
    Ok(#(3, _, _, chunk)) -> Ok(Data(chunk))
    Ok(#(4, _, trailers, _)) -> Ok(Trailers(trailers))
    Ok(#(5, _, _, _)) -> Ok(End)
    Ok(_) -> Error(BackendFailure("invalid streaming event"))
    Error(error) -> Error(from_backend_failure(error, 0))
  }
}

/// Cancel a request stream idempotently.
pub fn cancel(stream: Stream) -> Result(Cancellation, Error) {
  let Stream(handle) = stream
  case client_stream_backend.cancel(handle) {
    Ok(1) -> Ok(Cancelled)
    Ok(2) -> Ok(AlreadyCancelled)
    Ok(3) -> Ok(AlreadyCompleted)
    Ok(_) -> Error(BackendFailure("invalid cancellation status"))
    Error(error) -> Error(from_backend_failure(error, 0))
  }
}

/// Close a connection and all of its streams idempotently.
pub fn close(connection: Connection) -> Result(CloseResult, Error) {
  let Connection(handle) = connection
  case client_stream_backend.close(handle) {
    Ok(1) -> Ok(Closed)
    Ok(2) -> Ok(AlreadyClosed)
    Ok(_) -> Error(BackendFailure("invalid close status"))
    Error(error) -> Error(from_backend_failure(error, 0))
  }
}

fn from_preparation_error(error: client_request.Error) -> Error {
  case error {
    client_request.InvalidScheme -> InvalidScheme
    client_request.InvalidHost -> InvalidHost
    client_request.InvalidPort(port) -> InvalidPort(port)
    client_request.InvalidBody -> InvalidBody
    client_request.UnsupportedMethod(method) -> UnsupportedMethod(method)
    client_request.InvalidPath(path) -> InvalidPath(path)
    client_request.InvalidHeader(name) -> InvalidHeader(name)
    client_request.InvalidContentLength -> InvalidContentLength
  }
}

fn from_backend_failure(
  failure: client_backend.Failure,
  response_body_limit: Int,
) -> Error {
  case failure {
    client_backend.ConnectFailed(message) -> ConnectFailed(message)
    client_backend.RequestFailed(message) -> RequestFailed(message)
    client_backend.Timeout -> Timeout
    client_backend.ResponseBodyTooLarge ->
      ResponseBodyTooLarge(response_body_limit)
    client_backend.ConnectionClosed -> ConnectionClosed
    client_backend.StreamReset(code) -> StreamReset(code)
    client_backend.ProtocolError(code, message) -> ProtocolError(code, message)
    client_backend.ConsumerTooSlow(limit) -> ConsumerTooSlow(limit)
    client_backend.ConcurrentReceive -> ConcurrentReceive
    client_backend.RequestAlreadyFinished -> RequestAlreadyFinished
    client_backend.StreamFinished -> StreamFinished
    client_backend.StreamCancelled -> StreamCancelled
    client_backend.OriginMismatch -> OriginMismatch
    client_backend.UnsafeEarlyDataMethod(method) ->
      UnsafeEarlyDataMethod(method)
    client_backend.ResumptionOriginMismatch -> ResumptionOriginMismatch
    client_backend.InvalidContentLength -> InvalidContentLength
    client_backend.BackendFailure(message) -> BackendFailure(message)
  }
}

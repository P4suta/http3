//// A bounded, buffered HTTP/3 client for the Erlang target.
////
//// Each call to `send` owns one HTTP/3 connection, waits for one complete
//// response, and closes the connection before returning. Request and response
//// bodies are `BitArray` values and are rejected when they exceed their
//// configured limits.
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
import gleam/http/response.{type Response, Response}
import http3/internal/client_backend
import http3/internal/client_request

const default_timeout_milliseconds = 30_000

const maximum_timeout_milliseconds = 3_600_000

const default_response_body_limit = 8_388_608

const default_request_body_limit = 8_388_608

/// Configuration for one-shot HTTP/3 requests.
pub opaque type Client {
  Client(
    timeout_milliseconds: Int,
    request_body_limit: Int,
    response_body_limit: Int,
    ca_certificates: List(BitArray),
  )
}

/// An invalid client configuration value.
pub type ConfigurationError {
  /// A timeout must be between one millisecond and one hour.
  InvalidTimeout

  /// A response body limit must be greater than zero bytes.
  InvalidResponseBodyLimit

  /// A request body limit must be greater than zero bytes.
  InvalidRequestBodyLimit

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
    ca_certificates: [],
  )
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
    Ok(#(status, headers, body)) -> Ok(Response(status, headers, body))
    Error(error) ->
      Error(from_backend_failure(error, client.response_body_limit))
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
    client_backend.BackendFailure(message) -> BackendFailure(message)
  }
}

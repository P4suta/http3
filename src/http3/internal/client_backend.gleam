//// Typed normalization around the Erlang HTTP/3 client FFI.

import gleam/int
import gleam/result
import gleam_quic/http3/client as native_client
import http3/internal/client_request.{type PreparedRequest, PreparedRequest}

/// A response returned by the backend boundary.
pub type Response =
  #(Int, List(#(String, String)), BitArray)

/// Primitive error data returned by the Erlang FFI.
pub type RawError =
  #(Int, Int, String)

/// A backend-independent client failure.
pub type Failure {
  ConnectFailed(String)
  RequestFailed(String)
  Timeout
  ResponseBodyTooLarge
  ConnectionClosed
  StreamReset(Int)
  ProtocolError(Int, String)
  ConsumerTooSlow(Int)
  ConcurrentReceive
  RequestAlreadyFinished
  StreamFinished
  StreamCancelled
  OriginMismatch
  UnsafeEarlyDataMethod(String)
  ResumptionOriginMismatch
  InvalidContentLength
  BackendFailure(String)
}

/// Return whether bytes decode as one DER X.509 certificate.
pub fn is_valid_ca_certificate(certificate: BitArray) -> Bool {
  native_client.is_valid_ca_certificate(certificate)
}

/// Execute one prepared request through the backend adapter.
pub fn send(
  request request: PreparedRequest,
  ca_certificates ca_certificates: List(BitArray),
  timeout_milliseconds timeout_milliseconds: Int,
  response_body_limit response_body_limit: Int,
) -> Result(Response, Failure) {
  let PreparedRequest(host, port, headers, body) = request
  use client <- result.try(
    native_client.new(host, port)
    |> result.map_error(from_native_configuration_error),
  )
  use client <- result.try(
    native_client.with_timeout(client, timeout_milliseconds)
    |> result.map_error(from_native_configuration_error),
  )
  use client <- result.try(
    native_client.with_response_body_limit(client, response_body_limit)
    |> result.map_error(from_native_configuration_error),
  )
  use client <- result.try(case ca_certificates {
    [] -> Ok(client)
    certificates ->
      native_client.with_ca_certificates(client, certificates)
      |> result.map_error(from_native_configuration_error)
  })
  case native_client.send(client, headers, body) {
    Ok(native_client.Response(status, headers, body)) ->
      Ok(#(status, headers, body))
    Error(error) -> Error(from_native_error(error))
  }
}

fn from_native_configuration_error(
  error: native_client.ConfigurationError,
) -> Failure {
  let message = case error {
    native_client.InvalidHost -> "invalid native host"
    native_client.InvalidPort(port) ->
      "invalid native port: " <> int.to_string(port)
    native_client.InvalidTimeout -> "invalid native timeout"
    native_client.InvalidResponseBodyLimit -> "invalid native response limit"
    native_client.InvalidCaCertificate -> "invalid CA certificate"
  }
  ConnectFailed(message)
}

fn from_native_error(error: native_client.Error) -> Failure {
  case error {
    native_client.InvalidRequest -> RequestFailed("invalid native request")
    native_client.ResolutionFailed -> ConnectFailed("name resolution failed")
    native_client.TrustStoreFailed -> ConnectFailed("trust store unavailable")
    native_client.ConnectFailed -> ConnectFailed("UDP connection failed")
    native_client.HandshakeFailed -> ConnectFailed("TLS handshake failed")
    native_client.TransportError(message) ->
      ProtocolError(0x0102, "native QUIC transport error: " <> message)
    native_client.Http3Error(message) ->
      ProtocolError(0x0102, "native HTTP/3 protocol error: " <> message)
    native_client.Timeout -> Timeout
    native_client.ConnectionClosed -> ConnectionClosed
    native_client.StreamReset(code) -> StreamReset(code)
    native_client.ProtocolError ->
      ProtocolError(0x0102, "native protocol error")
    native_client.InvalidHeaderEncoding ->
      ProtocolError(0x0102, "response header is not UTF-8")
    native_client.ResponseBodyTooLarge(_) -> ResponseBodyTooLarge
  }
}

/// Convert primitive FFI error data into an internal typed failure.
pub fn normalize_error(error: RawError) -> Failure {
  case error {
    #(1, _, message) -> ConnectFailed(message)
    #(2, _, message) -> RequestFailed(message)
    #(3, _, _) -> Timeout
    #(4, _, _) -> ResponseBodyTooLarge
    #(5, _, _) -> ConnectionClosed
    #(6, code, _) -> StreamReset(code)
    #(7, code, message) -> ProtocolError(code, message)
    #(14, _, _) -> InvalidContentLength
    #(15, limit, _) -> ConsumerTooSlow(limit)
    #(16, _, _) -> ConcurrentReceive
    #(17, _, _) -> RequestAlreadyFinished
    #(18, _, _) -> StreamFinished
    #(19, _, _) -> StreamCancelled
    #(20, _, _) -> OriginMismatch
    #(21, _, method) -> UnsafeEarlyDataMethod(method)
    #(22, _, _) -> ResumptionOriginMismatch
    #(_, _, message) -> BackendFailure(message)
  }
}

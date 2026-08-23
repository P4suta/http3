//// Typed normalization around the Erlang HTTP/3 client FFI.

import http3/internal/client_request.{type PreparedRequest, PreparedRequest}

@external(erlang, "http3_internal_client_ffi", "valid_ca_certificate")
fn raw_valid_ca_certificate(certificate: BitArray) -> Bool

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
  raw_valid_ca_certificate(certificate)
}

@external(erlang, "http3_internal_client_ffi", "send")
fn raw_send(
  host: String,
  port: Int,
  headers: List(#(String, String)),
  body: BitArray,
  ca_certificates: List(BitArray),
  timeout_milliseconds: Int,
  response_body_limit: Int,
) -> Result(Response, RawError)

/// Execute one prepared request through the backend adapter.
pub fn send(
  request request: PreparedRequest,
  ca_certificates ca_certificates: List(BitArray),
  timeout_milliseconds timeout_milliseconds: Int,
  response_body_limit response_body_limit: Int,
) -> Result(Response, Failure) {
  let PreparedRequest(host, port, headers, body) = request
  case
    raw_send(
      host,
      port,
      headers,
      body,
      ca_certificates,
      timeout_milliseconds,
      response_body_limit,
    )
  {
    Ok(response) -> Ok(response)
    Error(error) -> Error(normalize_error(error))
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

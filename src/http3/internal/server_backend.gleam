//// Typed normalization around the repository-owned HTTP/3 server.

import gleam/option.{None, Some}
import gleam/result
import gleam_quic/http3/server as native_server

pub type ListenerHandle =
  native_server.Listener

pub type RequestHandle =
  native_server.Request

pub type RawError =
  #(Int, Int, String)

pub type Incoming =
  #(RequestHandle, String, String, List(#(String, String)))

pub type RawEvent =
  #(Int, List(#(String, String)), BitArray)

pub type Failure {
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
  InvalidContentLength
  BackendFailure(String)
}

pub fn valid_certificate(certificate: BitArray) -> Bool {
  native_server.is_valid_certificate(certificate)
}

pub fn valid_private_key(private_key: BitArray) -> Bool {
  native_server.is_valid_private_key(private_key)
}

pub fn start(
  certificate certificate: BitArray,
  private_key private_key: BitArray,
  port port: Int,
  timeout_milliseconds timeout_milliseconds: Int,
  request_body_limit request_body_limit: Int,
  response_body_limit response_body_limit: Int,
  stream_buffer_limit stream_buffer_limit: Int,
  http_datagrams http_datagrams: Bool,
  qlog_directory qlog_directory: String,
) -> Result(ListenerHandle, Failure) {
  use configuration <- result.try(
    native_server.new(certificate, private_key)
    |> result.map_error(map_configuration_error),
  )
  use configuration <- result.try(
    native_server.with_port(configuration, port)
    |> result.map_error(map_configuration_error),
  )
  use configuration <- result.try(
    native_server.with_timeout(configuration, timeout_milliseconds)
    |> result.map_error(map_configuration_error),
  )
  use configuration <- result.try(
    native_server.with_request_body_limit(configuration, request_body_limit)
    |> result.map_error(map_configuration_error),
  )
  use configuration <- result.try(
    native_server.with_response_body_limit(configuration, response_body_limit)
    |> result.map_error(map_configuration_error),
  )
  use configuration <- result.try(
    native_server.with_stream_buffer_limit(configuration, stream_buffer_limit)
    |> result.map_error(map_configuration_error),
  )
  let configuration = case http_datagrams {
    True -> native_server.with_http_datagrams(configuration)
    False -> configuration
  }
  let configuration = case qlog_directory {
    "" -> Ok(configuration)
    _ -> native_server.with_qlog(configuration, qlog_directory)
  }
  use configuration <- result.try(
    configuration |> result.map_error(map_configuration_error),
  )
  native_server.start(configuration) |> result.map_error(map_native_error)
}

fn map_configuration_error(error: native_server.ConfigurationError) -> Failure {
  let detail = case error {
    native_server.InvalidCertificate -> "certificate"
    native_server.InvalidPrivateKey -> "private key"
    native_server.IncompatiblePrivateKey -> "certificate/private-key pairing"
    native_server.InvalidPort(_) -> "listener port"
    native_server.InvalidTimeout -> "listener timeout"
    native_server.InvalidRequestBodyLimit -> "request body limit"
    native_server.InvalidResponseBodyLimit -> "response body limit"
    native_server.InvalidStreamBufferLimit -> "stream buffer limit"
    native_server.InvalidQlogDirectory -> "qlog directory"
  }
  StartFailed("invalid server " <> detail)
}

pub fn port(listener: ListenerHandle) -> Result(Int, Failure) {
  native_server.port(listener) |> result.map_error(map_native_error)
}

pub fn accept(listener: ListenerHandle) -> Result(Incoming, Failure) {
  case native_server.accept(listener) {
    Ok(native_server.Incoming(request, method, path, headers)) ->
      Ok(#(request, method, path, headers))
    Error(error) -> Error(map_native_error(error))
  }
}

pub fn next_event(request: RequestHandle) -> Result(RawEvent, Failure) {
  case native_server.next_event(request) {
    Ok(native_server.Data(bytes)) -> Ok(#(1, [], bytes))
    Ok(native_server.Trailers(headers)) -> Ok(#(2, headers, <<>>))
    Ok(native_server.End) -> Ok(#(3, [], <<>>))
    Error(error) -> Error(map_native_error(error))
  }
}

pub fn respond(
  request request: RequestHandle,
  status status: Int,
  headers headers: List(#(String, String)),
  body body: BitArray,
) -> Result(Nil, Failure) {
  native_server.respond(request, status, headers, body)
  |> result.map_error(map_native_error)
}

pub fn send_response(
  request request: RequestHandle,
  status status: Int,
  headers headers: List(#(String, String)),
  declared_content_length declared_content_length: Int,
) -> Result(Nil, Failure) {
  let declared = case declared_content_length {
    -1 -> None
    value -> Some(value)
  }
  native_server.send_response(request, status, headers, declared)
  |> result.map_error(map_native_error)
}

pub fn send_chunk(
  request request: RequestHandle,
  chunk chunk: BitArray,
) -> Result(Nil, Failure) {
  native_server.send_chunk(request, chunk) |> result.map_error(map_native_error)
}

pub fn finish_response(request: RequestHandle) -> Result(Nil, Failure) {
  native_server.finish_response(request) |> result.map_error(map_native_error)
}

pub fn stop(listener: ListenerHandle) -> Result(Int, Failure) {
  case native_server.stop(listener) {
    Ok(native_server.Stopped) -> Ok(1)
    Ok(native_server.AlreadyStopped) -> Ok(2)
    Error(error) -> Error(map_native_error(error))
  }
}

pub fn normalize_error(error: RawError) -> Failure {
  case error {
    #(1, _, message) -> StartFailed(message)
    #(2, _, _) -> Timeout
    #(3, _, _) -> ListenerClosed
    #(4, _, _) -> ConnectionClosed
    #(5, code, _) -> StreamReset(code)
    #(6, code, message) -> ProtocolError(code, message)
    #(7, limit, _) -> RequestBodyTooLarge(limit)
    #(8, limit, _) -> ResponseBodyTooLarge(limit)
    #(9, limit, _) -> ConsumerTooSlow(limit)
    #(10, _, _) -> ConcurrentAccept
    #(11, _, _) -> ConcurrentReceive
    #(12, _, _) -> ResponseAlreadyStarted
    #(13, _, _) -> ResponseNotStarted
    #(14, _, _) -> ResponseAlreadyFinished
    #(15, _, _) -> InvalidContentLength
    #(_, _, message) -> BackendFailure(message)
  }
}

fn map_native_error(error: native_server.Error) -> Failure {
  case error {
    native_server.StartFailed -> StartFailed("native listener start failed")
    native_server.Timeout -> Timeout
    native_server.ListenerClosed -> ListenerClosed
    native_server.ConnectionClosed -> ConnectionClosed
    native_server.StreamReset(code) -> StreamReset(code)
    native_server.ProtocolError(code, message) -> ProtocolError(code, message)
    native_server.RequestBodyTooLarge(limit) -> RequestBodyTooLarge(limit)
    native_server.ResponseBodyTooLarge(limit) -> ResponseBodyTooLarge(limit)
    native_server.ConsumerTooSlow(limit) -> ConsumerTooSlow(limit)
    native_server.ConcurrentAccept -> ConcurrentAccept
    native_server.ConcurrentReceive -> ConcurrentReceive
    native_server.ResponseAlreadyStarted -> ResponseAlreadyStarted
    native_server.ResponseNotStarted -> ResponseNotStarted
    native_server.ResponseAlreadyFinished -> ResponseAlreadyFinished
    native_server.InvalidContentLength -> InvalidContentLength
    native_server.InvalidInput
    | native_server.InvalidHeaderEncoding
    | native_server.DatagramsNotNegotiated
    | native_server.DatagramTooLarge(_)
    | native_server.DatagramBufferExceeded(_)
    | native_server.ConcurrentDatagramReceive
    | native_server.StreamFinished
    | native_server.CongestionLimited -> BackendFailure("native server failure")
    native_server.BackendFailure(message) -> BackendFailure(message)
  }
}

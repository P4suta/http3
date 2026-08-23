//// Typed normalization around the Erlang HTTP/3 server worker.

/// Opaque backend-owned listener identity.
pub type ListenerHandle

/// Opaque backend-owned request identity.
pub type RequestHandle

/// Primitive error data returned by the Erlang FFI.
pub type RawError =
  #(Int, Int, String)

/// Primitive accepted request data.
pub type Incoming =
  #(RequestHandle, String, String, List(#(String, String)))

/// Primitive request-body event data.
pub type RawEvent =
  #(Int, List(#(String, String)), BitArray)

/// A normalized server backend failure.
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

@external(erlang, "http3_internal_server_ffi", "valid_certificate")
pub fn valid_certificate(certificate: BitArray) -> Bool

@external(erlang, "http3_internal_server_ffi", "valid_private_key")
pub fn valid_private_key(private_key: BitArray) -> Bool

@external(erlang, "http3_internal_server_ffi", "start")
fn raw_start(
  certificate: BitArray,
  private_key: BitArray,
  port: Int,
  timeout_milliseconds: Int,
  request_body_limit: Int,
  response_body_limit: Int,
  stream_buffer_limit: Int,
  http_datagrams: Bool,
  qlog_directory: String,
) -> Result(ListenerHandle, RawError)

@external(erlang, "http3_internal_server_ffi", "port")
fn raw_port(listener: ListenerHandle) -> Result(Int, RawError)

@external(erlang, "http3_internal_server_ffi", "accept")
fn raw_accept(listener: ListenerHandle) -> Result(Incoming, RawError)

@external(erlang, "http3_internal_server_ffi", "next_event")
fn raw_next_event(request: RequestHandle) -> Result(RawEvent, RawError)

@external(erlang, "http3_internal_server_ffi", "respond")
fn raw_respond(
  request: RequestHandle,
  status: Int,
  headers: List(#(String, String)),
  body: BitArray,
) -> Result(Nil, RawError)

@external(erlang, "http3_internal_server_ffi", "send_response")
fn raw_send_response(
  request: RequestHandle,
  status: Int,
  headers: List(#(String, String)),
  declared_content_length: Int,
) -> Result(Nil, RawError)

@external(erlang, "http3_internal_server_ffi", "send_chunk")
fn raw_send_chunk(
  request: RequestHandle,
  chunk: BitArray,
) -> Result(Nil, RawError)

@external(erlang, "http3_internal_server_ffi", "finish_response")
fn raw_finish_response(request: RequestHandle) -> Result(Nil, RawError)

@external(erlang, "http3_internal_server_ffi", "stop")
fn raw_stop(listener: ListenerHandle) -> Result(Int, RawError)

/// Start a listener worker.
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
  raw_start(
    certificate,
    private_key,
    port,
    timeout_milliseconds,
    request_body_limit,
    response_body_limit,
    stream_buffer_limit,
    http_datagrams,
    qlog_directory,
  )
  |> normalize_result
}

/// Return the bound UDP port.
pub fn port(listener: ListenerHandle) -> Result(Int, Failure) {
  raw_port(listener) |> normalize_result
}

/// Pull the next request head.
pub fn accept(listener: ListenerHandle) -> Result(Incoming, Failure) {
  raw_accept(listener) |> normalize_result
}

/// Pull one request-body event.
pub fn next_event(request: RequestHandle) -> Result(RawEvent, Failure) {
  raw_next_event(request) |> normalize_result
}

/// Send one bounded response.
pub fn respond(
  request request: RequestHandle,
  status status: Int,
  headers headers: List(#(String, String)),
  body body: BitArray,
) -> Result(Nil, Failure) {
  raw_respond(request, status, headers, body) |> normalize_result
}

/// Send a streaming response head.
pub fn send_response(
  request request: RequestHandle,
  status status: Int,
  headers headers: List(#(String, String)),
  declared_content_length declared_content_length: Int,
) -> Result(Nil, Failure) {
  raw_send_response(request, status, headers, declared_content_length)
  |> normalize_result
}

/// Send one streaming response-body chunk.
pub fn send_chunk(
  request request: RequestHandle,
  chunk chunk: BitArray,
) -> Result(Nil, Failure) {
  raw_send_chunk(request, chunk) |> normalize_result
}

/// Finish a streaming response body.
pub fn finish_response(request: RequestHandle) -> Result(Nil, Failure) {
  raw_finish_response(request) |> normalize_result
}

/// Stop a listener and return a primitive idempotence status.
pub fn stop(listener: ListenerHandle) -> Result(Int, Failure) {
  raw_stop(listener) |> normalize_result
}

/// Normalize primitive FFI error data.
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

fn normalize_result(result: Result(value, RawError)) -> Result(value, Failure) {
  case result {
    Ok(value) -> Ok(value)
    Error(error) -> Error(normalize_error(error))
  }
}

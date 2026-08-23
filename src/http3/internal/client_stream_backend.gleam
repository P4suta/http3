//// Typed boundary around the reusable HTTP/3 client worker.

import gleam/option.{None, Some}
import http3/internal/client_backend
import http3/internal/client_request.{
  type PreparedStreamingRequest, PreparedStreamingRequest,
}

/// Opaque backend-owned connection identity.
pub type ConnectionHandle

/// Opaque backend-owned request-stream identity.
pub type StreamHandle

/// Opaque backend-owned TLS resumption material.
pub type ResumptionTicketHandle

/// Primitive event data returned across the FFI boundary.
pub type RawEvent =
  #(Int, Int, List(#(String, String)), BitArray)

@external(erlang, "http3_internal_stream_ffi", "connect")
fn raw_connect(
  host: String,
  port: Int,
  ca_certificates: List(BitArray),
  timeout_milliseconds: Int,
  stream_buffer_limit: Int,
  http_datagrams: Bool,
  qlog_directory: String,
  resumption_tickets: List(ResumptionTicketHandle),
) -> Result(ConnectionHandle, client_backend.RawError)

@external(erlang, "http3_internal_stream_ffi", "open_stream")
fn raw_open_stream(
  connection: ConnectionHandle,
  host: String,
  port: Int,
  headers: List(#(String, String)),
  declared_content_length: Int,
) -> Result(StreamHandle, client_backend.RawError)

@external(erlang, "http3_internal_stream_ffi", "send_chunk")
fn raw_send_chunk(
  stream: StreamHandle,
  chunk: BitArray,
) -> Result(Nil, client_backend.RawError)

@external(erlang, "http3_internal_stream_ffi", "finish")
fn raw_finish(stream: StreamHandle) -> Result(Nil, client_backend.RawError)

@external(erlang, "http3_internal_stream_ffi", "next_event")
fn raw_next_event(
  stream: StreamHandle,
) -> Result(RawEvent, client_backend.RawError)

@external(erlang, "http3_internal_stream_ffi", "cancel")
fn raw_cancel(stream: StreamHandle) -> Result(Int, client_backend.RawError)

@external(erlang, "http3_internal_stream_ffi", "close")
fn raw_close(
  connection: ConnectionHandle,
) -> Result(Int, client_backend.RawError)

/// Establish one reusable, securely verified HTTP/3 connection.
pub fn connect(
  host host: String,
  port port: Int,
  ca_certificates ca_certificates: List(BitArray),
  timeout_milliseconds timeout_milliseconds: Int,
  stream_buffer_limit stream_buffer_limit: Int,
  http_datagrams http_datagrams: Bool,
  qlog_directory qlog_directory: String,
  resumption_tickets resumption_tickets: List(ResumptionTicketHandle),
) -> Result(ConnectionHandle, client_backend.Failure) {
  raw_connect(
    host,
    port,
    ca_certificates,
    timeout_milliseconds,
    stream_buffer_limit,
    http_datagrams,
    qlog_directory,
    resumption_tickets,
  )
  |> normalize_result
}

/// Open a request stream without ending its request body.
pub fn open_stream(
  connection connection: ConnectionHandle,
  request request: PreparedStreamingRequest,
) -> Result(StreamHandle, client_backend.Failure) {
  let PreparedStreamingRequest(host, port, headers, content_length) = request
  let content_length = case content_length {
    Some(length) -> length
    None -> -1
  }
  raw_open_stream(connection, host, port, headers, content_length)
  |> normalize_result
}

/// Send one request-body chunk with synchronous flow-control feedback.
pub fn send_chunk(
  stream stream: StreamHandle,
  chunk chunk: BitArray,
) -> Result(Nil, client_backend.Failure) {
  raw_send_chunk(stream, chunk) |> normalize_result
}

/// End a request body.
pub fn finish(stream: StreamHandle) -> Result(Nil, client_backend.Failure) {
  raw_finish(stream) |> normalize_result
}

/// Pull the next response event.
pub fn next_event(
  stream: StreamHandle,
) -> Result(RawEvent, client_backend.Failure) {
  raw_next_event(stream) |> normalize_result
}

/// Cancel a request stream and return a primitive idempotence status.
pub fn cancel(stream: StreamHandle) -> Result(Int, client_backend.Failure) {
  raw_cancel(stream) |> normalize_result
}

/// Close a connection and return a primitive idempotence status.
pub fn close(
  connection: ConnectionHandle,
) -> Result(Int, client_backend.Failure) {
  raw_close(connection) |> normalize_result
}

fn normalize_result(
  result: Result(value, client_backend.RawError),
) -> Result(value, client_backend.Failure) {
  case result {
    Ok(value) -> Ok(value)
    Error(error) -> Error(client_backend.normalize_error(error))
  }
}

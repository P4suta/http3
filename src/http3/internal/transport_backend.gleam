//// Typed normalization for advanced QUIC and HTTP/3 transport controls.

import http3/internal/client_stream_backend
import http3/internal/server_backend

/// Primitive transport error data returned by the Erlang FFI.
pub type RawError =
  #(Int, Int, String)

/// Primitive negotiated capability data.
pub type RawCapabilities =
  #(Bool, Bool, Bool, Bool)

/// Primitive path metrics.
pub type RawPathStats =
  #(Int, Int, Int, Int, Int, Int, Bool, Bool)

/// Primitive connection counters.
pub type RawConnectionStats =
  #(Int, Int, Int, Int, Int, Int, Int, Int)

/// A normalized advanced transport failure.
pub type Failure {
  ConnectionClosed
  Timeout
  DatagramsNotNegotiated
  DatagramTooLarge(Int)
  CongestionLimited
  UnknownStream
  DatagramBufferExceeded(Int)
  ConcurrentDatagramReceive
  MigrationUnavailable
  NotConnected
  BackendFailure(String)
}

@external(erlang, "http3_internal_stream_ffi", "transport_capabilities")
fn raw_client_capabilities(
  connection: client_stream_backend.ConnectionHandle,
) -> Result(RawCapabilities, RawError)

@external(erlang, "http3_internal_stream_ffi", "transport_stream_capabilities")
fn raw_client_stream_capabilities(
  stream: client_stream_backend.StreamHandle,
) -> Result(RawCapabilities, RawError)

@external(erlang, "http3_internal_stream_ffi", "max_datagram_size")
fn raw_client_max_datagram_size(
  stream: client_stream_backend.StreamHandle,
) -> Result(Int, RawError)

@external(erlang, "http3_internal_stream_ffi", "send_datagram")
fn raw_client_send_datagram(
  stream: client_stream_backend.StreamHandle,
  payload: BitArray,
) -> Result(Nil, RawError)

@external(erlang, "http3_internal_stream_ffi", "next_datagram")
fn raw_client_next_datagram(
  stream: client_stream_backend.StreamHandle,
) -> Result(BitArray, RawError)

@external(erlang, "http3_internal_stream_ffi", "set_priority")
fn raw_client_set_priority(
  stream: client_stream_backend.StreamHandle,
  urgency: Int,
  incremental: Bool,
) -> Result(Nil, RawError)

@external(erlang, "http3_internal_stream_ffi", "get_priority")
fn raw_client_get_priority(
  stream: client_stream_backend.StreamHandle,
) -> Result(#(Int, Bool), RawError)

@external(erlang, "http3_internal_stream_ffi", "early_data_status")
fn raw_client_early_data_status(
  connection: client_stream_backend.ConnectionHandle,
) -> Result(Int, RawError)

@external(erlang, "http3_internal_stream_ffi", "stream_early_data_status")
fn raw_client_stream_early_data_status(
  stream: client_stream_backend.StreamHandle,
) -> Result(Int, RawError)

@external(erlang, "http3_internal_stream_ffi", "resumption_ticket")
fn raw_resumption_ticket(
  connection: client_stream_backend.ConnectionHandle,
) -> Result(client_stream_backend.ResumptionTicketHandle, RawError)

@external(erlang, "http3_internal_stream_ffi", "migrate")
fn raw_migrate(
  connection: client_stream_backend.ConnectionHandle,
) -> Result(Nil, RawError)

@external(erlang, "http3_internal_stream_ffi", "set_congestion_control")
fn raw_set_congestion_control(
  connection: client_stream_backend.ConnectionHandle,
  algorithm: Int,
) -> Result(Nil, RawError)

@external(erlang, "http3_internal_stream_ffi", "ping")
fn raw_ping(
  connection: client_stream_backend.ConnectionHandle,
) -> Result(Nil, RawError)

@external(erlang, "http3_internal_stream_ffi", "maximum_transmission_unit")
fn raw_maximum_transmission_unit(
  connection: client_stream_backend.ConnectionHandle,
) -> Result(Int, RawError)

@external(erlang, "http3_internal_stream_ffi", "path_stats")
fn raw_path_stats(
  connection: client_stream_backend.ConnectionHandle,
) -> Result(RawPathStats, RawError)

@external(erlang, "http3_internal_stream_ffi", "connection_stats")
fn raw_connection_stats(
  connection: client_stream_backend.ConnectionHandle,
) -> Result(RawConnectionStats, RawError)

@external(erlang, "http3_internal_server_ffi", "transport_stream_capabilities")
fn raw_server_stream_capabilities(
  request: server_backend.RequestHandle,
) -> Result(RawCapabilities, RawError)

@external(erlang, "http3_internal_server_ffi", "max_datagram_size")
fn raw_server_max_datagram_size(
  request: server_backend.RequestHandle,
) -> Result(Int, RawError)

@external(erlang, "http3_internal_server_ffi", "send_datagram")
fn raw_server_send_datagram(
  request: server_backend.RequestHandle,
  payload: BitArray,
) -> Result(Nil, RawError)

@external(erlang, "http3_internal_server_ffi", "next_datagram")
fn raw_server_next_datagram(
  request: server_backend.RequestHandle,
) -> Result(BitArray, RawError)

@external(erlang, "http3_internal_server_ffi", "set_priority")
fn raw_server_set_priority(
  request: server_backend.RequestHandle,
  urgency: Int,
  incremental: Bool,
) -> Result(Nil, RawError)

@external(erlang, "http3_internal_server_ffi", "get_priority")
fn raw_server_get_priority(
  request: server_backend.RequestHandle,
) -> Result(#(Int, Bool), RawError)

@external(erlang, "http3_internal_server_ffi", "early_data_status")
fn raw_server_early_data_status(
  request: server_backend.RequestHandle,
) -> Result(Int, RawError)

pub fn client_capabilities(
  connection: client_stream_backend.ConnectionHandle,
) -> Result(RawCapabilities, Failure) {
  raw_client_capabilities(connection) |> normalize_result
}

pub fn client_stream_capabilities(
  stream: client_stream_backend.StreamHandle,
) -> Result(RawCapabilities, Failure) {
  raw_client_stream_capabilities(stream) |> normalize_result
}

pub fn server_stream_capabilities(
  request: server_backend.RequestHandle,
) -> Result(RawCapabilities, Failure) {
  raw_server_stream_capabilities(request) |> normalize_result
}

pub fn client_max_datagram_size(
  stream: client_stream_backend.StreamHandle,
) -> Result(Int, Failure) {
  raw_client_max_datagram_size(stream) |> normalize_result
}

pub fn server_max_datagram_size(
  request: server_backend.RequestHandle,
) -> Result(Int, Failure) {
  raw_server_max_datagram_size(request) |> normalize_result
}

pub fn client_send_datagram(
  stream stream: client_stream_backend.StreamHandle,
  payload payload: BitArray,
) -> Result(Nil, Failure) {
  raw_client_send_datagram(stream, payload) |> normalize_result
}

pub fn server_send_datagram(
  request request: server_backend.RequestHandle,
  payload payload: BitArray,
) -> Result(Nil, Failure) {
  raw_server_send_datagram(request, payload) |> normalize_result
}

pub fn client_next_datagram(
  stream: client_stream_backend.StreamHandle,
) -> Result(BitArray, Failure) {
  raw_client_next_datagram(stream) |> normalize_result
}

pub fn server_next_datagram(
  request: server_backend.RequestHandle,
) -> Result(BitArray, Failure) {
  raw_server_next_datagram(request) |> normalize_result
}

pub fn client_set_priority(
  stream stream: client_stream_backend.StreamHandle,
  urgency urgency: Int,
  incremental incremental: Bool,
) -> Result(Nil, Failure) {
  raw_client_set_priority(stream, urgency, incremental) |> normalize_result
}

pub fn server_set_priority(
  request request: server_backend.RequestHandle,
  urgency urgency: Int,
  incremental incremental: Bool,
) -> Result(Nil, Failure) {
  raw_server_set_priority(request, urgency, incremental) |> normalize_result
}

pub fn client_get_priority(
  stream: client_stream_backend.StreamHandle,
) -> Result(#(Int, Bool), Failure) {
  raw_client_get_priority(stream) |> normalize_result
}

pub fn server_get_priority(
  request: server_backend.RequestHandle,
) -> Result(#(Int, Bool), Failure) {
  raw_server_get_priority(request) |> normalize_result
}

pub fn client_early_data_status(
  connection: client_stream_backend.ConnectionHandle,
) -> Result(Int, Failure) {
  raw_client_early_data_status(connection) |> normalize_result
}

pub fn client_stream_early_data_status(
  stream: client_stream_backend.StreamHandle,
) -> Result(Int, Failure) {
  raw_client_stream_early_data_status(stream) |> normalize_result
}

pub fn server_early_data_status(
  request: server_backend.RequestHandle,
) -> Result(Int, Failure) {
  raw_server_early_data_status(request) |> normalize_result
}

pub fn resumption_ticket(
  connection: client_stream_backend.ConnectionHandle,
) -> Result(client_stream_backend.ResumptionTicketHandle, Failure) {
  raw_resumption_ticket(connection) |> normalize_result
}

pub fn migrate(
  connection: client_stream_backend.ConnectionHandle,
) -> Result(Nil, Failure) {
  raw_migrate(connection) |> normalize_result
}

pub fn set_congestion_control(
  connection connection: client_stream_backend.ConnectionHandle,
  algorithm algorithm: Int,
) -> Result(Nil, Failure) {
  raw_set_congestion_control(connection, algorithm) |> normalize_result
}

pub fn ping(
  connection: client_stream_backend.ConnectionHandle,
) -> Result(Nil, Failure) {
  raw_ping(connection) |> normalize_result
}

pub fn maximum_transmission_unit(
  connection: client_stream_backend.ConnectionHandle,
) -> Result(Int, Failure) {
  raw_maximum_transmission_unit(connection) |> normalize_result
}

pub fn path_stats(
  connection: client_stream_backend.ConnectionHandle,
) -> Result(RawPathStats, Failure) {
  raw_path_stats(connection) |> normalize_result
}

pub fn connection_stats(
  connection: client_stream_backend.ConnectionHandle,
) -> Result(RawConnectionStats, Failure) {
  raw_connection_stats(connection) |> normalize_result
}

pub fn normalize_error(error: RawError) -> Failure {
  case error {
    #(1, _, _) -> ConnectionClosed
    #(2, _, _) -> Timeout
    #(3, _, _) -> DatagramsNotNegotiated
    #(4, maximum, _) -> DatagramTooLarge(maximum)
    #(5, _, _) -> CongestionLimited
    #(6, _, _) -> UnknownStream
    #(7, limit, _) -> DatagramBufferExceeded(limit)
    #(8, _, _) -> ConcurrentDatagramReceive
    #(9, _, _) -> MigrationUnavailable
    #(10, _, _) -> NotConnected
    #(_, _, message) -> BackendFailure(message)
  }
}

fn normalize_result(result: Result(value, RawError)) -> Result(value, Failure) {
  case result {
    Ok(value) -> Ok(value)
    Error(error) -> Error(normalize_error(error))
  }
}

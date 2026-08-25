//// Typed normalization for advanced QUIC and HTTP/3 transport controls.

import gleam/option.{None}
import gleam/result
import http3/failure as runtime_failure
import http3/internal/client_stream_backend
import http3/internal/native/client as native_client
import http3/internal/native/server as native_server
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

/// Primitive bounded diagnostic-writer counters.
pub type RawTelemetryStats =
  #(Int, Int, Int)

pub opaque type TicketStorageKey {
  TicketStorageKey(native: native_client.TicketStorageKey)
}

/// A normalized advanced transport failure.
pub type Failure {
  ConnectionClosed
  Timeout
  DatagramsNotNegotiated
  DatagramNotAssociated
  DatagramTooLarge(Int)
  CongestionLimited
  UnknownStream
  DatagramBufferExceeded(Int)
  ConcurrentDatagramReceive
  MigrationUnavailable
  NotConnected
  InvalidResumptionTicket
  RuntimeFailure(runtime_failure.Failure)
}

pub fn ticket_storage_key(bytes: BitArray) -> Result(TicketStorageKey, Nil) {
  native_client.ticket_storage_key(bytes)
  |> result.map(TicketStorageKey)
  |> result.replace_error(Nil)
}

pub fn export_resumption_ticket(
  ticket ticket: client_stream_backend.ResumptionTicketHandle,
  key key: TicketStorageKey,
) -> Result(BitArray, Failure) {
  native_client.export_resumption_ticket(ticket, key.native)
  |> map_native_result
}

pub fn import_resumption_ticket(
  bytes bytes: BitArray,
  key key: TicketStorageKey,
) -> Result(client_stream_backend.ResumptionTicketHandle, Failure) {
  native_client.import_resumption_ticket(bytes, key.native)
  |> map_native_result
}

pub fn client_capabilities(
  connection: client_stream_backend.ConnectionHandle,
) -> Result(RawCapabilities, Failure) {
  native_client.capabilities(connection)
  |> result.map(fn(capabilities) {
    let native_client.Capabilities(a, b, c, d) = capabilities
    #(a, b, c, d)
  })
  |> map_native_result
}

pub fn client_stream_capabilities(
  stream: client_stream_backend.StreamHandle,
) -> Result(RawCapabilities, Failure) {
  native_client.capabilities_for_stream(stream)
  |> result.map(fn(capabilities) {
    let native_client.Capabilities(a, b, c, d) = capabilities
    #(a, b, c, d)
  })
  |> map_native_result
}

pub fn server_stream_capabilities(
  request: server_backend.RequestHandle,
) -> Result(RawCapabilities, Failure) {
  native_server.capabilities(request) |> map_native_server_result
}

pub fn client_max_datagram_size(
  stream: client_stream_backend.StreamHandle,
) -> Result(Int, Failure) {
  native_client.maximum_datagram_size(stream) |> map_native_result
}

pub fn server_max_datagram_size(
  request: server_backend.RequestHandle,
) -> Result(Int, Failure) {
  native_server.maximum_datagram_size(request) |> map_native_server_result
}

pub fn client_send_datagram(
  stream stream: client_stream_backend.StreamHandle,
  payload payload: BitArray,
) -> Result(Nil, Failure) {
  native_client.send_datagram(stream, payload) |> map_native_result
}

pub fn server_send_datagram(
  request request: server_backend.RequestHandle,
  payload payload: BitArray,
) -> Result(Nil, Failure) {
  native_server.send_datagram(request, payload) |> map_native_server_result
}

pub fn client_next_datagram(
  stream: client_stream_backend.StreamHandle,
) -> Result(BitArray, Failure) {
  native_client.next_datagram(stream) |> map_native_result
}

pub fn server_next_datagram(
  request: server_backend.RequestHandle,
) -> Result(BitArray, Failure) {
  native_server.next_datagram(request) |> map_native_server_result
}

pub fn client_set_priority(
  stream stream: client_stream_backend.StreamHandle,
  urgency urgency: Int,
  incremental incremental: Bool,
) -> Result(Nil, Failure) {
  native_client.set_priority(stream, urgency, incremental) |> map_native_result
}

pub fn server_set_priority(
  request request: server_backend.RequestHandle,
  urgency urgency: Int,
  incremental incremental: Bool,
) -> Result(Nil, Failure) {
  native_server.set_priority(request, urgency, incremental)
  |> map_native_server_result
}

pub fn client_get_priority(
  stream: client_stream_backend.StreamHandle,
) -> Result(#(Int, Bool), Failure) {
  native_client.get_priority(stream) |> map_native_result
}

pub fn server_get_priority(
  request: server_backend.RequestHandle,
) -> Result(#(Int, Bool), Failure) {
  native_server.get_priority(request) |> map_native_server_result
}

pub fn client_early_data_status(
  connection: client_stream_backend.ConnectionHandle,
) -> Result(Int, Failure) {
  native_client.early_data_status(connection)
  |> result.map(early_data_code)
  |> map_native_result
}

pub fn client_resumption_status(
  connection: client_stream_backend.ConnectionHandle,
) -> Result(Int, Failure) {
  native_client.resumption_status(connection)
  |> result.map(resumption_code)
  |> map_native_result
}

pub fn client_stream_early_data_status(
  stream: client_stream_backend.StreamHandle,
) -> Result(Int, Failure) {
  native_client.early_data_status_for_stream(stream)
  |> result.map(early_data_code)
  |> map_native_result
}

pub fn server_early_data_status(
  request: server_backend.RequestHandle,
) -> Result(Int, Failure) {
  native_server.early_data_status(request)
  |> result.map(server_early_data_code)
  |> map_native_server_result
}

pub fn resumption_ticket(
  connection: client_stream_backend.ConnectionHandle,
) -> Result(client_stream_backend.ResumptionTicketHandle, Failure) {
  native_client.resumption_ticket(connection) |> map_native_result
}

pub fn migrate(
  connection: client_stream_backend.ConnectionHandle,
) -> Result(Nil, Failure) {
  native_client.migrate(connection) |> map_native_result
}

pub fn set_congestion_control(
  connection connection: client_stream_backend.ConnectionHandle,
  algorithm algorithm: Int,
) -> Result(Nil, Failure) {
  native_client.set_congestion_control(connection, algorithm)
  |> map_native_result
}

pub fn ping(
  connection: client_stream_backend.ConnectionHandle,
) -> Result(Nil, Failure) {
  native_client.ping(connection) |> map_native_result
}

pub fn maximum_transmission_unit(
  connection: client_stream_backend.ConnectionHandle,
) -> Result(Int, Failure) {
  native_client.maximum_transmission_unit(connection) |> map_native_result
}

pub fn client_stream_maximum_transmission_unit(
  stream: client_stream_backend.StreamHandle,
) -> Result(Int, Failure) {
  native_client.maximum_transmission_unit_for_stream(stream)
  |> map_native_result
}

pub fn server_stream_maximum_transmission_unit(
  request: server_backend.RequestHandle,
) -> Result(Int, Failure) {
  native_server.maximum_transmission_unit(request) |> map_native_server_result
}

pub fn path_stats(
  connection: client_stream_backend.ConnectionHandle,
) -> Result(RawPathStats, Failure) {
  native_client.path_stats(connection)
  |> result.map(fn(stats) {
    let native_client.PathStats(a, b, c, d, e, f, g, h) = stats
    #(a, b, c, d, e, f, g, h)
  })
  |> map_native_result
}

pub fn client_stream_path_stats(
  stream: client_stream_backend.StreamHandle,
) -> Result(RawPathStats, Failure) {
  native_client.path_stats_for_stream(stream)
  |> result.map(fn(stats) {
    let native_client.PathStats(a, b, c, d, e, f, g, h) = stats
    #(a, b, c, d, e, f, g, h)
  })
  |> map_native_result
}

pub fn server_stream_path_stats(
  request: server_backend.RequestHandle,
) -> Result(RawPathStats, Failure) {
  native_server.path_stats(request)
  |> result.map(fn(stats) {
    let native_server.PathStats(a, b, c, d, e, f, g, h) = stats
    #(b * 1000, a * 1000, c * 1000, d * 1000, e, f, g, h)
  })
  |> map_native_server_result
}

pub fn connection_stats(
  connection: client_stream_backend.ConnectionHandle,
) -> Result(RawConnectionStats, Failure) {
  native_client.connection_stats(connection)
  |> result.map(fn(stats) {
    let native_client.ConnectionStats(a, b, c, d, e, f, g, h) = stats
    #(a, b, c, d, e, f, g, h)
  })
  |> map_native_result
}

pub fn client_stream_connection_stats(
  stream: client_stream_backend.StreamHandle,
) -> Result(RawConnectionStats, Failure) {
  native_client.connection_stats_for_stream(stream)
  |> result.map(fn(stats) {
    let native_client.ConnectionStats(a, b, c, d, e, f, g, h) = stats
    #(a, b, c, d, e, f, g, h)
  })
  |> map_native_result
}

pub fn server_stream_connection_stats(
  request: server_backend.RequestHandle,
) -> Result(RawConnectionStats, Failure) {
  native_server.connection_stats(request)
  |> result.map(fn(stats) {
    let native_server.ConnectionStats(a, b, c, d, e, f, g, h) = stats
    #(a, b, c, d, e, f, g, h)
  })
  |> map_native_server_result
}

pub fn telemetry_stats(
  connection: client_stream_backend.ConnectionHandle,
) -> Result(RawTelemetryStats, Failure) {
  native_client.telemetry_stats(connection)
  |> result.map(fn(stats) {
    let native_client.TelemetryStats(a, b, c) = stats
    #(a, b, c)
  })
  |> map_native_result
}

pub fn client_stream_telemetry_stats(
  stream: client_stream_backend.StreamHandle,
) -> Result(RawTelemetryStats, Failure) {
  native_client.telemetry_stats_for_stream(stream)
  |> result.map(fn(stats) {
    let native_client.TelemetryStats(a, b, c) = stats
    #(a, b, c)
  })
  |> map_native_result
}

pub fn server_stream_telemetry_stats(
  request: server_backend.RequestHandle,
) -> Result(RawTelemetryStats, Failure) {
  native_server.telemetry_stats(request)
  |> result.map(fn(stats) {
    let native_server.TelemetryStats(a, b, c) = stats
    #(a, b, c)
  })
  |> map_native_server_result
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
    #(_, _, _) ->
      RuntimeFailure(runtime_failure.Http3(runtime_failure.Local, None))
  }
}

fn map_native_result(
  value: Result(value, native_client.Error),
) -> Result(value, Failure) {
  result.map_error(value, map_native_error)
}

fn map_native_server_result(
  value: Result(value, native_server.Error),
) -> Result(value, Failure) {
  result.map_error(value, map_native_server_error)
}

fn map_native_error(error: native_client.Error) -> Failure {
  case error {
    native_client.ConnectionClosed -> ConnectionClosed
    native_client.TimedOut(_) | native_client.TicketUnavailable -> Timeout
    native_client.DatagramsNotNegotiated -> DatagramsNotNegotiated
    native_client.DatagramNotAssociated -> DatagramNotAssociated
    native_client.DatagramTooLarge(maximum) -> DatagramTooLarge(maximum)
    native_client.DatagramBufferExceeded(limit) -> DatagramBufferExceeded(limit)
    native_client.ConcurrentDatagramReceive -> ConcurrentDatagramReceive
    native_client.MigrationUnavailable -> MigrationUnavailable
    native_client.CongestionLimited -> CongestionLimited
    native_client.StreamFinished
    | native_client.StreamCancelled
    | native_client.StreamReset(_)
    | native_client.RequestRejected -> UnknownStream
    native_client.ConnectionDraining -> ConnectionClosed
    native_client.ConnectFailed
    | native_client.HandshakeFailed
    | native_client.ResolutionFailed
    | native_client.TrustStoreFailed -> NotConnected
    native_client.UnsupportedCongestionControl ->
      RuntimeFailure(runtime_failure.Quic(runtime_failure.Local, None))
    native_client.Failure(failure) -> RuntimeFailure(failure)
    native_client.InvalidStoredTicket -> InvalidResumptionTicket
    _ -> RuntimeFailure(runtime_failure.Http3(runtime_failure.Local, None))
  }
}

fn map_native_server_error(error: native_server.Error) -> Failure {
  case error {
    native_server.ConnectionClosed | native_server.ListenerClosed ->
      ConnectionClosed
    native_server.Timeout -> Timeout
    native_server.DatagramsNotNegotiated -> DatagramsNotNegotiated
    native_server.DatagramNotAssociated -> DatagramNotAssociated
    native_server.DatagramTooLarge(maximum) -> DatagramTooLarge(maximum)
    native_server.DatagramBufferExceeded(limit) -> DatagramBufferExceeded(limit)
    native_server.ConcurrentDatagramReceive -> ConcurrentDatagramReceive
    native_server.CongestionLimited -> CongestionLimited
    native_server.StreamFinished | native_server.StreamReset(_) -> UnknownStream
    native_server.Failure(failure) -> RuntimeFailure(failure)
    _ -> RuntimeFailure(runtime_failure.Http3(runtime_failure.Local, None))
  }
}

fn early_data_code(status: native_client.EarlyDataStatus) -> Int {
  case status {
    native_client.NotAttempted -> 0
    native_client.Pending -> 1
    native_client.Accepted -> 2
    native_client.Rejected -> 3
  }
}

fn resumption_code(status: native_client.ResumptionStatus) -> Int {
  case status {
    native_client.ResumptionNotAttempted -> 0
    native_client.ResumptionPending -> 1
    native_client.Resumed -> 2
    native_client.FullHandshake -> 3
  }
}

fn server_early_data_code(status: native_server.EarlyDataStatus) -> Int {
  case status {
    native_server.NotAttempted -> 0
    native_server.Pending -> 1
    native_server.Accepted -> 2
    native_server.Rejected -> 3
  }
}

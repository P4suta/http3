//// Typed advanced HTTP/3 and QUIC capabilities.
////
//// Backend handles and message formats remain private. Connections and
//// streams are obtained from `http3/client` and `http3/server` accessors.

import gleam/bit_array
import gleam/bool
import gleam/option.{None}
import gleam/result
import gleam/string
import http3/failure as runtime_failure
import http3/internal/client_stream_backend
import http3/internal/server_backend
import http3/internal/transport_backend

/// Advanced controls for one reusable client connection.
pub opaque type Connection {
  Connection(handle: client_stream_backend.ConnectionHandle)
}

/// Advanced controls for one client or server request stream.
pub opaque type Stream {
  ClientStream(handle: client_stream_backend.StreamHandle)
  ServerStream(handle: server_backend.RequestHandle)
}

/// An opaque TLS session-resumption ticket.
///
/// Tickets contain key material. This API exposes no fields or plaintext
/// serialization. Persistence is available only as caller-key authenticated,
/// versioned ciphertext through `export_resumption_ticket`.
pub opaque type ResumptionTicket {
  ResumptionTicket(handle: client_stream_backend.ResumptionTicketHandle)
}

/// A validated 256-bit key for authenticated ticket persistence.
pub opaque type TicketStorageKey {
  TicketStorageKey(handle: transport_backend.TicketStorageKey)
}

/// RFC 9218 stream priority.
pub opaque type Priority {
  Priority(urgency: Int, incremental: Bool)
}

/// Explicit qlog output configuration.
pub opaque type Qlog {
  Qlog(directory: String)
}

/// Invalid advanced transport configuration.
pub type ConfigurationError {
  InvalidUrgency(Int)
  InvalidQlogDirectory
  InvalidTicketStorageKey
}

/// A typed advanced transport failure.
pub type Error {
  /// A typed runtime failure with no backend-formatted or secret text.
  Failure(runtime_failure.Failure)
  DatagramsNotNegotiated
  DatagramNotAssociated
  DatagramTooLarge(maximum: Int)
  CongestionLimited
  UnknownStream
  DatagramBufferExceeded(limit: Int)
  ConcurrentDatagramReceive
  MigrationUnavailable
  NotConnected
  InvalidDatagram
  InvalidResumptionTicket
}

/// Negotiated and configured capabilities for a live transport.
pub type Capabilities {
  Capabilities(
    http_datagrams: Bool,
    active_migration: Bool,
    zero_rtt_attempted: Bool,
    qlog_enabled: Bool,
  )
}

/// The outcome of an explicit 0-RTT resumption attempt.
pub type EarlyDataStatus {
  NotAttempted
  Pending
  Accepted
  Rejected
}

/// Outcome of a caller-supplied TLS resumption ticket.
pub type ResumptionStatus {
  ResumptionNotAttempted
  ResumptionPending
  Resumed
  FullHandshake
}

/// A supported live congestion-control algorithm.
pub type CongestionControl {
  NewReno
  Cubic
}

/// QUIC wire version initially attempted by a client.
pub type QuicVersion {
  QuicV1
  QuicV2
}

/// A snapshot of path RTT and congestion metrics.
pub type PathStats {
  PathStats(
    smoothed_rtt_microseconds: Int,
    latest_rtt_microseconds: Int,
    minimum_rtt_microseconds: Int,
    rtt_variance_microseconds: Int,
    congestion_window: Int,
    bytes_in_flight: Int,
    in_recovery: Bool,
    congested: Bool,
  )
}

/// A snapshot of connection traffic and send-path counters.
pub type ConnectionStats {
  ConnectionStats(
    packets_received: Int,
    packets_sent: Int,
    data_received: Int,
    data_sent: Int,
    acknowledgements_sent: Int,
    retransmissions: Int,
    batch_flushes: Int,
    packets_coalesced: Int,
  )
}

/// Health of bounded asynchronous diagnostic output.
pub type TelemetryStats {
  TelemetryStats(
    qlog_dropped_events: Int,
    qlog_write_errors: Int,
    qlog_queued_events: Int,
  )
}

/// Construct an RFC 9218 priority. Urgency ranges from zero through seven.
pub fn priority(
  urgency urgency: Int,
  incremental incremental: Bool,
) -> Result(Priority, ConfigurationError) {
  use <- bool.guard(
    when: urgency < 0 || urgency > 7,
    return: Error(InvalidUrgency(urgency)),
  )
  Ok(Priority(urgency, incremental))
}

/// Return a priority's urgency.
pub fn urgency(priority: Priority) -> Int {
  priority.urgency
}

/// Return whether a priority permits incremental processing.
pub fn is_incremental(priority: Priority) -> Bool {
  priority.incremental
}

/// Configure qlog output in a non-empty directory path.
///
/// qlog is disabled unless this explicit value is attached to a client or
/// server configuration. Trace files can contain sensitive metadata. Output
/// is diagnostic JSON-SEQ pinned to qlog main schema 14 and QUIC/HTTP3 events
/// revision 13; these revisions are Internet-Drafts, not protocol guarantees.
pub fn qlog(directory: String) -> Result(Qlog, ConfigurationError) {
  use <- bool.guard(
    when: string.is_empty(directory)
      || string.length(directory) > 4096
      || string.contains(directory, "\u{0000}"),
    return: Error(InvalidQlogDirectory),
  )
  Ok(Qlog(directory))
}

/// Return the configured qlog directory.
pub fn qlog_directory(qlog: Qlog) -> String {
  qlog.directory
}

/// Validate a caller-managed ticket storage key.
///
/// Key bytes can be supplied once but cannot be read back through the API.
pub fn ticket_storage_key(
  bytes: BitArray,
) -> Result(TicketStorageKey, ConfigurationError) {
  transport_backend.ticket_storage_key(bytes)
  |> result.map(TicketStorageKey)
  |> result.replace_error(InvalidTicketStorageKey)
}

/// Export all origin-bound ticket state as versioned authenticated ciphertext.
pub fn export_resumption_ticket(
  ticket ticket: ResumptionTicket,
  key key: TicketStorageKey,
) -> Result(BitArray, Error) {
  let ResumptionTicket(handle) = ticket
  let TicketStorageKey(key_handle) = key
  transport_backend.export_resumption_ticket(handle, key_handle) |> map_failure
}

/// Authenticate and restore a versioned encrypted resumption ticket.
pub fn import_resumption_ticket(
  bytes bytes: BitArray,
  key key: TicketStorageKey,
) -> Result(ResumptionTicket, Error) {
  let TicketStorageKey(key_handle) = key
  transport_backend.import_resumption_ticket(bytes, key_handle)
  |> result.map(ResumptionTicket)
  |> map_failure
}

/// Return live client-connection capabilities.
pub fn capabilities(connection: Connection) -> Result(Capabilities, Error) {
  let Connection(handle) = connection
  transport_backend.client_capabilities(handle)
  |> map_capabilities
}

/// Return live capabilities for a client or server request stream.
pub fn stream_capabilities(stream: Stream) -> Result(Capabilities, Error) {
  case stream {
    ClientStream(handle) ->
      transport_backend.client_stream_capabilities(handle)
      |> map_capabilities
    ServerStream(handle) ->
      transport_backend.server_stream_capabilities(handle)
      |> map_capabilities
  }
}

/// Return the largest currently sendable HTTP Datagram payload.
pub fn maximum_datagram_size(stream: Stream) -> Result(Int, Error) {
  case stream {
    ClientStream(handle) ->
      transport_backend.client_max_datagram_size(handle) |> map_failure
    ServerStream(handle) ->
      transport_backend.server_max_datagram_size(handle) |> map_failure
  }
}

/// Send one byte-aligned unreliable HTTP Datagram on a request stream.
pub fn send_datagram(
  stream stream: Stream,
  payload payload: BitArray,
) -> Result(Nil, Error) {
  use <- bool.guard(
    when: bit_array.bit_size(payload) % 8 != 0,
    return: Error(InvalidDatagram),
  )
  case stream {
    ClientStream(handle) ->
      transport_backend.client_send_datagram(handle, payload) |> map_failure
    ServerStream(handle) ->
      transport_backend.server_send_datagram(handle, payload) |> map_failure
  }
}

/// Pull one unreliable HTTP Datagram with the owning stream's fixed timeout.
pub fn next_datagram(stream: Stream) -> Result(BitArray, Error) {
  case stream {
    ClientStream(handle) ->
      transport_backend.client_next_datagram(handle) |> map_failure
    ServerStream(handle) ->
      transport_backend.server_next_datagram(handle) |> map_failure
  }
}

/// Set a live request stream's RFC 9218 transport priority.
pub fn set_priority(
  stream stream: Stream,
  priority priority: Priority,
) -> Result(Nil, Error) {
  case stream {
    ClientStream(handle) ->
      transport_backend.client_set_priority(
        handle,
        priority.urgency,
        priority.incremental,
      )
      |> map_failure
    ServerStream(handle) ->
      transport_backend.server_set_priority(
        handle,
        priority.urgency,
        priority.incremental,
      )
      |> map_failure
  }
}

/// Read a live request stream's transport priority.
pub fn get_priority(stream: Stream) -> Result(Priority, Error) {
  let result = case stream {
    ClientStream(handle) -> transport_backend.client_get_priority(handle)
    ServerStream(handle) -> transport_backend.server_get_priority(handle)
  }
  case result {
    Ok(#(urgency, incremental)) -> Ok(Priority(urgency, incremental))
    Error(error) -> Error(from_backend_failure(error))
  }
}

/// Return the state of an explicit client 0-RTT attempt.
pub fn early_data_status(
  connection: Connection,
) -> Result(EarlyDataStatus, Error) {
  let Connection(handle) = connection
  transport_backend.client_early_data_status(handle)
  |> map_early_data_status
}

/// Return whether a supplied ticket resumed TLS or safely fell back.
pub fn resumption_status(
  connection: Connection,
) -> Result(ResumptionStatus, Error) {
  let Connection(handle) = connection
  transport_backend.client_resumption_status(handle)
  |> map_resumption_status
}

/// Return the 0-RTT state associated with a client or server stream.
pub fn stream_early_data_status(
  stream: Stream,
) -> Result(EarlyDataStatus, Error) {
  let result = case stream {
    ClientStream(handle) ->
      transport_backend.client_stream_early_data_status(handle)
    ServerStream(handle) -> transport_backend.server_early_data_status(handle)
  }
  result |> map_early_data_status
}

/// Wait up to the connection timeout for the newest origin-bound ticket.
pub fn resumption_ticket(
  connection: Connection,
) -> Result(ResumptionTicket, Error) {
  let Connection(handle) = connection
  case transport_backend.resumption_ticket(handle) {
    Ok(ticket) -> Ok(ResumptionTicket(ticket))
    Error(error) -> Error(from_backend_failure(error))
  }
}

/// Trigger active migration to a new local UDP path.
pub fn migrate(connection: Connection) -> Result(Nil, Error) {
  let Connection(handle) = connection
  transport_backend.migrate(handle) |> map_failure
}

/// Change congestion control on a live connection.
pub fn set_congestion_control(
  connection connection: Connection,
  algorithm algorithm: CongestionControl,
) -> Result(Nil, Error) {
  let Connection(handle) = connection
  let code = case algorithm {
    NewReno -> 1
    Cubic -> 2
  }
  transport_backend.set_congestion_control(handle, code) |> map_failure
}

/// Send a transport PING for liveness without opening a request stream.
pub fn ping(connection: Connection) -> Result(Nil, Error) {
  let Connection(handle) = connection
  transport_backend.ping(handle) |> map_failure
}

/// Return the current discovered QUIC path MTU in bytes.
pub fn maximum_transmission_unit(connection: Connection) -> Result(Int, Error) {
  let Connection(handle) = connection
  transport_backend.maximum_transmission_unit(handle) |> map_failure
}

/// Return the current discovered path MTU for a client or server stream.
pub fn stream_maximum_transmission_unit(stream: Stream) -> Result(Int, Error) {
  case stream {
    ClientStream(handle) ->
      transport_backend.client_stream_maximum_transmission_unit(handle)
      |> map_failure
    ServerStream(handle) ->
      transport_backend.server_stream_maximum_transmission_unit(handle)
      |> map_failure
  }
}

/// Snapshot path RTT and congestion metrics.
pub fn path_stats(connection: Connection) -> Result(PathStats, Error) {
  let Connection(handle) = connection
  case transport_backend.path_stats(handle) {
    Ok(#(
      smoothed,
      latest,
      minimum,
      variance,
      window,
      in_flight,
      recovery,
      congested,
    )) ->
      Ok(PathStats(
        smoothed,
        latest,
        minimum,
        variance,
        window,
        in_flight,
        recovery,
        congested,
      ))
    Error(error) -> Error(from_backend_failure(error))
  }
}

/// Snapshot path RTT and congestion metrics for a client or server stream.
pub fn stream_path_stats(stream: Stream) -> Result(PathStats, Error) {
  let result = case stream {
    ClientStream(handle) -> transport_backend.client_stream_path_stats(handle)
    ServerStream(handle) -> transport_backend.server_stream_path_stats(handle)
  }
  map_path_stats(result)
}

/// Snapshot connection traffic and batching counters.
pub fn connection_stats(
  connection: Connection,
) -> Result(ConnectionStats, Error) {
  let Connection(handle) = connection
  case transport_backend.connection_stats(handle) {
    Ok(#(
      received,
      sent,
      data_received,
      data_sent,
      acknowledgements,
      retransmissions,
      flushes,
      coalesced,
    )) ->
      Ok(ConnectionStats(
        received,
        sent,
        data_received,
        data_sent,
        acknowledgements,
        retransmissions,
        flushes,
        coalesced,
      ))
    Error(error) -> Error(from_backend_failure(error))
  }
}

/// Snapshot connection counters for a client or server request stream.
pub fn stream_connection_stats(
  stream: Stream,
) -> Result(ConnectionStats, Error) {
  let result = case stream {
    ClientStream(handle) ->
      transport_backend.client_stream_connection_stats(handle)
    ServerStream(handle) ->
      transport_backend.server_stream_connection_stats(handle)
  }
  map_connection_stats(result)
}

/// Snapshot diagnostic health for a reusable client connection.
///
/// All values are zero when qlog is disabled. No peer identifiers, paths,
/// headers, payloads, certificate material, or secrets are returned.
pub fn telemetry_stats(
  connection: Connection,
) -> Result(TelemetryStats, Error) {
  let Connection(handle) = connection
  transport_backend.telemetry_stats(handle) |> map_telemetry_stats
}

/// Snapshot diagnostic health for a client or server request stream.
pub fn stream_telemetry_stats(stream: Stream) -> Result(TelemetryStats, Error) {
  let result = case stream {
    ClientStream(handle) ->
      transport_backend.client_stream_telemetry_stats(handle)
    ServerStream(handle) ->
      transport_backend.server_stream_telemetry_stats(handle)
  }
  map_telemetry_stats(result)
}

fn map_capabilities(
  result: Result(transport_backend.RawCapabilities, transport_backend.Failure),
) -> Result(Capabilities, Error) {
  case result {
    Ok(#(datagrams, migration, zero_rtt, qlog)) ->
      Ok(Capabilities(datagrams, migration, zero_rtt, qlog))
    Error(error) -> Error(from_backend_failure(error))
  }
}

fn map_path_stats(
  result: Result(transport_backend.RawPathStats, transport_backend.Failure),
) -> Result(PathStats, Error) {
  case result {
    Ok(#(
      smoothed,
      latest,
      minimum,
      variance,
      window,
      in_flight,
      recovery,
      congested,
    )) ->
      Ok(PathStats(
        smoothed,
        latest,
        minimum,
        variance,
        window,
        in_flight,
        recovery,
        congested,
      ))
    Error(error) -> Error(from_backend_failure(error))
  }
}

fn map_connection_stats(
  result: Result(
    transport_backend.RawConnectionStats,
    transport_backend.Failure,
  ),
) -> Result(ConnectionStats, Error) {
  case result {
    Ok(#(
      received,
      sent,
      data_received,
      data_sent,
      acknowledgements,
      retransmissions,
      flushes,
      coalesced,
    )) ->
      Ok(ConnectionStats(
        received,
        sent,
        data_received,
        data_sent,
        acknowledgements,
        retransmissions,
        flushes,
        coalesced,
      ))
    Error(error) -> Error(from_backend_failure(error))
  }
}

fn map_telemetry_stats(
  result: Result(transport_backend.RawTelemetryStats, transport_backend.Failure),
) -> Result(TelemetryStats, Error) {
  case result {
    Ok(#(dropped, errors, queued)) ->
      Ok(TelemetryStats(dropped, errors, queued))
    Error(error) -> Error(from_backend_failure(error))
  }
}

fn map_early_data_status(
  result: Result(Int, transport_backend.Failure),
) -> Result(EarlyDataStatus, Error) {
  case result {
    Ok(0) -> Ok(NotAttempted)
    Ok(1) -> Ok(Pending)
    Ok(2) -> Ok(Accepted)
    Ok(3) -> Ok(Rejected)
    Ok(_) -> Error(Failure(runtime_failure.Http3(runtime_failure.Local, None)))
    Error(error) -> Error(from_backend_failure(error))
  }
}

fn map_resumption_status(
  result: Result(Int, transport_backend.Failure),
) -> Result(ResumptionStatus, Error) {
  case result {
    Ok(0) -> Ok(ResumptionNotAttempted)
    Ok(1) -> Ok(ResumptionPending)
    Ok(2) -> Ok(Resumed)
    Ok(3) -> Ok(FullHandshake)
    Ok(_) -> Error(Failure(runtime_failure.Http3(runtime_failure.Local, None)))
    Error(error) -> Error(from_backend_failure(error))
  }
}

fn map_failure(
  result: Result(value, transport_backend.Failure),
) -> Result(value, Error) {
  case result {
    Ok(value) -> Ok(value)
    Error(error) -> Error(from_backend_failure(error))
  }
}

fn from_backend_failure(failure: transport_backend.Failure) -> Error {
  case failure {
    transport_backend.ConnectionClosed ->
      Failure(runtime_failure.Closed(runtime_failure.Peer, None))
    transport_backend.Timeout ->
      Failure(runtime_failure.Timeout(runtime_failure.Operation))
    transport_backend.DatagramsNotNegotiated -> DatagramsNotNegotiated
    transport_backend.DatagramNotAssociated -> DatagramNotAssociated
    transport_backend.DatagramTooLarge(maximum) -> DatagramTooLarge(maximum)
    transport_backend.CongestionLimited -> CongestionLimited
    transport_backend.UnknownStream -> UnknownStream
    transport_backend.DatagramBufferExceeded(limit) ->
      DatagramBufferExceeded(limit)
    transport_backend.ConcurrentDatagramReceive -> ConcurrentDatagramReceive
    transport_backend.MigrationUnavailable -> MigrationUnavailable
    transport_backend.NotConnected -> NotConnected
    transport_backend.InvalidResumptionTicket -> InvalidResumptionTicket
    transport_backend.RuntimeFailure(failure) -> Failure(failure)
  }
}

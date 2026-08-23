//// Bounded HTTP/3 client powered by the repository-owned QUIC stack.

import gleam/bit_array
import gleam/list
import gleam/option.{type Option, None, Some}
import gleam/result
import gleam_quic/internal/connection_state as transport
import gleam_quic/internal/http3/bounded_client
import gleam_quic/internal/http3/client_connection
import gleam_quic/internal/http3/client_worker
import gleam_quic/internal/qpack/header.{type Header, Header}
import gleam_quic/internal/tls/authentication

const default_timeout_milliseconds = 30_000

const maximum_timeout_milliseconds = 3_600_000

const default_response_body_limit = 8_388_608

const default_stream_buffer_limit = 262_144

type Trust {
  SystemTrust
  ExplicitTrust(List(BitArray))
}

/// Secure bounded-client configuration.
pub opaque type Client {
  Client(
    hostname: String,
    port: Int,
    timeout_milliseconds: Int,
    response_body_limit: Int,
    stream_buffer_limit: Int,
    trust: Trust,
    http_datagrams: Bool,
    qlog_directory: String,
    resumption_ticket: Option(ResumptionTicket),
  )
}

/// One reusable secure HTTP/3 connection.
pub opaque type Connection {
  Connection(handle: client_worker.Connection)
}

/// One request and pull-based streaming response.
pub opaque type Stream {
  Stream(handle: client_worker.Stream)
}

/// Opaque origin-bound TLS resumption state.
pub opaque type ResumptionTicket {
  ResumptionTicket(handle: client_worker.ResumptionTicket)
}

/// Negotiated advanced transport capabilities.
pub type Capabilities {
  Capabilities(
    http_datagrams: Bool,
    active_migration: Bool,
    zero_rtt_attempted: Bool,
    qlog_enabled: Bool,
  )
}

/// State of an explicit 0-RTT attempt.
pub type EarlyDataStatus {
  NotAttempted
  Pending
  Accepted
  Rejected
}

/// A live path snapshot in microseconds and bytes.
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

/// Runtime traffic counters for one native connection.
pub type ConnectionStats {
  ConnectionStats(Int, Int, Int, Int, Int, Int, Int, Int)
}

/// One streaming response event.
pub type ResponseEvent {
  InformationalResponse(status: Int, headers: List(#(String, String)))
  ResponseHeaders(status: Int, headers: List(#(String, String)))
  Data(BitArray)
  Trailers(List(#(String, String)))
  End
}

/// Idempotent cancellation outcome.
pub type Cancellation {
  Cancelled
  AlreadyCancelled
  AlreadyCompleted
}

/// Idempotent connection-close outcome.
pub type CloseResult {
  Closed
  AlreadyClosed
}

/// Invalid client policy or endpoint input.
pub type ConfigurationError {
  InvalidHost
  InvalidPort(Int)
  InvalidTimeout
  InvalidResponseBodyLimit
  InvalidStreamBufferLimit
  InvalidCaCertificate
  InvalidQlogDirectory
}

/// A complete response retained within the configured body bound.
pub type Response {
  Response(status: Int, headers: List(#(String, String)), body: BitArray)
}

/// Native name resolution, TLS, QUIC, HTTP/3, or resource failure.
pub type Error {
  InvalidRequest
  ResolutionFailed
  TrustStoreFailed
  ConnectFailed
  HandshakeFailed
  TransportError(String)
  Http3Error(String)
  Timeout
  ConnectionClosed
  StreamReset(Int)
  ProtocolError
  InvalidHeaderEncoding
  InvalidContentLength
  ResponseBodyTooLarge(Int)
  ConsumerTooSlow(Int)
  ConcurrentReceive
  RequestAlreadyFinished
  StreamFinished
  StreamCancelled
  OriginMismatch
  UnsafeEarlyDataMethod(String)
  ResumptionOriginMismatch
  DatagramsNotNegotiated
  DatagramTooLarge(Int)
  DatagramBufferExceeded(Int)
  ConcurrentDatagramReceive
  MigrationUnavailable
  CongestionLimited
  UnsupportedCongestionControl
  TicketUnavailable
  QlogUnavailable
}

// nolint: unused_exports -- consumed by the parent http3 package.
/// Configure one secure origin. Certificate and hostname checks are mandatory.
pub fn new(
  hostname hostname: String,
  port port: Int,
) -> Result(Client, ConfigurationError) {
  case hostname, port {
    "", _ -> Error(InvalidHost)
    _, value if value <= 0 || value > 65_535 -> Error(InvalidPort(value))
    _, _ ->
      Ok(Client(
        hostname,
        port,
        default_timeout_milliseconds,
        default_response_body_limit,
        default_stream_buffer_limit,
        SystemTrust,
        False,
        "",
        None,
      ))
  }
}

// nolint: unused_exports -- consumed by the parent http3 package.
/// Set the maximum queued response-body bytes retained per stream.
pub fn with_stream_buffer_limit(
  client client: Client,
  bytes bytes: Int,
) -> Result(Client, ConfigurationError) {
  case bytes > 0 {
    True -> Ok(Client(..client, stream_buffer_limit: bytes))
    False -> Error(InvalidStreamBufferLimit)
  }
}

// nolint: unused_exports -- consumed by the parent http3 package.
/// Negotiate RFC 9221 QUIC DATAGRAM and RFC 9297 HTTP Datagrams.
pub fn with_http_datagrams(client: Client) -> Client {
  Client(..client, http_datagrams: True)
}

// nolint: unused_exports -- consumed by the parent http3 package.
/// Write a streaming qlog trace in an explicitly selected directory.
pub fn with_qlog(
  client: Client,
  directory: String,
) -> Result(Client, ConfigurationError) {
  case directory == "" {
    True -> Error(InvalidQlogDirectory)
    False -> Ok(Client(..client, qlog_directory: directory))
  }
}

// nolint: unused_exports -- consumed by the parent http3 package.
/// Attach one opaque origin-bound ticket for resumption.
pub fn with_resumption_ticket(
  client: Client,
  ticket: ResumptionTicket,
) -> Client {
  Client(..client, resumption_ticket: Some(ticket))
}

// nolint: unused_exports -- consumed by the parent http3 package.
/// Set one total connect/request deadline from one millisecond to one hour.
pub fn with_timeout(
  client client: Client,
  milliseconds milliseconds: Int,
) -> Result(Client, ConfigurationError) {
  case milliseconds > 0 && milliseconds <= maximum_timeout_milliseconds {
    True -> Ok(Client(..client, timeout_milliseconds: milliseconds))
    False -> Error(InvalidTimeout)
  }
}

// nolint: unused_exports -- consumed by the parent http3 package.
/// Set the maximum buffered response body in bytes.
pub fn with_response_body_limit(
  client client: Client,
  bytes bytes: Int,
) -> Result(Client, ConfigurationError) {
  case bytes > 0 {
    True -> Ok(Client(..client, response_body_limit: bytes))
    False -> Error(InvalidResponseBodyLimit)
  }
}

// nolint: unused_exports -- consumed by the parent http3 package.
/// Replace system roots with a non-empty explicit DER trust set.
pub fn with_ca_certificates(
  client client: Client,
  certificates certificates: List(BitArray),
) -> Result(Client, ConfigurationError) {
  case certificates, valid_certificate_alignment(certificates) {
    [], _ -> Error(InvalidCaCertificate)
    _, False -> Error(InvalidCaCertificate)
    _, True ->
      case authentication.trust_store_from_der(certificates) {
        Ok(_) -> Ok(Client(..client, trust: ExplicitTrust(certificates)))
        Error(_) -> Error(InvalidCaCertificate)
      }
  }
}

// nolint: unused_exports -- consumed by the parent http3 package.
/// Return whether bytes are one valid DER X.509 trust anchor.
pub fn is_valid_ca_certificate(certificate: BitArray) -> Bool {
  authentication.trust_store_from_der([certificate]) |> result.is_ok
}

// nolint: unused_exports -- consumed by the parent http3 package.
/// Execute one bounded request and close its connection before returning.
pub fn send(
  client client: Client,
  headers headers: List(#(String, String)),
  body body: BitArray,
) -> Result(Response, Error) {
  use trust_store <- result.try(load_trust(client.trust))
  let config =
    bounded_client.Config(
      hostname: client.hostname,
      port: client.port,
      timeout_milliseconds: client.timeout_milliseconds,
      maximum_response_body_bytes: client.response_body_limit,
      trust_store: trust_store,
    )
  case bounded_client.send(config, headers, body) {
    Ok(bounded_client.Response(status, headers, body)) ->
      Ok(Response(status, headers, body))
    Error(error) -> Error(map_error(error))
  }
}

// nolint: unused_exports -- consumed by the parent http3 package.
/// Establish one reusable origin-bound connection in an owner-monitoring actor.
pub fn connect(client: Client) -> Result(Connection, Error) {
  use trust_store <- result.try(load_trust(client.trust))
  let ticket = case client.resumption_ticket {
    Some(ResumptionTicket(ticket)) -> Some(ticket)
    None -> None
  }
  client_worker.connect(
    client.hostname,
    client.port,
    client.timeout_milliseconds,
    client.stream_buffer_limit,
    trust_store,
    client.http_datagrams,
    client.qlog_directory,
    ticket,
  )
  |> result.map(Connection)
  |> result.map_error(map_worker_error)
}

// nolint: unused_exports -- consumed by the parent http3 package.
/// Open one request stream while leaving its request body open.
pub fn open_stream(
  connection: Connection,
  hostname: String,
  port: Int,
  headers: List(#(String, String)),
) -> Result(Stream, Error) {
  let Connection(handle) = connection
  use encoded <- result.try(encode_headers(headers))
  client_worker.open_stream(handle, hostname, port, encoded)
  |> result.map(Stream)
  |> result.map_error(map_worker_error)
}

// nolint: unused_exports -- consumed by the parent http3 package.
/// Queue one request-body chunk with synchronous flow-control feedback.
pub fn send_chunk(stream: Stream, bytes: BitArray) -> Result(Nil, Error) {
  let Stream(handle) = stream
  case bit_array.bit_size(bytes) % 8 {
    0 ->
      client_worker.send_data(handle, bytes)
      |> result.map_error(map_worker_error)
    _ -> Error(InvalidRequest)
  }
}

// nolint: unused_exports -- consumed by the parent http3 package.
/// Finish a streaming request body.
pub fn finish(stream: Stream) -> Result(Nil, Error) {
  let Stream(handle) = stream
  client_worker.finish(handle) |> result.map_error(map_worker_error)
}

// nolint: unused_exports -- consumed by the parent http3 package.
/// Pull the next response event within the configured operation timeout.
pub fn next_event(stream: Stream) -> Result(ResponseEvent, Error) {
  let Stream(handle) = stream
  case client_worker.next_event(handle) {
    Ok(client_worker.Informational(status, headers)) ->
      Ok(InformationalResponse(status, headers))
    Ok(client_worker.Response(status, headers)) ->
      Ok(ResponseHeaders(status, headers))
    Ok(client_worker.Data(bytes)) -> Ok(Data(bytes))
    Ok(client_worker.Trailers(headers)) -> Ok(Trailers(headers))
    Ok(client_worker.End) -> Ok(End)
    Error(error) -> Error(map_worker_error(error))
  }
}

// nolint: unused_exports -- consumed by the parent http3 package.
/// Cancel one request stream idempotently.
pub fn cancel(stream: Stream) -> Result(Cancellation, Error) {
  let Stream(handle) = stream
  case client_worker.cancel(handle) {
    Ok(client_worker.Cancelled) -> Ok(Cancelled)
    Ok(client_worker.AlreadyCancelled) -> Ok(AlreadyCancelled)
    Ok(client_worker.AlreadyCompleted) -> Ok(AlreadyCompleted)
    Error(error) -> Error(map_worker_error(error))
  }
}

// nolint: unused_exports -- consumed by the parent http3 package.
/// Close one reusable connection idempotently.
pub fn close(connection: Connection) -> Result(CloseResult, Error) {
  let Connection(handle) = connection
  case client_worker.close(handle) {
    Ok(client_worker.Closed) -> Ok(Closed)
    Ok(client_worker.AlreadyClosed) -> Ok(AlreadyClosed)
    Error(error) -> Error(map_worker_error(error))
  }
}

// nolint: unused_exports -- consumed by the parent http3 package.
/// Return live advanced capabilities.
pub fn capabilities(connection: Connection) -> Result(Capabilities, Error) {
  let Connection(handle) = connection
  client_worker.capabilities(handle)
  |> result.map(fn(value) {
    let #(datagrams, migration, zero_rtt, qlog) = value
    Capabilities(datagrams, migration, zero_rtt, qlog)
  })
  |> result.map_error(map_worker_error)
}

// nolint: unused_exports -- consumed by the parent http3 package.
/// Return live capabilities through a stream's owning connection.
pub fn capabilities_for_stream(stream: Stream) -> Result(Capabilities, Error) {
  let Stream(handle) = stream
  client_worker.capabilities(client_worker.stream_connection(handle))
  |> result.map(fn(value) {
    let #(datagrams, migration, zero_rtt, qlog) = value
    Capabilities(datagrams, migration, zero_rtt, qlog)
  })
  |> result.map_error(map_worker_error)
}

// nolint: unused_exports -- consumed by the parent http3 package.
/// Return the largest HTTP Datagram payload for one request stream.
pub fn maximum_datagram_size(stream: Stream) -> Result(Int, Error) {
  let Stream(handle) = stream
  client_worker.maximum_datagram_size(handle)
  |> result.map_error(map_worker_error)
}

// nolint: unused_exports -- consumed by the parent http3 package.
/// Send one unreliable HTTP Datagram.
pub fn send_datagram(stream: Stream, payload: BitArray) -> Result(Nil, Error) {
  let Stream(handle) = stream
  client_worker.send_datagram(handle, payload)
  |> result.map_error(map_worker_error)
}

// nolint: unused_exports -- consumed by the parent http3 package.
/// Pull one unreliable HTTP Datagram.
pub fn next_datagram(stream: Stream) -> Result(BitArray, Error) {
  let Stream(handle) = stream
  client_worker.next_datagram(handle) |> result.map_error(map_worker_error)
}

// nolint: unused_exports -- consumed by the parent http3 package.
/// Set one request stream's RFC 9218 priority.
pub fn set_priority(
  stream: Stream,
  urgency: Int,
  incremental: Bool,
) -> Result(Nil, Error) {
  let Stream(handle) = stream
  client_worker.set_priority(handle, urgency, incremental)
  |> result.map_error(map_worker_error)
}

// nolint: unused_exports -- consumed by the parent http3 package.
/// Return one request stream's effective priority.
pub fn get_priority(stream: Stream) -> Result(#(Int, Bool), Error) {
  let Stream(handle) = stream
  client_worker.get_priority(handle) |> result.map_error(map_worker_error)
}

// nolint: unused_exports -- consumed by the parent http3 package.
/// Return the connection's explicit 0-RTT state.
pub fn early_data_status(
  connection: Connection,
) -> Result(EarlyDataStatus, Error) {
  let Connection(handle) = connection
  case client_worker.early_data_status(handle) {
    Ok(client_worker.NotAttempted) -> Ok(NotAttempted)
    Ok(client_worker.Pending) -> Ok(Pending)
    Ok(client_worker.Accepted) -> Ok(Accepted)
    Ok(client_worker.Rejected) -> Ok(Rejected)
    Error(error) -> Error(map_worker_error(error))
  }
}

// nolint: unused_exports -- consumed by the parent http3 package.
/// Return 0-RTT state through a stream's owning connection.
pub fn early_data_status_for_stream(
  stream: Stream,
) -> Result(EarlyDataStatus, Error) {
  let Stream(handle) = stream
  let connection = client_worker.stream_connection(handle)
  case client_worker.early_data_status(connection) {
    Ok(client_worker.NotAttempted) -> Ok(NotAttempted)
    Ok(client_worker.Pending) -> Ok(Pending)
    Ok(client_worker.Accepted) -> Ok(Accepted)
    Ok(client_worker.Rejected) -> Ok(Rejected)
    Error(error) -> Error(map_worker_error(error))
  }
}

// nolint: unused_exports -- consumed by the parent http3 package.
/// Wait for the newest origin-bound session ticket.
pub fn resumption_ticket(
  connection: Connection,
) -> Result(ResumptionTicket, Error) {
  let Connection(handle) = connection
  client_worker.resumption_ticket(handle)
  |> result.map(ResumptionTicket)
  |> result.map_error(map_worker_error)
}

// nolint: unused_exports -- consumed by the parent http3 package.
/// Migrate to a fresh local UDP path.
pub fn migrate(connection: Connection) -> Result(Nil, Error) {
  let Connection(handle) = connection
  client_worker.migrate(handle) |> result.map_error(map_worker_error)
}

// nolint: unused_exports -- consumed by the parent http3 package.
/// Change live congestion control (1 = NewReno, 2 = CUBIC).
pub fn set_congestion_control(
  connection: Connection,
  algorithm: Int,
) -> Result(Nil, Error) {
  let Connection(handle) = connection
  client_worker.set_congestion_control(handle, algorithm)
  |> result.map_error(map_worker_error)
}

// nolint: unused_exports -- consumed by the parent http3 package.
/// Send a transport PING.
pub fn ping(connection: Connection) -> Result(Nil, Error) {
  let Connection(handle) = connection
  client_worker.ping(handle) |> result.map_error(map_worker_error)
}

// nolint: unused_exports -- consumed by the parent http3 package.
/// Return the current path MTU.
pub fn maximum_transmission_unit(connection: Connection) -> Result(Int, Error) {
  let Connection(handle) = connection
  client_worker.maximum_transmission_unit(handle)
  |> result.map_error(map_worker_error)
}

// nolint: unused_exports -- consumed by the parent http3 package.
/// Snapshot path RTT and congestion state.
pub fn path_stats(connection: Connection) -> Result(PathStats, Error) {
  let Connection(handle) = connection
  case client_worker.path_stats(handle) {
    Ok(transport.PathSnapshot(
      latest,
      smoothed,
      minimum,
      variation,
      window,
      in_flight,
      recovery,
      congested,
    )) ->
      Ok(PathStats(
        smoothed * 1000,
        latest * 1000,
        minimum * 1000,
        variation * 1000,
        window,
        in_flight,
        recovery,
        congested,
      ))
    Error(error) -> Error(map_worker_error(error))
  }
}

// nolint: unused_exports -- consumed by the parent http3 package.
/// Snapshot runtime traffic counters.
pub fn connection_stats(
  connection: Connection,
) -> Result(ConnectionStats, Error) {
  let Connection(handle) = connection
  case client_worker.connection_stats(handle) {
    Ok(client_connection.Stats(a, b, c, d, e, f, g, h)) ->
      Ok(ConnectionStats(a, b, c, d, e, f, g, h))
    Error(error) -> Error(map_worker_error(error))
  }
}

fn load_trust(trust: Trust) -> Result(authentication.TrustStore, Error) {
  let loaded = case trust {
    SystemTrust -> authentication.system_trust_store()
    ExplicitTrust(certificates) ->
      authentication.trust_store_from_der(certificates)
  }
  loaded |> result.replace_error(TrustStoreFailed)
}

fn valid_certificate_alignment(certificates: List(BitArray)) -> Bool {
  list.all(certificates, fn(certificate) {
    bit_array.byte_size(certificate) > 0
    && bit_array.bit_size(certificate) % 8 == 0
  })
}

fn encode_headers(
  fields: List(#(String, String)),
) -> Result(List(Header), Error) {
  list.map(fields, fn(field) {
    let #(name, value) = field
    Header(bit_array.from_string(name), bit_array.from_string(value), False)
  })
  |> Ok
}

fn map_error(error: bounded_client.Error) -> Error {
  case error {
    bounded_client.InvalidInput -> InvalidRequest
    bounded_client.ResolutionFailed -> ResolutionFailed
    bounded_client.SocketUnavailable -> ConnectFailed
    bounded_client.Timeout -> Timeout
    bounded_client.TlsHandshakeFailed -> HandshakeFailed
    bounded_client.QuicTransportFailed(operation, error) ->
      TransportError(operation <> ": " <> driver_error_name(error))
    bounded_client.Http3ProtocolFailed -> Http3Error("invalid response state")
    bounded_client.Http3OperationFailed(operation, error) ->
      Http3Error(operation <> ": " <> session_error_name(error))
    bounded_client.PeerClosed -> ConnectionClosed
    bounded_client.StreamReset(code) -> StreamReset(code)
    bounded_client.InvalidHeaderEncoding -> InvalidHeaderEncoding
    bounded_client.ResponseBodyTooLarge(limit) -> ResponseBodyTooLarge(limit)
  }
}

fn map_worker_error(error: client_worker.Error) -> Error {
  case error {
    client_worker.InvalidInput -> InvalidRequest
    client_worker.ResolutionFailed -> ResolutionFailed
    client_worker.SocketUnavailable -> ConnectFailed
    client_worker.Timeout -> Timeout
    client_worker.TlsHandshakeFailed -> HandshakeFailed
    client_worker.TransportFailed(operation) -> TransportError(operation)
    client_worker.Http3Failed(operation) -> Http3Error(operation)
    client_worker.ConnectionClosed -> ConnectionClosed
    client_worker.StreamReset(code) -> StreamReset(code)
    client_worker.ProtocolError -> ProtocolError
    client_worker.InvalidHeaderEncoding -> InvalidHeaderEncoding
    client_worker.InvalidContentLength -> InvalidContentLength
    client_worker.ConsumerTooSlow(limit) -> ConsumerTooSlow(limit)
    client_worker.ConcurrentReceive -> ConcurrentReceive
    client_worker.RequestAlreadyFinished -> RequestAlreadyFinished
    client_worker.StreamFinished -> StreamFinished
    client_worker.StreamCancelled -> StreamCancelled
    client_worker.OriginMismatch -> OriginMismatch
    client_worker.UnsafeEarlyDataMethod(method) -> UnsafeEarlyDataMethod(method)
    client_worker.ResumptionOriginMismatch -> ResumptionOriginMismatch
    client_worker.DatagramsNotNegotiated -> DatagramsNotNegotiated
    client_worker.DatagramTooLarge(maximum) -> DatagramTooLarge(maximum)
    client_worker.DatagramBufferExceeded(limit) -> DatagramBufferExceeded(limit)
    client_worker.ConcurrentDatagramReceive -> ConcurrentDatagramReceive
    client_worker.MigrationUnavailable -> MigrationUnavailable
    client_worker.CongestionLimited -> CongestionLimited
    client_worker.UnsupportedCongestionControl -> UnsupportedCongestionControl
    client_worker.TicketUnavailable -> TicketUnavailable
    client_worker.QlogUnavailable -> QlogUnavailable
  }
}

fn driver_error_name(error: bounded_client.DriverError) -> String {
  bounded_client.driver_error_name(error)
}

fn session_error_name(error: bounded_client.SessionError) -> String {
  bounded_client.session_error_name(error)
}

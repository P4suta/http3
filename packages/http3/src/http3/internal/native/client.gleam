//// Bounded HTTP/3 client powered by the repository-owned QUIC stack.

import gleam/bit_array
import gleam/list
import gleam/option.{type Option, None, Some}
import gleam/result
import http3/failure as runtime_failure
import http3/internal/native/bounded_client
import http3/internal/native/client_connection
import http3/internal/native/client_worker
import http3/internal/qpack/header.{type Header, Header}
import quic_core.{type AddressFamily, DualStack}
import quic_core/diagnostics
import quic_core/failure as core_failure

const default_timeout_milliseconds = 30_000

const maximum_timeout_milliseconds = 3_600_000

const default_response_body_limit = 8_388_608

const default_stream_buffer_limit = 262_144

const default_endpoint_memory_limit = 67_108_864

const default_queue_limit = 1024

const default_telemetry_limit = 1024

const default_bidirectional_stream_limit = 100

const default_unidirectional_stream_limit = 100

const default_frame_limit = 65_536

const default_datagram_limit = 65_527

const default_qpack_table_limit = 4096

const default_qpack_blocked_stream_limit = 16

const default_maximum_pushes = 16

const minimum_keepalive_milliseconds = 1000

const maximum_keepalive_milliseconds = 29_000

type Trust {
  SystemTrust
  ExplicitTrust(List(BitArray))
}

/// Secure bounded-client configuration.
pub opaque type Client {
  Client(
    hostname: String,
    port: Int,
    address_family: AddressFamily,
    connect_address: Option(BitArray),
    dns_timeout_milliseconds: Int,
    connect_timeout_milliseconds: Int,
    handshake_timeout_milliseconds: Int,
    timeout_milliseconds: Int,
    operation_timeout_milliseconds: Int,
    idle_timeout_milliseconds: Int,
    response_body_limit: Int,
    stream_buffer_limit: Int,
    endpoint_memory_limit: Int,
    queue_limit: Int,
    telemetry_limit: Int,
    bidirectional_stream_limit: Int,
    unidirectional_stream_limit: Int,
    frame_limit: Int,
    datagram_limit: Int,
    qpack_table_limit: Int,
    qpack_blocked_stream_limit: Int,
    trust: Trust,
    http_datagrams: Bool,
    maximum_pushes: Int,
    keepalive_milliseconds: Int,
    quic_version: QuicVersion,
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

/// One validated server push promise and its pull-based response.
pub opaque type Push {
  Push(
    handle: client_worker.Push,
    method: String,
    path: String,
    headers: List(#(String, String)),
  )
}

/// Opaque origin-bound TLS resumption state.
pub opaque type ResumptionTicket {
  ResumptionTicket(handle: client_worker.ResumptionTicket)
}

/// A validated 256-bit key for encrypted ticket persistence.
pub opaque type TicketStorageKey {
  TicketStorageKey(bytes: BitArray)
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

/// Outcome of a caller-supplied TLS resumption ticket.
pub type ResumptionStatus {
  ResumptionNotAttempted
  ResumptionPending
  Resumed
  FullHandshake
}

/// Redacted client-handshake inputs and their current protocol outcome.
pub type HandshakeAttempt {
  HandshakeAttempt(
    ticket_supplied: Bool,
    zero_rtt_enabled: Bool,
    ticket_allows_zero_rtt: Bool,
    early_data: EarlyDataStatus,
    resumption: ResumptionStatus,
  )
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

/// Bounded diagnostic writer counters with no trace contents.
pub type TelemetryStats {
  TelemetryStats(
    qlog_dropped_events: Int,
    qlog_write_errors: Int,
    qlog_queued_events: Int,
  )
}

/// Preferred QUIC wire version. Compatible negotiation remains enabled.
pub type QuicVersion {
  QuicV1
  QuicV2
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
  InvalidEndpointMemoryLimit
  InvalidQueueLimit
  InvalidTelemetryLimit
  InvalidBidirectionalStreamLimit
  InvalidUnidirectionalStreamLimit
  InvalidFrameLimit
  InvalidDatagramLimit
  InvalidQpackTableLimit
  InvalidQpackBlockedStreamLimit
  InvalidPushLimit
  InvalidKeepalive
  InvalidCaCertificate
  InvalidQlogDirectory
  InvalidTicketStorageKey
}

/// A complete response retained within the configured body bound.
pub type Response {
  Response(status: Int, headers: List(#(String, String)), body: BitArray)
}

/// The finite client deadline that expired.
pub type TimeoutPhase {
  Dns
  Connect
  Handshake
  Operation
  Total
}

/// Native name resolution, TLS, QUIC, HTTP/3, or resource failure.
pub type Error {
  InvalidRequest
  ResolutionFailed
  TrustStoreFailed
  ConnectFailed
  HandshakeFailed
  Failure(runtime_failure.Failure)
  TimedOut(TimeoutPhase)
  ConnectionClosed
  StreamReset(Int)
  ProtocolError
  InvalidHeaderEncoding
  InvalidContentLength
  ResponseBodyTooLarge(Int)
  ConsumerTooSlow(Int)
  OperationQueueFull(Int)
  ConcurrentReceive
  RequestAlreadyFinished
  StreamFinished
  StreamCancelled
  ConnectionDraining
  RequestRejected
  OriginMismatch
  UnsafeEarlyDataMethod(String)
  ResumptionOriginMismatch
  DatagramsNotNegotiated
  DatagramNotAssociated
  DatagramTooLarge(Int)
  DatagramBufferExceeded(Int)
  ConcurrentDatagramReceive
  CapsuleProtocolUnavailable
  MigrationUnavailable
  CongestionLimited
  UnsupportedCongestionControl
  TicketUnavailable
  InvalidStoredTicket
  QlogUnavailable
  VersionNegotiationFailed
}

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
        DualStack,
        None,
        5000,
        10_000,
        10_000,
        default_timeout_milliseconds,
        default_timeout_milliseconds,
        default_timeout_milliseconds,
        default_response_body_limit,
        default_stream_buffer_limit,
        default_endpoint_memory_limit,
        default_queue_limit,
        default_telemetry_limit,
        default_bidirectional_stream_limit,
        default_unidirectional_stream_limit,
        default_frame_limit,
        default_datagram_limit,
        default_qpack_table_limit,
        default_qpack_blocked_stream_limit,
        SystemTrust,
        False,
        default_maximum_pushes,
        0,
        QuicV1,
        "",
        None,
      ))
  }
}

/// Select IPv4, IPv6, or dual-stack address candidates.
pub fn with_address_family(
  client: Client,
  address_family: AddressFamily,
) -> Client {
  Client(..client, address_family: address_family)
}

/// Select one already-validated UDP dial address without changing the TLS
/// server name. Invalid byte lengths are rejected later by the bounded core.
pub fn with_connect_address(client: Client, address: BitArray) -> Client {
  Client(..client, connect_address: Some(address))
}

/// Set the finite DNS-resolution timeout.
pub fn with_dns_timeout(
  client client: Client,
  milliseconds milliseconds: Int,
) -> Result(Client, ConfigurationError) {
  case milliseconds > 0 && milliseconds <= maximum_timeout_milliseconds {
    True -> Ok(Client(..client, dns_timeout_milliseconds: milliseconds))
    False -> Error(InvalidTimeout)
  }
}

/// Set the finite socket and candidate setup timeout.
pub fn with_connect_timeout(
  client client: Client,
  milliseconds milliseconds: Int,
) -> Result(Client, ConfigurationError) {
  case milliseconds > 0 && milliseconds <= maximum_timeout_milliseconds {
    True -> Ok(Client(..client, connect_timeout_milliseconds: milliseconds))
    False -> Error(InvalidTimeout)
  }
}

/// Set the finite TLS and HTTP/3 settings handshake timeout.
pub fn with_handshake_timeout(
  client client: Client,
  milliseconds milliseconds: Int,
) -> Result(Client, ConfigurationError) {
  case milliseconds > 0 && milliseconds <= maximum_timeout_milliseconds {
    True -> Ok(Client(..client, handshake_timeout_milliseconds: milliseconds))
    False -> Error(InvalidTimeout)
  }
}

/// Configure periodic QUIC PING frames from one through twenty-nine seconds.
pub fn with_keepalive(
  client: Client,
  milliseconds: Int,
) -> Result(Client, ConfigurationError) {
  case
    milliseconds >= minimum_keepalive_milliseconds
    && milliseconds <= maximum_keepalive_milliseconds
  {
    True -> Ok(Client(..client, keepalive_milliseconds: milliseconds))
    False -> Error(InvalidKeepalive)
  }
}

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

/// Set the maximum bytes retained by this client's QUIC endpoint.
pub fn with_endpoint_memory_limit(
  client client: Client,
  bytes bytes: Int,
) -> Result(Client, ConfigurationError) {
  case bytes > 0 {
    True -> Ok(Client(..client, endpoint_memory_limit: bytes))
    False -> Error(InvalidEndpointMemoryLimit)
  }
}

/// Set the maximum number of unconsumed events retained per stream.
pub fn with_queue_limit(
  client client: Client,
  maximum maximum: Int,
) -> Result(Client, ConfigurationError) {
  case maximum > 0 {
    True -> Ok(Client(..client, queue_limit: maximum))
    False -> Error(InvalidQueueLimit)
  }
}

/// Set the maximum asynchronous qlog events waiting behind one active write.
pub fn with_telemetry_limit(
  client client: Client,
  maximum maximum: Int,
) -> Result(Client, ConfigurationError) {
  case maximum > 0 {
    True -> Ok(Client(..client, telemetry_limit: maximum))
    False -> Error(InvalidTelemetryLimit)
  }
}

/// Set the maximum concurrently active bidirectional streams.
pub fn with_bidirectional_stream_limit(
  client client: Client,
  maximum maximum: Int,
) -> Result(Client, ConfigurationError) {
  case maximum > 0 {
    True -> Ok(Client(..client, bidirectional_stream_limit: maximum))
    False -> Error(InvalidBidirectionalStreamLimit)
  }
}

/// Set the maximum concurrently active unidirectional streams.
pub fn with_unidirectional_stream_limit(
  client client: Client,
  maximum maximum: Int,
) -> Result(Client, ConfigurationError) {
  case maximum > 0 {
    True -> Ok(Client(..client, unidirectional_stream_limit: maximum))
    False -> Error(InvalidUnidirectionalStreamLimit)
  }
}

/// Set the maximum HTTP/3 frame payload accepted from the peer.
pub fn with_frame_limit(
  client client: Client,
  bytes bytes: Int,
) -> Result(Client, ConfigurationError) {
  case bytes > 0 {
    True -> Ok(Client(..client, frame_limit: bytes))
    False -> Error(InvalidFrameLimit)
  }
}

/// Set the maximum QUIC Datagram payload advertised and retained.
pub fn with_datagram_limit(
  client client: Client,
  bytes bytes: Int,
) -> Result(Client, ConfigurationError) {
  case bytes > 0 {
    True -> Ok(Client(..client, datagram_limit: bytes))
    False -> Error(InvalidDatagramLimit)
  }
}

/// Set the maximum QPACK dynamic-table capacity advertised to the peer.
pub fn with_qpack_table_limit(
  client client: Client,
  bytes bytes: Int,
) -> Result(Client, ConfigurationError) {
  case bytes > 0 {
    True -> Ok(Client(..client, qpack_table_limit: bytes))
    False -> Error(InvalidQpackTableLimit)
  }
}

/// Set the maximum QPACK-blocked streams accepted from the peer.
pub fn with_qpack_blocked_stream_limit(
  client client: Client,
  maximum maximum: Int,
) -> Result(Client, ConfigurationError) {
  case maximum > 0 {
    True -> Ok(Client(..client, qpack_blocked_stream_limit: maximum))
    False -> Error(InvalidQpackBlockedStreamLimit)
  }
}

/// Negotiate RFC 9221 QUIC DATAGRAM and RFC 9297 HTTP Datagrams.
pub fn with_http_datagrams(client: Client) -> Client {
  Client(..client, http_datagrams: True)
}

/// Set the maximum number of server push promises retained per connection.
/// Zero disables server push.
pub fn with_push_limit(
  client client: Client,
  pushes pushes: Int,
) -> Result(Client, ConfigurationError) {
  case pushes >= 0 && pushes <= 1024 {
    True -> Ok(Client(..client, maximum_pushes: pushes))
    False -> Error(InvalidPushLimit)
  }
}

/// Select the initially attempted QUIC version.
pub fn with_quic_version(client: Client, quic_version: QuicVersion) -> Client {
  Client(..client, quic_version: quic_version)
}

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

/// Attach one opaque origin-bound ticket for resumption.
pub fn with_resumption_ticket(
  client: Client,
  ticket: ResumptionTicket,
) -> Client {
  Client(..client, resumption_ticket: Some(ticket))
}

/// Validate a caller-managed key for encrypted ticket persistence.
pub fn ticket_storage_key(
  bytes: BitArray,
) -> Result(TicketStorageKey, ConfigurationError) {
  case bit_array.bit_size(bytes) % 8 == 0 && bit_array.byte_size(bytes) == 32 {
    True -> Ok(TicketStorageKey(bytes))
    False -> Error(InvalidTicketStorageKey)
  }
}

/// Export an opaque ticket as a versioned authenticated ciphertext.
pub fn export_resumption_ticket(
  ticket: ResumptionTicket,
  key: TicketStorageKey,
) -> Result(BitArray, Error) {
  let ResumptionTicket(handle) = ticket
  client_worker.export_resumption_ticket(handle, key.bytes)
  |> result.map_error(map_worker_error)
}

/// Import a versioned authenticated ticket ciphertext.
pub fn import_resumption_ticket(
  bytes: BitArray,
  key: TicketStorageKey,
) -> Result(ResumptionTicket, Error) {
  client_worker.import_resumption_ticket(bytes, key.bytes)
  |> result.map(ResumptionTicket)
  |> result.map_error(map_worker_error)
}

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

/// Set the finite timeout used by stream and connection operations.
pub fn with_operation_timeout(
  client client: Client,
  milliseconds milliseconds: Int,
) -> Result(Client, ConfigurationError) {
  case milliseconds > 0 && milliseconds <= maximum_timeout_milliseconds {
    True -> Ok(Client(..client, operation_timeout_milliseconds: milliseconds))
    False -> Error(InvalidTimeout)
  }
}

/// Set the advertised and locally enforced QUIC idle timeout.
pub fn with_idle_timeout(
  client client: Client,
  milliseconds milliseconds: Int,
) -> Result(Client, ConfigurationError) {
  case milliseconds > 0 && milliseconds <= maximum_timeout_milliseconds {
    True -> Ok(Client(..client, idle_timeout_milliseconds: milliseconds))
    False -> Error(InvalidTimeout)
  }
}

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

/// Replace system roots with a non-empty explicit DER trust set.
pub fn with_ca_certificates(
  client client: Client,
  certificates certificates: List(BitArray),
) -> Result(Client, ConfigurationError) {
  case certificates, valid_certificate_alignment(certificates) {
    [], _ -> Error(InvalidCaCertificate)
    _, False -> Error(InvalidCaCertificate)
    _, True ->
      case bounded_client.valid_ca_certificates(certificates) {
        True -> Ok(Client(..client, trust: ExplicitTrust(certificates)))
        False -> Error(InvalidCaCertificate)
      }
  }
}

/// Return whether bytes are one valid DER X.509 trust anchor.
pub fn is_valid_ca_certificate(certificate: BitArray) -> Bool {
  bounded_client.valid_ca_certificates([certificate])
}

/// Execute one bounded request and close its connection before returning.
pub fn send(
  client client: Client,
  headers headers: List(#(String, String)),
  body body: BitArray,
) -> Result(Response, Error) {
  let config =
    bounded_client.Config(
      hostname: client.hostname,
      port: client.port,
      address_family: client.address_family,
      connect_address: client.connect_address,
      dns_timeout_milliseconds: client.dns_timeout_milliseconds,
      connect_timeout_milliseconds: client.connect_timeout_milliseconds,
      handshake_timeout_milliseconds: client.handshake_timeout_milliseconds,
      timeout_milliseconds: client.timeout_milliseconds,
      operation_timeout_milliseconds: client.operation_timeout_milliseconds,
      idle_timeout_milliseconds: client.idle_timeout_milliseconds,
      maximum_request_body_bytes: bit_array.byte_size(body),
      maximum_response_body_bytes: client.response_body_limit,
      endpoint_memory_limit: client.endpoint_memory_limit,
      telemetry_limit: client.telemetry_limit,
      ca_certificates: trust_certificates(client.trust),
      quic_version: case client.quic_version {
        QuicV1 -> quic_core.QuicV1
        QuicV2 -> quic_core.QuicV2
      },
      keepalive_milliseconds: client.keepalive_milliseconds,
      qlog_directory: client.qlog_directory,
    )
  case bounded_client.send(config, headers, body) {
    Ok(bounded_client.Response(status, headers, body)) ->
      Ok(Response(status, headers, body))
    Error(error) -> Error(map_error(error))
  }
}

/// Establish one reusable origin-bound connection in an owner-monitoring actor.
pub fn connect(client: Client) -> Result(Connection, Error) {
  let ticket = case client.resumption_ticket {
    Some(ResumptionTicket(ticket)) -> Some(ticket)
    None -> None
  }
  client_worker.connect(
    client.hostname,
    client.port,
    client.address_family,
    client.connect_address,
    client.dns_timeout_milliseconds,
    client.connect_timeout_milliseconds,
    client.handshake_timeout_milliseconds,
    client.timeout_milliseconds,
    client.operation_timeout_milliseconds,
    client.idle_timeout_milliseconds,
    client.stream_buffer_limit,
    client.endpoint_memory_limit,
    client.queue_limit,
    client.telemetry_limit,
    client.bidirectional_stream_limit,
    client.unidirectional_stream_limit,
    client.frame_limit,
    client.datagram_limit,
    client.qpack_table_limit,
    client.qpack_blocked_stream_limit,
    trust_certificates(client.trust),
    client.http_datagrams,
    client.maximum_pushes,
    client.keepalive_milliseconds,
    case client.quic_version {
      QuicV1 -> quic_core.QuicV1
      QuicV2 -> quic_core.QuicV2
    },
    client.qlog_directory,
    ticket,
  )
  |> result.map(Connection)
  |> result.map_error(map_worker_error)
}

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

/// Pull the next server push promise within the connection timeout.
pub fn next_push(connection: Connection) -> Result(Push, Error) {
  let Connection(handle) = connection
  case client_worker.next_push(handle) {
    Ok(client_worker.IncomingPush(push, method, path, headers)) ->
      Ok(Push(push, method, path, headers))
    Error(error) -> Error(map_worker_error(error))
  }
}

/// Return the promised request method.
pub fn push_method(push: Push) -> String {
  push.method
}

/// Return the promised request path and query.
pub fn push_path(push: Push) -> String {
  push.path
}

/// Return the promised request's regular fields.
pub fn push_headers(push: Push) -> List(#(String, String)) {
  push.headers
}

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

/// Queue pre-encoded Capsule Protocol bytes after successful negotiation.
pub fn send_capsule(stream: Stream, bytes: BitArray) -> Result(Nil, Error) {
  let Stream(handle) = stream
  case bit_array.bit_size(bytes) % 8 {
    0 ->
      client_worker.send_capsule(handle, bytes)
      |> result.map_error(map_worker_error)
    _ -> Error(InvalidRequest)
  }
}

/// Send request trailers and finish the request stream atomically.
pub fn send_trailers(
  stream: Stream,
  headers: List(#(String, String)),
) -> Result(Nil, Error) {
  let Stream(handle) = stream
  use encoded <- result.try(encode_headers(headers))
  client_worker.send_trailers(handle, encoded)
  |> result.map_error(map_worker_error)
}

/// Finish a streaming request body.
pub fn finish(stream: Stream) -> Result(Nil, Error) {
  let Stream(handle) = stream
  client_worker.finish(handle) |> result.map_error(map_worker_error)
}

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

/// Pull the next response event for a server push.
pub fn next_push_event(push: Push) -> Result(ResponseEvent, Error) {
  case client_worker.next_push_event(push.handle) {
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

/// Cancel a server push idempotently.
pub fn cancel_push(push: Push) -> Result(Cancellation, Error) {
  case client_worker.cancel_push(push.handle) {
    Ok(client_worker.Cancelled) -> Ok(Cancelled)
    Ok(client_worker.AlreadyCancelled) -> Ok(AlreadyCancelled)
    Ok(client_worker.AlreadyCompleted) -> Ok(AlreadyCompleted)
    Error(error) -> Error(map_worker_error(error))
  }
}

/// Close one reusable connection idempotently.
pub fn close(connection: Connection) -> Result(CloseResult, Error) {
  let Connection(handle) = connection
  case client_worker.close(handle) {
    Ok(client_worker.Closed) -> Ok(Closed)
    Ok(client_worker.AlreadyClosed) -> Ok(AlreadyClosed)
    Error(error) -> Error(map_worker_error(error))
  }
}

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

/// Return the largest HTTP Datagram payload for one request stream.
pub fn maximum_datagram_size(stream: Stream) -> Result(Int, Error) {
  let Stream(handle) = stream
  client_worker.maximum_datagram_size(handle)
  |> result.map_error(map_worker_error)
}

/// Return a request's lifetime-stable HTTP Datagram payload ceiling.
pub fn guaranteed_datagram_size(stream: Stream) -> Result(Int, Error) {
  let Stream(handle) = stream
  client_worker.guaranteed_datagram_size(handle)
  |> result.map_error(map_worker_error)
}

/// Send one unreliable HTTP Datagram.
pub fn send_datagram(stream: Stream, payload: BitArray) -> Result(Nil, Error) {
  let Stream(handle) = stream
  client_worker.send_datagram(handle, payload)
  |> result.map_error(map_worker_error)
}

/// Pull one unreliable HTTP Datagram.
pub fn next_datagram(stream: Stream) -> Result(BitArray, Error) {
  let Stream(handle) = stream
  client_worker.next_datagram(handle) |> result.map_error(map_worker_error)
}

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

/// Return one request stream's effective priority.
pub fn get_priority(stream: Stream) -> Result(#(Int, Bool), Error) {
  let Stream(handle) = stream
  client_worker.get_priority(handle) |> result.map_error(map_worker_error)
}

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

/// Return whether a supplied ticket resumed TLS or used a full handshake.
pub fn resumption_status(
  connection: Connection,
) -> Result(ResumptionStatus, Error) {
  let Connection(handle) = connection
  case client_worker.resumption_status(handle) {
    Ok(client_worker.ResumptionNotAttempted) -> Ok(ResumptionNotAttempted)
    Ok(client_worker.ResumptionPending) -> Ok(ResumptionPending)
    Ok(client_worker.Resumed) -> Ok(Resumed)
    Ok(client_worker.FullHandshake) -> Ok(FullHandshake)
    Error(error) -> Error(map_worker_error(error))
  }
}

/// Return one bounded snapshot with no ticket, identity, endpoint, or payload.
pub fn handshake_attempt(
  connection: Connection,
) -> Result(HandshakeAttempt, Error) {
  let Connection(handle) = connection
  case client_worker.handshake_attempt(handle) {
    Ok(client_worker.HandshakeAttempt(
      ticket_supplied,
      zero_rtt_enabled,
      ticket_allows_zero_rtt,
      early,
      resumption,
    )) ->
      Ok(
        HandshakeAttempt(
          ticket_supplied:,
          zero_rtt_enabled:,
          ticket_allows_zero_rtt:,
          early_data: case early {
            client_worker.NotAttempted -> NotAttempted
            client_worker.Pending -> Pending
            client_worker.Accepted -> Accepted
            client_worker.Rejected -> Rejected
          },
          resumption: case resumption {
            client_worker.ResumptionNotAttempted -> ResumptionNotAttempted
            client_worker.ResumptionPending -> ResumptionPending
            client_worker.Resumed -> Resumed
            client_worker.FullHandshake -> FullHandshake
          },
        ),
      )
    Error(error) -> Error(map_worker_error(error))
  }
}

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

/// Wait for the newest origin-bound session ticket.
pub fn resumption_ticket(
  connection: Connection,
) -> Result(ResumptionTicket, Error) {
  let Connection(handle) = connection
  client_worker.resumption_ticket(handle)
  |> result.map(ResumptionTicket)
  |> result.map_error(map_worker_error)
}

/// Migrate to a fresh local UDP path.
pub fn migrate(connection: Connection) -> Result(Nil, Error) {
  let Connection(handle) = connection
  client_worker.migrate(handle) |> result.map_error(map_worker_error)
}

/// Change live congestion control (1 = NewReno, 2 = CUBIC).
pub fn set_congestion_control(
  connection: Connection,
  algorithm: Int,
) -> Result(Nil, Error) {
  let Connection(handle) = connection
  client_worker.set_congestion_control(handle, algorithm)
  |> result.map_error(map_worker_error)
}

/// Send a transport PING.
pub fn ping(connection: Connection) -> Result(Nil, Error) {
  let Connection(handle) = connection
  client_worker.ping(handle) |> result.map_error(map_worker_error)
}

/// Return the current path MTU.
pub fn maximum_transmission_unit(connection: Connection) -> Result(Int, Error) {
  let Connection(handle) = connection
  client_worker.maximum_transmission_unit(handle)
  |> result.map_error(map_worker_error)
}

/// Snapshot path RTT and congestion state.
pub fn path_stats(connection: Connection) -> Result(PathStats, Error) {
  let Connection(handle) = connection
  case client_worker.path_stats(handle) {
    Ok(diagnostics.PathStats(
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

/// Test-only payload-free snapshot of retained stream and connection state.
@internal
pub fn resource_state_stats(
  connection: Connection,
) -> Result(#(Int, Int, Int, Int, Int, Int, Int, Int, Int), Error) {
  let Connection(handle) = connection
  client_worker.resource_state_stats(handle)
  |> result.map_error(map_worker_error)
}

/// Snapshot diagnostic writer health for a reusable connection.
pub fn telemetry_stats(
  connection: Connection,
) -> Result(TelemetryStats, Error) {
  let Connection(handle) = connection
  client_worker.telemetry_stats(handle)
  |> result.map(fn(stats) {
    let #(dropped, errors, queued) = stats
    TelemetryStats(dropped, errors, queued)
  })
  |> result.map_error(map_worker_error)
}

/// Return the current path MTU for a request stream's connection.
pub fn maximum_transmission_unit_for_stream(
  stream: Stream,
) -> Result(Int, Error) {
  let Stream(handle) = stream
  client_worker.stream_connection(handle)
  |> client_worker.maximum_transmission_unit
  |> result.map_error(map_worker_error)
}

/// Snapshot path state for a request stream's connection.
pub fn path_stats_for_stream(stream: Stream) -> Result(PathStats, Error) {
  let Stream(handle) = stream
  let connection = client_worker.stream_connection(handle)
  case client_worker.path_stats(connection) {
    Ok(diagnostics.PathStats(
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

/// Snapshot counters for a request stream's connection.
pub fn connection_stats_for_stream(
  stream: Stream,
) -> Result(ConnectionStats, Error) {
  let Stream(handle) = stream
  let connection = client_worker.stream_connection(handle)
  case client_worker.connection_stats(connection) {
    Ok(client_connection.Stats(a, b, c, d, e, f, g, h)) ->
      Ok(ConnectionStats(a, b, c, d, e, f, g, h))
    Error(error) -> Error(map_worker_error(error))
  }
}

/// Snapshot diagnostic writer health for a stream's connection.
pub fn telemetry_stats_for_stream(
  stream: Stream,
) -> Result(TelemetryStats, Error) {
  let Stream(handle) = stream
  client_worker.stream_connection(handle)
  |> client_worker.telemetry_stats
  |> result.map(fn(stats) {
    let #(dropped, errors, queued) = stats
    TelemetryStats(dropped, errors, queued)
  })
  |> result.map_error(map_worker_error)
}

fn trust_certificates(trust: Trust) -> Option(List(BitArray)) {
  case trust {
    SystemTrust -> None
    ExplicitTrust(certificates) -> Some(certificates)
  }
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
    bounded_client.DnsTimeout -> TimedOut(Dns)
    bounded_client.ConnectTimeout -> TimedOut(Connect)
    bounded_client.HandshakeTimeout -> TimedOut(Handshake)
    bounded_client.OperationTimeout -> TimedOut(Operation)
    bounded_client.TotalTimeout -> TimedOut(Total)
    bounded_client.TrustStoreFailed -> TrustStoreFailed
    bounded_client.TlsHandshakeFailed -> HandshakeFailed
    bounded_client.QuicTransportFailed ->
      Failure(runtime_failure.Quic(runtime_failure.Local, None))
    bounded_client.CoreFailure(failure) -> Failure(map_core_failure(failure))
    bounded_client.Http3ProtocolFailed ->
      Failure(runtime_failure.Http3(runtime_failure.Peer, None))
    bounded_client.Http3OperationFailed ->
      Failure(runtime_failure.Http3(runtime_failure.Local, None))
    bounded_client.PeerClosed -> ConnectionClosed
    bounded_client.StreamReset(code) -> StreamReset(code)
    bounded_client.InvalidHeaderEncoding -> InvalidHeaderEncoding
    bounded_client.ResponseBodyTooLarge(limit) -> ResponseBodyTooLarge(limit)
    bounded_client.QlogUnavailable -> QlogUnavailable
    bounded_client.VersionNegotiationReceived -> VersionNegotiationFailed
    bounded_client.VersionNegotiationFailed -> VersionNegotiationFailed
  }
}

fn map_worker_error(error: client_worker.Error) -> Error {
  case error {
    client_worker.InvalidInput -> InvalidRequest
    client_worker.ResolutionFailed -> ResolutionFailed
    client_worker.SocketUnavailable -> ConnectFailed
    client_worker.DnsTimeout -> TimedOut(Dns)
    client_worker.ConnectTimeout -> TimedOut(Connect)
    client_worker.HandshakeTimeout -> TimedOut(Handshake)
    client_worker.OperationTimeout -> TimedOut(Operation)
    client_worker.TotalTimeout -> TimedOut(Total)
    client_worker.TrustStoreFailed -> TrustStoreFailed
    client_worker.TlsHandshakeFailed -> HandshakeFailed
    client_worker.QuicFailure ->
      Failure(runtime_failure.Quic(runtime_failure.Local, None))
    client_worker.CoreFailure(failure) -> Failure(map_core_failure(failure))
    client_worker.Http3Failure ->
      Failure(runtime_failure.Http3(runtime_failure.Local, None))
    client_worker.ConcurrentSend ->
      Failure(runtime_failure.Overload(runtime_failure.Queue))
    client_worker.ConnectionClosed -> ConnectionClosed
    client_worker.StreamReset(code) -> StreamReset(code)
    client_worker.ProtocolError -> ProtocolError
    client_worker.InvalidHeaderEncoding -> InvalidHeaderEncoding
    client_worker.InvalidContentLength -> InvalidContentLength
    client_worker.ConsumerTooSlow(limit) -> ConsumerTooSlow(limit)
    client_worker.OperationQueueFull(limit) -> OperationQueueFull(limit)
    client_worker.ResponseEventQueueExceeded(limit)
    | client_worker.DatagramQueueExceeded(limit) ->
      Failure(runtime_failure.Limit(runtime_failure.Queue, limit))
    client_worker.ConcurrentReceive -> ConcurrentReceive
    client_worker.RequestAlreadyFinished -> RequestAlreadyFinished
    client_worker.StreamFinished -> StreamFinished
    client_worker.StreamCancelled -> StreamCancelled
    client_worker.ConnectionDraining -> ConnectionDraining
    client_worker.RequestRejected -> RequestRejected
    client_worker.OriginMismatch -> OriginMismatch
    client_worker.UnsafeEarlyDataMethod(method) -> UnsafeEarlyDataMethod(method)
    client_worker.ResumptionOriginMismatch -> ResumptionOriginMismatch
    client_worker.DatagramsNotNegotiated -> DatagramsNotNegotiated
    client_worker.DatagramNotAssociated -> DatagramNotAssociated
    client_worker.DatagramTooLarge(maximum) -> DatagramTooLarge(maximum)
    client_worker.DatagramBufferExceeded(limit) -> DatagramBufferExceeded(limit)
    client_worker.ConcurrentDatagramReceive -> ConcurrentDatagramReceive
    client_worker.CapsuleProtocolUnavailable -> CapsuleProtocolUnavailable
    client_worker.MigrationUnavailable -> MigrationUnavailable
    client_worker.CongestionLimited -> CongestionLimited
    client_worker.UnsupportedCongestionControl -> UnsupportedCongestionControl
    client_worker.TicketUnavailable -> TicketUnavailable
    client_worker.InvalidStoredTicket -> InvalidStoredTicket
    client_worker.QlogUnavailable -> QlogUnavailable
    client_worker.VersionNegotiationFailed -> VersionNegotiationFailed
  }
}

fn map_core_failure(failure: core_failure.Failure) -> runtime_failure.Failure {
  case failure {
    core_failure.Resolution -> runtime_failure.Resolution
    core_failure.Socket(operation) ->
      runtime_failure.Socket(map_core_socket_operation(operation))
    core_failure.Tls(origin) -> runtime_failure.Tls(map_core_origin(origin))
    core_failure.Quic(origin, code) ->
      runtime_failure.Quic(map_core_origin(origin), code)
    core_failure.Timeout(phase) ->
      runtime_failure.Timeout(map_core_timeout_phase(phase))
    core_failure.Cancelled -> runtime_failure.Cancelled
    core_failure.Closed(origin, code) ->
      runtime_failure.Closed(map_core_origin(origin), code)
    core_failure.Limit(resource, maximum) ->
      runtime_failure.Limit(map_core_resource(resource), maximum)
    core_failure.Overload(resource) ->
      runtime_failure.Overload(map_core_resource(resource))
  }
}

fn map_core_origin(origin: core_failure.Origin) -> runtime_failure.Origin {
  case origin {
    core_failure.Local -> runtime_failure.Local
    core_failure.Peer -> runtime_failure.Peer
  }
}

fn map_core_socket_operation(
  operation: core_failure.SocketOperation,
) -> runtime_failure.SocketOperation {
  case operation {
    core_failure.OpenSocket -> runtime_failure.OpenSocket
    core_failure.BindSocket -> runtime_failure.BindSocket
    core_failure.ConnectSocket -> runtime_failure.ConnectSocket
    core_failure.SendDatagram -> runtime_failure.SendDatagram
    core_failure.ReceiveDatagram -> runtime_failure.ReceiveDatagram
    core_failure.ReadFile -> runtime_failure.ReadFile
    core_failure.WriteFile -> runtime_failure.WriteFile
  }
}

fn map_core_timeout_phase(
  phase: core_failure.TimeoutPhase,
) -> runtime_failure.TimeoutPhase {
  case phase {
    core_failure.Dns -> runtime_failure.Dns
    core_failure.Connect -> runtime_failure.Connect
    core_failure.Handshake -> runtime_failure.Handshake
    core_failure.Operation -> runtime_failure.Operation
    core_failure.Idle -> runtime_failure.Idle
    core_failure.Drain -> runtime_failure.Drain
    core_failure.Total -> runtime_failure.Total
  }
}

fn map_core_resource(
  resource: core_failure.Resource,
) -> runtime_failure.Resource {
  case resource {
    core_failure.Connections -> runtime_failure.Connections
    core_failure.Handshakes -> runtime_failure.Handshakes
    core_failure.BidirectionalStreams -> runtime_failure.BidirectionalStreams
    core_failure.UnidirectionalStreams -> runtime_failure.UnidirectionalStreams
    core_failure.Buffer -> runtime_failure.Buffer
    core_failure.EndpointMemory -> runtime_failure.EndpointMemory
    core_failure.Queue -> runtime_failure.Queue
    core_failure.Datagram -> runtime_failure.Datagram
    core_failure.AcceptWaiters -> runtime_failure.AcceptWaiters
    core_failure.Telemetry -> runtime_failure.Telemetry
  }
}

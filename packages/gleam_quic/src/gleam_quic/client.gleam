//// Secure, bounded generic QUIC client.
////
//// The common path is `new`, `connect`, `open_bidirectional`, `send`,
//// `receive`, and `close`. Connections and streams are opaque; no process,
//// socket, mailbox value, TLS state, or traffic secret crosses this module.

import gleam/bit_array
import gleam/erlang/process
import gleam/list
import gleam/option.{type Option, None, Some}
import gleam/result
import gleam_quic.{type AddressFamily, type CongestionControl, type Version}
import gleam_quic/config.{type Deadlines, type Limits}
import gleam_quic/diagnostics
import gleam_quic/failure
import gleam_quic/internal/connection_state as transport
import gleam_quic/internal/qlog
import gleam_quic/internal/runtime/client_worker
import gleam_quic/internal/runtime/connection as runtime_connection
import gleam_quic/internal/runtime/ticket_store
import gleam_quic/internal/tls/authentication
import gleam_quic/internal/tls/engine
import gleam_quic/internal/tls/hello
import gleam_quic/version as wire_version

/// Validated secure client configuration.
pub opaque type Client {
  Client(
    hostname: String,
    port: Int,
    application_protocols: List(BitArray),
    address_family: AddressFamily,
    deadlines: Deadlines,
    limits: Limits,
    trust_store: authentication.TrustStore,
    client_credential: Option(engine.ClientCredential),
    version: Version,
    congestion_control: CongestionControl,
    qlog_directory: String,
    resumption_ticket: Option(client_worker.ResumptionTicket),
    allow_zero_rtt: Bool,
  )
}

/// One reusable secure generic QUIC connection.
pub opaque type Connection {
  Connection(handle: client_worker.Connection)
}

/// One bidirectional or unidirectional QUIC stream.
pub opaque type Stream {
  Stream(handle: client_worker.Stream)
}

/// One peer-initiated stream and its directionality.
pub type IncomingStream {
  IncomingStream(stream: Stream, kind: StreamKind)
}

/// Whether one or both endpoints may send on a stream.
pub type StreamKind {
  Bidirectional
  Unidirectional
}

/// One bounded pull from a stream receive direction.
pub type Read {
  Data(bytes: BitArray, finished: Bool)
  Finished
  Reset(application_error_code: Int)
}

/// Opaque origin-bound TLS resumption state.
pub opaque type ResumptionTicket {
  ResumptionTicket(handle: client_worker.ResumptionTicket)
}

/// A validated 256-bit caller key for encrypted ticket persistence.
pub opaque type TicketStorageKey {
  TicketStorageKey(bytes: BitArray)
}

/// Idempotent close outcome.
pub type CloseResult {
  Closed
  AlreadyClosed
}

/// Invalid endpoint, TLS, diagnostic, or persistence configuration.
pub type ConfigurationError {
  InvalidHost
  InvalidPort(Int)
  InvalidApplicationProtocol
  TrustStoreUnavailable
  InvalidCaCertificate
  InvalidClientCertificate
  InvalidClientPrivateKey
  IncompatibleClientPrivateKey
  InvalidQlogDirectory
  InvalidTicketOrigin
  InvalidTicketStorageKey
}

/// Typed transport failure or safe local misuse result.
pub type Error {
  Failure(failure.Failure)
  InvalidOperation
  InvalidDirection
  StreamFinished
  ConcurrentOperation
  StreamReset(Int)
  TicketUnavailable
  InvalidStoredTicket
}

/// Configure one secure origin and one ALPN protocol using bounded defaults.
/// Certificate-chain and service-identity verification are always enabled.
pub fn new(
  hostname hostname: String,
  port port: Int,
  application_protocol application_protocol: String,
) -> Result(Client, ConfigurationError) {
  use protocols <- result.try(validate_protocols([application_protocol]))
  use trust_store <- result.try(
    authentication.system_trust_store()
    |> result.replace_error(TrustStoreUnavailable),
  )
  case hostname, port {
    "", _ -> Error(InvalidHost)
    _, value if value <= 0 || value > 65_535 -> Error(InvalidPort(value))
    _, _ ->
      Ok(Client(
        hostname,
        port,
        protocols,
        gleam_quic.DualStack,
        config.default_deadlines(),
        config.default_limits(),
        trust_store,
        None,
        gleam_quic.QuicV1,
        gleam_quic.NewReno,
        "",
        None,
        False,
      ))
  }
}

/// Replace the ordered ALPN preference list.
pub fn with_application_protocols(
  client: Client,
  protocols: List(String),
) -> Result(Client, ConfigurationError) {
  validate_protocols(protocols)
  |> result.map(fn(values) { Client(..client, application_protocols: values) })
}

/// Select IPv4, IPv6, or staggered dual-stack racing.
pub fn with_address_family(client: Client, family: AddressFamily) -> Client {
  Client(..client, address_family: family)
}

/// Attach an already validated finite deadline policy atomically.
pub fn with_deadlines(client: Client, deadlines: Deadlines) -> Client {
  Client(..client, deadlines: deadlines)
}

/// Attach an already validated finite resource policy atomically.
pub fn with_limits(client: Client, limits: Limits) -> Client {
  Client(..client, limits: limits)
}

/// Prefer QUIC v1 or v2 while retaining compatible version negotiation.
pub fn with_version(client: Client, version: Version) -> Client {
  Client(..client, version: version)
}

/// Select one implemented congestion controller.
pub fn with_congestion_control(
  client: Client,
  algorithm: CongestionControl,
) -> Client {
  Client(..client, congestion_control: algorithm)
}

/// Replace system roots with explicitly supplied PEM trust anchors.
/// Hostname or IP identity verification remains mandatory.
pub fn with_ca_certificates(
  client: Client,
  certificate_pem: BitArray,
) -> Result(Client, ConfigurationError) {
  authentication.trust_store_from_pem(certificate_pem)
  |> result.map(fn(trust_store) { Client(..client, trust_store: trust_store) })
  |> result.replace_error(InvalidCaCertificate)
}

/// Present one client certificate chain when a server requests mTLS.
/// The decoded private key remains runtime-owned and is never exposed.
pub fn with_client_certificate(
  client: Client,
  certificate_pem: BitArray,
  private_key_pem: BitArray,
) -> Result(Client, ConfigurationError) {
  use certificate_chain <- result.try(
    authentication.certificate_chain_from_pem(certificate_pem)
    |> result.replace_error(InvalidClientCertificate),
  )
  use Nil <- result.try(
    authentication.validate_client_certificate_purpose(certificate_chain)
    |> result.replace_error(InvalidClientCertificate),
  )
  use signing_key <- result.try(
    authentication.signing_key_from_pem(private_key_pem)
    |> result.replace_error(InvalidClientPrivateKey),
  )
  use signature_scheme <- result.try(
    authentication.signing_key_scheme(signing_key)
    |> result.replace_error(IncompatibleClientPrivateKey),
  )
  use matches <- result.try(
    authentication.signing_key_matches_certificate(
      certificate_chain,
      signing_key,
      signature_scheme,
    )
    |> result.replace_error(IncompatibleClientPrivateKey),
  )
  case matches {
    False -> Error(IncompatibleClientPrivateKey)
    True ->
      Ok(
        Client(
          ..client,
          client_credential: Some(engine.ClientCredential(
            certificate_chain,
            signing_key,
            signature_scheme,
          )),
        ),
      )
  }
}

/// Enable one bounded asynchronous qlog writer per connection.
/// An empty path disables qlog.
pub fn with_qlog(
  client: Client,
  directory: String,
) -> Result(Client, ConfigurationError) {
  case directory {
    "" -> Ok(Client(..client, qlog_directory: ""))
    value ->
      qlog.validate_directory(value)
      |> result.map(fn(_) { Client(..client, qlog_directory: value) })
      |> result.replace_error(InvalidQlogDirectory)
  }
}

/// Offer an origin-bound ticket for authenticated resumption.
/// This does not enable 0-RTT.
pub fn with_resumption_ticket(
  client: Client,
  ticket: ResumptionTicket,
) -> Result(Client, ConfigurationError) {
  let ResumptionTicket(handle) = ticket
  case client_worker.ticket_origin(handle) == #(client.hostname, client.port) {
    True -> Ok(Client(..client, resumption_ticket: Some(handle)))
    False -> Error(InvalidTicketOrigin)
  }
}

/// Explicitly permit 0-RTT when the supplied ticket and server both permit it.
/// The default remains authenticated 1-RTT resumption.
pub fn with_zero_rtt(client: Client) -> Client {
  Client(..client, allow_zero_rtt: True)
}

/// Establish an owner-bound reusable connection.
pub fn connect(client: Client) -> Result(Connection, Error) {
  client_worker.connect(
    process.self(),
    client.hostname,
    client.port,
    client.address_family,
    config.deadline(client.deadlines, failure.Dns),
    config.deadline(client.deadlines, failure.Connect),
    config.deadline(client.deadlines, failure.Handshake),
    config.deadline(client.deadlines, failure.Total),
    config.deadline(client.deadlines, failure.Operation),
    config.deadline(client.deadlines, failure.Idle),
    config.limit(client.limits, failure.Buffer),
    config.limit(client.limits, failure.Queue),
    config.limit(client.limits, failure.Telemetry),
    config.limit(client.limits, failure.BidirectionalStreams),
    config.limit(client.limits, failure.UnidirectionalStreams),
    config.limit(client.limits, failure.Datagram),
    client.trust_store,
    client.client_credential,
    client.application_protocols,
    to_wire_version(client.version),
    to_transport_congestion(client.congestion_control),
    client.qlog_directory,
    client.resumption_ticket,
    client.allow_zero_rtt,
  )
  |> result.map(Connection)
  |> result.map_error(map_error)
}

/// Open the next locally initiated bidirectional stream.
pub fn open_bidirectional(connection: Connection) -> Result(Stream, Error) {
  let Connection(handle) = connection
  client_worker.open_bidirectional(handle)
  |> result.map(Stream)
  |> result.map_error(map_error)
}

/// Open the next locally initiated unidirectional stream.
pub fn open_unidirectional(connection: Connection) -> Result(Stream, Error) {
  let Connection(handle) = connection
  client_worker.open_unidirectional(handle)
  |> result.map(Stream)
  |> result.map_error(map_error)
}

/// Wait for one peer-initiated stream.
pub fn accept_stream(connection: Connection) -> Result(IncomingStream, Error) {
  let Connection(handle) = connection
  client_worker.accept_stream(handle)
  |> result.map(fn(incoming) {
    let client_worker.IncomingStream(stream, bidirectional) = incoming
    IncomingStream(Stream(stream), case bidirectional {
      True -> Bidirectional
      False -> Unidirectional
    })
  })
  |> result.map_error(map_error)
}

/// Queue bytes with synchronous transport backpressure.
pub fn send(stream: Stream, bytes: BitArray) -> Result(Nil, Error) {
  let Stream(handle) = stream
  client_worker.send(handle, bytes) |> result.map_error(map_error)
}

/// Queue the stream FIN after all previous bytes.
pub fn finish(stream: Stream) -> Result(Nil, Error) {
  let Stream(handle) = stream
  client_worker.finish(handle) |> result.map_error(map_error)
}

/// Queue bytes and FIN as one caller operation.
pub fn send_and_finish(stream: Stream, bytes: BitArray) -> Result(Nil, Error) {
  let Stream(handle) = stream
  client_worker.send_and_finish(handle, bytes) |> result.map_error(map_error)
}

/// Pull at most `maximum_bytes`; no public receive queue grows without a pull.
pub fn receive(stream: Stream, maximum_bytes: Int) -> Result(Read, Error) {
  let Stream(handle) = stream
  client_worker.receive(handle, maximum_bytes)
  |> result.map(fn(read) {
    case read {
      client_worker.Data(bytes, finished) -> Data(bytes, finished)
      client_worker.Finished -> Finished
      client_worker.Reset(code) -> Reset(code)
    }
  })
  |> result.map_error(map_error)
}

/// Abort locally usable stream directions with an application error code.
pub fn reset(
  stream: Stream,
  application_error_code: Int,
) -> Result(Nil, Error) {
  let Stream(handle) = stream
  client_worker.reset(handle, application_error_code)
  |> result.map_error(map_error)
}

/// Queue one connection-scoped QUIC Datagram.
pub fn send_datagram(
  connection: Connection,
  payload: BitArray,
) -> Result(Nil, Error) {
  let Connection(handle) = connection
  client_worker.send_datagram(handle, payload) |> result.map_error(map_error)
}

/// Pull one connection-scoped QUIC Datagram.
pub fn receive_datagram(connection: Connection) -> Result(BitArray, Error) {
  let Connection(handle) = connection
  client_worker.receive_datagram(handle) |> result.map_error(map_error)
}

/// Return the largest raw QUIC Datagram payload for the live path.
pub fn maximum_datagram_size(connection: Connection) -> Result(Int, Error) {
  let Connection(handle) = connection
  client_worker.maximum_datagram_size(handle) |> result.map_error(map_error)
}

/// Validate a fresh local path and migrate only after peer authentication.
pub fn migrate(connection: Connection) -> Result(Nil, Error) {
  let Connection(handle) = connection
  client_worker.migrate(handle) |> result.map_error(map_error)
}

/// Queue one ack-eliciting PING.
pub fn ping(connection: Connection) -> Result(Nil, Error) {
  let Connection(handle) = connection
  client_worker.ping(handle) |> result.map_error(map_error)
}

/// Change the live congestion controller without exposing recovery state.
pub fn set_congestion_control(
  connection: Connection,
  algorithm: CongestionControl,
) -> Result(Nil, Error) {
  let Connection(handle) = connection
  client_worker.set_congestion_control(
    handle,
    to_transport_congestion(algorithm),
  )
  |> result.map_error(map_error)
}

/// Snapshot the live path without exposing native handles or addresses.
pub fn path_stats(
  connection: Connection,
) -> Result(diagnostics.PathStats, Error) {
  let Connection(handle) = connection
  client_worker.path_stats(handle)
  |> result.map(fn(stats) {
    let transport.PathSnapshot(a, b, c, d, e, f, g, h) = stats
    diagnostics.PathStats(a, b, c, d, e, f, g, h)
  })
  |> result.map_error(map_error)
}

/// Snapshot runtime-owned packet and byte counters.
pub fn connection_stats(
  connection: Connection,
) -> Result(diagnostics.ConnectionStats, Error) {
  let Connection(handle) = connection
  client_worker.connection_stats(handle)
  |> result.map(fn(stats) {
    let runtime_connection.Stats(a, b, c, d, e, f, g, h) = stats
    diagnostics.ConnectionStats(a, b, c, d, e, f, g, h)
  })
  |> result.map_error(map_error)
}

/// Snapshot bounded asynchronous qlog health without trace contents.
pub fn telemetry_stats(
  connection: Connection,
) -> Result(diagnostics.TelemetryStats, Error) {
  let Connection(handle) = connection
  client_worker.telemetry_stats(handle)
  |> result.map(fn(stats) {
    let qlog.Stats(dropped, errors, queued) = stats
    diagnostics.TelemetryStats(dropped, errors, queued)
  })
  |> result.map_error(map_error)
}

/// Return stable lifecycle progress.
pub fn phase(connection: Connection) -> Result(diagnostics.Phase, Error) {
  let Connection(handle) = connection
  client_worker.phase(handle)
  |> result.map(fn(value) {
    case value {
      transport.Handshaking -> diagnostics.Handshaking
      transport.Established -> diagnostics.Established
      transport.Closing -> diagnostics.Closing
      transport.Draining -> diagnostics.Draining
      transport.Closed -> diagnostics.Closed
    }
  })
  |> result.map_error(map_error)
}

/// Return non-secret negotiated/configured connection metadata.
pub fn connection_info(
  connection: Connection,
) -> Result(diagnostics.ConnectionInfo, Error) {
  let Connection(handle) = connection
  use #(version, protocol, congestion, cipher) <- result.try(
    client_worker.negotiated_protocol(handle) |> result.map_error(map_error),
  )
  use protocol <- result.try(
    bit_array.to_string(protocol) |> result.replace_error(InvalidOperation),
  )
  use early <- result.try(
    client_worker.early_data_status(handle) |> result.map_error(map_error),
  )
  use resumption <- result.try(
    client_worker.resumption_status(handle) |> result.map_error(map_error),
  )
  use cipher <- result.try(map_cipher(cipher))
  Ok(
    diagnostics.ConnectionInfo(
      from_wire_version(version),
      protocol,
      cipher,
      from_transport_congestion(congestion),
      case early {
        client_worker.NotAttempted -> diagnostics.NotAttempted
        client_worker.PendingEarlyData -> diagnostics.Pending
        client_worker.EarlyDataAccepted -> diagnostics.Accepted
        client_worker.EarlyDataRejected -> diagnostics.Rejected
      },
      case resumption {
        client_worker.ResumptionNotAttempted ->
          diagnostics.ResumptionNotAttempted
        client_worker.ResumptionPending -> diagnostics.ResumptionPending
        client_worker.Resumed -> diagnostics.Resumed
        client_worker.FullHandshake -> diagnostics.FullHandshake
      },
    ),
  )
}

fn map_cipher(
  cipher: Option(hello.CipherSuite),
) -> Result(diagnostics.CipherSuite, Error) {
  case cipher {
    Some(hello.Aes128GcmSha256) -> Ok(diagnostics.Aes128GcmSha256)
    Some(hello.Aes256GcmSha384) -> Ok(diagnostics.Aes256GcmSha384)
    Some(hello.Chacha20Poly1305Sha256) -> Ok(diagnostics.Chacha20Poly1305Sha256)
    _ -> Error(InvalidOperation)
  }
}

/// Wait for the latest opaque origin-bound resumption ticket.
pub fn resumption_ticket(
  connection: Connection,
) -> Result(ResumptionTicket, Error) {
  let Connection(handle) = connection
  client_worker.resumption_ticket(handle)
  |> result.map(ResumptionTicket)
  |> result.map_error(map_error)
}

/// Validate a caller-managed 256-bit persistence key.
pub fn ticket_storage_key(
  bytes: BitArray,
) -> Result(TicketStorageKey, ConfigurationError) {
  case bit_array.bit_size(bytes) % 8 == 0 && bit_array.byte_size(bytes) == 32 {
    True -> Ok(TicketStorageKey(bytes))
    False -> Error(InvalidTicketStorageKey)
  }
}

/// Export a versioned caller-key-encrypted ticket and address token.
pub fn export_resumption_ticket(
  ticket: ResumptionTicket,
  key: TicketStorageKey,
) -> Result(BitArray, Error) {
  let ResumptionTicket(handle) = ticket
  let TicketStorageKey(bytes) = key
  let #(hostname, port) = client_worker.ticket_origin(handle)
  ticket_store.export(
    ticket_store.Stored(
      hostname,
      port,
      client_worker.ticket_native(handle),
      client_worker.ticket_address_token(handle),
    ),
    bytes,
  )
  |> result.replace_error(InvalidStoredTicket)
}

/// Authenticate and restore a versioned ticket after process restart.
pub fn import_resumption_ticket(
  stored: BitArray,
  key: TicketStorageKey,
) -> Result(ResumptionTicket, Error) {
  let TicketStorageKey(bytes) = key
  ticket_store.restore(stored, bytes)
  |> result.map(fn(value) {
    let ticket_store.Stored(hostname, port, ticket, token) = value
    ResumptionTicket(client_worker.restored_ticket(
      hostname,
      port,
      ticket,
      token,
    ))
  })
  |> result.replace_error(InvalidStoredTicket)
}

/// Close the connection idempotently.
pub fn close(connection: Connection) -> Result(CloseResult, Error) {
  let Connection(handle) = connection
  case client_worker.close(handle) {
    Ok(client_worker.Closed) -> Ok(Closed)
    Ok(client_worker.AlreadyClosed) -> Ok(AlreadyClosed)
    Error(client_worker.ConnectionClosed) -> Ok(AlreadyClosed)
    Error(error) -> Error(map_error(error))
  }
}

fn validate_protocols(
  protocols: List(String),
) -> Result(List(BitArray), ConfigurationError) {
  case protocols {
    [] -> Error(InvalidApplicationProtocol)
    _ -> validate_protocol_entries(protocols, [], [])
  }
}

fn validate_protocol_entries(
  protocols: List(String),
  seen: List(BitArray),
  reversed: List(BitArray),
) -> Result(List(BitArray), ConfigurationError) {
  case protocols {
    [] -> Ok(list.reverse(reversed))
    [protocol, ..rest] -> {
      let bytes = <<protocol:utf8>>
      let size = bit_array.byte_size(bytes)
      case size > 0 && size <= 255 && !list.contains(seen, bytes) {
        False -> Error(InvalidApplicationProtocol)
        True ->
          validate_protocol_entries(rest, [bytes, ..seen], [bytes, ..reversed])
      }
    }
  }
}

fn to_wire_version(version: Version) -> wire_version.Version {
  case version {
    gleam_quic.QuicV1 -> wire_version.Version1
    gleam_quic.QuicV2 -> wire_version.Version2
  }
}

fn from_wire_version(version: wire_version.Version) -> Version {
  case version {
    wire_version.Version2 -> gleam_quic.QuicV2
    _ -> gleam_quic.QuicV1
  }
}

fn to_transport_congestion(
  algorithm: CongestionControl,
) -> transport.CongestionAlgorithm {
  case algorithm {
    gleam_quic.NewReno -> transport.NewReno
    gleam_quic.Cubic -> transport.Cubic
  }
}

fn from_transport_congestion(
  algorithm: transport.CongestionAlgorithm,
) -> CongestionControl {
  case algorithm {
    transport.NewReno -> gleam_quic.NewReno
    transport.Cubic -> gleam_quic.Cubic
  }
}

fn map_error(error: client_worker.Error) -> Error {
  case error {
    client_worker.InvalidInput -> InvalidOperation
    client_worker.ResolutionFailed -> Failure(failure.Resolution)
    client_worker.SocketUnavailable ->
      Failure(failure.Socket(failure.ReceiveDatagram))
    client_worker.DnsTimeout -> Failure(failure.Timeout(failure.Dns))
    client_worker.ConnectTimeout -> Failure(failure.Timeout(failure.Connect))
    client_worker.HandshakeTimeout ->
      Failure(failure.Timeout(failure.Handshake))
    client_worker.OperationTimeout ->
      Failure(failure.Timeout(failure.Operation))
    client_worker.TotalTimeout -> Failure(failure.Timeout(failure.Total))
    client_worker.TlsHandshakeFailed -> Failure(failure.Tls(failure.Peer))
    client_worker.QuicFailure | client_worker.VersionNegotiationFailed ->
      Failure(failure.Quic(failure.Peer, None))
    client_worker.ConnectionClosed ->
      Failure(failure.Closed(failure.Peer, None))
    client_worker.StreamClosed -> StreamFinished
    client_worker.StreamReset(code) -> StreamReset(code)
    client_worker.InvalidDirection -> InvalidDirection
    client_worker.ConcurrentSend
    | client_worker.ConcurrentReceive
    | client_worker.ConcurrentAccept
    | client_worker.ConcurrentDatagramReceive -> ConcurrentOperation
    client_worker.SendBufferExceeded(maximum) ->
      Failure(failure.Limit(failure.Buffer, maximum))
    client_worker.IncomingStreamQueueExceeded(maximum) ->
      Failure(failure.Limit(failure.Queue, maximum))
    client_worker.DatagramQueueExceeded(maximum) ->
      Failure(failure.Limit(failure.Datagram, maximum))
    client_worker.DatagramTooLarge(maximum) ->
      Failure(failure.Limit(failure.Datagram, maximum))
    client_worker.DatagramsNotNegotiated ->
      Failure(failure.Quic(failure.Peer, None))
    client_worker.MigrationUnavailable ->
      Failure(failure.Quic(failure.Local, None))
    client_worker.CongestionLimited -> Failure(failure.Overload(failure.Queue))
    client_worker.TicketUnavailable -> TicketUnavailable
    client_worker.InvalidStoredTicket -> InvalidStoredTicket
    client_worker.QlogUnavailable -> Failure(failure.Socket(failure.WriteFile))
  }
}

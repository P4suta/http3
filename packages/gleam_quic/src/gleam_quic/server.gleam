//// Secure, bounded generic QUIC server.
////
//// A listener accepts opaque connections; each connection opens or accepts
//// opaque streams and exchanges raw application bytes selected by ALPN. No
//// process, socket, mailbox value, TLS state, private key, or secret crosses
//// this module.

import gleam/bit_array
import gleam/erlang/process
import gleam/list
import gleam/option.{type Option, None, Some}
import gleam/result
import gleam_quic.{type AddressFamily, type CongestionControl}
import gleam_quic/config.{type Deadlines, type Limits}
import gleam_quic/diagnostics
import gleam_quic/failure
import gleam_quic/internal/connection_state as transport
import gleam_quic/internal/qlog
import gleam_quic/internal/runtime/connection as runtime_connection
import gleam_quic/internal/runtime/connection_worker
import gleam_quic/internal/runtime/server_worker
import gleam_quic/internal/tls/authentication
import gleam_quic/internal/tls/engine
import gleam_quic/internal/tls/extension_value
import gleam_quic/internal/tls/hello
import gleam_quic/internal/tls/replay_guard as external_replay_guard
import gleam_quic/version as wire_version

/// Validated secure listener configuration.
pub opaque type Server {
  Server(
    certificate_chain: List(BitArray),
    signing_key: authentication.SigningKey,
    signature_scheme: extension_value.SignatureScheme,
    alternative_credentials: List(engine.ServerCredential),
    client_authentication: engine.ClientAuthentication,
    application_protocols: List(BitArray),
    port: Int,
    address_family: AddressFamily,
    deadlines: Deadlines,
    limits: Limits,
    congestion_control: CongestionControl,
    qlog_directory: String,
    allow_zero_rtt: Bool,
    replay_guard: Option(external_replay_guard.Guard),
    operational_keys: Option(OperationalKeys),
  )
}

/// Runtime-owned trust anchors accepted for TLS client authentication.
pub opaque type ClientCertificateAuthorities {
  ClientCertificateAuthorities(trust_store: authentication.TrustStore)
}

/// Whether a listener requests or requires an authenticated client identity.
pub type ClientAuthentication {
  Disabled
  Optional(ClientCertificateAuthorities)
  Required(ClientCertificateAuthorities)
}

/// A redacted, verified client identity safe to retain or log.
pub opaque type ClientIdentity {
  ClientIdentity(fingerprint: BitArray)
}

/// A validated 256-bit operational key with no secret accessor.
pub opaque type OperationalKey {
  OperationalKey(bytes: BitArray)
}

/// Current and optional previous key generations for atomic rotation.
pub opaque type KeyRing {
  KeyRing(current: OperationalKey, previous: Option(OperationalKey))
}

/// Three domain-separated rings for restart-safe server operation.
pub opaque type OperationalKeys {
  OperationalKeys(
    ticket: KeyRing,
    address_token: KeyRing,
    stateless_reset: KeyRing,
  )
}

/// A finite caller-managed atomic 0-RTT replay check.
pub opaque type ReplayGuard {
  ReplayGuard(handle: external_replay_guard.Guard)
}

/// Running owner-bound listener.
pub opaque type Listener {
  Listener(handle: server_worker.Listener)
}

/// One accepted generic QUIC connection.
pub opaque type Connection {
  Connection(handle: connection_worker.Connection)
}

/// One bidirectional or unidirectional stream.
pub opaque type Stream {
  Stream(handle: connection_worker.Stream)
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

/// Idempotent listener stop outcome.
pub type StopResult {
  Stopped
  AlreadyStopped
}

/// Idempotent connection close outcome.
pub type CloseResult {
  Closed
  AlreadyClosed
}

/// Invalid credentials, ALPN, endpoint, qlog, replay, or key policy.
pub type ConfigurationError {
  InvalidCertificate
  InvalidPrivateKey
  IncompatiblePrivateKey
  InvalidClientCaCertificate
  InvalidApplicationProtocol
  InvalidServerName
  DuplicateServerName
  InvalidPort(Int)
  InvalidQlogDirectory
  InvalidReplayGuardTimeout
  InvalidOperationalKey
  DuplicateOperationalKey
}

/// Typed transport failure or safe local misuse result.
pub type Error {
  Failure(failure.Failure)
  InvalidOperation
  InvalidDirection
  StreamFinished
  ConcurrentOperation
}

/// Decode one certificate/key pair and configure one ALPN protocol.
pub fn new(
  certificate_pem certificate_pem: BitArray,
  private_key_pem private_key_pem: BitArray,
  application_protocol application_protocol: String,
) -> Result(Server, ConfigurationError) {
  use protocols <- result.try(validate_protocols([application_protocol]))
  use certificate_chain <- result.try(
    authentication.certificate_chain_from_pem(certificate_pem)
    |> result.replace_error(InvalidCertificate),
  )
  use signing_key <- result.try(
    authentication.signing_key_from_pem(private_key_pem)
    |> result.replace_error(InvalidPrivateKey),
  )
  use signature_scheme <- result.try(
    authentication.signing_key_scheme(signing_key)
    |> result.replace_error(IncompatiblePrivateKey),
  )
  use matches <- result.try(
    authentication.signing_key_matches_certificate(
      certificate_chain,
      signing_key,
      signature_scheme,
    )
    |> result.replace_error(IncompatiblePrivateKey),
  )
  case matches {
    False -> Error(IncompatiblePrivateKey)
    True ->
      Ok(Server(
        certificate_chain,
        signing_key,
        signature_scheme,
        [],
        engine.ClientAuthenticationDisabled,
        protocols,
        0,
        gleam_quic.DualStack,
        config.default_deadlines(),
        config.default_limits(),
        gleam_quic.NewReno,
        "",
        False,
        None,
        None,
      ))
  }
}

/// Decode the PEM trust anchors used only for authenticating client chains.
pub fn client_certificate_authorities(
  certificate_pem: BitArray,
) -> Result(ClientCertificateAuthorities, ConfigurationError) {
  authentication.trust_store_from_pem(certificate_pem)
  |> result.map(ClientCertificateAuthorities)
  |> result.replace_error(InvalidClientCaCertificate)
}

/// Atomically select disabled, optional, or required client authentication.
pub fn with_client_authentication(
  server: Server,
  policy: ClientAuthentication,
) -> Server {
  let internal = case policy {
    Disabled -> engine.ClientAuthenticationDisabled
    Optional(ClientCertificateAuthorities(store)) ->
      engine.ClientAuthenticationOptional(store)
    Required(ClientCertificateAuthorities(store)) ->
      engine.ClientAuthenticationRequired(store)
  }
  Server(..server, client_authentication: internal)
}

/// Replace the ordered ALPN preference list.
pub fn with_application_protocols(
  server: Server,
  protocols: List(String),
) -> Result(Server, ConfigurationError) {
  validate_protocols(protocols)
  |> result.map(fn(values) { Server(..server, application_protocols: values) })
}

/// Bind a fixed port; zero asks the operating system for an ephemeral port.
pub fn with_port(
  server: Server,
  port: Int,
) -> Result(Server, ConfigurationError) {
  case port >= 0 && port <= 65_535 {
    True -> Ok(Server(..server, port: port))
    False -> Error(InvalidPort(port))
  }
}

/// Select an IPv4, IPv6, or dual-stack listener.
pub fn with_address_family(server: Server, family: AddressFamily) -> Server {
  Server(..server, address_family: family)
}

/// Attach an already validated finite deadline policy atomically.
pub fn with_deadlines(server: Server, deadlines: Deadlines) -> Server {
  Server(..server, deadlines: deadlines)
}

/// Attach an already validated finite resource policy atomically.
pub fn with_limits(server: Server, limits: Limits) -> Server {
  Server(..server, limits: limits)
}

/// Select one implemented congestion controller for new connections.
pub fn with_congestion_control(
  server: Server,
  algorithm: CongestionControl,
) -> Server {
  Server(..server, congestion_control: algorithm)
}

/// Add one SNI-selected certificate to the next atomic certificate set.
pub fn with_certificate(
  server: Server,
  server_name: String,
  certificate_pem: BitArray,
  private_key_pem: BitArray,
) -> Result(Server, ConfigurationError) {
  use Nil <- result.try(validate_server_name(server, server_name))
  use certificate_chain <- result.try(
    authentication.certificate_chain_from_pem(certificate_pem)
    |> result.replace_error(InvalidCertificate),
  )
  use signing_key <- result.try(
    authentication.signing_key_from_pem(private_key_pem)
    |> result.replace_error(InvalidPrivateKey),
  )
  use signature_scheme <- result.try(
    authentication.signing_key_scheme(signing_key)
    |> result.replace_error(IncompatiblePrivateKey),
  )
  use matches <- result.try(
    authentication.signing_key_matches_certificate(
      certificate_chain,
      signing_key,
      signature_scheme,
    )
    |> result.replace_error(IncompatiblePrivateKey),
  )
  case matches {
    False -> Error(IncompatiblePrivateKey)
    True ->
      Ok(
        Server(..server, alternative_credentials: [
          engine.ServerCredential(
            server_name,
            certificate_chain,
            signing_key,
            signature_scheme,
          ),
          ..server.alternative_credentials
        ]),
      )
  }
}

/// Enable one bounded asynchronous qlog writer per connection.
pub fn with_qlog(
  server: Server,
  directory: String,
) -> Result(Server, ConfigurationError) {
  case directory {
    "" -> Ok(Server(..server, qlog_directory: ""))
    value ->
      qlog.validate_directory(value)
      |> result.map(fn(_) { Server(..server, qlog_directory: value) })
      |> result.replace_error(InvalidQlogDirectory)
  }
}

/// Validate a finite external atomic test-and-record callback.
pub fn replay_guard(
  timeout_milliseconds: Int,
  check: fn(BitArray, Int) -> Result(Bool, Nil),
) -> Result(ReplayGuard, ConfigurationError) {
  external_replay_guard.new(timeout_milliseconds, check)
  |> result.map(ReplayGuard)
  |> result.replace_error(InvalidReplayGuardTimeout)
}

/// Enable 0-RTT with this listener actor's finite single-node replay cache.
pub fn with_single_node_zero_rtt(server: Server) -> Server {
  Server(..server, allow_zero_rtt: True, replay_guard: None)
}

/// Enable 0-RTT only after a finite external replay guard accepts it.
pub fn with_external_zero_rtt(server: Server, guard: ReplayGuard) -> Server {
  let ReplayGuard(handle) = guard
  Server(..server, allow_zero_rtt: True, replay_guard: Some(handle))
}

/// Validate one caller-managed AES/HMAC operational key.
pub fn operational_key(
  bytes: BitArray,
) -> Result(OperationalKey, ConfigurationError) {
  case bit_array.bit_size(bytes) % 8 == 0 && bit_array.byte_size(bytes) == 32 {
    True -> Ok(OperationalKey(bytes))
    False -> Error(InvalidOperationalKey)
  }
}

/// Start a key ring with one current generation.
pub fn key_ring(current: OperationalKey) -> KeyRing {
  KeyRing(current, None)
}

/// Rotate atomically while retaining exactly the former current generation.
pub fn rotate_key_ring(
  ring: KeyRing,
  current: OperationalKey,
) -> Result(KeyRing, ConfigurationError) {
  case current.bytes == ring.current.bytes {
    True -> Error(DuplicateOperationalKey)
    False -> Ok(KeyRing(current, Some(ring.current)))
  }
}

/// Assemble distinct ticket, address-token, and stateless-reset key rings.
pub fn operational_keys(
  ticket ticket: KeyRing,
  address_token address_token: KeyRing,
  stateless_reset stateless_reset: KeyRing,
) -> Result(OperationalKeys, ConfigurationError) {
  let values =
    list.append(
      key_ring_values(Some(ticket)),
      list.append(
        key_ring_values(Some(address_token)),
        key_ring_values(Some(stateless_reset)),
      ),
    )
  case all_keys_distinct(values) {
    True -> Ok(OperationalKeys(ticket, address_token, stateless_reset))
    False -> Error(DuplicateOperationalKey)
  }
}

/// Attach one validated operational-key bundle to this server.
pub fn with_operational_keys(server: Server, keys: OperationalKeys) -> Server {
  Server(..server, operational_keys: Some(keys))
}

/// Start an owner-bound listener.
pub fn start(server: Server) -> Result(Listener, Error) {
  let #(ticket_keys, address_token_keys, stateless_reset_keys) =
    operational_key_values(server.operational_keys)
  server_worker.start(
    process.self(),
    server.port,
    server.address_family,
    config.deadline(server.deadlines, failure.Operation),
    config.deadline(server.deadlines, failure.Idle),
    config.limit(server.limits, failure.Buffer),
    config.limit(server.limits, failure.Queue),
    config.limit(server.limits, failure.Telemetry),
    config.limit(server.limits, failure.Connections),
    config.limit(server.limits, failure.Handshakes),
    config.limit(server.limits, failure.AcceptWaiters),
    config.limit(server.limits, failure.BidirectionalStreams),
    config.limit(server.limits, failure.UnidirectionalStreams),
    config.limit(server.limits, failure.Datagram),
    config.limit(server.limits, failure.EndpointMemory),
    server.certificate_chain,
    server.signing_key,
    server.signature_scheme,
    server.alternative_credentials,
    server.client_authentication,
    server.application_protocols,
    to_transport_congestion(server.congestion_control),
    server.qlog_directory,
    server.allow_zero_rtt,
    server.replay_guard,
    ticket_keys,
    address_token_keys,
    stateless_reset_keys,
  )
  |> result.map(Listener)
  |> result.map_error(map_error)
}

/// Return the concrete bound port, including an OS-assigned ephemeral port.
pub fn port(listener: Listener) -> Result(Int, Error) {
  let Listener(handle) = listener
  server_worker.port(handle) |> result.map_error(map_error)
}

/// Wait for one authenticated connection.
pub fn accept(listener: Listener) -> Result(Connection, Error) {
  let Listener(handle) = listener
  server_worker.accept(handle)
  |> result.map(Connection)
  |> result.map_error(map_error)
}

pub fn open_bidirectional(connection: Connection) -> Result(Stream, Error) {
  let Connection(handle) = connection
  connection_worker.open_bidirectional(handle)
  |> result.map(Stream)
  |> result.map_error(map_error)
}

pub fn open_unidirectional(connection: Connection) -> Result(Stream, Error) {
  let Connection(handle) = connection
  connection_worker.open_unidirectional(handle)
  |> result.map(Stream)
  |> result.map_error(map_error)
}

pub fn accept_stream(connection: Connection) -> Result(IncomingStream, Error) {
  let Connection(handle) = connection
  connection_worker.accept_stream(handle)
  |> result.map(fn(incoming) {
    let connection_worker.IncomingStream(stream, bidirectional) = incoming
    IncomingStream(Stream(stream), case bidirectional {
      True -> Bidirectional
      False -> Unidirectional
    })
  })
  |> result.map_error(map_error)
}

pub fn send(stream: Stream, bytes: BitArray) -> Result(Nil, Error) {
  let Stream(handle) = stream
  connection_worker.send(handle, bytes) |> result.map_error(map_error)
}

pub fn finish(stream: Stream) -> Result(Nil, Error) {
  let Stream(handle) = stream
  connection_worker.finish(handle) |> result.map_error(map_error)
}

pub fn send_and_finish(stream: Stream, bytes: BitArray) -> Result(Nil, Error) {
  let Stream(handle) = stream
  connection_worker.send_and_finish(handle, bytes)
  |> result.map_error(map_error)
}

pub fn receive(stream: Stream, maximum_bytes: Int) -> Result(Read, Error) {
  let Stream(handle) = stream
  connection_worker.receive(handle, maximum_bytes)
  |> result.map(fn(read) {
    case read {
      connection_worker.Data(bytes, finished) -> Data(bytes, finished)
      connection_worker.Finished -> Finished
      connection_worker.Reset(code) -> Reset(code)
    }
  })
  |> result.map_error(map_error)
}

pub fn reset(
  stream: Stream,
  application_error_code: Int,
) -> Result(Nil, Error) {
  let Stream(handle) = stream
  connection_worker.reset(handle, application_error_code)
  |> result.map_error(map_error)
}

pub fn send_datagram(
  connection: Connection,
  payload: BitArray,
) -> Result(Nil, Error) {
  let Connection(handle) = connection
  connection_worker.send_datagram(handle, payload)
  |> result.map_error(map_error)
}

pub fn receive_datagram(connection: Connection) -> Result(BitArray, Error) {
  let Connection(handle) = connection
  connection_worker.receive_datagram(handle) |> result.map_error(map_error)
}

/// Return the largest QUIC Datagram payload this connection accepts right now.
///
/// The value is a point-in-time bound, not a fixed property of the connection:
/// it grows as path MTU discovery confirms a larger path, drops back to the
/// pre-validation floor when the path is reset, and shrinks while an
/// acknowledgement is scheduled, because a Datagram is indivisible and has to
/// leave room for the acknowledgement sharing its packet. Read it again after
/// a `DatagramTooLarge` result rather than caching it.
pub fn maximum_datagram_size(connection: Connection) -> Result(Int, Error) {
  let Connection(handle) = connection
  connection_worker.maximum_datagram_size(handle) |> result.map_error(map_error)
}

pub fn ping(connection: Connection) -> Result(Nil, Error) {
  let Connection(handle) = connection
  connection_worker.ping(handle) |> result.map_error(map_error)
}

pub fn set_congestion_control(
  connection: Connection,
  algorithm: CongestionControl,
) -> Result(Nil, Error) {
  let Connection(handle) = connection
  connection_worker.set_congestion_control(
    handle,
    to_transport_congestion(algorithm),
  )
  |> result.map_error(map_error)
}

pub fn path_stats(
  connection: Connection,
) -> Result(diagnostics.PathStats, Error) {
  let Connection(handle) = connection
  connection_worker.path_stats(handle)
  |> result.map(fn(stats) {
    let transport.PathSnapshot(a, b, c, d, e, f, g, h) = stats
    diagnostics.PathStats(a, b, c, d, e, f, g, h)
  })
  |> result.map_error(map_error)
}

pub fn connection_stats(
  connection: Connection,
) -> Result(diagnostics.ConnectionStats, Error) {
  let Connection(handle) = connection
  connection_worker.connection_stats(handle)
  |> result.map(fn(stats) {
    let #(runtime_connection.Stats(a, b, c, d, e, f, g, h), _dropped) = stats
    diagnostics.ConnectionStats(a, b, c, d, e, f, g, h)
  })
  |> result.map_error(map_error)
}

/// Count the inbound datagrams this connection lost before its owner could see
/// them, for want of room to hold them.
///
/// Two bounds drop datagrams here, and both are counted together because both
/// are the same loss from the peer's side. The listener hands each connection
/// only as many routed datagrams as that connection's delivery window admits,
/// so one flooded connection can neither grow its own actor's mailbox nor delay
/// any other connection. And a connection whose endpoint has refused it more
/// memory drops an RFC 9221 Datagram frame that would take it past the room it
/// was granted, which RFC 9221 permits precisely because a Datagram is
/// droppable. QUIC is loss tolerant, so a datagram dropped either way is
/// recovered exactly like one the network lost.
///
/// This counter is deliberately server-only: a client owns its own socket and
/// its own connection, with no listener in front of it to route, credit, or
/// drop for it, so there is no client counterpart to report.
pub fn dropped_datagrams(connection: Connection) -> Result(Int, Error) {
  let Connection(handle) = connection
  connection_worker.connection_stats(handle)
  |> result.map(fn(stats) {
    let #(_counters, dropped) = stats
    dropped
  })
  |> result.map_error(map_error)
}

/// Return the verified client identity, or `None` when mTLS was disabled or
/// optional and the client did not present a certificate.
pub fn client_identity(
  connection: Connection,
) -> Result(Option(ClientIdentity), Error) {
  let Connection(handle) = connection
  connection_worker.client_identity(handle)
  |> result.map(fn(identity) {
    case identity {
      None -> None
      Some(fingerprint) -> Some(ClientIdentity(fingerprint))
    }
  })
  |> result.map_error(map_error)
}

/// Return the SHA-256 leaf-certificate fingerprint of a verified identity.
pub fn client_identity_fingerprint(identity: ClientIdentity) -> BitArray {
  identity.fingerprint
}

pub fn telemetry_stats(
  connection: Connection,
) -> Result(diagnostics.TelemetryStats, Error) {
  let Connection(handle) = connection
  connection_worker.telemetry_stats(handle)
  |> result.map(fn(stats) {
    let qlog.Stats(dropped, errors, queued) = stats
    diagnostics.TelemetryStats(dropped, errors, queued)
  })
  |> result.map_error(map_error)
}

pub fn phase(connection: Connection) -> Result(diagnostics.Phase, Error) {
  let Connection(handle) = connection
  connection_worker.phase(handle)
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
  use
    #(
      version,
      protocol,
      congestion,
      cipher,
      resumed,
      early_attempted,
      early_accepted,
    )
  <- result.try(
    connection_worker.negotiated_protocol(handle) |> result.map_error(map_error),
  )
  use protocol <- result.try(
    bit_array.to_string(protocol) |> result.replace_error(InvalidOperation),
  )
  use cipher <- result.try(map_cipher(cipher))
  Ok(
    diagnostics.ConnectionInfo(
      case version {
        wire_version.Version2 -> gleam_quic.QuicV2
        _ -> gleam_quic.QuicV1
      },
      protocol,
      cipher,
      from_transport_congestion(congestion),
      case early_attempted, early_accepted {
        _, True -> diagnostics.Accepted
        True, False -> diagnostics.Rejected
        False, False -> diagnostics.NotAttempted
      },
      case resumed {
        True -> diagnostics.Resumed
        False -> diagnostics.FullHandshake
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

/// Atomically install the certificate set from a validated server value.
pub fn reload_certificates(
  listener: Listener,
  certificates: Server,
) -> Result(Nil, Error) {
  let Listener(handle) = listener
  server_worker.reload_certificates(
    handle,
    certificates.certificate_chain,
    certificates.signing_key,
    certificates.signature_scheme,
    certificates.alternative_credentials,
  )
  |> result.map_error(map_error)
}

/// Atomically install current/previous ticket, address-token, and reset keys.
pub fn reload_operational_keys(
  listener: Listener,
  keys: OperationalKeys,
) -> Result(Nil, Error) {
  let Listener(handle) = listener
  let OperationalKeys(ticket, address_token, stateless_reset) = keys
  server_worker.reload_keys(
    handle,
    key_ring_values(Some(ticket)),
    key_ring_values(Some(address_token)),
    key_ring_values(Some(stateless_reset)),
  )
  |> result.map_error(map_error)
}

pub fn close(connection: Connection) -> Result(CloseResult, Error) {
  let Connection(handle) = connection
  case connection_worker.close(handle) {
    Ok(connection_worker.Closed) -> Ok(Closed)
    Ok(connection_worker.AlreadyClosed) -> Ok(AlreadyClosed)
    Error(connection_worker.ConnectionClosed) -> Ok(AlreadyClosed)
    Error(error) -> Error(map_error(error))
  }
}

pub fn stop(listener: Listener) -> Result(StopResult, Error) {
  let Listener(handle) = listener
  case server_worker.stop(handle) {
    Ok(server_worker.Stopped) -> Ok(Stopped)
    Ok(server_worker.AlreadyStopped) -> Ok(AlreadyStopped)
    Error(connection_worker.ListenerClosed) -> Ok(AlreadyStopped)
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

fn validate_server_name(
  server: Server,
  server_name: String,
) -> Result(Nil, ConfigurationError) {
  let duplicate =
    list.any(server.alternative_credentials, fn(credential) {
      let engine.ServerCredential(name, _, _, _) = credential
      name == server_name
    })
  case engine.valid_server_name_pattern(server_name), duplicate {
    False, _ -> Error(InvalidServerName)
    _, True -> Error(DuplicateServerName)
    True, False -> Ok(Nil)
  }
}

fn key_ring_values(ring: Option(KeyRing)) -> List(BitArray) {
  case ring {
    None -> []
    Some(KeyRing(current, None)) -> [current.bytes]
    Some(KeyRing(current, Some(previous))) -> [current.bytes, previous.bytes]
  }
}

fn operational_key_values(
  keys: Option(OperationalKeys),
) -> #(List(BitArray), List(BitArray), List(BitArray)) {
  case keys {
    None -> #([], [], [])
    Some(OperationalKeys(ticket, address_token, stateless_reset)) -> #(
      key_ring_values(Some(ticket)),
      key_ring_values(Some(address_token)),
      key_ring_values(Some(stateless_reset)),
    )
  }
}

fn all_keys_distinct(keys: List(BitArray)) -> Bool {
  case keys {
    [] -> True
    [key, ..rest] -> !list.contains(rest, key) && all_keys_distinct(rest)
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

fn map_error(error: connection_worker.Error) -> Error {
  case error {
    connection_worker.InvalidInput -> InvalidOperation
    connection_worker.StartFailed -> Failure(failure.Socket(failure.BindSocket))
    connection_worker.OperationTimeout ->
      Failure(failure.Timeout(failure.Operation))
    connection_worker.ListenerClosed ->
      Failure(failure.Closed(failure.Local, None))
    connection_worker.ConnectionClosed ->
      Failure(failure.Closed(failure.Peer, None))
    connection_worker.StreamClosed -> StreamFinished
    connection_worker.InvalidDirection -> InvalidDirection
    connection_worker.ConcurrentSend
    | connection_worker.ConcurrentReceive
    | connection_worker.ConcurrentAccept
    | connection_worker.ConcurrentDatagramReceive -> ConcurrentOperation
    connection_worker.ConnectionLimitExceeded(maximum) ->
      Failure(failure.Limit(failure.Connections, maximum))
    connection_worker.HandshakeLimitExceeded(maximum) ->
      Failure(failure.Limit(failure.Handshakes, maximum))
    connection_worker.AcceptQueueExceeded(maximum) ->
      Failure(failure.Limit(failure.AcceptWaiters, maximum))
    connection_worker.IncomingStreamQueueExceeded(maximum) ->
      Failure(failure.Limit(failure.Queue, maximum))
    connection_worker.DatagramQueueExceeded(maximum)
    | connection_worker.DatagramTooLarge(maximum) ->
      Failure(failure.Limit(failure.Datagram, maximum))
    connection_worker.DatagramsNotNegotiated | connection_worker.QuicFailure ->
      Failure(failure.Quic(failure.Peer, None))
    connection_worker.CongestionLimited ->
      Failure(failure.Overload(failure.Queue))
    connection_worker.EndpointMemoryExceeded ->
      Failure(failure.Overload(failure.EndpointMemory))
    connection_worker.QlogUnavailable ->
      Failure(failure.Socket(failure.WriteFile))
  }
}

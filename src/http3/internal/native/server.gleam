//// Bounded and streaming HTTP/3 server powered by the native QUIC stack.

import gleam/bit_array
import gleam/list
import gleam/option.{type Option, None, Some}
import gleam/result
import gleam/string
import gleam_quic.{type AddressFamily, Ipv4, Ipv6}
import gleam_quic/internal/connection_state as transport
import gleam_quic/internal/tls/authentication
import gleam_quic/internal/tls/engine
import gleam_quic/internal/tls/extension_value
import gleam_quic/internal/tls/replay_guard as external_replay_guard
import http3/failure as runtime_failure
import http3/internal/native/server_connection
import http3/internal/native/server_worker

const maximum_timeout_milliseconds = 3_600_000

const minimum_keepalive_milliseconds = 1000

const maximum_keepalive_milliseconds = 29_000

/// Secure listener configuration with decoded runtime-owned credentials.
pub opaque type Server {
  Server(
    certificate_chain: List(BitArray),
    signing_key: authentication.SigningKey,
    signature_scheme: extension_value.SignatureScheme,
    alternative_credentials: List(engine.ServerCredential),
    port: Int,
    bind_address: Option(BitArray),
    timeout_milliseconds: Int,
    drain_timeout_milliseconds: Int,
    idle_timeout_milliseconds: Int,
    request_body_limit: Int,
    response_body_limit: Int,
    stream_buffer_limit: Int,
    connection_limit: Int,
    handshake_limit: Int,
    queue_limit: Int,
    telemetry_limit: Int,
    bidirectional_stream_limit: Int,
    unidirectional_stream_limit: Int,
    frame_limit: Int,
    datagram_limit: Int,
    qpack_table_limit: Int,
    qpack_blocked_stream_limit: Int,
    accept_waiter_limit: Int,
    http_datagrams: Bool,
    keepalive_milliseconds: Int,
    address_family: AddressFamily,
    qlog_directory: String,
    allow_zero_rtt: Bool,
    replay_guard: Option(external_replay_guard.Guard),
    ticket_keys: Option(KeyRing),
    address_token_keys: Option(KeyRing),
    stateless_reset_keys: Option(KeyRing),
  )
}

/// A validated 256-bit server operational key with no secret accessor.
pub opaque type OperationalKey {
  OperationalKey(bytes: BitArray)
}

/// The current and optional previous generation for atomic key rotation.
pub opaque type KeyRing {
  KeyRing(current: OperationalKey, previous: Option(OperationalKey))
}

/// A finite caller-managed atomic 0-RTT replay check.
pub opaque type ReplayGuard {
  ReplayGuard(handle: external_replay_guard.Guard)
}

/// A running owner-bound listener.
pub opaque type Listener {
  Listener(handle: server_worker.Listener)
}

/// One accepted request stream.
pub opaque type Request {
  Request(handle: server_worker.Request)
}

/// One promised server push response.
pub opaque type Push {
  Push(handle: server_worker.Push)
}

/// Primitive accepted request data for the parent HTTP adapter.
pub type Incoming {
  Incoming(
    request: Request,
    method: String,
    path: String,
    protocol: Option(String),
    scheme: String,
    authority: String,
    headers: List(#(String, String)),
  )
}

/// One pull-based request-body event.
pub type RequestEvent {
  Data(BitArray)
  Trailers(List(#(String, String)))
  End
}

/// Idempotent listener-stop result.
pub type StopResult {
  Stopped
  AlreadyStopped
}

/// Outcome of GOAWAY-based graceful listener shutdown.
pub type DrainResult {
  Drained
  Forced
  AlreadyDrained
}

/// State of a request's connection-level early-data attempt.
pub type EarlyDataStatus {
  NotAttempted
  Pending
  Accepted
  Rejected
}

/// A live request path snapshot in microseconds and bytes.
pub type PathStats {
  PathStats(Int, Int, Int, Int, Int, Int, Bool, Bool)
}

/// Runtime traffic counters for one accepted connection.
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

/// Invalid secure server configuration.
pub type ConfigurationError {
  InvalidCertificate
  InvalidPrivateKey
  IncompatiblePrivateKey
  InvalidServerName
  DuplicateServerName
  InvalidPort(Int)
  InvalidBindAddress
  InvalidTimeout
  InvalidRequestBodyLimit
  InvalidResponseBodyLimit
  InvalidStreamBufferLimit
  InvalidConnectionLimit
  InvalidHandshakeLimit
  InvalidQueueLimit
  InvalidTelemetryLimit
  InvalidBidirectionalStreamLimit
  InvalidUnidirectionalStreamLimit
  InvalidFrameLimit
  InvalidDatagramLimit
  InvalidQpackTableLimit
  InvalidQpackBlockedStreamLimit
  InvalidAcceptWaiterLimit
  InvalidKeepalive
  InvalidQlogDirectory
  InvalidReplayGuardTimeout
  InvalidOperationalKey
  DuplicateOperationalKey
}

/// Native listener, request, protocol, or resource failure.
pub type Error {
  InvalidInput
  StartFailed
  Timeout
  ListenerClosed
  ConnectionClosed
  StreamReset(Int)
  Failure(runtime_failure.Failure)
  RequestBodyTooLarge(Int)
  ResponseBodyTooLarge(Int)
  ConsumerTooSlow(Int)
  ConcurrentAccept
  ConcurrentDrain
  ConcurrentReceive
  ResponseAlreadyStarted
  ResponseNotStarted
  ResponseAlreadyFinished
  InvalidContentLength
  InvalidHeaderEncoding
  DatagramsNotNegotiated
  DatagramNotAssociated
  DatagramTooLarge(Int)
  DatagramBufferExceeded(Int)
  ConcurrentDatagramReceive
  StreamFinished
  PushCancelled
  CongestionLimited
}

/// Decode a certificate chain and private signing key.
pub fn new(
  certificate_pem: BitArray,
  private_key_pem: BitArray,
) -> Result(Server, ConfigurationError) {
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
  Ok(Server(
    certificate_chain,
    signing_key,
    signature_scheme,
    [],
    0,
    None,
    30_000,
    30_000,
    30_000,
    8_388_608,
    8_388_608,
    262_144,
    1024,
    128,
    1024,
    1024,
    100,
    100,
    65_536,
    65_527,
    4096,
    16,
    1,
    False,
    0,
    Ipv4,
    "",
    False,
    None,
    None,
    None,
    None,
  ))
}

/// Enable 0-RTT with this listener actor's bounded replay cache.
///
/// The safe default is disabled. This cache is intentionally single-process
/// and does not survive a node restart; distributed or restart-spanning
/// deployments must keep 0-RTT disabled until an external guard is attached.
pub fn with_single_node_zero_rtt(server: Server) -> Server {
  Server(..server, allow_zero_rtt: True, replay_guard: None)
}

/// Validate a finite external atomic test-and-record operation.
///
/// The callback receives a domain-separated replay fingerprint and its
/// remaining validity in milliseconds. It must atomically accept and store a
/// previously unseen fingerprint, returning `Ok(True)` only on that first
/// insertion. Error, process exit, and timeout safely reject early data while
/// allowing authenticated resumption to continue at 1-RTT.
pub fn replay_guard(
  timeout_milliseconds: Int,
  check: fn(BitArray, Int) -> Result(Bool, Nil),
) -> Result(ReplayGuard, ConfigurationError) {
  external_replay_guard.new(timeout_milliseconds, check)
  |> result.map(ReplayGuard)
  |> result.replace_error(InvalidReplayGuardTimeout)
}

/// Enable 0-RTT only after the caller-managed replay guard accepts it.
pub fn with_external_zero_rtt(server: Server, guard: ReplayGuard) -> Server {
  Server(..server, allow_zero_rtt: True, replay_guard: Some(guard.handle))
}

/// Validate a caller-managed AES/HMAC operational key.
///
/// The key is retained opaquely and can never be read back through this API.
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

/// Atomically rotate a ring, retaining exactly the former current key.
pub fn rotate_key_ring(
  ring: KeyRing,
  current: OperationalKey,
) -> Result(KeyRing, ConfigurationError) {
  case current.bytes == ring.current.bytes {
    True -> Error(DuplicateOperationalKey)
    False -> Ok(KeyRing(current, Some(ring.current)))
  }
}

/// Configure domain-separated ticket, address-token, and stateless-reset keys.
///
/// Supplying the same key bytes for two purposes is rejected. Omitting this
/// call keeps secure ephemeral defaults, which intentionally do not survive a
/// listener restart.
pub fn with_operational_key_rings(
  server: Server,
  ticket_keys: KeyRing,
  address_token_keys: KeyRing,
  stateless_reset_keys: KeyRing,
) -> Result(Server, ConfigurationError) {
  let keys =
    list.append(
      key_ring_values(ticket_keys),
      list.append(
        key_ring_values(address_token_keys),
        key_ring_values(stateless_reset_keys),
      ),
    )
  case all_keys_distinct(keys) {
    False -> Error(DuplicateOperationalKey)
    True ->
      Ok(
        Server(
          ..server,
          ticket_keys: Some(ticket_keys),
          address_token_keys: Some(address_token_keys),
          stateless_reset_keys: Some(stateless_reset_keys),
        ),
      )
  }
}

/// Return whether three opaque rings are domain-separated.
pub fn operational_key_rings_are_distinct(
  ticket_keys: KeyRing,
  address_token_keys: KeyRing,
  stateless_reset_keys: KeyRing,
) -> Bool {
  all_keys_distinct(list.append(
    key_ring_values(ticket_keys),
    list.append(
      key_ring_values(address_token_keys),
      key_ring_values(stateless_reset_keys),
    ),
  ))
}

/// Return whether a name is an exact DNS name or single-label wildcard.
pub fn is_valid_server_name(server_name: String) -> Bool {
  engine.valid_server_name_pattern(server_name)
}

/// Add an SNI-selected certificate, with exact names preferred to wildcards.
pub fn with_certificate(
  server: Server,
  server_name: String,
  certificate_pem: BitArray,
  private_key_pem: BitArray,
) -> Result(Server, ConfigurationError) {
  let server_name = string.lowercase(server_name)
  use Nil <- result.try(case engine.valid_server_name_pattern(server_name) {
    True -> Ok(Nil)
    False -> Error(InvalidServerName)
  })
  use Nil <- result.try(
    case
      list.any(server.alternative_credentials, fn(credential) {
        credential.server_name == server_name
      })
    {
      True -> Error(DuplicateServerName)
      False -> Ok(Nil)
    },
  )
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
  let credential =
    engine.ServerCredential(
      server_name,
      certificate_chain,
      signing_key,
      signature_scheme,
    )
  Ok(
    Server(..server, alternative_credentials: [
      credential,
      ..server.alternative_credentials
    ]),
  )
}

/// Configure periodic QUIC PING frames on accepted connections.
pub fn with_keepalive(
  server: Server,
  milliseconds: Int,
) -> Result(Server, ConfigurationError) {
  case
    milliseconds >= minimum_keepalive_milliseconds
    && milliseconds <= maximum_keepalive_milliseconds
  {
    True -> Ok(Server(..server, keepalive_milliseconds: milliseconds))
    False -> Error(InvalidKeepalive)
  }
}

/// Return whether bytes decode as a non-empty PEM certificate chain.
pub fn is_valid_certificate(certificate_pem: BitArray) -> Bool {
  authentication.certificate_chain_from_pem(certificate_pem) |> result.is_ok
}

/// Return whether bytes decode as a supported unencrypted private key.
pub fn is_valid_private_key(private_key_pem: BitArray) -> Bool {
  case authentication.signing_key_from_pem(private_key_pem) {
    Error(_) -> False
    Ok(key) -> authentication.signing_key_scheme(key) |> result.is_ok
  }
}

/// Set the UDP port; zero requests an operating-system-assigned port.
pub fn with_port(
  server: Server,
  port: Int,
) -> Result(Server, ConfigurationError) {
  case port >= 0 && port <= 65_535 {
    True -> Ok(Server(..server, port: port))
    False -> Error(InvalidPort(port))
  }
}

/// Bind the listener to one exact network-order IPv4 or IPv6 address.
pub fn with_bind_address(
  server: Server,
  address: BitArray,
) -> Result(Server, ConfigurationError) {
  case bit_array.byte_size(address), bit_array.bit_size(address) % 8 {
    4, 0 | 16, 0 -> Ok(Server(..server, bind_address: Some(address)))
    _, _ -> Error(InvalidBindAddress)
  }
}

/// Set one fixed operation timeout from one millisecond to one hour.
pub fn with_timeout(
  server: Server,
  milliseconds: Int,
) -> Result(Server, ConfigurationError) {
  case milliseconds > 0 && milliseconds <= maximum_timeout_milliseconds {
    True -> Ok(Server(..server, timeout_milliseconds: milliseconds))
    False -> Error(InvalidTimeout)
  }
}

/// Set the finite GOAWAY and graceful-drain deadline.
pub fn with_drain_timeout(
  server: Server,
  milliseconds: Int,
) -> Result(Server, ConfigurationError) {
  case milliseconds > 0 && milliseconds <= maximum_timeout_milliseconds {
    True -> Ok(Server(..server, drain_timeout_milliseconds: milliseconds))
    False -> Error(InvalidTimeout)
  }
}

/// Set the advertised and locally enforced QUIC idle timeout.
pub fn with_idle_timeout(
  server: Server,
  milliseconds: Int,
) -> Result(Server, ConfigurationError) {
  case milliseconds > 0 && milliseconds <= maximum_timeout_milliseconds {
    True -> Ok(Server(..server, idle_timeout_milliseconds: milliseconds))
    False -> Error(InvalidTimeout)
  }
}

/// Set the maximum accepted request body size.
pub fn with_request_body_limit(
  server: Server,
  bytes: Int,
) -> Result(Server, ConfigurationError) {
  case bytes > 0 {
    True -> Ok(Server(..server, request_body_limit: bytes))
    False -> Error(InvalidRequestBodyLimit)
  }
}

/// Set the maximum emitted response body size.
pub fn with_response_body_limit(
  server: Server,
  bytes: Int,
) -> Result(Server, ConfigurationError) {
  case bytes > 0 {
    True -> Ok(Server(..server, response_body_limit: bytes))
    False -> Error(InvalidResponseBodyLimit)
  }
}

/// Set the maximum unconsumed body or Datagram bytes per request.
pub fn with_stream_buffer_limit(
  server: Server,
  bytes: Int,
) -> Result(Server, ConfigurationError) {
  case bytes > 0 {
    True -> Ok(Server(..server, stream_buffer_limit: bytes))
    False -> Error(InvalidStreamBufferLimit)
  }
}

/// Set the maximum live connections admitted by this listener.
pub fn with_connection_limit(
  server: Server,
  maximum: Int,
) -> Result(Server, ConfigurationError) {
  case maximum > 0 {
    True -> Ok(Server(..server, connection_limit: maximum))
    False -> Error(InvalidConnectionLimit)
  }
}

/// Set the maximum concurrently handshaking connections.
pub fn with_handshake_limit(
  server: Server,
  maximum: Int,
) -> Result(Server, ConfigurationError) {
  case maximum > 0 {
    True -> Ok(Server(..server, handshake_limit: maximum))
    False -> Error(InvalidHandshakeLimit)
  }
}

/// Set the finite pending request/event/Datagram queue length.
pub fn with_queue_limit(
  server: Server,
  maximum: Int,
) -> Result(Server, ConfigurationError) {
  case maximum > 0 {
    True -> Ok(Server(..server, queue_limit: maximum))
    False -> Error(InvalidQueueLimit)
  }
}

/// Set the maximum asynchronous qlog events waiting behind one active write.
pub fn with_telemetry_limit(
  server server: Server,
  maximum maximum: Int,
) -> Result(Server, ConfigurationError) {
  case maximum > 0 {
    True -> Ok(Server(..server, telemetry_limit: maximum))
    False -> Error(InvalidTelemetryLimit)
  }
}

/// Set the maximum client-initiated bidirectional streams per connection.
pub fn with_bidirectional_stream_limit(
  server server: Server,
  maximum maximum: Int,
) -> Result(Server, ConfigurationError) {
  case maximum > 0 {
    True -> Ok(Server(..server, bidirectional_stream_limit: maximum))
    False -> Error(InvalidBidirectionalStreamLimit)
  }
}

/// Set the maximum client-initiated unidirectional streams per connection.
pub fn with_unidirectional_stream_limit(
  server server: Server,
  maximum maximum: Int,
) -> Result(Server, ConfigurationError) {
  case maximum > 0 {
    True -> Ok(Server(..server, unidirectional_stream_limit: maximum))
    False -> Error(InvalidUnidirectionalStreamLimit)
  }
}

/// Set the maximum HTTP/3 frame payload accepted from a peer.
pub fn with_frame_limit(
  server server: Server,
  bytes bytes: Int,
) -> Result(Server, ConfigurationError) {
  case bytes > 0 {
    True -> Ok(Server(..server, frame_limit: bytes))
    False -> Error(InvalidFrameLimit)
  }
}

/// Set the maximum QUIC Datagram payload advertised and retained.
pub fn with_datagram_limit(
  server server: Server,
  bytes bytes: Int,
) -> Result(Server, ConfigurationError) {
  case bytes > 0 {
    True -> Ok(Server(..server, datagram_limit: bytes))
    False -> Error(InvalidDatagramLimit)
  }
}

/// Set the maximum QPACK dynamic-table capacity advertised to a peer.
pub fn with_qpack_table_limit(
  server server: Server,
  bytes bytes: Int,
) -> Result(Server, ConfigurationError) {
  case bytes > 0 {
    True -> Ok(Server(..server, qpack_table_limit: bytes))
    False -> Error(InvalidQpackTableLimit)
  }
}

/// Set the maximum number of QPACK-blocked streams accepted from a peer.
pub fn with_qpack_blocked_stream_limit(
  server server: Server,
  maximum maximum: Int,
) -> Result(Server, ConfigurationError) {
  case maximum > 0 {
    True -> Ok(Server(..server, qpack_blocked_stream_limit: maximum))
    False -> Error(InvalidQpackBlockedStreamLimit)
  }
}

/// Set the maximum concurrent callers waiting in `accept`.
pub fn with_accept_waiter_limit(
  server server: Server,
  maximum maximum: Int,
) -> Result(Server, ConfigurationError) {
  case maximum > 0 {
    True -> Ok(Server(..server, accept_waiter_limit: maximum))
    False -> Error(InvalidAcceptWaiterLimit)
  }
}

/// Negotiate RFC 9221 and RFC 9297 Datagram support.
pub fn with_http_datagrams(server: Server) -> Server {
  Server(..server, http_datagrams: True)
}

/// Bind the listener to the IPv6 wildcard address instead of IPv4.
pub fn with_ipv6(server: Server) -> Server {
  with_address_family(server, Ipv6)
}

/// Select an IPv4, IPv6, or dual-stack listener socket.
pub fn with_address_family(
  server: Server,
  address_family: AddressFamily,
) -> Server {
  Server(..server, address_family: address_family)
}

/// Write a streaming qlog trace in an explicitly selected directory.
pub fn with_qlog(
  server: Server,
  directory: String,
) -> Result(Server, ConfigurationError) {
  case directory == "" {
    True -> Error(InvalidQlogDirectory)
    False -> Ok(Server(..server, qlog_directory: directory))
  }
}

/// Start the listener actor and bind UDP.
pub fn start(server: Server) -> Result(Listener, Error) {
  server_worker.start(
    server.port,
    server.bind_address,
    server.timeout_milliseconds,
    server.drain_timeout_milliseconds,
    server.idle_timeout_milliseconds,
    server.request_body_limit,
    server.response_body_limit,
    server.stream_buffer_limit,
    server.connection_limit,
    server.handshake_limit,
    server.queue_limit,
    server.telemetry_limit,
    server.bidirectional_stream_limit,
    server.unidirectional_stream_limit,
    server.frame_limit,
    server.datagram_limit,
    server.qpack_table_limit,
    server.qpack_blocked_stream_limit,
    server.accept_waiter_limit,
    server.certificate_chain,
    server.signing_key,
    server.signature_scheme,
    server.alternative_credentials,
    server.http_datagrams,
    server.keepalive_milliseconds,
    server.address_family,
    server.qlog_directory,
    server.allow_zero_rtt,
    server.replay_guard,
    optional_key_ring_values(server.ticket_keys),
    optional_key_ring_values(server.address_token_keys),
    optional_key_ring_values(server.stateless_reset_keys),
  )
  |> result.map(Listener)
  |> result.map_error(map_error)
}

fn optional_key_ring_values(ring: Option(KeyRing)) -> List(BitArray) {
  case ring {
    None -> []
    Some(ring) -> key_ring_values(ring)
  }
}

fn key_ring_values(ring: KeyRing) -> List(BitArray) {
  case ring.previous {
    None -> [ring.current.bytes]
    Some(previous) -> [ring.current.bytes, previous.bytes]
  }
}

fn all_keys_distinct(keys: List(BitArray)) -> Bool {
  case keys {
    [] -> True
    [key, ..rest] -> !list.contains(rest, key) && all_keys_distinct(rest)
  }
}

/// Return the concrete bound UDP port.
pub fn port(listener: Listener) -> Result(Int, Error) {
  let Listener(handle) = listener
  server_worker.port(handle) |> result.map_error(map_error)
}

/// Atomically replace the complete certificate set for new handshakes.
///
/// The certificate fields of `replacement` are already decoded and validated;
/// its port, deadlines, limits, and transport settings are intentionally
/// ignored. Existing authenticated connections retain their original state.
pub fn reload_certificates(
  listener: Listener,
  replacement: Server,
) -> Result(Nil, Error) {
  let Listener(handle) = listener
  server_worker.reload_certificates(
    handle,
    replacement.certificate_chain,
    replacement.signing_key,
    replacement.signature_scheme,
    replacement.alternative_credentials,
  )
  |> result.map_error(map_error)
}

/// Atomically replace all operational key rings without stopping the listener.
///
/// New tickets and tokens use each current generation. Exactly one previous
/// generation remains accepted during the caller-controlled transition.
pub fn reload_operational_key_rings(
  listener: Listener,
  ticket_keys: KeyRing,
  address_token_keys: KeyRing,
  stateless_reset_keys: KeyRing,
) -> Result(Nil, Error) {
  case
    operational_key_rings_are_distinct(
      ticket_keys,
      address_token_keys,
      stateless_reset_keys,
    )
  {
    False -> Error(InvalidInput)
    True -> {
      let Listener(handle) = listener
      server_worker.reload_operational_keys(
        handle,
        key_ring_values(ticket_keys),
        key_ring_values(address_token_keys),
        key_ring_values(stateless_reset_keys),
      )
      |> result.map_error(map_error)
    }
  }
}

/// Pull the next validated request head.
pub fn accept(listener: Listener) -> Result(Incoming, Error) {
  let Listener(handle) = listener
  case server_worker.accept(handle) {
    Ok(server_worker.Incoming(
      request,
      method,
      path,
      protocol,
      scheme,
      authority,
      headers,
    )) ->
      Ok(Incoming(
        Request(request),
        method,
        path,
        protocol,
        scheme,
        authority,
        headers,
      ))
    Error(error) -> Error(map_error(error))
  }
}

/// Return the request connection's currently validated peer endpoint.
pub fn peer_endpoint(request: Request) -> Result(#(BitArray, Int), Error) {
  let Request(handle) = request
  server_worker.peer_endpoint(handle) |> result.map_error(map_error)
}

/// Pull one request-body event.
pub fn next_event(request: Request) -> Result(RequestEvent, Error) {
  let Request(handle) = request
  case server_worker.next_event(handle) {
    Ok(server_worker.Data(bytes)) -> Ok(Data(bytes))
    Ok(server_worker.Trailers(headers)) -> Ok(Trailers(headers))
    Ok(server_worker.End) -> Ok(End)
    Error(error) -> Error(map_error(error))
  }
}

/// Send one complete bounded response.
pub fn respond(
  request: Request,
  status: Int,
  headers: List(#(String, String)),
  body: BitArray,
) -> Result(Nil, Error) {
  use Nil <- result.try(send_response(
    request,
    status,
    headers,
    Some(bit_array.byte_size(body)),
  ))
  use Nil <- result.try(send_chunk(request, body))
  finish_response(request)
}

/// Send one final streaming response head.
pub fn send_response(
  request: Request,
  status: Int,
  headers: List(#(String, String)),
  declared_content_length: Option(Int),
) -> Result(Nil, Error) {
  let Request(handle) = request
  server_worker.send_response(handle, status, headers, declared_content_length)
  |> result.map_error(map_error)
}

/// Send one informational response before the final response head.
pub fn send_informational(
  request: Request,
  status: Int,
  headers: List(#(String, String)),
) -> Result(Nil, Error) {
  let Request(handle) = request
  server_worker.send_informational(handle, status, headers)
  |> result.map_error(map_error)
}

/// Send one response-body chunk with producer backpressure.
pub fn send_chunk(request: Request, bytes: BitArray) -> Result(Nil, Error) {
  let Request(handle) = request
  server_worker.send_chunk(handle, bytes) |> result.map_error(map_error)
}

/// Finish the response body.
pub fn finish_response(request: Request) -> Result(Nil, Error) {
  let Request(handle) = request
  server_worker.finish_response(handle) |> result.map_error(map_error)
}

/// Send response trailers and finish the response atomically.
pub fn send_trailers(
  request: Request,
  headers: List(#(String, String)),
) -> Result(Nil, Error) {
  let Request(handle) = request
  server_worker.send_trailers(handle, headers) |> result.map_error(map_error)
}

/// Promise one same-origin GET on an accepted request.
pub fn promise_push(
  request: Request,
  path: String,
  headers: List(#(String, String)),
) -> Result(Push, Error) {
  let Request(handle) = request
  server_worker.promise_push(handle, path, headers)
  |> result.map(Push)
  |> result.map_error(map_error)
}

/// Send one final pushed response head.
pub fn send_push_response(
  push: Push,
  status: Int,
  headers: List(#(String, String)),
  declared_content_length: Option(Int),
) -> Result(Nil, Error) {
  let Push(handle) = push
  server_worker.send_push_response(
    handle,
    status,
    headers,
    declared_content_length,
  )
  |> result.map_error(map_error)
}

/// Send one pushed response-body chunk with backpressure.
pub fn send_push_chunk(push: Push, bytes: BitArray) -> Result(Nil, Error) {
  let Push(handle) = push
  server_worker.send_push_chunk(handle, bytes) |> result.map_error(map_error)
}

/// Finish one pushed response.
pub fn finish_push(push: Push) -> Result(Nil, Error) {
  let Push(handle) = push
  server_worker.finish_push(handle) |> result.map_error(map_error)
}

/// Send pushed response trailers and finish atomically.
pub fn send_push_trailers(
  push: Push,
  headers: List(#(String, String)),
) -> Result(Nil, Error) {
  let Push(handle) = push
  server_worker.send_push_trailers(handle, headers)
  |> result.map_error(map_error)
}

/// Stop the listener and every owned connection idempotently.
pub fn stop(listener: Listener) -> Result(StopResult, Error) {
  let Listener(handle) = listener
  case server_worker.stop(handle) {
    Ok(server_worker.Stopped) -> Ok(Stopped)
    Ok(server_worker.AlreadyStopped) -> Ok(AlreadyStopped)
    Error(error) -> Error(map_error(error))
  }
}

/// Send two-stage GOAWAY, drain active requests, and release the listener.
pub fn graceful_stop(listener: Listener) -> Result(DrainResult, Error) {
  let Listener(handle) = listener
  case server_worker.graceful_stop(handle) {
    Ok(server_worker.Drained) -> Ok(Drained)
    Ok(server_worker.Forced) -> Ok(Forced)
    Ok(server_worker.AlreadyDrained) -> Ok(AlreadyDrained)
    Error(error) -> Error(map_error(error))
  }
}

/// Return advanced capability flags for one request stream.
pub fn capabilities(
  request: Request,
) -> Result(#(Bool, Bool, Bool, Bool), Error) {
  let Request(handle) = request
  server_worker.capabilities(handle) |> result.map_error(map_error)
}

/// Snapshot one accepted request's QUIC path metrics.
pub fn path_stats(request: Request) -> Result(PathStats, Error) {
  let Request(handle) = request
  server_worker.path_stats(handle)
  |> result.map(fn(snapshot) {
    let transport.PathSnapshot(a, b, c, d, e, f, g, h) = snapshot
    PathStats(a, b, c, d, e, f, g, h)
  })
  |> result.map_error(map_error)
}

/// Snapshot one accepted request's connection counters.
pub fn connection_stats(request: Request) -> Result(ConnectionStats, Error) {
  let Request(handle) = request
  server_worker.connection_stats(handle)
  |> result.map(fn(stats) {
    let server_connection.Stats(a, b, c, d, e, f, g, h) = stats
    ConnectionStats(a, b, c, d, e, f, g, h)
  })
  |> result.map_error(map_error)
}

/// Snapshot diagnostic writer health for an accepted request's connection.
pub fn telemetry_stats(request: Request) -> Result(TelemetryStats, Error) {
  let Request(handle) = request
  server_worker.telemetry_stats(handle)
  |> result.map(fn(stats) {
    let #(dropped, errors, queued) = stats
    TelemetryStats(dropped, errors, queued)
  })
  |> result.map_error(map_error)
}

/// Return the current non-fragmenting QUIC UDP payload size.
pub fn maximum_transmission_unit(request: Request) -> Result(Int, Error) {
  let Request(handle) = request
  server_worker.maximum_transmission_unit(handle) |> result.map_error(map_error)
}

/// Return the largest HTTP Datagram payload for one request.
pub fn maximum_datagram_size(request: Request) -> Result(Int, Error) {
  let Request(handle) = request
  server_worker.maximum_datagram_size(handle) |> result.map_error(map_error)
}

/// Send one unreliable HTTP Datagram.
pub fn send_datagram(
  request: Request,
  payload: BitArray,
) -> Result(Nil, Error) {
  let Request(handle) = request
  server_worker.send_datagram(handle, payload) |> result.map_error(map_error)
}

/// Pull one unreliable HTTP Datagram.
pub fn next_datagram(request: Request) -> Result(BitArray, Error) {
  let Request(handle) = request
  server_worker.next_datagram(handle) |> result.map_error(map_error)
}

/// Set a locally effective response priority.
pub fn set_priority(
  request: Request,
  urgency: Int,
  incremental: Bool,
) -> Result(Nil, Error) {
  let Request(handle) = request
  server_worker.set_priority(handle, urgency, incremental)
  |> result.map_error(map_error)
}

/// Return one request's effective priority.
pub fn get_priority(request: Request) -> Result(#(Int, Bool), Error) {
  let Request(handle) = request
  server_worker.get_priority(handle) |> result.map_error(map_error)
}

/// Return the request connection's early-data outcome.
pub fn early_data_status(request: Request) -> Result(EarlyDataStatus, Error) {
  let Request(handle) = request
  case server_worker.early_data_status(handle) {
    Ok(server_connection.NotAttempted) -> Ok(NotAttempted)
    Ok(server_connection.Pending) -> Ok(Pending)
    Ok(server_connection.Accepted) -> Ok(Accepted)
    Ok(server_connection.Rejected) -> Ok(Rejected)
    Error(error) -> Error(map_error(error))
  }
}

fn map_error(error: server_worker.Error) -> Error {
  case error {
    server_worker.InvalidInput -> InvalidInput
    server_worker.StartFailed -> StartFailed
    server_worker.Timeout -> Timeout
    server_worker.ListenerClosed -> ListenerClosed
    server_worker.ConnectionClosed -> ConnectionClosed
    server_worker.StreamReset(code) -> StreamReset(code)
    server_worker.ProtocolError(code, _) ->
      Failure(runtime_failure.Http3(runtime_failure.Peer, Some(code)))
    server_worker.RequestBodyTooLarge(limit) -> RequestBodyTooLarge(limit)
    server_worker.ResponseBodyTooLarge(limit) -> ResponseBodyTooLarge(limit)
    server_worker.ConsumerTooSlow(limit) -> ConsumerTooSlow(limit)
    server_worker.ConcurrentAccept -> ConcurrentAccept
    server_worker.ConcurrentDrain -> ConcurrentDrain
    server_worker.ConcurrentReceive -> ConcurrentReceive
    server_worker.ResponseAlreadyStarted -> ResponseAlreadyStarted
    server_worker.ResponseNotStarted -> ResponseNotStarted
    server_worker.ResponseAlreadyFinished -> ResponseAlreadyFinished
    server_worker.InvalidContentLength -> InvalidContentLength
    server_worker.InvalidHeaderEncoding -> InvalidHeaderEncoding
    server_worker.DatagramsNotNegotiated -> DatagramsNotNegotiated
    server_worker.DatagramNotAssociated -> DatagramNotAssociated
    server_worker.DatagramTooLarge(limit) -> DatagramTooLarge(limit)
    server_worker.DatagramBufferExceeded(limit) -> DatagramBufferExceeded(limit)
    server_worker.ConcurrentDatagramReceive -> ConcurrentDatagramReceive
    server_worker.StreamFinished -> StreamFinished
    server_worker.PushCancelled -> PushCancelled
    server_worker.CongestionLimited -> CongestionLimited
    server_worker.PathUnavailable ->
      Failure(runtime_failure.Quic(runtime_failure.Local, None))
    server_worker.QlogUnavailable ->
      Failure(runtime_failure.Socket(runtime_failure.WriteFile))
    server_worker.ConcurrentSend ->
      Failure(runtime_failure.Overload(runtime_failure.Queue))
    server_worker.PendingRequestLimitExceeded(limit) ->
      Failure(runtime_failure.Limit(runtime_failure.Queue, limit))
    server_worker.RequestEventQueueExceeded(limit)
    | server_worker.DatagramQueueExceeded(limit) ->
      Failure(runtime_failure.Limit(runtime_failure.Queue, limit))
    server_worker.InvalidConnectionState ->
      Failure(runtime_failure.Http3(runtime_failure.Local, None))
  }
}

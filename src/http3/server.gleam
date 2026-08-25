//// A bounded and streaming HTTP/3 server for the Erlang target.

import gleam/bit_array
import gleam/bool
import gleam/http
import gleam/list
import gleam/option.{type Option, None, Some}
import gleam/result
import gleam/string
import http3/capsule
import http3/config as policy
import http3/failure as runtime_failure
import http3/internal/server_backend
import http3/internal/server_response
import http3/transport

const minimum_keepalive_milliseconds = 1000

const maximum_keepalive_milliseconds = 29_000

@external(erlang, "http3_internal_transport_ffi", "server_stream")
fn make_transport_stream(
  handle: server_backend.RequestHandle,
) -> transport.Stream

/// Secure listener configuration.
pub opaque type Configuration {
  Configuration(
    certificate: BitArray,
    private_key: BitArray,
    alternative_certificates: List(#(String, BitArray, BitArray)),
    port: Int,
    deadlines: policy.Deadlines,
    limits: policy.Limits,
    http_datagrams: Bool,
    keepalive_milliseconds: Int,
    address_family: policy.AddressFamily,
    qlog_directory: String,
    allow_zero_rtt: Bool,
    replay_guard: Option(server_backend.ReplayGuard),
    operational_keys: Option(OperationalKeys),
  )
}

/// A validated 256-bit server key with no secret accessor.
pub opaque type OperationalKey {
  OperationalKey(handle: server_backend.OperationalKey)
}

/// A two-generation operational key ring.
pub opaque type KeyRing {
  KeyRing(handle: server_backend.KeyRing)
}

/// Domain-separated server ticket, token, and stateless-reset rings.
pub opaque type OperationalKeys {
  OperationalKeys(handle: server_backend.OperationalKeys)
}

/// One non-secret input to a caller-managed distributed replay check.
pub opaque type ReplayAttempt {
  ReplayAttempt(fingerprint: BitArray, valid_for_milliseconds: Int)
}

/// The result of an atomic external test-and-record operation.
pub type ReplayDecision {
  AcceptEarlyData
  RejectEarlyData
}

/// A finite external 0-RTT replay guard.
pub opaque type ReplayGuard {
  ReplayGuard(handle: server_backend.ReplayGuard)
}

/// A running HTTP/3 listener.
pub opaque type Listener {
  Listener(handle: server_backend.ListenerHandle)
}

/// One accepted HTTP/3 request.
pub opaque type Request {
  Request(
    handle: server_backend.RequestHandle,
    method: http.Method,
    path: String,
    protocol: Option(String),
    headers: List(#(String, String)),
  )
}

/// One promised server push response.
pub opaque type Push {
  Push(handle: server_backend.PushHandle)
}

/// One streaming request-body event.
pub type RequestEvent {
  Data(BitArray)
  Trailers(List(#(String, String)))
  End
}

/// The result of idempotently stopping a listener.
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

/// An invalid listener configuration.
pub type ConfigurationError {
  InvalidCertificate
  InvalidPrivateKey
  InvalidServerName
  DuplicateServerName
  InvalidPort(Int)
  InvalidTimeout
  InvalidRequestBodyLimit
  InvalidResponseBodyLimit
  InvalidStreamBufferLimit
  InvalidKeepalive
  InvalidReplayGuardTimeout
  InvalidOperationalKey
  DuplicateOperationalKey
}

/// A server, request, or response failure.
pub type Error {
  /// A typed runtime failure with no backend-formatted or secret text.
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
  InvalidStatus(Int)
  InvalidHeader(String)
  InvalidPath(String)
  InvalidContentLength
  InvalidBody
  CapsuleError(capsule.Error)

  /// The client cancelled a promised push.
  PushCancelled
}

/// Construct secure server configuration from PEM certificate and key bytes.
pub fn new(
  certificate certificate: BitArray,
  private_key private_key: BitArray,
) -> Result(Configuration, ConfigurationError) {
  use <- bool.guard(
    when: bit_array.bit_size(certificate) == 0
      || bit_array.bit_size(certificate) % 8 != 0
      || !server_backend.valid_certificate(certificate),
    return: Error(InvalidCertificate),
  )
  use <- bool.guard(
    when: bit_array.bit_size(private_key) == 0
      || bit_array.bit_size(private_key) % 8 != 0
      || !server_backend.valid_private_key(private_key),
    return: Error(InvalidPrivateKey),
  )
  Ok(Configuration(
    certificate: certificate,
    private_key: private_key,
    alternative_certificates: [],
    port: 0,
    deadlines: policy.default_deadlines(),
    limits: policy.default_limits(),
    http_datagrams: False,
    keepalive_milliseconds: 0,
    address_family: policy.Ipv4,
    qlog_directory: "",
    allow_zero_rtt: False,
    replay_guard: None,
    operational_keys: None,
  ))
}

/// Enable 0-RTT using this listener process's finite replay cache.
///
/// Disabled by default. This mode is suitable only while a single listener
/// actor remains alive; it safely rejects early data after a restart.
pub fn with_single_node_zero_rtt(
  configuration: Configuration,
) -> Configuration {
  Configuration(..configuration, allow_zero_rtt: True, replay_guard: None)
}

/// Construct a bounded external atomic test-and-record guard.
///
/// The callback must store an unseen fingerprint for at least the supplied
/// validity interval and return `AcceptEarlyData` only when that insertion was
/// atomic and successful. `Error`, callback exit, rejection, and timeout all
/// fall back to authenticated 1-RTT without failing the connection. The guard
/// deadline must be from one through 10,000 milliseconds.
pub fn replay_guard(
  timeout_milliseconds timeout_milliseconds: Int,
  check check: fn(ReplayAttempt) -> Result(ReplayDecision, Nil),
) -> Result(ReplayGuard, ConfigurationError) {
  server_backend.replay_guard(timeout_milliseconds, fn(fingerprint, valid_for) {
    check(ReplayAttempt(fingerprint, valid_for))
    |> result.map(fn(decision) {
      case decision {
        AcceptEarlyData -> True
        RejectEarlyData -> False
      }
    })
  })
  |> result.map(ReplayGuard)
  |> result.replace_error(InvalidReplayGuardTimeout)
}

/// Enable 0-RTT only when a caller-managed replay guard accepts the attempt.
pub fn with_external_zero_rtt(
  configuration configuration: Configuration,
  guard guard: ReplayGuard,
) -> Configuration {
  Configuration(
    ..configuration,
    allow_zero_rtt: True,
    replay_guard: Some(guard.handle),
  )
}

/// Return the domain-separated replay fingerprint used as the storage key.
pub fn replay_fingerprint(attempt: ReplayAttempt) -> BitArray {
  attempt.fingerprint
}

/// Return the minimum external retention interval for this fingerprint.
pub fn replay_valid_for_milliseconds(attempt: ReplayAttempt) -> Int {
  attempt.valid_for_milliseconds
}

/// Validate a caller-managed 256-bit operational key.
pub fn operational_key(
  bytes: BitArray,
) -> Result(OperationalKey, ConfigurationError) {
  server_backend.operational_key(bytes)
  |> result.map(OperationalKey)
  |> result.replace_error(InvalidOperationalKey)
}

/// Start a ring with one current generation.
pub fn key_ring(key: OperationalKey) -> KeyRing {
  KeyRing(server_backend.key_ring(key.handle))
}

/// Rotate a ring atomically and retain only its former current generation.
pub fn rotate_key_ring(
  ring ring: KeyRing,
  key key: OperationalKey,
) -> Result(KeyRing, ConfigurationError) {
  server_backend.rotate_key_ring(ring.handle, key.handle)
  |> result.map(KeyRing)
  |> result.replace_error(DuplicateOperationalKey)
}

/// Assemble three domain-separated rings for restart-safe operation.
pub fn operational_keys(
  ticket ticket: KeyRing,
  address_token address_token: KeyRing,
  stateless_reset stateless_reset: KeyRing,
) -> Result(OperationalKeys, ConfigurationError) {
  server_backend.operational_keys(
    ticket.handle,
    address_token.handle,
    stateless_reset.handle,
  )
  |> result.map(OperationalKeys)
  |> result.replace_error(DuplicateOperationalKey)
}

/// Attach restart-safe operational keys to a listener configuration.
pub fn with_operational_keys(
  configuration configuration: Configuration,
  keys keys: OperationalKeys,
) -> Configuration {
  Configuration(..configuration, operational_keys: Some(keys))
}

// nolint: unused_exports -- stable public configuration API for downstream users.
/// Apply one validated set of finite phase deadlines atomically.
pub fn with_deadlines(
  configuration configuration: Configuration,
  deadlines deadlines: policy.Deadlines,
) -> Configuration {
  Configuration(..configuration, deadlines: deadlines)
}

/// Apply one validated set of finite resource limits atomically.
pub fn with_limits(
  configuration configuration: Configuration,
  limits limits: policy.Limits,
) -> Configuration {
  Configuration(..configuration, limits: limits)
}

/// Add a certificate selected by an exact SNI name or `*.` wildcard.
///
/// Exact names take precedence over wildcard names. The certificate and key
/// are parsed eagerly; the original certificate remains the fallback for an
/// unknown name or a client that omits SNI.
pub fn with_certificate(
  configuration configuration: Configuration,
  server_name server_name: String,
  certificate certificate: BitArray,
  private_key private_key: BitArray,
) -> Result(Configuration, ConfigurationError) {
  let server_name = string.lowercase(server_name)
  use <- bool.guard(
    when: !server_backend.valid_server_name(server_name),
    return: Error(InvalidServerName),
  )
  use <- bool.guard(
    when: list.any(configuration.alternative_certificates, fn(entry) {
      let #(configured, _, _) = entry
      configured == server_name
    }),
    return: Error(DuplicateServerName),
  )
  use <- bool.guard(
    when: bit_array.bit_size(certificate) == 0
      || bit_array.bit_size(certificate) % 8 != 0
      || !server_backend.valid_certificate(certificate),
    return: Error(InvalidCertificate),
  )
  use <- bool.guard(
    when: bit_array.bit_size(private_key) == 0
      || bit_array.bit_size(private_key) % 8 != 0
      || !server_backend.valid_private_key(private_key),
    return: Error(InvalidPrivateKey),
  )
  Ok(
    Configuration(..configuration, alternative_certificates: [
      #(server_name, certificate, private_key),
      ..configuration.alternative_certificates
    ]),
  )
}

/// Send periodic QUIC PING frames on accepted connections.
///
/// Keepalive is disabled by default. The interval must be from one through
/// twenty-nine seconds so it remains below the advertised idle timeout.
pub fn with_keepalive(
  configuration configuration: Configuration,
  milliseconds milliseconds: Int,
) -> Result(Configuration, ConfigurationError) {
  use <- bool.guard(
    when: milliseconds < minimum_keepalive_milliseconds
      || milliseconds > maximum_keepalive_milliseconds,
    return: Error(InvalidKeepalive),
  )
  Ok(Configuration(..configuration, keepalive_milliseconds: milliseconds))
}

/// Enable RFC 9297 HTTP Datagrams for accepted connections.
pub fn with_http_datagrams(configuration: Configuration) -> Configuration {
  Configuration(..configuration, http_datagrams: True)
}

/// Select the IP family used by the UDP listener.
pub fn with_address_family(
  configuration configuration: Configuration,
  address_family address_family: policy.AddressFamily,
) -> Configuration {
  Configuration(..configuration, address_family: address_family)
}

// nolint: unused_exports -- stable public convenience API for downstream users.
/// Bind the listener to the IPv6 wildcard address.
pub fn with_ipv6(configuration: Configuration) -> Configuration {
  with_address_family(configuration: configuration, address_family: policy.Ipv6)
}

/// Enable qlog tracing for accepted connections.
///
/// Trace files can contain sensitive connection metadata. qlog remains off
/// unless this function is called explicitly.
pub fn with_qlog(
  configuration configuration: Configuration,
  qlog qlog: transport.Qlog,
) -> Configuration {
  Configuration(..configuration, qlog_directory: transport.qlog_directory(qlog))
}

/// Set the UDP port, using zero for an operating-system-assigned port.
pub fn with_port(
  configuration configuration: Configuration,
  port port: Int,
) -> Result(Configuration, ConfigurationError) {
  use <- bool.guard(
    when: port < 0 || port > 65_535,
    return: Error(InvalidPort(port)),
  )
  Ok(Configuration(..configuration, port: port))
}

/// Set the total timeout for accept, request, and response operations.
pub fn with_timeout(
  configuration configuration: Configuration,
  milliseconds milliseconds: Int,
) -> Result(Configuration, ConfigurationError) {
  case policy.uniform_deadlines(milliseconds) {
    Ok(deadlines) -> Ok(Configuration(..configuration, deadlines: deadlines))
    Error(_) -> Error(InvalidTimeout)
  }
}

/// Set the maximum request body size in bytes.
pub fn with_request_body_limit(
  configuration configuration: Configuration,
  bytes bytes: Int,
) -> Result(Configuration, ConfigurationError) {
  case
    policy.with_limit(configuration.limits, runtime_failure.RequestBody, bytes)
  {
    Ok(limits) -> Ok(Configuration(..configuration, limits: limits))
    Error(_) -> Error(InvalidRequestBodyLimit)
  }
}

/// Set the maximum response body size in bytes.
pub fn with_response_body_limit(
  configuration configuration: Configuration,
  bytes bytes: Int,
) -> Result(Configuration, ConfigurationError) {
  case
    policy.with_limit(configuration.limits, runtime_failure.ResponseBody, bytes)
  {
    Ok(limits) -> Ok(Configuration(..configuration, limits: limits))
    Error(_) -> Error(InvalidResponseBodyLimit)
  }
}

/// Set the maximum unconsumed request data retained per stream.
pub fn with_stream_buffer_limit(
  configuration configuration: Configuration,
  bytes bytes: Int,
) -> Result(Configuration, ConfigurationError) {
  case policy.with_limit(configuration.limits, runtime_failure.Buffer, bytes) {
    Ok(limits) -> Ok(Configuration(..configuration, limits: limits))
    Error(_) -> Error(InvalidStreamBufferLimit)
  }
}

/// Start an HTTP/3 listener owned by the calling process.
pub fn start(configuration: Configuration) -> Result(Listener, Error) {
  let Configuration(
    certificate,
    private_key,
    alternative_certificates,
    port,
    deadlines,
    limits,
    http_datagrams,
    keepalive_milliseconds,
    address_family,
    qlog_directory,
    allow_zero_rtt,
    replay_guard,
    operational_keys,
  ) = configuration
  case
    server_backend.start(
      certificate,
      private_key,
      alternative_certificates,
      port,
      policy.deadline(deadlines, runtime_failure.Operation),
      policy.deadline(deadlines, runtime_failure.Drain),
      policy.deadline(deadlines, runtime_failure.Idle),
      policy.limit(limits, runtime_failure.RequestBody),
      policy.limit(limits, runtime_failure.ResponseBody),
      policy.limit(limits, runtime_failure.Buffer),
      policy.limit(limits, runtime_failure.Connections),
      policy.limit(limits, runtime_failure.Handshakes),
      policy.limit(limits, runtime_failure.Queue),
      policy.limit(limits, runtime_failure.Telemetry),
      policy.limit(limits, runtime_failure.BidirectionalStreams),
      policy.limit(limits, runtime_failure.UnidirectionalStreams),
      policy.limit(limits, runtime_failure.Frame),
      policy.limit(limits, runtime_failure.Datagram),
      policy.limit(limits, runtime_failure.QpackTable),
      policy.limit(limits, runtime_failure.QpackBlockedStreams),
      policy.limit(limits, runtime_failure.AcceptWaiters),
      http_datagrams,
      keepalive_milliseconds,
      address_family,
      qlog_directory,
      allow_zero_rtt,
      replay_guard,
      case operational_keys {
        None -> None
        Some(keys) -> Some(keys.handle)
      },
    )
  {
    Ok(handle) -> Ok(Listener(handle))
    Error(error) -> Error(from_backend_failure(error))
  }
}

/// Obtain typed advanced controls for an accepted request stream.
pub fn request_transport(request: Request) -> transport.Stream {
  make_transport_stream(request.handle)
}

/// Return the listener's bound UDP port.
pub fn port(listener: Listener) -> Result(Int, Error) {
  let Listener(handle) = listener
  map_backend(server_backend.port(handle))
}

/// Atomically replace the complete certificate set for future handshakes.
///
/// Build `replacement` with `new` and `with_certificate`. All non-certificate
/// settings on it are ignored. Existing connections remain authenticated and
/// open; a validation failure occurs before this function can be called.
pub fn reload_certificates(
  listener listener: Listener,
  replacement replacement: Configuration,
) -> Result(Nil, Error) {
  let Listener(handle) = listener
  server_backend.reload_certificates(
    handle,
    replacement.certificate,
    replacement.private_key,
    replacement.alternative_certificates,
  )
  |> map_backend
}

/// Atomically rotate ticket, address-token, and stateless-reset key rings.
///
/// New values use each current key while values authenticated by the single
/// previous generation remain valid for a bounded deployment transition.
pub fn reload_operational_keys(
  listener listener: Listener,
  keys keys: OperationalKeys,
) -> Result(Nil, Error) {
  let Listener(handle) = listener
  server_backend.reload_operational_keys(handle, keys.handle) |> map_backend
}

/// Pull the next accepted request head.
pub fn accept(listener: Listener) -> Result(Request, Error) {
  let Listener(handle) = listener
  case server_backend.accept(handle) {
    Ok(#(request_handle, method, path, protocol, headers)) -> {
      let method = case http.parse_method(method) {
        Ok(method) -> method
        Error(parse_error) -> {
          let _parse_error = parse_error
          http.Other(method)
        }
      }
      Ok(Request(request_handle, method, path, protocol, headers))
    }
    Error(error) -> Error(from_backend_failure(error))
  }
}

/// Return an accepted request's method.
pub fn method(request: Request) -> http.Method {
  request.method
}

/// Return an accepted request's path and query string.
pub fn path(request: Request) -> String {
  request.path
}

/// Return the negotiated Extended CONNECT protocol, if present.
pub fn protocol(request: Request) -> Option(String) {
  request.protocol
}

/// Return an accepted request's non-pseudo headers.
pub fn headers(request: Request) -> List(#(String, String)) {
  request.headers
}

/// Pull the next request-body event.
pub fn next_event(request: Request) -> Result(RequestEvent, Error) {
  case server_backend.next_event(request.handle) {
    Ok(#(1, _, chunk)) -> Ok(Data(chunk))
    Ok(#(2, trailers, _)) -> Ok(Trailers(trailers))
    Ok(#(3, _, _)) -> Ok(End)
    Ok(_) -> Error(Failure(runtime_failure.Http3(runtime_failure.Local, None)))
    Error(error) -> Error(from_backend_failure(error))
  }
}

/// Collect a request body within the configured server limit.
pub fn read_body(request: Request) -> Result(BitArray, Error) {
  read_body_loop(request, [])
}

fn read_body_loop(
  request: Request,
  chunks: List(BitArray),
) -> Result(BitArray, Error) {
  case next_event(request) {
    Ok(Data(chunk)) -> read_body_loop(request, [chunk, ..chunks])
    Ok(Trailers(_)) -> read_body_loop(request, chunks)
    Ok(End) -> Ok(bit_array.concat(list.reverse(chunks)))
    Error(error) -> Error(error)
  }
}

/// Send a complete bounded response.
pub fn respond(
  request request: Request,
  status status: Int,
  headers headers: List(#(String, String)),
  body body: BitArray,
) -> Result(Nil, Error) {
  use <- bool.guard(
    when: bit_array.bit_size(body) % 8 != 0,
    return: Error(InvalidBody),
  )
  case
    server_response.prepare_bounded(status, headers, bit_array.byte_size(body))
  {
    Ok(headers) ->
      map_backend(server_backend.respond(request.handle, status, headers, body))
    Error(error) -> Error(from_response_error(error))
  }
}

/// Send a streaming response head.
pub fn send_response(
  request request: Request,
  status status: Int,
  headers headers: List(#(String, String)),
) -> Result(Nil, Error) {
  case server_response.prepare_streaming(status, headers) {
    Ok(#(headers, declared_content_length)) -> {
      let declared_content_length = case declared_content_length {
        Some(length) -> length
        None -> -1
      }
      map_backend(server_backend.send_response(
        request.handle,
        status,
        headers,
        declared_content_length,
      ))
    }
    Error(error) -> Error(from_response_error(error))
  }
}

/// Send one informational response before the final response.
///
/// Status 101 is forbidden by HTTP/3. Multiple informational responses are
/// permitted until the final response head is sent.
pub fn send_informational(
  request request: Request,
  status status: Int,
  headers headers: List(#(String, String)),
) -> Result(Nil, Error) {
  case server_response.prepare_informational(status, headers) {
    Ok(headers) ->
      map_backend(server_backend.send_informational(
        request.handle,
        status,
        headers,
      ))
    Error(error) -> Error(from_response_error(error))
  }
}

/// Send one byte-aligned streaming response-body chunk with backpressure.
pub fn send_chunk(
  request request: Request,
  chunk chunk: BitArray,
) -> Result(Nil, Error) {
  use <- bool.guard(
    when: bit_array.bit_size(chunk) % 8 != 0,
    return: Error(InvalidBody),
  )
  map_backend(server_backend.send_chunk(request.handle, chunk))
}

/// Encode and send one RFC 9297 Capsule on an Extended CONNECT response.
pub fn send_capsule(
  request request: Request,
  capsule capsule_value: capsule.Capsule,
) -> Result(Nil, Error) {
  use encoded <- result.try(
    capsule.encode(capsule_value) |> result.map_error(CapsuleError),
  )
  send_chunk(request: request, chunk: encoded)
}

/// Finish a streaming response body.
pub fn finish_response(request: Request) -> Result(Nil, Error) {
  map_backend(server_backend.finish_response(request.handle))
}

/// Send response trailers and finish the response stream atomically.
pub fn send_trailers(
  request request: Request,
  trailers trailers: List(#(String, String)),
) -> Result(Nil, Error) {
  case server_response.prepare_trailers(trailers) {
    Ok(trailers) ->
      map_backend(server_backend.send_trailers(request.handle, trailers))
    Error(error) -> Error(from_response_error(error))
  }
}

/// Promise one same-origin GET request.
///
/// The path must be absolute and cannot contain a fragment. Push capacity is
/// explicitly bounded by the client's `with_push_limit` configuration.
pub fn promise_push(
  request request: Request,
  path path: String,
  headers headers: List(#(String, String)),
) -> Result(Push, Error) {
  use <- bool.guard(
    when: !string.starts_with(path, "/") || string.contains(path, "#"),
    return: Error(InvalidPath(path)),
  )
  use headers <- result.try(
    server_response.prepare_push_request(headers)
    |> result.map_error(from_response_error),
  )
  server_backend.promise_push(
    request: request.handle,
    path: path,
    headers: headers,
  )
  |> result.map(Push)
  |> result.map_error(from_backend_failure)
}

// nolint: unused_exports -- stable public API exercised by downstream users.
/// Send a complete bounded server push response.
pub fn respond_push(
  push push: Push,
  status status: Int,
  headers headers: List(#(String, String)),
  body body: BitArray,
) -> Result(Nil, Error) {
  use <- bool.guard(
    when: bit_array.bit_size(body) % 8 != 0,
    return: Error(InvalidBody),
  )
  use headers <- result.try(
    server_response.prepare_bounded(status, headers, bit_array.byte_size(body))
    |> result.map_error(from_response_error),
  )
  use Nil <- result.try(
    map_backend(server_backend.send_push_response(
      push: push.handle,
      status: status,
      headers: headers,
      declared_content_length: bit_array.byte_size(body),
    )),
  )
  use Nil <- result.try(
    map_backend(server_backend.send_push_chunk(push: push.handle, chunk: body)),
  )
  map_backend(server_backend.finish_push(push.handle))
}

/// Send one streaming server push response head.
pub fn send_push_response(
  push push: Push,
  status status: Int,
  headers headers: List(#(String, String)),
) -> Result(Nil, Error) {
  use #(headers, declared) <- result.try(
    server_response.prepare_streaming(status, headers)
    |> result.map_error(from_response_error),
  )
  map_backend(
    server_backend.send_push_response(
      push: push.handle,
      status: status,
      headers: headers,
      declared_content_length: case declared {
        Some(value) -> value
        None -> -1
      },
    ),
  )
}

/// Send one pushed response body chunk with flow-control backpressure.
pub fn send_push_chunk(
  push push: Push,
  chunk chunk: BitArray,
) -> Result(Nil, Error) {
  use <- bool.guard(
    when: bit_array.bit_size(chunk) % 8 != 0,
    return: Error(InvalidBody),
  )
  map_backend(server_backend.send_push_chunk(push: push.handle, chunk: chunk))
}

// nolint: unused_exports -- stable public API exercised by downstream users.
/// Finish one streaming server push response.
pub fn finish_push(push: Push) -> Result(Nil, Error) {
  map_backend(server_backend.finish_push(push.handle))
}

/// Send pushed response trailers and finish atomically.
pub fn send_push_trailers(
  push push: Push,
  trailers trailers: List(#(String, String)),
) -> Result(Nil, Error) {
  use trailers <- result.try(
    server_response.prepare_trailers(trailers)
    |> result.map_error(from_response_error),
  )
  map_backend(server_backend.send_push_trailers(
    push: push.handle,
    headers: trailers,
  ))
}

/// Stop a listener and all owned connections idempotently.
pub fn stop(listener: Listener) -> Result(StopResult, Error) {
  let Listener(handle) = listener
  case server_backend.stop(handle) {
    Ok(1) -> Ok(Stopped)
    Ok(2) -> Ok(AlreadyStopped)
    Ok(_) -> Error(Failure(runtime_failure.Http3(runtime_failure.Local, None)))
    Error(error) -> Error(from_backend_failure(error))
  }
}

/// Stop accepting new work, send GOAWAY, and drain active requests.
///
/// `Forced` means the configured listener timeout expired; all remaining
/// streams are then closed deterministically before this function returns.
pub fn graceful_stop(listener: Listener) -> Result(DrainResult, Error) {
  let Listener(handle) = listener
  case server_backend.graceful_stop(handle) {
    Ok(1) -> Ok(Drained)
    Ok(2) -> Ok(Forced)
    Ok(3) -> Ok(AlreadyDrained)
    Ok(_) -> Error(Failure(runtime_failure.Http3(runtime_failure.Local, None)))
    Error(error) -> Error(from_backend_failure(error))
  }
}

fn map_backend(
  result: Result(value, server_backend.Failure),
) -> Result(value, Error) {
  case result {
    Ok(value) -> Ok(value)
    Error(error) -> Error(from_backend_failure(error))
  }
}

fn from_response_error(error: server_response.Error) -> Error {
  case error {
    server_response.InvalidStatus(status) -> InvalidStatus(status)
    server_response.InvalidHeader(name) -> InvalidHeader(name)
    server_response.InvalidContentLength -> InvalidContentLength
  }
}

fn from_backend_failure(failure: server_backend.Failure) -> Error {
  case failure {
    server_backend.RuntimeFailure(failure) -> Failure(failure)
    server_backend.RequestBodyTooLarge(limit) -> RequestBodyTooLarge(limit)
    server_backend.ResponseBodyTooLarge(limit) -> ResponseBodyTooLarge(limit)
    server_backend.ConsumerTooSlow(limit) -> ConsumerTooSlow(limit)
    server_backend.ConcurrentAccept -> ConcurrentAccept
    server_backend.ConcurrentDrain -> ConcurrentDrain
    server_backend.ConcurrentReceive -> ConcurrentReceive
    server_backend.ResponseAlreadyStarted -> ResponseAlreadyStarted
    server_backend.ResponseNotStarted -> ResponseNotStarted
    server_backend.ResponseAlreadyFinished -> ResponseAlreadyFinished
    server_backend.PushCancelled -> PushCancelled
    server_backend.InvalidContentLength -> InvalidContentLength
  }
}

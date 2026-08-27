//// An HTTP/3 client for the Erlang target.
////
//// `send` owns one connection, collects one response within explicit limits,
//// and closes the connection before returning. `connect` instead creates a
//// reusable connection whose streams use synchronous request-body
//// backpressure and pull-based response events with bounded buffering.
////
//// ```gleam
//// import gleam/http/request
//// import http3/client
////
//// pub fn fetch() {
////   let assert Ok(request) = request.to("https://example.com/")
////   let request = request.set_body(request, <<>>)
////
////   client.send(client.new(), request)
//// }
//// ```

import gleam/bit_array
import gleam/bool
import gleam/http/request.{type Request}
import gleam/http/response.{type Response}
import gleam/option.{type Option, None, Some}
import gleam/result
import http3/address
import http3/capsule
import http3/config as policy
import http3/failure as runtime_failure
import http3/internal/client_backend
import http3/internal/client_request
import http3/internal/client_stream_backend
import http3/transport

const default_maximum_pushes = 16

const minimum_keepalive_milliseconds = 1000

const maximum_keepalive_milliseconds = 29_000

@external(erlang, "http3_internal_transport_ffi", "client_connection")
fn make_transport_connection(
  handle: client_stream_backend.ConnectionHandle,
) -> transport.Connection

@external(erlang, "http3_internal_transport_ffi", "client_stream")
fn make_transport_stream(
  handle: client_stream_backend.StreamHandle,
) -> transport.Stream

@external(erlang, "http3_internal_transport_ffi", "ticket_handle")
fn resumption_ticket_handle(
  ticket: transport.ResumptionTicket,
) -> client_stream_backend.ResumptionTicketHandle

/// Configuration for one-shot HTTP/3 requests.
pub opaque type Client {
  Client(
    deadlines: policy.Deadlines,
    limits: policy.Limits,
    address_family: policy.AddressFamily,
    ca_certificates: List(BitArray),
    http_datagrams: Bool,
    maximum_pushes: Int,
    keepalive_milliseconds: Int,
    quic_version: transport.QuicVersion,
    qlog_directory: String,
    resumption_tickets: List(client_stream_backend.ResumptionTicketHandle),
  )
}

/// A reusable secure HTTP/3 connection.
pub opaque type Connection {
  Connection(handle: client_stream_backend.ConnectionHandle)
}

/// One request and response stream on an HTTP/3 connection.
pub opaque type Stream {
  Stream(handle: client_stream_backend.StreamHandle)
}

/// One server push promise and its pull-based response stream.
pub opaque type Push {
  Push(
    handle: client_stream_backend.PushHandle,
    method: String,
    path: String,
    headers: List(#(String, String)),
  )
}

/// One event from a streaming response.
pub type ResponseEvent {
  /// An informational response from status 100 through 199.
  InformationalResponse(status: Int, headers: List(#(String, String)))

  /// The final response head.
  Response(status: Int, headers: List(#(String, String)))

  /// A non-empty response-body chunk.
  Data(BitArray)

  /// Response trailers.
  Trailers(List(#(String, String)))

  /// The response stream ended successfully.
  End
}

/// The result of an idempotent stream cancellation.
pub type Cancellation {
  Cancelled
  AlreadyCancelled
  AlreadyCompleted
}

/// The result of idempotently closing a connection.
pub type CloseResult {
  Closed
  AlreadyClosed
}

/// An invalid client configuration value.
pub type ConfigurationError {
  /// A timeout must be between one millisecond and one hour.
  InvalidTimeout

  /// A response body limit must be greater than zero bytes.
  InvalidResponseBodyLimit

  /// A request body limit must be greater than zero bytes.
  InvalidRequestBodyLimit

  /// A streaming response buffer limit must be greater than zero bytes.
  InvalidStreamBufferLimit

  /// A push limit must be between zero and 1024.
  InvalidPushLimit

  /// A keepalive interval must be from one through twenty-nine seconds.
  InvalidKeepalive

  /// A CA certificate must be a non-empty, byte-aligned DER certificate.
  InvalidCaCertificate
}

/// A bounded HTTP/3 request failure.
pub type Error {
  /// HTTP/3 requests require the HTTPS scheme.
  InvalidScheme

  /// The request host is empty or contains surrounding whitespace.
  InvalidHost

  /// The request port is outside the UDP port range.
  InvalidPort(Int)

  /// The request body is not byte-aligned.
  InvalidBody

  /// The method is not supported by the bounded client.
  UnsupportedMethod(String)

  /// The request target is not an absolute path.
  InvalidPath(String)

  /// A request header is invalid for HTTP/3.
  InvalidHeader(String)

  /// The declared content length does not match the buffered request body.
  InvalidContentLength

  /// The Extended CONNECT protocol is not a valid HTTP token.
  InvalidProtocol(String)

  /// The response body exceeded the configured byte limit.
  ResponseBodyTooLarge(limit: Int)

  /// The request body exceeded the configured byte limit.
  RequestBodyTooLarge(limit: Int)

  /// A typed runtime failure with no backend-formatted or secret text.
  Failure(runtime_failure.Failure)

  /// A streaming consumer did not pull data before its buffer filled.
  ConsumerTooSlow(limit: Int)

  /// More than one process tried to receive from the same stream.
  ConcurrentReceive

  /// Request data was sent after its stream was finished.
  RequestAlreadyFinished

  /// No more response events are available from this completed stream.
  StreamFinished

  /// The peer sent GOAWAY; new work must use another connection.
  ConnectionDraining

  /// The peer did not process this request; replay it only when safe.
  RequestRejected

  /// A request does not match the connection's host and port.
  OriginMismatch

  /// A resumed 0-RTT connection only permits replay-safe request methods.
  UnsafeEarlyDataMethod(String)

  /// A resumption ticket belongs to a different host or port.
  ResumptionOriginMismatch

  /// A Capsule Protocol value could not be encoded safely.
  CapsuleError(capsule.Error)
}

/// Construct a client with secure TLS verification and bounded defaults.
///
/// The total timeout is 30 seconds. Buffered request and response bodies are
/// each limited to 8 MiB. Certificate chains are checked against the operating
/// system trust store and the request host is verified.
pub fn new() -> Client {
  Client(
    deadlines: policy.default_deadlines(),
    limits: policy.default_limits(),
    address_family: policy.DualStack,
    ca_certificates: [],
    http_datagrams: False,
    maximum_pushes: default_maximum_pushes,
    keepalive_milliseconds: 0,
    quic_version: transport.QuicV1,
    qlog_directory: "",
    resumption_tickets: [],
  )
}

// nolint: unused_exports -- stable public configuration API for downstream users.
/// Apply one validated set of finite phase deadlines atomically.
pub fn with_deadlines(
  client client: Client,
  deadlines deadlines: policy.Deadlines,
) -> Client {
  Client(..client, deadlines: deadlines)
}

/// Apply one validated set of finite resource limits atomically.
pub fn with_limits(
  client client: Client,
  limits limits: policy.Limits,
) -> Client {
  Client(..client, limits: limits)
}

/// Select IPv4, IPv6, or staggered dual-stack connection attempts.
pub fn with_address_family(
  client client: Client,
  address_family address_family: policy.AddressFamily,
) -> Client {
  Client(..client, address_family: address_family)
}

/// Send periodic QUIC PING frames while waiting or reusing a connection.
///
/// Keepalive is disabled by default. The interval must remain below the
/// advertised 30-second idle timeout and cannot be shorter than one second.
pub fn with_keepalive(
  client client: Client,
  milliseconds milliseconds: Int,
) -> Result(Client, ConfigurationError) {
  use <- bool.guard(
    when: milliseconds < minimum_keepalive_milliseconds
      || milliseconds > maximum_keepalive_milliseconds,
    return: Error(InvalidKeepalive),
  )
  Ok(Client(..client, keepalive_milliseconds: milliseconds))
}

/// Enable RFC 9297 HTTP Datagrams for reusable connections.
pub fn with_http_datagrams(client: Client) -> Client {
  Client(..client, http_datagrams: True)
}

/// Set the maximum server push promises retained per connection.
///
/// Zero disables server push. The default is 16.
pub fn with_push_limit(
  client client: Client,
  pushes pushes: Int,
) -> Result(Client, ConfigurationError) {
  use <- bool.guard(
    when: pushes < 0 || pushes > 1024,
    return: Error(InvalidPushLimit),
  )
  Ok(Client(..client, maximum_pushes: pushes))
}

/// Select the initially attempted QUIC wire version.
///
/// Compatible version negotiation remains enabled for v1 and v2.
pub fn with_quic_version(
  client client: Client,
  quic_version quic_version: transport.QuicVersion,
) -> Client {
  Client(..client, quic_version: quic_version)
}

/// Enable qlog tracing for reusable connections.
///
/// Trace files can contain sensitive connection metadata. qlog remains off
/// unless this function is called explicitly.
pub fn with_qlog(client client: Client, qlog qlog: transport.Qlog) -> Client {
  Client(..client, qlog_directory: transport.qlog_directory(qlog))
}

/// Attach one origin-bound session ticket for an explicit 0-RTT attempt.
///
/// Early requests are restricted to GET, HEAD, and OPTIONS because 0-RTT data
/// can be replayed by the network.
pub fn with_resumption_ticket(
  client client: Client,
  ticket ticket: transport.ResumptionTicket,
) -> Client {
  Client(..client, resumption_tickets: [resumption_ticket_handle(ticket)])
}

/// Set the total request timeout from one millisecond through one hour.
pub fn with_timeout(
  client client: Client,
  milliseconds milliseconds: Int,
) -> Result(Client, ConfigurationError) {
  case policy.uniform_deadlines(milliseconds) {
    Ok(deadlines) -> Ok(Client(..client, deadlines: deadlines))
    Error(_) -> Error(InvalidTimeout)
  }
}

/// Set the maximum buffered response body size in bytes.
pub fn with_response_body_limit(
  client client: Client,
  bytes bytes: Int,
) -> Result(Client, ConfigurationError) {
  case policy.with_limit(client.limits, runtime_failure.ResponseBody, bytes) {
    Ok(limits) -> Ok(Client(..client, limits: limits))
    Error(_) -> Error(InvalidResponseBodyLimit)
  }
}

/// Set the maximum buffered request body size in bytes.
pub fn with_request_body_limit(
  client client: Client,
  bytes bytes: Int,
) -> Result(Client, ConfigurationError) {
  case policy.with_limit(client.limits, runtime_failure.RequestBody, bytes) {
    Ok(limits) -> Ok(Client(..client, limits: limits))
    Error(_) -> Error(InvalidRequestBodyLimit)
  }
}

/// Set the maximum unconsumed response data retained per stream.
pub fn with_stream_buffer_limit(
  client client: Client,
  bytes bytes: Int,
) -> Result(Client, ConfigurationError) {
  case policy.with_limit(client.limits, runtime_failure.Buffer, bytes) {
    Ok(limits) -> Ok(Client(..client, limits: limits))
    Error(_) -> Error(InvalidStreamBufferLimit)
  }
}

/// Add a DER-encoded CA certificate without disabling TLS verification.
///
/// Once a certificate is added, the configured certificates form an explicit
/// trust set in place of the operating system trust store. This is suitable
/// for private certificate authorities and local test fixtures. Hostname
/// verification remains enabled.
pub fn with_ca_certificate(
  client client: Client,
  certificate certificate: BitArray,
) -> Result(Client, ConfigurationError) {
  use <- bool.guard(
    when: bit_array.bit_size(certificate) == 0
      || bit_array.bit_size(certificate) % 8 != 0
      || !client_backend.is_valid_ca_certificate(certificate),
    return: Error(InvalidCaCertificate),
  )
  Ok(Client(..client, ca_certificates: [certificate, ..client.ca_certificates]))
}

/// Send one bounded, buffered HTTP/3 request.
///
/// The request must use HTTPS and an absolute path. CONNECT and HTTP/3-forbidden
/// connection-specific headers are rejected before a socket is opened. A new
/// connection is always closed before this function returns.
pub fn send(
  client client: Client,
  request request: Request(BitArray),
) -> Result(Response(BitArray), Error) {
  send_to_address(client:, request:, connect_address: None)
}

/// Send one bounded request to an exact IP address while retaining the
/// request host for TLS SNI, certificate identity, and HTTP authority checks.
///
/// This is intended for health probes and controlled routing where DNS or a
/// NAT hairpin must not select the UDP peer. It never weakens TLS validation.
pub fn send_to(
  client client: Client,
  address address: address.Address,
  request request: Request(BitArray),
) -> Result(Response(BitArray), Error) {
  send_to_address(client:, request:, connect_address: Some(address))
}

fn send_to_address(
  client client: Client,
  request request: Request(BitArray),
  connect_address connect_address: Option(address.Address),
) -> Result(Response(BitArray), Error) {
  case client_request.prepare(request) {
    Ok(prepared) -> {
      let request_body_limit =
        policy.limit(client.limits, runtime_failure.RequestBody)
      case bit_array.byte_size(request.body) > request_body_limit {
        True -> Error(RequestBodyTooLarge(request_body_limit))
        False -> send_prepared(client:, request: prepared, connect_address:)
      }
    }
    Error(error) -> Error(from_preparation_error(error))
  }
}

fn send_prepared(
  client client: Client,
  request request: client_request.PreparedRequest,
  connect_address connect_address: Option(address.Address),
) -> Result(Response(BitArray), Error) {
  case
    client_backend.send(
      request,
      connect_address,
      client.ca_certificates,
      client.address_family,
      policy.deadline(client.deadlines, runtime_failure.Dns),
      policy.deadline(client.deadlines, runtime_failure.Connect),
      policy.deadline(client.deadlines, runtime_failure.Handshake),
      policy.deadline(client.deadlines, runtime_failure.Total),
      policy.deadline(client.deadlines, runtime_failure.Operation),
      policy.deadline(client.deadlines, runtime_failure.Idle),
      policy.limit(client.limits, runtime_failure.ResponseBody),
      client.quic_version == transport.QuicV2,
      client.keepalive_milliseconds,
    )
  {
    Ok(#(status, headers, body)) -> Ok(response.Response(status, headers, body))
    Error(error) ->
      Error(from_backend_failure(
        error,
        policy.limit(client.limits, runtime_failure.ResponseBody),
        runtime_failure.Total,
      ))
  }
}

/// Establish a reusable HTTP/3 connection with TLS verification enabled.
///
/// All streams opened on the connection must use the same host and port. The
/// connection is owned by the process that calls this function and is closed
/// automatically if that process exits.
pub fn connect(
  client client: Client,
  host host: String,
  port port: Int,
) -> Result(Connection, Error) {
  case client_request.prepare_origin(host, port) {
    Ok(_) ->
      case
        client_stream_backend.connect(
          host,
          port,
          client.ca_certificates,
          client.address_family,
          policy.deadline(client.deadlines, runtime_failure.Dns),
          policy.deadline(client.deadlines, runtime_failure.Connect),
          policy.deadline(client.deadlines, runtime_failure.Handshake),
          policy.deadline(client.deadlines, runtime_failure.Total),
          policy.deadline(client.deadlines, runtime_failure.Operation),
          policy.deadline(client.deadlines, runtime_failure.Idle),
          policy.limit(client.limits, runtime_failure.Buffer),
          policy.limit(client.limits, runtime_failure.Queue),
          policy.limit(client.limits, runtime_failure.Telemetry),
          policy.limit(client.limits, runtime_failure.BidirectionalStreams),
          policy.limit(client.limits, runtime_failure.UnidirectionalStreams),
          policy.limit(client.limits, runtime_failure.Frame),
          policy.limit(client.limits, runtime_failure.Datagram),
          policy.limit(client.limits, runtime_failure.QpackTable),
          policy.limit(client.limits, runtime_failure.QpackBlockedStreams),
          client.http_datagrams,
          client.maximum_pushes,
          client.keepalive_milliseconds,
          client.quic_version == transport.QuicV2,
          client.qlog_directory,
          client.resumption_tickets,
        )
      {
        Ok(handle) -> Ok(Connection(handle))
        Error(error) ->
          Error(from_backend_failure(
            error,
            policy.limit(client.limits, runtime_failure.ResponseBody),
            runtime_failure.Handshake,
          ))
      }
    Error(error) -> Error(from_preparation_error(error))
  }
}

/// Obtain typed advanced controls for a reusable connection.
pub fn connection_transport(connection: Connection) -> transport.Connection {
  let Connection(handle) = connection
  make_transport_connection(handle)
}

/// Open a request stream, leaving its request body open for chunks.
pub fn open_stream(
  connection connection: Connection,
  request request: Request(Nil),
) -> Result(Stream, Error) {
  let Connection(handle) = connection
  case client_request.prepare_streaming(request) {
    Ok(prepared) ->
      case client_stream_backend.open_stream(handle, prepared) {
        Ok(stream) -> Ok(Stream(stream))
        Error(error) ->
          Error(from_backend_failure(error, 0, runtime_failure.Operation))
      }
    Error(error) -> Error(from_preparation_error(error))
  }
}

/// Open an RFC 9220 Extended CONNECT stream.
///
/// The supplied request contributes the HTTPS origin, path, query, and regular
/// headers. This function emits the CONNECT and `:protocol` pseudo-fields and
/// is the only stable client surface that authorizes HTTP Datagrams.
pub fn open_extended_connect(
  connection connection: Connection,
  request request: Request(Nil),
  protocol protocol: String,
) -> Result(Stream, Error) {
  let Connection(handle) = connection
  case
    client_request.prepare_extended_connect(
      request: request,
      protocol: protocol,
    )
  {
    Ok(prepared) ->
      client_stream_backend.open_stream(handle, prepared)
      |> result.map(Stream)
      |> result.map_error(fn(error) {
        from_backend_failure(error, 0, runtime_failure.Operation)
      })
    Error(error) -> Error(from_preparation_error(error))
  }
}

/// Pull the next validated server push promise.
pub fn next_push(connection: Connection) -> Result(Push, Error) {
  let Connection(handle) = connection
  case client_stream_backend.next_push(handle) {
    Ok(#(push, method, path, headers)) -> Ok(Push(push, method, path, headers))
    Error(error) ->
      Error(from_backend_failure(error, 0, runtime_failure.Operation))
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

/// Return the promised request's regular header fields.
pub fn push_headers(push: Push) -> List(#(String, String)) {
  push.headers
}

/// Obtain typed advanced controls for a request stream.
pub fn stream_transport(stream: Stream) -> transport.Stream {
  let Stream(handle) = stream
  make_transport_stream(handle)
}

/// Send one byte-aligned request-body chunk.
///
/// The call does not return successfully until the backend accepts the chunk,
/// so a producer observes QUIC flow-control pressure.
pub fn send_chunk(
  stream stream: Stream,
  chunk chunk: BitArray,
) -> Result(Nil, Error) {
  use <- bool.guard(
    when: bit_array.bit_size(chunk) % 8 != 0,
    return: Error(InvalidBody),
  )
  let Stream(handle) = stream
  case client_stream_backend.send_chunk(handle, chunk) {
    Ok(value) -> Ok(value)
    Error(error) ->
      Error(from_backend_failure(error, 0, runtime_failure.Operation))
  }
}

/// Encode and send one RFC 9297 Capsule on an Extended CONNECT stream.
pub fn send_capsule(
  stream stream: Stream,
  capsule capsule_value: capsule.Capsule,
) -> Result(Nil, Error) {
  use encoded <- result.try(
    capsule.encode(capsule_value) |> result.map_error(CapsuleError),
  )
  send_chunk(stream: stream, chunk: encoded)
}

/// Send request trailers and finish the request stream atomically.
///
/// Trailer fields that affect framing, routing, authentication, or content
/// interpretation are rejected before reaching the connection actor.
pub fn send_trailers(
  stream stream: Stream,
  trailers trailers: List(#(String, String)),
) -> Result(Nil, Error) {
  use trailers <- result.try(
    client_request.prepare_trailers(trailers)
    |> result.map_error(from_preparation_error),
  )
  let Stream(handle) = stream
  client_stream_backend.send_trailers(handle, trailers)
  |> result.map_error(fn(error) {
    from_backend_failure(error, 0, runtime_failure.Operation)
  })
}

/// Finish a streaming request body.
pub fn finish(stream: Stream) -> Result(Nil, Error) {
  let Stream(handle) = stream
  case client_stream_backend.finish(handle) {
    Ok(value) -> Ok(value)
    Error(error) ->
      Error(from_backend_failure(error, 0, runtime_failure.Operation))
  }
}

/// Pull the next response event, waiting up to the configured stream timeout.
pub fn next_event(stream: Stream) -> Result(ResponseEvent, Error) {
  let Stream(handle) = stream
  case client_stream_backend.next_event(handle) {
    Ok(#(1, status, headers, _)) -> Ok(InformationalResponse(status, headers))
    Ok(#(2, status, headers, _)) -> Ok(Response(status, headers))
    Ok(#(3, _, _, chunk)) -> Ok(Data(chunk))
    Ok(#(4, _, trailers, _)) -> Ok(Trailers(trailers))
    Ok(#(5, _, _, _)) -> Ok(End)
    Ok(_) -> Error(Failure(runtime_failure.Http3(runtime_failure.Local, None)))
    Error(error) ->
      Error(from_backend_failure(error, 0, runtime_failure.Operation))
  }
}

/// Pull the next response event for a server push.
pub fn next_push_event(push: Push) -> Result(ResponseEvent, Error) {
  case client_stream_backend.next_push_event(push.handle) {
    Ok(#(1, status, headers, _)) -> Ok(InformationalResponse(status, headers))
    Ok(#(2, status, headers, _)) -> Ok(Response(status, headers))
    Ok(#(3, _, _, chunk)) -> Ok(Data(chunk))
    Ok(#(4, _, trailers, _)) -> Ok(Trailers(trailers))
    Ok(#(5, _, _, _)) -> Ok(End)
    Ok(_) -> Error(Failure(runtime_failure.Http3(runtime_failure.Local, None)))
    Error(error) ->
      Error(from_backend_failure(error, 0, runtime_failure.Operation))
  }
}

/// Cancel a request stream idempotently.
pub fn cancel(stream: Stream) -> Result(Cancellation, Error) {
  let Stream(handle) = stream
  case client_stream_backend.cancel(handle) {
    Ok(1) -> Ok(Cancelled)
    Ok(2) -> Ok(AlreadyCancelled)
    Ok(3) -> Ok(AlreadyCompleted)
    Ok(_) -> Error(Failure(runtime_failure.Http3(runtime_failure.Local, None)))
    Error(error) ->
      Error(from_backend_failure(error, 0, runtime_failure.Operation))
  }
}

/// Cancel a server push idempotently.
pub fn cancel_push(push: Push) -> Result(Cancellation, Error) {
  case client_stream_backend.cancel_push(push.handle) {
    Ok(1) -> Ok(Cancelled)
    Ok(2) -> Ok(AlreadyCancelled)
    Ok(3) -> Ok(AlreadyCompleted)
    Ok(_) -> Error(Failure(runtime_failure.Http3(runtime_failure.Local, None)))
    Error(error) ->
      Error(from_backend_failure(error, 0, runtime_failure.Operation))
  }
}

/// Close a connection and all of its streams idempotently.
pub fn close(connection: Connection) -> Result(CloseResult, Error) {
  let Connection(handle) = connection
  case client_stream_backend.close(handle) {
    Ok(1) -> Ok(Closed)
    Ok(2) -> Ok(AlreadyClosed)
    Ok(_) -> Error(Failure(runtime_failure.Http3(runtime_failure.Local, None)))
    Error(error) ->
      Error(from_backend_failure(error, 0, runtime_failure.Operation))
  }
}

fn from_preparation_error(error: client_request.Error) -> Error {
  case error {
    client_request.InvalidScheme -> InvalidScheme
    client_request.InvalidHost -> InvalidHost
    client_request.InvalidPort(port) -> InvalidPort(port)
    client_request.InvalidBody -> InvalidBody
    client_request.UnsupportedMethod(method) -> UnsupportedMethod(method)
    client_request.InvalidPath(path) -> InvalidPath(path)
    client_request.InvalidHeader(name) -> InvalidHeader(name)
    client_request.InvalidContentLength -> InvalidContentLength
    client_request.InvalidProtocol(protocol) -> InvalidProtocol(protocol)
  }
}

fn from_backend_failure(
  failure: client_backend.Failure,
  response_body_limit: Int,
  _timeout_phase: runtime_failure.TimeoutPhase,
) -> Error {
  case failure {
    client_backend.RuntimeFailure(failure) -> Failure(failure)
    client_backend.ResponseBodyTooLarge ->
      ResponseBodyTooLarge(response_body_limit)
    client_backend.ConsumerTooSlow(limit) -> ConsumerTooSlow(limit)
    client_backend.ConcurrentReceive -> ConcurrentReceive
    client_backend.RequestAlreadyFinished -> RequestAlreadyFinished
    client_backend.StreamFinished -> StreamFinished
    client_backend.StreamCancelled -> Failure(runtime_failure.Cancelled)
    client_backend.ConnectionDraining -> ConnectionDraining
    client_backend.RequestRejected -> RequestRejected
    client_backend.OriginMismatch -> OriginMismatch
    client_backend.UnsafeEarlyDataMethod(method) ->
      UnsafeEarlyDataMethod(method)
    client_backend.ResumptionOriginMismatch -> ResumptionOriginMismatch
    client_backend.InvalidContentLength -> InvalidContentLength
  }
}

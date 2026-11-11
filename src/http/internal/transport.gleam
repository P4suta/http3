//// Small typed active-once TCP boundary for HTTP runtimes.

import gleam/bit_array
import gleam/erlang/process.{type Pid, type Selector, type Subject}
import gleam/list
import gleam/option.{type Option, None, Some}
import gleam/result
import gleam/string

const maximum_timeout_milliseconds = 2_147_483_647

const maximum_read_bytes = 67_108_864

/// A passive TCP listener owned by the calling process.
pub type Listener

/// A TCP byte stream and any bounded bytes split from its last active event.
pub type Socket

/// One bounded active-once read outcome.
pub type ReadOutcome {
  ReadData(BitArray, Socket)
  ReadEnd(Socket)
}

/// A socket event or one completion from the exchange's owned producer.
pub type SelectedRead(message) {
  ReadSocket(ReadOutcome)
  ReadMessage(message, Socket)
}

/// Negotiated TLS version without an OTP-native term.
pub type TlsVersion {
  Tls12
  Tls13
}

/// A verified TLS stream and its selected ALPN protocol.
pub type TlsReady {
  TlsReady(Socket, selected_alpn: BitArray, version: TlsVersion)
}

/// Normalized validation, deadline, ownership, or socket failure.
pub type Error {
  InvalidInput
  Timeout
  Closed
  DnsFailure
  DnsTimeout
  TotalTimeout
  ConnectFailure
  ReadFailure
  WriteFailure
  PermissionDenied
  AddressInUse
  AddressUnavailable
  NotOwner
  TlsHandshake
  TlsAuthentication
  AlpnFailure
  SocketFailure
}

/// An optional fixed-size trace shared by one dial and its TLS handshakes.
pub type Diagnostics

/// Causal transport phases, independent of endpoint and service identity.
pub type DiagnosticStep {
  Unpublished
  DnsStarted
  DnsCompleted
  DialStarted
  DialCompleted
  OwnershipStarted
  ConnectionCompleted
  AcceptStarted
  AcceptCompleted
  ClientTlsStarted
  ClientTlsCompleted
  ServerTlsStarted
  ServerTlsCompleted
}

pub type DiagnosticFamily {
  NoAddressFamily
  Ipv4
  Ipv6
}

pub type DiagnosticOutcome {
  Pending
  Successful
  Failed(Error)
  Abandoned
}

/// Sequence is the append position; time is relative to this trace's origin.
pub type DiagnosticEvent {
  DiagnosticEvent(
    step: DiagnosticStep,
    family: DiagnosticFamily,
    attempt: Int,
    elapsed_milliseconds: Int,
    outcome: DiagnosticOutcome,
  )
}

pub type DiagnosticSnapshot {
  DiagnosticSnapshot(
    consistent: Bool,
    dropped_events: Int,
    events: List(DiagnosticEvent),
  )
}

@external(erlang, "http_transport_ffi", "diagnostics_new")
pub fn diagnostics_new() -> Diagnostics

@external(erlang, "http_transport_ffi", "diagnostics_snapshot")
fn raw_diagnostics_snapshot(
  diagnostics: Diagnostics,
) -> #(Bool, Int, List(#(Int, Int, Int, Int, Int)))

/// Retain the paired accept and server TLS phases without endpoint values.
@external(erlang, "http_transport_ffi", "with_listener_diagnostics")
pub fn with_listener_diagnostics(
  listener: Listener,
  diagnostics: Diagnostics,
) -> Listener

/// Read at most 64 records; an overlapping publication is explicitly marked.
pub fn diagnostics_snapshot(diagnostics: Diagnostics) -> DiagnosticSnapshot {
  let #(consistent, dropped_events, events) =
    raw_diagnostics_snapshot(diagnostics)
  DiagnosticSnapshot(
    consistent:,
    dropped_events:,
    events: list.map(events, diagnostic_event),
  )
}

fn diagnostic_event(raw: #(Int, Int, Int, Int, Int)) -> DiagnosticEvent {
  let #(kind, family, attempt, elapsed_milliseconds, code) = raw
  let step = case kind {
    0 -> Unpublished
    1 -> DnsStarted
    2 -> DnsCompleted
    3 -> DialStarted
    4 -> DialCompleted
    5 -> OwnershipStarted
    6 -> ConnectionCompleted
    7 -> AcceptStarted
    8 -> AcceptCompleted
    9 -> ClientTlsStarted
    10 -> ClientTlsCompleted
    11 -> ServerTlsStarted
    _ -> ServerTlsCompleted
  }
  let family = case family {
    4 -> Ipv4
    6 -> Ipv6
    _ -> NoAddressFamily
  }
  let outcome = case kind, kind % 2, code {
    0, _, _ | _, 1, _ -> Pending
    _, _, 0 -> Successful
    _, _, 18 -> Abandoned
    _, _, _ -> Failed(map_raw_error(code))
  }
  DiagnosticEvent(step:, family:, attempt:, elapsed_milliseconds:, outcome:)
}

@external(erlang, "http_transport_ffi", "listen")
fn raw_listen(
  address: BitArray,
  port: Int,
  backlog: Int,
  send_timeout_milliseconds: Int,
) -> Result(Listener, Int)

@external(erlang, "http_transport_ffi", "local_endpoint")
fn raw_local_endpoint(listener: Listener) -> Result(#(BitArray, Int), Int)

@external(erlang, "http_transport_ffi", "socket_local_endpoint")
fn raw_socket_local_endpoint(socket: Socket) -> Result(#(BitArray, Int), Int)

@external(erlang, "http_transport_ffi", "peer_endpoint")
fn raw_peer_endpoint(socket: Socket) -> Result(#(BitArray, Int), Int)

@external(erlang, "http_transport_ffi", "accept")
fn raw_accept(
  listener: Listener,
  timeout_milliseconds: Int,
) -> Result(Socket, Int)

@external(erlang, "http_transport_ffi", "connect")
fn raw_connect(
  host: String,
  port: Int,
  connect_timeout_milliseconds: Int,
  send_timeout_milliseconds: Int,
) -> Result(Socket, Int)

@external(erlang, "http_transport_ffi", "connect_with_timeouts")
fn raw_connect_with_timeouts(
  host: String,
  port: Int,
  dns_timeout_milliseconds: Int,
  connect_timeout_milliseconds: Int,
  send_timeout_milliseconds: Int,
) -> Result(Socket, Int)

@external(erlang, "http_transport_ffi", "connect_with_deadlines")
fn raw_connect_with_deadlines(
  host: String,
  port: Int,
  dns_timeout_milliseconds: Int,
  connect_timeout_milliseconds: Int,
  total_timeout_milliseconds: Int,
  send_timeout_milliseconds: Int,
) -> Result(Socket, Int)

@external(erlang, "http_transport_ffi", "connect_with_diagnostics")
fn raw_connect_with_diagnostics(
  host: String,
  port: Int,
  dns_timeout_milliseconds: Int,
  connect_timeout_milliseconds: Int,
  total_timeout_milliseconds: Int,
  send_timeout_milliseconds: Int,
  diagnostics: Diagnostics,
) -> Result(Socket, Int)

@external(erlang, "http_transport_ffi", "send")
fn raw_send(socket: Socket, bytes: BitArray) -> Result(Nil, Int)

@external(erlang, "http_transport_ffi", "read")
fn raw_read(
  socket: Socket,
  maximum_bytes: Int,
  timeout_milliseconds: Int,
) -> Result(#(Socket, BitArray, Int), Int)

@external(erlang, "http_transport_ffi", "read_or_message")
fn raw_read_or_message(
  socket: Socket,
  maximum_bytes: Int,
  timeout_milliseconds: Int,
  subject: Subject(message),
) -> Result(#(Socket, BitArray, Int, Option(message)), Int)

@external(erlang, "http_transport_ffi", "read_or_select")
fn raw_read_or_select(
  socket: Socket,
  maximum: Int,
  timeout: Int,
  selector: Selector(message),
) -> Result(#(Socket, BitArray, Int, Option(message)), Int)

/// TCP read EOF permits the existing half-close response contract.
/// TLS close terminates the stream and must cancel an outstanding response producer.
@external(erlang, "http_transport_ffi", "read_end_is_terminal")
pub fn read_end_is_terminal(socket: Socket) -> Bool

@external(erlang, "http_transport_ffi", "close")
fn raw_close(socket: Socket) -> Result(Nil, Int)

@external(erlang, "http_transport_ffi", "shutdown_write")
fn raw_shutdown_write(socket: Socket) -> Result(Nil, Int)

@external(erlang, "http_transport_ffi", "enable_half_close")
fn raw_enable_half_close(socket: Socket) -> Result(Nil, Int)

@external(erlang, "http_transport_ffi", "stop")
fn raw_stop(listener: Listener) -> Result(Nil, Int)

@external(erlang, "http_transport_ffi", "upgrade_client_tls")
fn raw_upgrade_client_tls(
  socket: Socket,
  server_name: String,
  ca_certificates: List(BitArray),
  alpn_protocols: List(BitArray),
  timeout_milliseconds: Int,
) -> Result(#(Socket, BitArray, Int), Int)

@external(erlang, "http_transport_ffi", "upgrade_server_tls")
fn raw_upgrade_server_tls(
  socket: Socket,
  certificate_pem: BitArray,
  private_key_pem: BitArray,
  alpn_protocols: List(BitArray),
  timeout_milliseconds: Int,
) -> Result(#(Socket, BitArray, Int), Int)

@external(erlang, "http_transport_ffi", "transfer_owner")
fn raw_transfer_owner(socket: Socket, owner: Pid) -> Result(Nil, Int)

@external(erlang, "http_transport_ffi", "transfer_listener_owner")
fn raw_transfer_listener_owner(
  listener: Listener,
  owner: Pid,
) -> Result(Nil, Int)

@external(erlang, "http_transport_ffi", "monotonic_millisecond")
fn raw_monotonic_millisecond() -> Int

@external(erlang, "http_transport_ffi", "unix_millisecond")
fn raw_unix_millisecond() -> Int

/// Bind one passive IPv4 or IPv6 listener. Port zero requests an ephemeral
/// port from the operating system.
pub fn listen(
  address: BitArray,
  port: Int,
  backlog: Int,
  send_timeout_milliseconds: Int,
) -> Result(Listener, Error) {
  case
    byte_aligned_address(address)
    && port >= 0
    && port <= 65_535
    && backlog > 0
    && backlog <= 1024
    && valid_timeout(send_timeout_milliseconds)
  {
    False -> Error(InvalidInput)
    True ->
      raw_listen(address, port, backlog, send_timeout_milliseconds)
      |> map_raw_result
  }
}

/// Return a listener's concrete address bytes and assigned port.
pub fn local_endpoint(listener: Listener) -> Result(#(BitArray, Int), Error) {
  raw_local_endpoint(listener) |> map_raw_result
}

/// Return the concrete local endpoint of one connected stream.
pub fn socket_local_endpoint(
  socket: Socket,
) -> Result(#(BitArray, Int), Error) {
  raw_socket_local_endpoint(socket) |> map_raw_result
}

/// Return the concrete peer endpoint of one connected stream.
pub fn peer_endpoint(socket: Socket) -> Result(#(BitArray, Int), Error) {
  raw_peer_endpoint(socket) |> map_raw_result
}

/// Accept one connection under a finite deadline.
pub fn accept(
  listener: Listener,
  timeout_milliseconds: Int,
) -> Result(Socket, Error) {
  case valid_timeout(timeout_milliseconds) {
    False -> Error(InvalidInput)
    True -> raw_accept(listener, timeout_milliseconds) |> map_raw_result
  }
}

/// Resolve and connect to one host under a single finite deadline.
pub fn connect(
  host: String,
  port: Int,
  connect_timeout_milliseconds: Int,
  send_timeout_milliseconds: Int,
) -> Result(Socket, Error) {
  case
    !string.is_empty(host)
    && string.length(host) <= 253
    && !string.contains(host, "\u{0000}")
    && port > 0
    && port <= 65_535
    && valid_timeout(connect_timeout_milliseconds)
    && valid_timeout(send_timeout_milliseconds)
  {
    False -> Error(InvalidInput)
    True ->
      raw_connect(
        host,
        port,
        connect_timeout_milliseconds,
        send_timeout_milliseconds,
      )
      |> map_raw_result
  }
}

/// Resolve and connect with independent finite DNS and transport budgets.
pub fn connect_with_timeouts(
  host: String,
  port: Int,
  dns_timeout_milliseconds: Int,
  connect_timeout_milliseconds: Int,
  send_timeout_milliseconds: Int,
) -> Result(Socket, Error) {
  case
    !string.is_empty(host)
    && string.length(host) <= 253
    && !string.contains(host, "\u{0000}")
    && port > 0
    && port <= 65_535
    && valid_timeout(dns_timeout_milliseconds)
    && valid_timeout(connect_timeout_milliseconds)
    && valid_timeout(send_timeout_milliseconds)
  {
    False -> Error(InvalidInput)
    True ->
      raw_connect_with_timeouts(
        host,
        port,
        dns_timeout_milliseconds,
        connect_timeout_milliseconds,
        send_timeout_milliseconds,
      )
      |> map_raw_result
  }
}

/// Resolve and connect under phase budgets and one hard total deadline.
pub fn connect_with_deadlines(
  host: String,
  port: Int,
  dns_timeout_milliseconds: Int,
  connect_timeout_milliseconds: Int,
  total_timeout_milliseconds: Int,
  send_timeout_milliseconds: Int,
) -> Result(Socket, Error) {
  case
    !string.is_empty(host)
    && string.length(host) <= 253
    && !string.contains(host, "\u{0000}")
    && port > 0
    && port <= 65_535
    && valid_timeout(dns_timeout_milliseconds)
    && valid_timeout(connect_timeout_milliseconds)
    && valid_timeout(total_timeout_milliseconds)
    && valid_timeout(send_timeout_milliseconds)
  {
    False -> Error(InvalidInput)
    True ->
      raw_connect_with_deadlines(
        host,
        port,
        dns_timeout_milliseconds,
        connect_timeout_milliseconds,
        total_timeout_milliseconds,
        send_timeout_milliseconds,
      )
      |> map_raw_result
  }
}

/// Dial with the same validated budgets while retaining DNS, candidate,
/// ownership, and subsequent client TLS observations in one bounded trace.
pub fn connect_with_diagnostics(
  host: String,
  port: Int,
  dns_timeout_milliseconds: Int,
  connect_timeout_milliseconds: Int,
  total_timeout_milliseconds: Int,
  send_timeout_milliseconds: Int,
  diagnostics: Diagnostics,
) -> Result(Socket, Error) {
  raw_connect_with_diagnostics(
    host,
    port,
    dns_timeout_milliseconds,
    connect_timeout_milliseconds,
    total_timeout_milliseconds,
    send_timeout_milliseconds,
    diagnostics,
  )
  |> map_raw_result
}

/// Write one byte-aligned chunk. The socket's finite send timeout was fixed
/// before it became visible to the caller.
pub fn send(socket: Socket, bytes: BitArray) -> Result(Nil, Error) {
  case bit_array.bit_size(bytes) % 8 {
    0 -> raw_send(socket, bytes) |> map_raw_result
    _ -> Error(InvalidInput)
  }
}

/// Arm the stream exactly once and return at most `maximum_bytes`.
///
/// A read timeout closes the socket before returning, preventing a late active
/// message from being mistaken for a later operation.
pub fn read(
  socket: Socket,
  maximum_bytes: Int,
  timeout_milliseconds: Int,
) -> Result(ReadOutcome, Error) {
  case
    maximum_bytes > 0
    && maximum_bytes <= maximum_read_bytes
    && valid_timeout(timeout_milliseconds)
  {
    False -> Error(InvalidInput)
    True -> {
      use #(socket, bytes, ended) <- result.try(
        raw_read(socket, maximum_bytes, timeout_milliseconds)
        |> map_raw_result,
      )
      case ended {
        0 -> Ok(ReadData(bytes, socket))
        _ -> Ok(ReadEnd(socket))
      }
    }
  }
}

/// Receive peer input while a supervised source is producing one chunk.
/// An interrupted active-once read keeps its outstanding socket credit.
pub fn read_or_message(
  socket: Socket,
  maximum_bytes: Int,
  timeout_milliseconds: Int,
  subject: Subject(message),
) -> Result(SelectedRead(message), Error) {
  case
    maximum_bytes > 0
    && maximum_bytes <= maximum_read_bytes
    && valid_timeout(timeout_milliseconds)
  {
    False -> Error(InvalidInput)
    True -> {
      use #(socket, bytes, kind, message) <- result.try(
        raw_read_or_message(
          socket,
          maximum_bytes,
          timeout_milliseconds,
          subject,
        )
        |> map_raw_result,
      )
      case kind, message {
        0, None -> Ok(ReadSocket(ReadData(bytes, socket)))
        1, None -> Ok(ReadSocket(ReadEnd(socket)))
        2, Some(message) -> Ok(ReadMessage(message, socket))
        _, _ -> Error(InvalidInput)
      }
    }
  }
}

/// Receive owned socket input together with bounded lifecycle controls.
/// Producer activity never replenishes the caller's absolute deadline.
pub fn read_or_select(
  socket: Socket,
  maximum_bytes: Int,
  timeout_milliseconds: Int,
  selector: Selector(message),
) -> Result(SelectedRead(message), Error) {
  case
    maximum_bytes > 0
    && maximum_bytes <= maximum_read_bytes
    && valid_timeout(timeout_milliseconds)
  {
    False -> Error(InvalidInput)
    True -> {
      use #(socket, bytes, kind, message) <- result.try(
        raw_read_or_select(
          socket,
          maximum_bytes,
          timeout_milliseconds,
          selector,
        )
        |> map_raw_result,
      )
      case kind, message {
        0, None -> Ok(ReadSocket(ReadData(bytes, socket)))
        1, None -> Ok(ReadSocket(ReadEnd(socket)))
        2, Some(message) -> Ok(ReadMessage(message, socket))
        _, _ -> Error(InvalidInput)
      }
    }
  }
}

/// Upgrade a TCP stream to TLS 1.2 or TLS 1.3 with mandatory certificate-chain
/// and service-identity verification. An empty CA list uses OTP's OS trust
/// store; a non-empty list replaces it with explicit DER certificates.
pub fn upgrade_client_tls(
  socket: Socket,
  server_name: String,
  ca_certificates: List(BitArray),
  alpn_protocols: List(BitArray),
  timeout_milliseconds: Int,
) -> Result(TlsReady, Error) {
  case
    !string.is_empty(server_name)
    && string.length(server_name) <= 253
    && !string.contains(server_name, "\u{0000}")
    && valid_certificates(ca_certificates)
    && valid_alpn(alpn_protocols)
    && valid_timeout(timeout_milliseconds)
  {
    False -> Error(InvalidInput)
    True -> {
      use #(socket, selected_alpn, version) <- result.try(
        raw_upgrade_client_tls(
          socket,
          server_name,
          ca_certificates,
          alpn_protocols,
          timeout_milliseconds,
        )
        |> map_raw_result,
      )
      Ok(TlsReady(socket, selected_alpn, tls_version(version)))
    }
  }
}

/// Upgrade an accepted TCP stream with an in-memory certificate chain and
/// private key. Client authentication is configured by the higher server
/// policy layer and is not disabled by this client-verification API.
pub fn upgrade_server_tls(
  socket: Socket,
  certificate_pem: BitArray,
  private_key_pem: BitArray,
  alpn_protocols: List(BitArray),
  timeout_milliseconds: Int,
) -> Result(TlsReady, Error) {
  case
    nonempty_bytes(certificate_pem)
    && nonempty_bytes(private_key_pem)
    && valid_alpn(alpn_protocols)
    && valid_timeout(timeout_milliseconds)
  {
    False -> Error(InvalidInput)
    True -> {
      use #(socket, selected_alpn, version) <- result.try(
        raw_upgrade_server_tls(
          socket,
          certificate_pem,
          private_key_pem,
          alpn_protocols,
          timeout_milliseconds,
        )
        |> map_raw_result,
      )
      Ok(TlsReady(socket, selected_alpn, tls_version(version)))
    }
  }
}

/// Transfer a TCP or TLS stream to its next actor owner.
pub fn transfer_owner(socket: Socket, owner: Pid) -> Result(Nil, Error) {
  raw_transfer_owner(socket, owner) |> map_raw_result
}

/// Transfer a passive listener to its acceptor actor.
pub fn transfer_listener_owner(
  listener: Listener,
  owner: Pid,
) -> Result(Nil, Error) {
  raw_transfer_listener_owner(listener, owner) |> map_raw_result
}

/// Return an opaque-origin monotonic millisecond counter for deadline
/// arithmetic. It must never be persisted or interpreted as wall time.
pub fn monotonic_millisecond() -> Int {
  raw_monotonic_millisecond()
}

/// Return wall-clock milliseconds since the Unix epoch.
///
/// This is the only clock here comparable with a date a peer sent. Read it
/// where such a field is parsed, turn it into a remaining duration there, and
/// measure the deadline itself on the monotonic counter: wall time can move
/// backwards, and a retained deadline measured against it moves with it.
pub fn unix_millisecond() -> Int {
  raw_unix_millisecond()
}

/// Close a stream idempotently.
pub fn close(socket: Socket) -> Result(Nil, Error) {
  raw_close(socket) |> map_raw_result
}

/// Half-close the write side while retaining the ability to receive bytes.
pub fn shutdown_write(socket: Socket) -> Result(Nil, Error) {
  raw_shutdown_write(socket) |> map_raw_result
}

/// Retain the write side of an accepted TCP socket after a peer FIN.
pub fn enable_half_close(socket: Socket) -> Result(Nil, Error) {
  raw_enable_half_close(socket) |> map_raw_result
}

/// Stop a listener idempotently.
pub fn stop(listener: Listener) -> Result(Nil, Error) {
  raw_stop(listener) |> map_raw_result
}

fn byte_aligned_address(address: BitArray) -> Bool {
  case bit_array.bit_size(address) % 8, bit_array.byte_size(address) {
    0, 4 | 0, 16 -> True
    _, _ -> False
  }
}

fn valid_timeout(timeout_milliseconds: Int) -> Bool {
  timeout_milliseconds > 0
  && timeout_milliseconds <= maximum_timeout_milliseconds
}

fn valid_certificates(certificates: List(BitArray)) -> Bool {
  case certificates {
    [] -> True
    [certificate, ..rest] ->
      nonempty_bytes(certificate) && valid_certificates(rest)
  }
}

fn valid_alpn(protocols: List(BitArray)) -> Bool {
  case protocols {
    [] -> False
    _ -> valid_alpn_protocols(protocols)
  }
}

fn valid_alpn_protocols(protocols: List(BitArray)) -> Bool {
  case protocols {
    [] -> True
    [protocol, ..rest] -> {
      let size = bit_array.byte_size(protocol)
      bit_array.bit_size(protocol) % 8 == 0
      && size > 0
      && size <= 255
      && valid_alpn_protocols(rest)
    }
  }
}

fn nonempty_bytes(bytes: BitArray) -> Bool {
  bit_array.bit_size(bytes) % 8 == 0 && bit_array.byte_size(bytes) > 0
}

fn tls_version(version: Int) -> TlsVersion {
  case version {
    13 -> Tls13
    _ -> Tls12
  }
}

fn map_raw_result(value: Result(value, Int)) -> Result(value, Error) {
  result.map_error(value, map_raw_error)
}

fn map_raw_error(code: Int) -> Error {
  case code {
    1 -> InvalidInput
    2 -> Timeout
    3 -> Closed
    4 -> DnsFailure
    5 -> ConnectFailure
    6 -> ReadFailure
    7 -> WriteFailure
    8 -> PermissionDenied
    9 -> AddressInUse
    10 -> AddressUnavailable
    11 -> NotOwner
    13 -> TlsHandshake
    14 -> TlsAuthentication
    15 -> AlpnFailure
    16 -> DnsTimeout
    17 -> TotalTimeout
    _ -> SocketFailure
  }
}

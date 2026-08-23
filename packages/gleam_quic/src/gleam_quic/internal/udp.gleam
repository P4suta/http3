//// Typed UDP, address, ECN, and monotonic-clock runtime boundary.

import gleam/bit_array
import gleam/list
import gleam/result
import gleam/string
import gleam_quic/internal/ecn
import gleam_quic/internal/packet_space

const maximum_udp_payload_bytes = 65_527

/// An IPv4 or IPv6 address in network byte order.
pub opaque type Address {
  Address(bytes: BitArray)
}

/// Address-family policy for name resolution.
pub type AddressFamily {
  Any
  Ipv4
  Ipv6
}

/// A validated UDP address and port.
pub opaque type Endpoint {
  Endpoint(address: Address, port: Int)
}

/// A passive UDP socket owned by the calling Erlang process.
pub type Socket

/// One received UDP datagram and its observed IP ECN marking.
pub type Datagram {
  Datagram(
    peer: Endpoint,
    payload: BitArray,
    ecn: packet_space.ReceivedCodepoint,
  )
}

/// Validation, OS, timeout, ownership, or capability failure.
pub type Error {
  InvalidInput
  Timeout
  Closed
  PermissionDenied
  AddressInUse
  AddressUnavailable
  EcnUnavailable
  SocketFailure
}

@external(erlang, "gleam_quic_udp_ffi", "open")
fn raw_open(address: BitArray, port: Int) -> Result(Socket, Int)

@external(erlang, "gleam_quic_udp_ffi", "local_endpoint")
fn raw_local_endpoint(socket: Socket) -> Result(#(BitArray, Int), Int)

@external(erlang, "gleam_quic_udp_ffi", "resolve")
fn raw_resolve(host: String, family: Int) -> Result(List(BitArray), Int)

@external(erlang, "gleam_quic_udp_ffi", "send")
fn raw_send(
  socket: Socket,
  address: BitArray,
  port: Int,
  payload: BitArray,
  ecn: Int,
) -> Result(Nil, Int)

@external(erlang, "gleam_quic_udp_ffi", "recv")
fn raw_receive(
  socket: Socket,
  timeout_milliseconds: Int,
) -> Result(#(BitArray, Int, BitArray, Int), Int)

@external(erlang, "gleam_quic_udp_ffi", "supports_ecn")
fn raw_supports_ecn(socket: Socket) -> Bool

@external(erlang, "gleam_quic_udp_ffi", "close")
fn raw_close(socket: Socket) -> Result(Nil, Int)

@external(erlang, "gleam_quic_udp_ffi", "monotonic_millisecond")
fn raw_monotonic_millisecond() -> Int

/// Construct a validated IPv4 address.
pub fn ipv4(a: Int, b: Int, c: Int, d: Int) -> Result(Address, Error) {
  case valid_octet(a) && valid_octet(b) && valid_octet(c) && valid_octet(d) {
    True -> Ok(Address(<<a, b, c, d>>))
    False -> Error(InvalidInput)
  }
}

/// Construct a validated IPv6 address from eight network-order words.
pub fn ipv6(
  a: Int,
  b: Int,
  c: Int,
  d: Int,
  e: Int,
  f: Int,
  g: Int,
  h: Int,
) -> Result(Address, Error) {
  case
    valid_word(a)
    && valid_word(b)
    && valid_word(c)
    && valid_word(d)
    && valid_word(e)
    && valid_word(f)
    && valid_word(g)
    && valid_word(h)
  {
    True -> Ok(Address(<<a:16, b:16, c:16, d:16, e:16, f:16, g:16, h:16>>))
    False -> Error(InvalidInput)
  }
}

/// Construct a validated endpoint. Port zero is accepted only for binding.
pub fn endpoint(address: Address, port: Int) -> Result(Endpoint, Error) {
  case port >= 0 && port <= 65_535 {
    True -> Ok(Endpoint(address, port))
    False -> Error(InvalidInput)
  }
}

/// Return an endpoint's address bytes and port without runtime-specific terms.
pub fn endpoint_parts(endpoint: Endpoint) -> #(BitArray, Int) {
  #(endpoint.address.bytes, endpoint.port)
}

/// Return an address in network byte order without exposing an Erlang tuple.
pub fn address_bytes(address: Address) -> BitArray {
  address.bytes
}

/// Reconstruct a typed address from four or sixteen network-order bytes.
pub fn address_from_bytes(bytes: BitArray) -> Result(Address, Error) {
  case bit_array.byte_size(bytes), bit_array.bit_size(bytes) % 8 {
    4, 0 | 16, 0 -> Ok(Address(bytes))
    _, _ -> Error(InvalidInput)
  }
}

/// Resolve a DNS name or address literal into bounded typed IP addresses.
pub fn resolve(
  host host: String,
  family family: AddressFamily,
) -> Result(List(Address), Error) {
  case
    string.is_empty(host)
    || string.length(host) > 253
    || string.contains(host, "\u{0000}")
  {
    True -> Error(InvalidInput)
    False -> {
      use addresses <- result.try(
        raw_resolve(host, address_family_code(family)) |> map_raw_result,
      )
      addresses_from_bytes(addresses, [])
    }
  }
}

/// Bind a passive socket. Port zero asks the OS for an ephemeral port.
pub fn open(local: Endpoint) -> Result(Socket, Error) {
  raw_open(local.address.bytes, local.port) |> map_raw_result
}

/// Return the concrete local endpoint assigned by the OS.
pub fn local_endpoint(socket: Socket) -> Result(Endpoint, Error) {
  use #(address, port) <- result.try(
    raw_local_endpoint(socket) |> map_raw_result,
  )
  endpoint_from_bytes(address, port)
}

/// Report whether this socket can receive and transmit ECN markings.
pub fn supports_ecn(socket: Socket) -> Bool {
  raw_supports_ecn(socket)
}

/// Send exactly one UDP datagram to a non-zero peer port.
pub fn send(
  socket: Socket,
  peer: Endpoint,
  payload: BitArray,
  codepoint: ecn.Codepoint,
) -> Result(Nil, Error) {
  case
    peer.port > 0
    && bit_array.bit_size(payload) % 8 == 0
    && bit_array.byte_size(payload) <= maximum_udp_payload_bytes
  {
    False -> Error(InvalidInput)
    True ->
      raw_send(
        socket,
        peer.address.bytes,
        peer.port,
        payload,
        outgoing_ecn(codepoint),
      )
      |> map_raw_result
  }
}

/// Receive one complete datagram with a fixed finite timeout.
pub fn receive(
  socket: Socket,
  timeout_milliseconds: Int,
) -> Result(Datagram, Error) {
  case timeout_milliseconds >= 0 && timeout_milliseconds <= 2_147_483_647 {
    False -> Error(InvalidInput)
    True -> {
      use #(address, port, payload, codepoint) <- result.try(
        raw_receive(socket, timeout_milliseconds) |> map_raw_result,
      )
      use peer <- result.try(endpoint_from_bytes(address, port))
      use marking <- result.try(received_ecn(codepoint))
      Ok(Datagram(peer, payload, marking))
    }
  }
}

/// Close the socket. Closing an already closed socket is successful.
pub fn close(socket: Socket) -> Result(Nil, Error) {
  raw_close(socket) |> map_raw_result
}

/// Milliseconds elapsed since the runtime boundary was initialized.
pub fn monotonic_millisecond() -> Int {
  raw_monotonic_millisecond()
}

fn endpoint_from_bytes(bytes: BitArray, port: Int) -> Result(Endpoint, Error) {
  case bit_array.byte_size(bytes), bit_array.bit_size(bytes) % 8, port {
    4, 0, value if value >= 0 && value <= 65_535 ->
      Ok(Endpoint(Address(bytes), port))
    16, 0, value if value >= 0 && value <= 65_535 ->
      Ok(Endpoint(Address(bytes), port))
    _, _, _ -> Error(InvalidInput)
  }
}

fn addresses_from_bytes(
  addresses: List(BitArray),
  reversed: List(Address),
) -> Result(List(Address), Error) {
  case addresses {
    [] -> Ok(list.reverse(reversed))
    [bytes, ..rest] -> {
      use Endpoint(address, _) <- result.try(endpoint_from_bytes(bytes, 0))
      addresses_from_bytes(rest, [address, ..reversed])
    }
  }
}

fn address_family_code(family: AddressFamily) -> Int {
  case family {
    Any -> 0
    Ipv4 -> 4
    Ipv6 -> 6
  }
}

fn outgoing_ecn(codepoint: ecn.Codepoint) -> Int {
  case codepoint {
    ecn.NotEct -> 0
    ecn.Ect1 -> 1
    ecn.Ect0 -> 2
  }
}

fn received_ecn(
  codepoint: Int,
) -> Result(packet_space.ReceivedCodepoint, Error) {
  case codepoint {
    0 -> Ok(packet_space.NotEct)
    1 -> Ok(packet_space.Ect1)
    2 -> Ok(packet_space.Ect0)
    3 -> Ok(packet_space.CongestionExperienced)
    _ -> Error(SocketFailure)
  }
}

fn valid_octet(value: Int) -> Bool {
  value >= 0 && value <= 255
}

fn valid_word(value: Int) -> Bool {
  value >= 0 && value <= 65_535
}

fn map_raw_result(value: Result(value, Int)) -> Result(value, Error) {
  case value {
    Ok(output) -> Ok(output)
    Error(1) -> Error(InvalidInput)
    Error(2) -> Error(Timeout)
    Error(3) -> Error(Closed)
    Error(4) -> Error(PermissionDenied)
    Error(5) -> Error(AddressInUse)
    Error(6) -> Error(AddressUnavailable)
    Error(7) -> Error(EcnUnavailable)
    Error(_) -> Error(SocketFailure)
  }
}

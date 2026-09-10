//// Public IPv4, IPv6, and UDP endpoint values.
////
//// Parsing accepts address literals only and never performs DNS resolution.

import gleam/bit_array
import gleam/bool
import gleam/int
import gleam/result
import gleam/string

/// A validated IPv4 or IPv6 literal.
pub opaque type Address {
  Address(bytes: BitArray, display: String)
}

/// A validated IP address and UDP port.
pub opaque type Endpoint {
  Endpoint(address: Address, port: Int)
}

/// The address family of a parsed literal.
pub type Family {
  Ipv4
  Ipv6
}

/// An invalid address literal, endpoint literal, or port.
pub type Error {
  InvalidAddress(String)
  InvalidEndpoint(String)
  InvalidPort(Int)
}

@external(erlang, "http3_address_ffi", "parse")
fn parse_bytes(value: String) -> Result(BitArray, Nil)

@external(erlang, "http3_address_ffi", "format")
fn format_bytes(value: BitArray) -> Result(String, Nil)

/// Parse an IPv4 or IPv6 literal without performing DNS resolution.
pub fn parse(value: String) -> Result(Address, Error) {
  use bytes <- result.try(
    parse_bytes(value) |> result.replace_error(InvalidAddress(value)),
  )
  from_bytes(bytes) |> result.replace_error(InvalidAddress(value))
}

/// Reconstruct an address from four or sixteen network-order bytes.
///
/// This is primarily useful at a datagram runtime boundary. It performs no
/// DNS lookup and rejects every other byte length.
pub fn from_bytes(bytes: BitArray) -> Result(Address, Error) {
  case bit_array.byte_size(bytes), bit_array.bit_size(bytes) % 8 {
    4, 0 | 16, 0 ->
      format_bytes(bytes)
      |> result.map(fn(display) { Address(bytes, display) })
      |> result.replace_error(InvalidAddress(""))
    _, _ -> Error(InvalidAddress(""))
  }
}

/// Return an address in network byte order.
///
/// The result contains exactly four bytes for IPv4 or sixteen for IPv6.
pub fn to_bytes(address: Address) -> BitArray {
  address.bytes
}

/// Return the canonical display form of an address.
pub fn to_string(address: Address) -> String {
  address.display
}

/// Return whether an address is IPv4 or IPv6.
pub fn family(address: Address) -> Family {
  case bit_array.byte_size(address.bytes) {
    4 -> Ipv4
    _ -> Ipv6
  }
}

/// Construct an endpoint. Port zero is valid for a local bind request.
pub fn endpoint(address: Address, port: Int) -> Result(Endpoint, Error) {
  use <- bool.guard(
    when: port < 0 || port > 65_535,
    return: Error(InvalidPort(port)),
  )
  Ok(Endpoint(address, port))
}

/// Parse `IPv4:port` or `[IPv6]:port` without performing DNS resolution.
pub fn parse_endpoint(value: String) -> Result(Endpoint, Error) {
  case string.starts_with(value, "[") {
    True -> parse_ipv6_endpoint(value)
    False -> parse_ipv4_endpoint(value)
  }
}

fn parse_ipv4_endpoint(value: String) -> Result(Endpoint, Error) {
  use #(literal, raw_port) <- result.try(
    string.split_once(value, ":")
    |> result.replace_error(InvalidEndpoint(value)),
  )
  use _ <- result.try(case string.contains(raw_port, ":") {
    True -> Error(InvalidEndpoint(value))
    False -> Ok(Nil)
  })
  build_parsed_endpoint(value, literal, raw_port)
}

fn parse_ipv6_endpoint(value: String) -> Result(Endpoint, Error) {
  use #(literal, raw_port) <- result.try(
    value
    |> string.drop_start(1)
    |> string.split_once("]:")
    |> result.replace_error(InvalidEndpoint(value)),
  )
  use parsed <- result.try(build_parsed_endpoint(value, literal, raw_port))
  case family(parsed.address) {
    Ipv6 -> Ok(parsed)
    Ipv4 -> Error(InvalidEndpoint(value))
  }
}

fn build_parsed_endpoint(
  original: String,
  literal: String,
  raw_port: String,
) -> Result(Endpoint, Error) {
  use address <- result.try(
    parse(literal) |> result.replace_error(InvalidEndpoint(original)),
  )
  use port <- result.try(
    int.parse(raw_port)
    |> result.replace_error(InvalidEndpoint(original)),
  )
  endpoint(address, port)
  |> result.replace_error(InvalidEndpoint(original))
}

/// Return an endpoint's address.
pub fn endpoint_address(value: Endpoint) -> Address {
  value.address
}

/// Return an endpoint's port.
pub fn port(value: Endpoint) -> Int {
  value.port
}

/// Return `IPv4:port` or `[IPv6]:port` in canonical form.
pub fn endpoint_to_string(value: Endpoint) -> String {
  case family(value.address) {
    Ipv4 -> value.address.display <> ":" <> int.to_string(value.port)
    Ipv6 -> "[" <> value.address.display <> "]:" <> int.to_string(value.port)
  }
}

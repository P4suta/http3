//// Runtime capability probe and small transport-neutral value types for the
//// repository-owned QUIC implementation.

import gleam/bit_array

/// Address-family policy for generic QUIC endpoints.
pub type AddressFamily {
  Ipv4
  Ipv6
  DualStack
}

/// Preferred QUIC wire version. Compatible version negotiation remains
/// enabled for clients.
pub type Version {
  QuicV1
  QuicV2
}

/// Implemented congestion controller for a connection path.
pub type CongestionControl {
  NewReno
  Cubic
}

/// A validated IPv4 or IPv6 literal in network byte order.
///
/// This is deliberately not an endpoint or socket address. It lets callers
/// select an exact dial or bind address without exposing the runtime UDP type.
pub opaque type IpAddress {
  IpAddress(bytes: BitArray)
}

/// Invalid network-order IP literal input.
pub type AddressError {
  InvalidIpAddress
}

/// Validate four-byte IPv4 or sixteen-byte IPv6 address bytes.
pub fn ip_address(bytes: BitArray) -> Result(IpAddress, AddressError) {
  case bit_array.bit_size(bytes) % 8, bit_array.byte_size(bytes) {
    0, 4 | 0, 16 -> Ok(IpAddress(bytes))
    _, _ -> Error(InvalidIpAddress)
  }
}

/// Return the four or sixteen network-order bytes of an IP literal.
pub fn ip_address_bytes(address: IpAddress) -> BitArray {
  address.bytes
}

/// A QUIC stream identifier kept distinct from application integers.
///
/// The numeric field is public because application protocols such as HTTP/3
/// carry the QUIC stream identifier in their own control messages. It is not a
/// runtime handle and grants no access to a connection or stream actor.
pub type StreamId {
  StreamId(value: Int)
}

/// Endpoint which initiated a typed stream identifier.
pub type StreamInitiator {
  ClientInitiated
  ServerInitiated
}

/// Direction encoded by a typed stream identifier.
pub type StreamDirection {
  BidirectionalStream
  UnidirectionalStream
}

/// Validated QUIC application close code.
pub opaque type ApplicationErrorCode {
  ApplicationErrorCode(value: Int)
}

/// Invalid application close-code input.
pub type CodeError {
  InvalidApplicationErrorCode(Int)
}

/// Return the integer carried by a typed stream identifier.
pub fn stream_id_value(identifier: StreamId) -> Int {
  identifier.value
}

/// Return which endpoint initiated a typed stream identifier.
pub fn stream_initiator(identifier: StreamId) -> StreamInitiator {
  case identifier.value % 2 {
    0 -> ClientInitiated
    _ -> ServerInitiated
  }
}

/// Return whether a typed stream identifier is bidirectional.
pub fn stream_direction(identifier: StreamId) -> StreamDirection {
  case identifier.value % 4 {
    0 | 1 -> BidirectionalStream
    _ -> UnidirectionalStream
  }
}

/// Validate an application close code in QUIC's 62-bit integer range.
pub fn application_error_code(
  value: Int,
) -> Result(ApplicationErrorCode, CodeError) {
  case value >= 0 && value <= 4_611_686_018_427_387_903 {
    True -> Ok(ApplicationErrorCode(value))
    False -> Error(InvalidApplicationErrorCode(value))
  }
}

/// Return the validated integer application close code.
pub fn application_error_code_value(code: ApplicationErrorCode) -> Int {
  code.value
}

/// Return whether the Erlang runtime provides every mandatory cryptographic
/// primitive used by the native QUIC/TLS implementation.
@external(erlang, "quic_core_crypto_ffi", "is_supported")
pub fn is_supported() -> Bool

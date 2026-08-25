//// Runtime capability probe for the repository-owned QUIC implementation.

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

/// Return whether the Erlang runtime provides every mandatory cryptographic
/// primitive used by the native QUIC/TLS implementation.
@external(erlang, "gleam_quic_crypto_ffi", "is_supported")
pub fn is_supported() -> Bool

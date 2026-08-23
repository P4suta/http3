//// Runtime capability probe for the repository-owned QUIC implementation.

/// Return whether the Erlang runtime provides every mandatory cryptographic
/// primitive used by the native QUIC/TLS implementation.
@external(erlang, "gleam_quic_crypto_ffi", "is_supported")
pub fn is_supported() -> Bool

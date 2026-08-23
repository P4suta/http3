//// TLS 1.3 X25519 key agreement with opaque private-key ownership.

import gleam/bit_array

/// A generated X25519 key pair. The private scalar has no accessor.
pub opaque type KeyPair {
  KeyPair(public_key: BitArray, private_key: BitArray)
}

/// An X25519 generation or peer-key failure.
pub type Error {
  NonByteAligned
  InvalidPrivateKey
  InvalidPeerKey
  WeakSharedSecret
  CryptoUnavailable
}

@external(erlang, "gleam_quic_crypto_ffi", "x25519_generate")
fn raw_generate_x25519() -> Result(#(BitArray, BitArray), Int)

@external(erlang, "gleam_quic_crypto_ffi", "x25519_public")
fn raw_x25519_public(private_key: BitArray) -> Result(BitArray, Int)

@external(erlang, "gleam_quic_crypto_ffi", "x25519_shared")
fn raw_x25519_shared(
  private_key: BitArray,
  peer_public_key: BitArray,
) -> Result(BitArray, Int)

/// Generate a cryptographically random X25519 key pair.
pub fn generate_x25519() -> Result(KeyPair, Error) {
  case raw_generate_x25519() {
    Ok(#(public_key, private_key)) ->
      case
        bit_array.byte_size(public_key) == 32
        && bit_array.byte_size(private_key) == 32
      {
        True -> Ok(KeyPair(public_key, private_key))
        False -> Error(CryptoUnavailable)
      }
    Error(_) -> Error(CryptoUnavailable)
  }
}

/// Reconstruct an X25519 key pair from a 32-byte private scalar.
///
/// This exists for deterministic vectors and controlled key restoration; normal
/// handshakes generate fresh keys with `generate_x25519`.
pub fn from_x25519_private(
  private_key private_key: BitArray,
) -> Result(KeyPair, Error) {
  case byte_aligned(private_key) {
    False -> Error(NonByteAligned)
    True ->
      case bit_array.byte_size(private_key) == 32 {
        False -> Error(InvalidPrivateKey)
        True ->
          case raw_x25519_public(private_key) {
            Ok(public_key) -> Ok(KeyPair(public_key, private_key))
            Error(1) -> Error(InvalidPrivateKey)
            Error(_) -> Error(CryptoUnavailable)
          }
      }
  }
}

/// Return the key-share bytes safe to send to a peer.
pub fn public_key(key_pair key_pair: KeyPair) -> BitArray {
  key_pair.public_key
}

/// Compute and validate an X25519 shared secret.
pub fn shared_secret(
  key_pair key_pair: KeyPair,
  peer_public_key peer_public_key: BitArray,
) -> Result(BitArray, Error) {
  case byte_aligned(peer_public_key) {
    False -> Error(NonByteAligned)
    True ->
      case bit_array.byte_size(peer_public_key) == 32 {
        False -> Error(InvalidPeerKey)
        True ->
          case raw_x25519_shared(key_pair.private_key, peer_public_key) {
            Ok(<<0:256>>) -> Error(WeakSharedSecret)
            Ok(secret) -> Ok(secret)
            Error(1) -> Error(InvalidPeerKey)
            Error(4) -> Error(WeakSharedSecret)
            Error(_) -> Error(CryptoUnavailable)
          }
      }
  }
}

fn byte_aligned(bytes: BitArray) -> Bool {
  bit_array.bit_size(bytes) % 8 == 0
}

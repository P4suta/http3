//// RFC 9001 AEAD confidentiality and forgery-attempt accounting.

import gleam/result
import gleam_quic/internal/tls/hello

/// Per-algorithm packet limits for one connection.
pub type Limits {
  Limits(confidentiality: Int, integrity: Int)
}

/// Connection-wide counters. Encryption resets on key update; failures do not.
pub opaque type Usage {
  Usage(
    cipher_suite: hello.CipherSuite,
    encrypted_packets: Int,
    authentication_failures: Int,
  )
}

/// A restored counter or usage-limit failure.
pub type Error {
  InvalidCount
  UnsupportedCipherSuite(hello.CipherSuite)
  ConfidentialityLimitReached
  IntegrityLimitReached
}

/// Return the conservative RFC 9001 limits for unrestricted packet sizes.
pub fn limits(cipher_suite: hello.CipherSuite) -> Result(Limits, Error) {
  case cipher_suite {
    hello.Aes128GcmSha256 | hello.Aes256GcmSha384 ->
      Ok(Limits(8_388_608, 4_503_599_627_370_496))
    hello.Chacha20Poly1305Sha256 ->
      Ok(Limits(4_611_686_018_427_387_904, 68_719_476_736))
    unsupported -> Error(UnsupportedCipherSuite(unsupported))
  }
}

/// Create zeroed counters for a negotiated QUIC cipher suite.
pub fn new(cipher_suite: hello.CipherSuite) -> Result(Usage, Error) {
  restore(cipher_suite, encrypted_packets: 0, authentication_failures: 0)
}

/// Restore validated counters after connection-state handoff.
pub fn restore(
  cipher_suite: hello.CipherSuite,
  encrypted_packets encrypted_packets: Int,
  authentication_failures authentication_failures: Int,
) -> Result(Usage, Error) {
  case encrypted_packets < 0 || authentication_failures < 0 {
    True -> Error(InvalidCount)
    False -> {
      use Limits(confidentiality, integrity) <- result.try(limits(cipher_suite))
      case
        encrypted_packets > confidentiality
        || authentication_failures > integrity
      {
        True -> Error(InvalidCount)
        False ->
          Ok(Usage(cipher_suite, encrypted_packets, authentication_failures))
      }
    }
  }
}

/// Account for one successfully protected packet under the current write key.
pub fn record_encrypted(usage: Usage) -> Result(Usage, Error) {
  let Usage(cipher_suite, encrypted_packets, authentication_failures) = usage
  use Limits(confidentiality, _) <- result.try(limits(cipher_suite))
  case encrypted_packets >= confidentiality {
    True -> Error(ConfidentialityLimitReached)
    False ->
      Ok(Usage(cipher_suite, encrypted_packets + 1, authentication_failures))
  }
}

/// Account for a packet that failed authentication across all read keys.
pub fn record_authentication_failure(usage: Usage) -> Result(Usage, Error) {
  let Usage(cipher_suite, encrypted_packets, authentication_failures) = usage
  use Limits(_, integrity) <- result.try(limits(cipher_suite))
  case authentication_failures >= integrity {
    True -> Error(IntegrityLimitReached)
    False ->
      Ok(Usage(cipher_suite, encrypted_packets, authentication_failures + 1))
  }
}

/// Return whether another packet would consume the final permitted nonce.
pub fn needs_key_update(usage: Usage) -> Bool {
  let Usage(cipher_suite, encrypted_packets, _) = usage
  case cipher_suite {
    hello.Aes128GcmSha256 | hello.Aes256GcmSha384 ->
      encrypted_packets >= 8_388_607
    hello.Chacha20Poly1305Sha256 ->
      encrypted_packets >= 4_611_686_018_427_387_903
    _ -> True
  }
}

/// Start counting encryption under newly installed write keys.
pub fn reset_encryption(usage: Usage) -> Usage {
  let Usage(cipher_suite, _, authentication_failures) = usage
  Usage(cipher_suite, 0, authentication_failures)
}

/// Inspect the write-key count for scheduling and diagnostics.
pub fn encrypted_packets(usage: Usage) -> Int {
  usage.encrypted_packets
}

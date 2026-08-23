//// QUIC Handshake, 0-RTT, and 1-RTT traffic-key derivation and AEAD dispatch.

import gleam/bit_array
import gleam/int
import gleam/result
import gleam_quic/internal/crypto
import gleam_quic/internal/tls/hello
import gleam_quic/internal/tls/key_schedule
import gleam_quic/varint
import gleam_quic/version.{type Version}

/// Fully derived packet and header-protection material for one traffic secret.
pub type TrafficKeys {
  TrafficKeys(
    version: Version,
    cipher_suite: hello.CipherSuite,
    hash_algorithm: crypto.HashAlgorithm,
    secret: BitArray,
    key: BitArray,
    iv: BitArray,
    header_protection_key: BitArray,
  )
}

/// Traffic-key derivation or packet-protection failure.
pub type Error {
  NonByteAligned
  InvalidInput
  UnsupportedVersion(Version)
  UnsupportedCipherSuite(hello.CipherSuite)
  CryptoFailure(crypto.Error)
}

/// Derive packet keys from a TLS traffic secret for QUIC v1 or v2.
pub fn from_secret(
  version version_value: Version,
  cipher_suite cipher_suite: hello.CipherSuite,
  secret secret: BitArray,
) -> Result(TrafficKeys, Error) {
  use hash_algorithm <- result.try(cipher_hash(cipher_suite))
  use #(key_label, iv_label, header_label, _) <- result.try(labels(
    version_value,
  ))
  let key_length = cipher_key_length(cipher_suite)
  use key <- result.try(
    key_schedule.expand_label(
      hash_algorithm,
      secret,
      key_label,
      <<>>,
      key_length,
    )
    |> map_crypto_result,
  )
  use iv <- result.try(
    key_schedule.expand_label(hash_algorithm, secret, iv_label, <<>>, 12)
    |> map_crypto_result,
  )
  use header_protection_key <- result.try(
    key_schedule.expand_label(
      hash_algorithm,
      secret,
      header_label,
      <<>>,
      key_length,
    )
    |> map_crypto_result,
  )
  Ok(TrafficKeys(
    version: version_value,
    cipher_suite:,
    hash_algorithm:,
    secret:,
    key:,
    iv:,
    header_protection_key:,
  ))
}

/// Derive the next QUIC traffic secret for a local or peer key phase.
pub fn next_secret(keys keys: TrafficKeys) -> Result(BitArray, Error) {
  use #(_, _, _, update_label) <- result.try(labels(keys.version))
  key_schedule.expand_label(
    keys.hash_algorithm,
    keys.secret,
    update_label,
    <<>>,
    crypto.hash_length(keys.hash_algorithm),
  )
  |> map_crypto_result
}

/// Generate the first five bytes of the QUIC header-protection mask.
pub fn header_protection_mask(
  keys keys: TrafficKeys,
  sample sample: BitArray,
) -> Result(BitArray, Error) {
  let protected = case keys.cipher_suite {
    hello.Aes128GcmSha256 ->
      crypto.aes_128_ecb_encrypt(keys.header_protection_key, sample)
    hello.Aes256GcmSha384 ->
      crypto.aes_256_ecb_encrypt(keys.header_protection_key, sample)
    hello.Chacha20Poly1305Sha256 ->
      crypto.chacha20_header_mask(keys.header_protection_key, sample)
    _ -> Error(crypto.InvalidInput)
  }
  protected |> map_crypto_result
}

/// Encrypt and authenticate a QUIC packet payload.
pub fn protect(
  keys keys: TrafficKeys,
  packet_number packet_number: Int,
  header header: BitArray,
  plaintext plaintext: BitArray,
) -> Result(BitArray, Error) {
  use packet_nonce <- result.try(nonce(keys.iv, packet_number))
  let protected = case keys.cipher_suite {
    hello.Aes128GcmSha256 ->
      crypto.aes_128_gcm_encrypt(keys.key, packet_nonce, header, plaintext)
    hello.Aes256GcmSha384 ->
      crypto.aes_256_gcm_encrypt(keys.key, packet_nonce, header, plaintext)
    hello.Chacha20Poly1305Sha256 ->
      crypto.chacha20_poly1305_encrypt(
        keys.key,
        packet_nonce,
        header,
        plaintext,
      )
    _ -> Error(crypto.InvalidInput)
  }
  protected |> map_crypto_result
}

/// Authenticate and decrypt a QUIC packet payload.
pub fn unprotect(
  keys keys: TrafficKeys,
  packet_number packet_number: Int,
  header header: BitArray,
  protected protected: BitArray,
) -> Result(BitArray, Error) {
  use packet_nonce <- result.try(nonce(keys.iv, packet_number))
  let plaintext = case keys.cipher_suite {
    hello.Aes128GcmSha256 ->
      crypto.aes_128_gcm_decrypt(keys.key, packet_nonce, header, protected)
    hello.Aes256GcmSha384 ->
      crypto.aes_256_gcm_decrypt(keys.key, packet_nonce, header, protected)
    hello.Chacha20Poly1305Sha256 ->
      crypto.chacha20_poly1305_decrypt(
        keys.key,
        packet_nonce,
        header,
        protected,
      )
    _ -> Error(crypto.InvalidInput)
  }
  plaintext |> map_crypto_result
}

fn cipher_hash(
  cipher_suite: hello.CipherSuite,
) -> Result(crypto.HashAlgorithm, Error) {
  case cipher_suite {
    hello.Aes128GcmSha256 | hello.Chacha20Poly1305Sha256 -> Ok(crypto.Sha256)
    hello.Aes256GcmSha384 -> Ok(crypto.Sha384)
    unsupported -> Error(UnsupportedCipherSuite(unsupported))
  }
}

fn cipher_key_length(cipher_suite: hello.CipherSuite) -> Int {
  case cipher_suite {
    hello.Aes128GcmSha256 -> 16
    _ -> 32
  }
}

fn labels(
  version_value: Version,
) -> Result(#(BitArray, BitArray, BitArray, BitArray), Error) {
  case version_value {
    version.Version1 ->
      Ok(#(<<"quic key">>, <<"quic iv">>, <<"quic hp">>, <<"quic ku">>))
    version.Version2 ->
      Ok(#(<<"quicv2 key">>, <<"quicv2 iv">>, <<"quicv2 hp">>, <<"quicv2 ku">>))
    _ -> Error(UnsupportedVersion(version_value))
  }
}

fn nonce(iv: BitArray, packet_number: Int) -> Result(BitArray, Error) {
  case bit_array.bit_size(iv) % 8 {
    remainder if remainder != 0 -> Error(NonByteAligned)
    _ ->
      case
        bit_array.byte_size(iv) == 12
        && packet_number >= 0
        && packet_number <= varint.maximum
      {
        False -> Error(InvalidInput)
        True -> xor_bytes(iv, <<packet_number:size(96)>>, <<>>)
      }
  }
}

fn xor_bytes(
  left: BitArray,
  right: BitArray,
  accumulator: BitArray,
) -> Result(BitArray, Error) {
  case left, right {
    <<>>, <<>> -> Ok(accumulator)
    <<left_byte, left_rest:bits>>, <<right_byte, right_rest:bits>> ->
      xor_bytes(left_rest, right_rest, <<
        accumulator:bits,
        int.bitwise_exclusive_or(left_byte, right_byte),
      >>)
    _, _ -> Error(InvalidInput)
  }
}

fn map_crypto_result(
  value: Result(BitArray, crypto.Error),
) -> Result(BitArray, Error) {
  case value {
    Ok(bytes) -> Ok(bytes)
    Error(crypto.NonByteAligned) -> Error(NonByteAligned)
    Error(crypto.InvalidInput) | Error(crypto.OutputTooLong) ->
      Error(InvalidInput)
    Error(error) -> Error(CryptoFailure(error))
  }
}

//// Bounded cryptographic primitives and the TLS 1.3 HKDF construction.

import gleam/bit_array
import gleam/result

const maximum_info_length = 65_535

/// A hash algorithm permitted by the TLS 1.3 cipher suites supported here.
pub type HashAlgorithm {
  Sha256
  Sha384
}

/// A cryptographic primitive or input failure.
pub type Error {
  NonByteAligned
  InvalidInput
  OutputTooLong
  CryptoUnavailable
  AuthenticationFailed
}

@external(erlang, "gleam_quic_crypto_ffi", "hmac_sha256")
fn raw_hmac_sha256(key: BitArray, data: BitArray) -> Result(BitArray, Int)

@external(erlang, "gleam_quic_crypto_ffi", "hmac_sha384")
fn raw_hmac_sha384(key: BitArray, data: BitArray) -> Result(BitArray, Int)

@external(erlang, "gleam_quic_crypto_ffi", "hash_sha256")
fn raw_hash_sha256(data: BitArray) -> Result(BitArray, Int)

@external(erlang, "gleam_quic_crypto_ffi", "hash_sha384")
fn raw_hash_sha384(data: BitArray) -> Result(BitArray, Int)

@external(erlang, "gleam_quic_crypto_ffi", "aes_128_ecb_encrypt")
fn raw_aes_128_ecb_encrypt(
  key: BitArray,
  block: BitArray,
) -> Result(BitArray, Int)

@external(erlang, "gleam_quic_crypto_ffi", "aes_128_gcm_encrypt")
fn raw_aes_128_gcm_encrypt(
  key: BitArray,
  nonce: BitArray,
  associated_data: BitArray,
  plaintext: BitArray,
) -> Result(BitArray, Int)

@external(erlang, "gleam_quic_crypto_ffi", "aes_128_gcm_decrypt")
fn raw_aes_128_gcm_decrypt(
  key: BitArray,
  nonce: BitArray,
  associated_data: BitArray,
  protected: BitArray,
) -> Result(BitArray, Int)

/// Return the output size of a supported hash in bytes.
pub fn hash_length(algorithm: HashAlgorithm) -> Int {
  case algorithm {
    Sha256 -> 32
    Sha384 -> 48
  }
}

/// Hash a byte-aligned message.
pub fn hash(
  algorithm algorithm: HashAlgorithm,
  data data: BitArray,
) -> Result(BitArray, Error) {
  case byte_aligned(data) {
    False -> Error(NonByteAligned)
    True ->
      case algorithm {
        Sha256 -> raw_hash_sha256(data)
        Sha384 -> raw_hash_sha384(data)
      }
      |> map_raw_result
  }
}

/// Compute HMAC with a TLS 1.3 hash algorithm.
pub fn hmac(
  algorithm algorithm: HashAlgorithm,
  key key: BitArray,
  data data: BitArray,
) -> Result(BitArray, Error) {
  case byte_aligned(key) && byte_aligned(data) {
    False -> Error(NonByteAligned)
    True ->
      case algorithm {
        Sha256 -> raw_hmac_sha256(key, data)
        Sha384 -> raw_hmac_sha384(key, data)
      }
      |> map_raw_result
  }
}

/// HKDF-Extract using a TLS 1.3 hash algorithm.
pub fn hkdf_extract(
  algorithm algorithm: HashAlgorithm,
  salt salt: BitArray,
  input_key_material input_key_material: BitArray,
) -> Result(BitArray, Error) {
  case byte_aligned(salt) && byte_aligned(input_key_material) {
    False -> Error(NonByteAligned)
    True -> hmac(algorithm: algorithm, key: salt, data: input_key_material)
  }
}

/// HKDF-Expand using a TLS 1.3 hash algorithm.
pub fn hkdf_expand(
  algorithm algorithm: HashAlgorithm,
  pseudorandom_key pseudorandom_key: BitArray,
  info info: BitArray,
  output_length output_length: Int,
) -> Result(BitArray, Error) {
  case byte_aligned(pseudorandom_key) && byte_aligned(info) {
    False -> Error(NonByteAligned)
    True -> {
      let digest_length = hash_length(algorithm)
      case
        bit_array.byte_size(pseudorandom_key) != digest_length
        || bit_array.byte_size(info) > maximum_info_length
        || output_length < 0
      {
        True -> Error(InvalidInput)
        False if output_length > digest_length * 255 -> Error(OutputTooLong)
        False if output_length == 0 -> Ok(<<>>)
        False ->
          expand_blocks(
            algorithm,
            pseudorandom_key,
            info,
            output_length,
            1,
            <<>>,
            <<>>,
          )
      }
    }
  }
}

/// HKDF-Extract using HMAC-SHA256.
pub fn hkdf_extract_sha256(
  salt salt: BitArray,
  input_key_material input_key_material: BitArray,
) -> Result(BitArray, Error) {
  hkdf_extract(
    algorithm: Sha256,
    salt: salt,
    input_key_material: input_key_material,
  )
}

/// HKDF-Expand using HMAC-SHA256.
pub fn hkdf_expand_sha256(
  pseudorandom_key pseudorandom_key: BitArray,
  info info: BitArray,
  output_length output_length: Int,
) -> Result(BitArray, Error) {
  hkdf_expand(
    algorithm: Sha256,
    pseudorandom_key: pseudorandom_key,
    info: info,
    output_length: output_length,
  )
}

/// Encrypt one 16-byte block using AES-128-ECB.
///
/// QUIC uses this primitive only to generate an AES header-protection mask.
pub fn aes_128_ecb_encrypt(
  key key: BitArray,
  block block: BitArray,
) -> Result(BitArray, Error) {
  case byte_aligned(key) && byte_aligned(block) {
    False -> Error(NonByteAligned)
    True ->
      case bit_array.byte_size(key) == 16 && bit_array.byte_size(block) == 16 {
        False -> Error(InvalidInput)
        True -> raw_aes_128_ecb_encrypt(key, block) |> map_raw_result
      }
  }
}

/// Encrypt and authenticate bytes using AES-128-GCM with a 16-byte tag.
pub fn aes_128_gcm_encrypt(
  key key: BitArray,
  nonce nonce: BitArray,
  associated_data associated_data: BitArray,
  plaintext plaintext: BitArray,
) -> Result(BitArray, Error) {
  case
    byte_aligned(key)
    && byte_aligned(nonce)
    && byte_aligned(associated_data)
    && byte_aligned(plaintext)
  {
    False -> Error(NonByteAligned)
    True ->
      case bit_array.byte_size(key) == 16 && bit_array.byte_size(nonce) == 12 {
        False -> Error(InvalidInput)
        True ->
          raw_aes_128_gcm_encrypt(key, nonce, associated_data, plaintext)
          |> map_raw_result
      }
  }
}

/// Authenticate and decrypt AES-128-GCM bytes carrying a 16-byte tag.
pub fn aes_128_gcm_decrypt(
  key key: BitArray,
  nonce nonce: BitArray,
  associated_data associated_data: BitArray,
  protected protected: BitArray,
) -> Result(BitArray, Error) {
  case
    byte_aligned(key)
    && byte_aligned(nonce)
    && byte_aligned(associated_data)
    && byte_aligned(protected)
  {
    False -> Error(NonByteAligned)
    True ->
      case
        bit_array.byte_size(key) == 16
        && bit_array.byte_size(nonce) == 12
        && bit_array.byte_size(protected) >= 16
      {
        False -> Error(InvalidInput)
        True ->
          raw_aes_128_gcm_decrypt(key, nonce, associated_data, protected)
          |> map_raw_result
      }
  }
}

fn expand_blocks(
  algorithm: HashAlgorithm,
  pseudorandom_key: BitArray,
  info: BitArray,
  output_length: Int,
  counter: Int,
  previous: BitArray,
  accumulator: BitArray,
) -> Result(BitArray, Error) {
  case bit_array.byte_size(accumulator) >= output_length {
    True -> take_prefix(accumulator, output_length)
    False -> {
      use next <- result.try(
        hmac(algorithm: algorithm, key: pseudorandom_key, data: <<
          previous:bits,
          info:bits,
          counter,
        >>),
      )
      expand_blocks(
        algorithm,
        pseudorandom_key,
        info,
        output_length,
        counter + 1,
        next,
        <<accumulator:bits, next:bits>>,
      )
    }
  }
}

fn map_raw_result(
  result_value: Result(BitArray, Int),
) -> Result(BitArray, Error) {
  case result_value {
    Ok(value) -> Ok(value)
    Error(1) -> Error(InvalidInput)
    Error(3) -> Error(AuthenticationFailed)
    Error(_) -> Error(CryptoUnavailable)
  }
}

fn take_prefix(bytes: BitArray, length: Int) -> Result(BitArray, Error) {
  let bit_length = length * 8
  case bytes {
    <<prefix:bits-size(bit_length), _:bits>> -> Ok(prefix)
    _ -> Error(InvalidInput)
  }
}

fn byte_aligned(bytes: BitArray) -> Bool {
  bit_array.bit_size(bytes) % 8 == 0
}

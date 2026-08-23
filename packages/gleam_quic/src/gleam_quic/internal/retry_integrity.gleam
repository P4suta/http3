//// QUIC v1/v2 Retry Integrity Tag generation and verification.

import gleam/bit_array
import gleam/int
import gleam/result
import gleam_quic/internal/crypto
import gleam_quic/version.{type Version}

const v1_key = <<
  0xbe,
  0x0c,
  0x69,
  0x0b,
  0x9f,
  0x66,
  0x57,
  0x5a,
  0x1d,
  0x76,
  0x6b,
  0x54,
  0xe3,
  0x68,
  0xc8,
  0x4e,
>>

const v1_nonce = <<
  0x46,
  0x15,
  0x99,
  0xd3,
  0x5d,
  0x63,
  0x2b,
  0xf2,
  0x23,
  0x98,
  0x25,
  0xbb,
>>

const v2_key = <<
  0x8f,
  0xb4,
  0xb0,
  0x1b,
  0x56,
  0xac,
  0x48,
  0xe2,
  0x60,
  0xfb,
  0xcb,
  0xce,
  0xad,
  0x7c,
  0xcc,
  0x92,
>>

const v2_nonce = <<
  0xd8,
  0x69,
  0x69,
  0xbc,
  0x2d,
  0x7c,
  0x6d,
  0x99,
  0x90,
  0xef,
  0xb0,
  0x4a,
>>

/// A Retry integrity input or authentication failure.
pub type Error {
  NonByteAligned
  InvalidInput
  UnsupportedVersion(Version)
  CryptoUnavailable
  AuthenticationFailed
}

/// Generate the 16-byte Retry Integrity Tag for a Retry packet without a tag.
pub fn tag(
  version version: Version,
  original_destination_connection_id original_destination_connection_id: BitArray,
  retry_without_tag retry_without_tag: BitArray,
) -> Result(BitArray, Error) {
  use #(key, nonce, pseudo_packet) <- result.try(inputs(
    version,
    original_destination_connection_id,
    retry_without_tag,
  ))
  crypto.aes_128_gcm_encrypt(key, nonce, pseudo_packet, <<>>)
  |> map_crypto_result
}

/// Authenticate a received Retry Integrity Tag.
pub fn verify(
  version version: Version,
  original_destination_connection_id original_destination_connection_id: BitArray,
  retry_without_tag retry_without_tag: BitArray,
  integrity_tag integrity_tag: BitArray,
) -> Result(Nil, Error) {
  use #(key, nonce, pseudo_packet) <- result.try(inputs(
    version,
    original_destination_connection_id,
    retry_without_tag,
  ))
  case byte_aligned(integrity_tag) {
    False -> Error(NonByteAligned)
    True ->
      case bit_array.byte_size(integrity_tag) != 16 {
        True -> Error(InvalidInput)
        False ->
          case
            crypto.aes_128_gcm_decrypt(key, nonce, pseudo_packet, integrity_tag)
          {
            Ok(<<>>) -> Ok(Nil)
            Ok(_) -> Error(InvalidInput)
            Error(error) -> map_crypto_error(error)
          }
      }
  }
}

fn inputs(
  version_value: Version,
  original_destination_connection_id: BitArray,
  retry_without_tag: BitArray,
) -> Result(#(BitArray, BitArray, BitArray), Error) {
  use #(key, nonce) <- result.try(key_and_nonce(version_value))
  case
    byte_aligned(original_destination_connection_id)
    && byte_aligned(retry_without_tag)
  {
    False -> Error(NonByteAligned)
    True -> {
      let original_length =
        bit_array.byte_size(original_destination_connection_id)
      case
        original_length > 20
        || !valid_retry_without_tag(version_value, retry_without_tag)
      {
        True -> Error(InvalidInput)
        False ->
          Ok(
            #(key, nonce, <<
              original_length,
              original_destination_connection_id:bits,
              retry_without_tag:bits,
            >>),
          )
      }
    }
  }
}

fn key_and_nonce(
  version_value: Version,
) -> Result(#(BitArray, BitArray), Error) {
  case version_value {
    version.Version1 -> Ok(#(v1_key, v1_nonce))
    version.Version2 -> Ok(#(v2_key, v2_nonce))
    _ -> Error(UnsupportedVersion(version_value))
  }
}

fn valid_retry_without_tag(
  version_value: Version,
  retry_without_tag: BitArray,
) -> Bool {
  case retry_without_tag {
    <<first_byte, wire_version:size(32), destination_length, rest:bits>> ->
      case
        int.bitwise_and(first_byte, 0xc0) != 0xc0 || destination_length > 20
      {
        True -> False
        False ->
          case version.to_wire(version_value) {
            Ok(expected_wire) if wire_version == expected_wire ->
              valid_retry_type_and_ids(
                version_value,
                first_byte,
                destination_length,
                rest,
              )
            _ -> False
          }
      }
    _ -> False
  }
}

fn valid_retry_type_and_ids(
  version_value: Version,
  first_byte: Int,
  destination_length: Int,
  bytes: BitArray,
) -> Bool {
  let type_bits =
    first_byte
    |> int.bitwise_shift_right(4)
    |> int.bitwise_and(3)
  case version.long_packet_type(version_value, type_bits) {
    Ok(version.Retry) -> valid_retry_ids(destination_length, bytes)
    _ -> False
  }
}

fn valid_retry_ids(destination_length: Int, bytes: BitArray) -> Bool {
  let destination_bits = destination_length * 8
  case bytes {
    <<_:bits-size(destination_bits), source_length, source_and_token:bits>> ->
      case source_length > 20 {
        True -> False
        False -> {
          let source_bits = source_length * 8
          case source_and_token {
            <<_:bits-size(source_bits), token:bits>> ->
              bit_array.byte_size(token) > 0
            _ -> False
          }
        }
      }
    _ -> False
  }
}

fn map_crypto_result(
  result_value: Result(BitArray, crypto.Error),
) -> Result(BitArray, Error) {
  case result_value {
    Ok(value) -> Ok(value)
    Error(error) -> map_crypto_error(error)
  }
}

fn map_crypto_error(error: crypto.Error) -> Result(a, Error) {
  case error {
    crypto.NonByteAligned -> Error(NonByteAligned)
    crypto.InvalidInput | crypto.OutputTooLong -> Error(InvalidInput)
    crypto.CryptoUnavailable -> Error(CryptoUnavailable)
    crypto.AuthenticationFailed -> Error(AuthenticationFailed)
  }
}

fn byte_aligned(bytes: BitArray) -> Bool {
  bit_array.bit_size(bytes) % 8 == 0
}

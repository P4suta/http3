//// QUIC v1/v2 Initial key derivation and AES packet-protection material.

import gleam/bit_array
import gleam/result
import gleam_quic/internal/crypto
import gleam_quic/version.{type Version}

const initial_salt_v1 = <<
  0x38,
  0x76,
  0x2c,
  0xf7,
  0xf5,
  0x59,
  0x34,
  0xb3,
  0x4d,
  0x17,
  0x9a,
  0xe6,
  0xa4,
  0xc8,
  0x0c,
  0xad,
  0xcc,
  0xbb,
  0x7f,
  0x0a,
>>

const initial_salt_v2 = <<
  0x0d,
  0xed,
  0xe3,
  0xde,
  0xf7,
  0x00,
  0xa6,
  0xdb,
  0x81,
  0x93,
  0x81,
  0xbe,
  0x6e,
  0x26,
  0x9d,
  0xcb,
  0xf9,
  0xbd,
  0x2e,
  0xd9,
>>

/// AES-128-GCM packet and header-protection keys derived from one secret.
pub type PacketKeys {
  PacketKeys(
    secret: BitArray,
    key: BitArray,
    iv: BitArray,
    header_protection_key: BitArray,
  )
}

/// The common, client, and server Initial material for one connection ID.
pub type InitialKeys {
  InitialKeys(initial_secret: BitArray, client: PacketKeys, server: PacketKeys)
}

/// A key-derivation or packet-protection primitive failure.
pub type Error {
  NonByteAligned
  InvalidInput
  UnsupportedVersion(Version)
  OutputTooLong
  CryptoUnavailable
  AuthenticationFailed
}

/// Construct the TLS 1.3 HkdfLabel encoding used by HKDF-Expand-Label.
pub fn hkdf_label(
  label label: BitArray,
  context context: BitArray,
  output_length output_length: Int,
) -> Result(BitArray, Error) {
  case byte_aligned(label) && byte_aligned(context) {
    False -> Error(NonByteAligned)
    True -> {
      let full_label = <<"tls13 ":utf8, label:bits>>
      let label_length = bit_array.byte_size(full_label)
      let context_length = bit_array.byte_size(context)
      case
        output_length < 0
        || output_length > 65_535
        || label_length < 7
        || label_length > 255
        || context_length > 255
      {
        True -> Error(InvalidInput)
        False ->
          Ok(<<
            output_length:size(16),
            label_length,
            full_label:bits,
            context_length,
            context:bits,
          >>)
      }
    }
  }
}

/// Derive the QUIC Initial secrets and AES-128-GCM keys for v1 or v2.
pub fn derive_initial(
  version version: Version,
  destination_connection_id destination_connection_id: BitArray,
) -> Result(InitialKeys, Error) {
  case byte_aligned(destination_connection_id) {
    False -> Error(NonByteAligned)
    True ->
      case bit_array.byte_size(destination_connection_id) > 20 {
        True -> Error(InvalidInput)
        False -> {
          use salt <- result.try(initial_salt(version))
          use initial_secret <- result.try(
            crypto.hkdf_extract_sha256(salt, destination_connection_id)
            |> map_crypto_result,
          )
          use client_secret <- result.try(expand_label(
            initial_secret,
            <<"client in":utf8>>,
            <<>>,
            32,
          ))
          use server_secret <- result.try(expand_label(
            initial_secret,
            <<"server in":utf8>>,
            <<>>,
            32,
          ))
          use client <- result.try(derive_packet_keys(version, client_secret))
          use server <- result.try(derive_packet_keys(version, server_secret))
          Ok(InitialKeys(initial_secret, client, server))
        }
      }
  }
}

/// Produce the first five bytes of the AES header-protection mask.
pub fn header_protection_mask(
  keys keys: PacketKeys,
  sample sample: BitArray,
) -> Result(BitArray, Error) {
  use encrypted <- result.try(
    crypto.aes_128_ecb_encrypt(keys.header_protection_key, sample)
    |> map_crypto_result,
  )
  take_prefix(encrypted, 5)
}

fn initial_salt(version_value: Version) -> Result(BitArray, Error) {
  case version_value {
    version.Version1 -> Ok(initial_salt_v1)
    version.Version2 -> Ok(initial_salt_v2)
    _ -> Error(UnsupportedVersion(version_value))
  }
}

fn derive_packet_keys(
  version_value: Version,
  secret: BitArray,
) -> Result(PacketKeys, Error) {
  use #(key_label, iv_label, header_label) <- result.try(packet_key_labels(
    version_value,
  ))
  use key <- result.try(expand_label(secret, key_label, <<>>, 16))
  use iv <- result.try(expand_label(secret, iv_label, <<>>, 12))
  use header_protection_key <- result.try(expand_label(
    secret,
    header_label,
    <<>>,
    16,
  ))
  Ok(PacketKeys(secret, key, iv, header_protection_key))
}

fn packet_key_labels(
  version_value: Version,
) -> Result(#(BitArray, BitArray, BitArray), Error) {
  case version_value {
    version.Version1 ->
      Ok(#(<<"quic key":utf8>>, <<"quic iv":utf8>>, <<"quic hp":utf8>>))
    version.Version2 ->
      Ok(#(<<"quicv2 key":utf8>>, <<"quicv2 iv":utf8>>, <<"quicv2 hp":utf8>>))
    _ -> Error(UnsupportedVersion(version_value))
  }
}

fn expand_label(
  secret: BitArray,
  label: BitArray,
  context: BitArray,
  output_length: Int,
) -> Result(BitArray, Error) {
  use encoded_label <- result.try(hkdf_label(
    label: label,
    context: context,
    output_length: output_length,
  ))
  crypto.hkdf_expand_sha256(secret, encoded_label, output_length)
  |> map_crypto_result
}

fn map_crypto_result(
  result_value: Result(BitArray, crypto.Error),
) -> Result(BitArray, Error) {
  case result_value {
    Ok(value) -> Ok(value)
    Error(crypto.NonByteAligned) -> Error(NonByteAligned)
    Error(crypto.InvalidInput) -> Error(InvalidInput)
    Error(crypto.OutputTooLong) -> Error(OutputTooLong)
    Error(crypto.CryptoUnavailable) -> Error(CryptoUnavailable)
    Error(crypto.AuthenticationFailed) -> Error(AuthenticationFailed)
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

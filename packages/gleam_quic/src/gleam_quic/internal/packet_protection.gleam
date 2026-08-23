//// QUIC AES-128-GCM payload protection and nonce construction.

import gleam/bit_array
import gleam/int
import gleam/result
import gleam_quic/internal/crypto
import gleam_quic/internal/initial_crypto.{type PacketKeys}
import gleam_quic/varint

/// A packet payload protection failure.
pub type Error {
  NonByteAligned
  InvalidInput
  CryptoUnavailable
  AuthenticationFailed
}

/// The invariant header form determines how many first-byte bits are masked.
pub type HeaderForm {
  Long
  Short
}

/// Header bytes recovered before packet-number reconstruction and AEAD.
pub type UnprotectedHeader {
  UnprotectedHeader(
    first_byte: Int,
    packet_number: BitArray,
    protected_payload: BitArray,
  )
}

/// Extract the 16-byte header-protection sample from a protected packet.
pub fn header_protection_sample(
  packet packet: BitArray,
  packet_number_offset packet_number_offset: Int,
) -> Result(BitArray, Error) {
  case byte_aligned(packet) {
    False -> Error(NonByteAligned)
    True ->
      case packet_number_offset < 0 {
        True -> Error(InvalidInput)
        False -> take_at(packet, packet_number_offset + 4, 16)
      }
  }
}

/// Apply a five-byte mask to an unprotected first byte and packet number.
pub fn protect_header(
  form form: HeaderForm,
  first_byte first_byte: Int,
  packet_number packet_number: BitArray,
  mask mask: BitArray,
) -> Result(#(Int, BitArray), Error) {
  case byte_aligned(packet_number) && byte_aligned(mask) {
    False -> Error(NonByteAligned)
    True -> {
      let packet_number_length = bit_array.byte_size(packet_number)
      case
        first_byte < 0
        || first_byte > 255
        || !form_matches(form, first_byte)
        || packet_number_length < 1
        || packet_number_length > 4
        || packet_number_length != int.bitwise_and(first_byte, 3) + 1
        || bit_array.byte_size(mask) < 5
      {
        True -> Error(InvalidInput)
        False -> {
          use #(first_mask, packet_number_mask) <- result.try(split_mask(
            mask,
            packet_number_length,
          ))
          use protected_packet_number <- result.try(
            xor_bytes(packet_number, packet_number_mask, <<>>),
          )
          let protected_first_byte =
            int.bitwise_exclusive_or(
              first_byte,
              int.bitwise_and(first_mask, first_byte_mask(form)),
            )
          Ok(#(protected_first_byte, protected_packet_number))
        }
      }
    }
  }
}

/// Remove header protection and split the encoded packet number from payload.
pub fn unprotect_header(
  form form: HeaderForm,
  protected_first_byte protected_first_byte: Int,
  protected_packet_number_and_payload protected_packet_number_and_payload: BitArray,
  mask mask: BitArray,
) -> Result(UnprotectedHeader, Error) {
  case byte_aligned(protected_packet_number_and_payload) && byte_aligned(mask) {
    False -> Error(NonByteAligned)
    True ->
      case
        protected_first_byte < 0
        || protected_first_byte > 255
        || !form_matches(form, protected_first_byte)
        || bit_array.byte_size(mask) < 5
      {
        True -> Error(InvalidInput)
        False -> {
          use #(first_mask, _) <- result.try(split_mask(mask, 1))
          let first_byte =
            int.bitwise_exclusive_or(
              protected_first_byte,
              int.bitwise_and(first_mask, first_byte_mask(form)),
            )
          let packet_number_length = int.bitwise_and(first_byte, 3) + 1
          use #(protected_packet_number, protected_payload) <- result.try(
            take_prefix_and_rest(
              protected_packet_number_and_payload,
              packet_number_length,
            ),
          )
          use #(_, packet_number_mask) <- result.try(split_mask(
            mask,
            packet_number_length,
          ))
          use packet_number <- result.try(
            xor_bytes(protected_packet_number, packet_number_mask, <<>>),
          )
          Ok(UnprotectedHeader(first_byte, packet_number, protected_payload))
        }
      }
  }
}

/// Build the QUIC AEAD nonce from an IV and packet number.
pub fn nonce(
  initialization_vector initialization_vector: BitArray,
  packet_number packet_number: Int,
) -> Result(BitArray, Error) {
  case byte_aligned(initialization_vector) {
    False -> Error(NonByteAligned)
    True ->
      case
        bit_array.byte_size(initialization_vector) != 12
        || packet_number < 0
        || packet_number > varint.maximum
      {
        True -> Error(InvalidInput)
        False ->
          xor_bytes(initialization_vector, <<packet_number:size(96)>>, <<>>)
      }
  }
}

/// Protect a payload with its unprotected QUIC header as associated data.
pub fn protect_payload(
  keys keys: PacketKeys,
  packet_number packet_number: Int,
  header header: BitArray,
  plaintext plaintext: BitArray,
) -> Result(BitArray, Error) {
  case byte_aligned(header) && byte_aligned(plaintext) {
    False -> Error(NonByteAligned)
    True -> {
      use packet_nonce <- result.try(nonce(
        initialization_vector: keys.iv,
        packet_number: packet_number,
      ))
      crypto.aes_128_gcm_encrypt(keys.key, packet_nonce, header, plaintext)
      |> map_crypto_result
    }
  }
}

/// Authenticate and decrypt a protected QUIC payload.
pub fn unprotect_payload(
  keys keys: PacketKeys,
  packet_number packet_number: Int,
  header header: BitArray,
  protected_payload protected_payload: BitArray,
) -> Result(BitArray, Error) {
  case byte_aligned(header) && byte_aligned(protected_payload) {
    False -> Error(NonByteAligned)
    True -> {
      use packet_nonce <- result.try(nonce(
        initialization_vector: keys.iv,
        packet_number: packet_number,
      ))
      crypto.aes_128_gcm_decrypt(
        keys.key,
        packet_nonce,
        header,
        protected_payload,
      )
      |> map_crypto_result
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

fn split_mask(
  mask: BitArray,
  packet_number_length: Int,
) -> Result(#(Int, BitArray), Error) {
  case mask {
    <<first_mask, packet_number_masks:bits>> -> {
      use packet_number_mask <- result.try(take_prefix(
        packet_number_masks,
        packet_number_length,
      ))
      Ok(#(first_mask, packet_number_mask))
    }
    _ -> Error(InvalidInput)
  }
}

fn first_byte_mask(form: HeaderForm) -> Int {
  case form {
    Long -> 0x0f
    Short -> 0x1f
  }
}

fn form_matches(form: HeaderForm, first_byte: Int) -> Bool {
  case form, int.bitwise_and(first_byte, 0x80) {
    Long, 0 -> False
    Long, _ -> True
    Short, 0 -> True
    Short, _ -> False
  }
}

fn take_at(
  bytes: BitArray,
  offset: Int,
  length: Int,
) -> Result(BitArray, Error) {
  case
    offset < 0 || length < 0 || offset + length > bit_array.byte_size(bytes)
  {
    True -> Error(InvalidInput)
    False -> {
      let offset_bits = offset * 8
      let length_bits = length * 8
      case bytes {
        <<_:bits-size(offset_bits), value:bits-size(length_bits), _:bits>> ->
          Ok(value)
        _ -> Error(InvalidInput)
      }
    }
  }
}

fn take_prefix(bytes: BitArray, length: Int) -> Result(BitArray, Error) {
  use #(prefix, _) <- result.try(take_prefix_and_rest(bytes, length))
  Ok(prefix)
}

fn take_prefix_and_rest(
  bytes: BitArray,
  length: Int,
) -> Result(#(BitArray, BitArray), Error) {
  case length < 0 || length > bit_array.byte_size(bytes) {
    True -> Error(InvalidInput)
    False -> {
      let bit_length = length * 8
      case bytes {
        <<prefix:bits-size(bit_length), rest:bits>> -> Ok(#(prefix, rest))
        _ -> Error(InvalidInput)
      }
    }
  }
}

fn map_crypto_result(
  result_value: Result(BitArray, crypto.Error),
) -> Result(BitArray, Error) {
  case result_value {
    Ok(value) -> Ok(value)
    Error(crypto.NonByteAligned) -> Error(NonByteAligned)
    Error(crypto.InvalidInput) | Error(crypto.OutputTooLong) ->
      Error(InvalidInput)
    Error(crypto.CryptoUnavailable) -> Error(CryptoUnavailable)
    Error(crypto.AuthenticationFailed) -> Error(AuthenticationFailed)
  }
}

fn byte_aligned(bytes: BitArray) -> Bool {
  bit_array.bit_size(bytes) % 8 == 0
}

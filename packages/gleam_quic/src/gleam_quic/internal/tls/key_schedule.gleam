//// TLS 1.3 key schedule primitives shared by QUIC encryption levels.

import gleam/bit_array
import gleam/option.{type Option, None, Some}
import gleam/result
import gleam_quic/internal/crypto.{type Error, type HashAlgorithm}

const tls_13_label_prefix_length = 6

const maximum_label_length = 249

const maximum_context_length = 255

/// Secrets established after processing ClientHello and ServerHello.
pub type HandshakeSecrets {
  HandshakeSecrets(
    early_secret: BitArray,
    handshake_secret: BitArray,
    client_handshake_traffic_secret: BitArray,
    server_handshake_traffic_secret: BitArray,
    master_secret: BitArray,
  )
}

/// Application traffic and exporter secrets established after server Finished.
pub type ApplicationSecrets {
  ApplicationSecrets(
    client_application_traffic_secret: BitArray,
    server_application_traffic_secret: BitArray,
    exporter_master_secret: BitArray,
  )
}

/// TLS 1.3 HKDF-Expand-Label.
pub fn expand_label(
  algorithm algorithm: HashAlgorithm,
  secret secret: BitArray,
  label label: BitArray,
  context context: BitArray,
  output_length output_length: Int,
) -> Result(BitArray, Error) {
  case byte_aligned(secret) && byte_aligned(label) && byte_aligned(context) {
    False -> Error(crypto.NonByteAligned)
    True -> {
      let label_length = bit_array.byte_size(label)
      let context_length = bit_array.byte_size(context)
      case
        bit_array.byte_size(secret) != crypto.hash_length(algorithm)
        || label_length < 1
        || label_length > maximum_label_length
        || context_length > maximum_context_length
        || output_length < 0
        || output_length > 65_535
      {
        True -> Error(crypto.InvalidInput)
        False -> {
          let full_label_length = tls_13_label_prefix_length + label_length
          crypto.hkdf_expand(
            algorithm,
            secret,
            <<
              output_length:16,
              full_label_length,
              "tls13 ",
              label:bits,
              context_length,
              context:bits,
            >>,
            output_length,
          )
        }
      }
    }
  }
}

// Derive a secret using an already-computed transcript hash.
// nolint: unused_exports -- composed by the bounded TLS state machine.
pub fn derive_secret_from_hash(
  algorithm algorithm: HashAlgorithm,
  secret secret: BitArray,
  label label: BitArray,
  transcript_hash transcript_hash: BitArray,
) -> Result(BitArray, Error) {
  case byte_aligned(transcript_hash) {
    False -> Error(crypto.NonByteAligned)
    True ->
      case
        bit_array.byte_size(transcript_hash) == crypto.hash_length(algorithm)
      {
        False -> Error(crypto.InvalidInput)
        True ->
          expand_label(
            algorithm: algorithm,
            secret: secret,
            label: label,
            context: transcript_hash,
            output_length: crypto.hash_length(algorithm),
          )
      }
  }
}

// Derive a secret from the hash of complete TLS Handshake messages.
// nolint: unused_exports -- useful when a caller owns complete transcript bytes.
pub fn derive_secret(
  algorithm algorithm: HashAlgorithm,
  secret secret: BitArray,
  label label: BitArray,
  transcript transcript: BitArray,
) -> Result(BitArray, Error) {
  use transcript_hash <- result.try(crypto.hash(algorithm, transcript))
  derive_secret_from_hash(
    algorithm: algorithm,
    secret: secret,
    label: label,
    transcript_hash: transcript_hash,
  )
}

/// Derive the TLS 1.3 early, handshake, traffic, and master secrets.
///
/// `hello_transcript_hash` is the transcript through ServerHello. `None` means
/// that no external or resumption PSK was selected.
pub fn derive_handshake_secrets(
  algorithm algorithm: HashAlgorithm,
  pre_shared_key pre_shared_key: Option(BitArray),
  shared_secret shared_secret: BitArray,
  hello_transcript_hash hello_transcript_hash: BitArray,
) -> Result(HandshakeSecrets, Error) {
  use Nil <- result.try(validate_handshake_inputs(
    algorithm,
    pre_shared_key,
    shared_secret,
    hello_transcript_hash,
  ))
  derive_valid_handshake_secrets(
    algorithm,
    pre_shared_key,
    shared_secret,
    hello_transcript_hash,
  )
}

fn derive_valid_handshake_secrets(
  algorithm: HashAlgorithm,
  pre_shared_key: Option(BitArray),
  shared_secret: BitArray,
  hello_transcript_hash: BitArray,
) -> Result(HandshakeSecrets, Error) {
  let zero = zero_hash(algorithm)
  let psk = case pre_shared_key {
    None -> zero
    Some(value) -> value
  }
  use early_secret <- result.try(crypto.hkdf_extract(algorithm, zero, psk))
  use empty_hash <- result.try(crypto.hash(algorithm, <<>>))
  use handshake_salt <- result.try(derive_secret_from_hash(
    algorithm: algorithm,
    secret: early_secret,
    label: <<"derived">>,
    transcript_hash: empty_hash,
  ))
  use handshake_secret <- result.try(crypto.hkdf_extract(
    algorithm,
    handshake_salt,
    shared_secret,
  ))
  use client_handshake_traffic_secret <- result.try(derive_secret_from_hash(
    algorithm: algorithm,
    secret: handshake_secret,
    label: <<"c hs traffic">>,
    transcript_hash: hello_transcript_hash,
  ))
  use server_handshake_traffic_secret <- result.try(derive_secret_from_hash(
    algorithm: algorithm,
    secret: handshake_secret,
    label: <<"s hs traffic">>,
    transcript_hash: hello_transcript_hash,
  ))
  use master_salt <- result.try(derive_secret_from_hash(
    algorithm: algorithm,
    secret: handshake_secret,
    label: <<"derived">>,
    transcript_hash: empty_hash,
  ))
  use master_secret <- result.try(crypto.hkdf_extract(
    algorithm,
    master_salt,
    zero,
  ))
  Ok(HandshakeSecrets(
    early_secret:,
    handshake_secret:,
    client_handshake_traffic_secret:,
    server_handshake_traffic_secret:,
    master_secret:,
  ))
}

/// Derive application traffic and exporter secrets after server Finished.
pub fn derive_application_secrets(
  algorithm algorithm: HashAlgorithm,
  master_secret master_secret: BitArray,
  server_finished_transcript_hash server_finished_transcript_hash: BitArray,
) -> Result(ApplicationSecrets, Error) {
  use Nil <- result.try(validate_secret_and_hash(
    algorithm,
    master_secret,
    server_finished_transcript_hash,
  ))
  use client_application_traffic_secret <- result.try(derive_secret_from_hash(
    algorithm: algorithm,
    secret: master_secret,
    label: <<"c ap traffic">>,
    transcript_hash: server_finished_transcript_hash,
  ))
  use server_application_traffic_secret <- result.try(derive_secret_from_hash(
    algorithm: algorithm,
    secret: master_secret,
    label: <<"s ap traffic">>,
    transcript_hash: server_finished_transcript_hash,
  ))
  use exporter_master_secret <- result.try(derive_secret_from_hash(
    algorithm: algorithm,
    secret: master_secret,
    label: <<"exp master">>,
    transcript_hash: server_finished_transcript_hash,
  ))
  Ok(ApplicationSecrets(
    client_application_traffic_secret:,
    server_application_traffic_secret:,
    exporter_master_secret:,
  ))
}

// Derive the resumption master secret after client Finished.
pub fn derive_resumption_master_secret(
  algorithm algorithm: HashAlgorithm,
  master_secret master_secret: BitArray,
  client_finished_transcript_hash client_finished_transcript_hash: BitArray,
) -> Result(BitArray, Error) {
  derive_secret_from_hash(
    algorithm: algorithm,
    secret: master_secret,
    label: <<"res master">>,
    transcript_hash: client_finished_transcript_hash,
  )
}

// Derive a PSK from the resumption master secret and a ticket nonce.
// nolint: unused_exports -- consumed by session-ticket handling.
pub fn derive_resumption_pre_shared_key(
  algorithm algorithm: HashAlgorithm,
  resumption_master_secret resumption_master_secret: BitArray,
  ticket_nonce ticket_nonce: BitArray,
) -> Result(BitArray, Error) {
  expand_label(
    algorithm: algorithm,
    secret: resumption_master_secret,
    label: <<"resumption">>,
    context: ticket_nonce,
    output_length: crypto.hash_length(algorithm),
  )
}

// Advance an application traffic secret for a QUIC key update.
// nolint: unused_exports -- consumed by QUIC key-phase management.
pub fn next_traffic_secret(
  algorithm algorithm: HashAlgorithm,
  current_secret current_secret: BitArray,
) -> Result(BitArray, Error) {
  expand_label(
    algorithm: algorithm,
    secret: current_secret,
    label: <<"traffic upd">>,
    context: <<>>,
    output_length: crypto.hash_length(algorithm),
  )
}

// Derive the client 0-RTT traffic secret from the early secret.
// nolint: unused_exports -- consumed when a ticket permits QUIC 0-RTT.
pub fn derive_client_early_traffic_secret(
  algorithm algorithm: HashAlgorithm,
  early_secret early_secret: BitArray,
  client_hello_transcript_hash client_hello_transcript_hash: BitArray,
) -> Result(BitArray, Error) {
  derive_secret_from_hash(
    algorithm: algorithm,
    secret: early_secret,
    label: <<"c e traffic">>,
    transcript_hash: client_hello_transcript_hash,
  )
}

// Derive an external-PSK or resumption-PSK binder key.
// nolint: unused_exports -- consumed by PSK binder generation and validation.
pub fn derive_binder_key(
  algorithm algorithm: HashAlgorithm,
  early_secret early_secret: BitArray,
  external external: Bool,
) -> Result(BitArray, Error) {
  use empty_hash <- result.try(crypto.hash(algorithm, <<>>))
  let label = case external {
    True -> <<"ext binder">>
    False -> <<"res binder">>
  }
  derive_secret_from_hash(
    algorithm: algorithm,
    secret: early_secret,
    label: label,
    transcript_hash: empty_hash,
  )
}

// Export keying material without exposing internal application traffic keys.
// nolint: unused_exports -- wired to the stable exporter capability later.
pub fn export_keying_material(
  algorithm algorithm: HashAlgorithm,
  exporter_master_secret exporter_master_secret: BitArray,
  label label: BitArray,
  context context: BitArray,
  output_length output_length: Int,
) -> Result(BitArray, Error) {
  use empty_hash <- result.try(crypto.hash(algorithm, <<>>))
  use derived_secret <- result.try(derive_secret_from_hash(
    algorithm: algorithm,
    secret: exporter_master_secret,
    label: label,
    transcript_hash: empty_hash,
  ))
  use context_hash <- result.try(crypto.hash(algorithm, context))
  expand_label(
    algorithm: algorithm,
    secret: derived_secret,
    label: <<"exporter">>,
    context: context_hash,
    output_length: output_length,
  )
}

// Compute TLS 1.3 Finished.verify_data from an existing transcript hash.
pub fn finished_verify_data_from_hash(
  algorithm algorithm: HashAlgorithm,
  base_traffic_secret base_traffic_secret: BitArray,
  transcript_hash transcript_hash: BitArray,
) -> Result(BitArray, Error) {
  let digest_length = crypto.hash_length(algorithm)
  case byte_aligned(transcript_hash) {
    False -> Error(crypto.NonByteAligned)
    True ->
      case bit_array.byte_size(transcript_hash) == digest_length {
        False -> Error(crypto.InvalidInput)
        True -> {
          use finished_key <- result.try(expand_label(
            algorithm: algorithm,
            secret: base_traffic_secret,
            label: <<"finished">>,
            context: <<>>,
            output_length: digest_length,
          ))
          crypto.hmac(algorithm, finished_key, transcript_hash)
        }
      }
  }
}

fn zero_hash(algorithm: HashAlgorithm) -> BitArray {
  case algorithm {
    crypto.Sha256 -> <<0:256>>
    crypto.Sha384 -> <<0:384>>
  }
}

fn option_is_byte_aligned(value: Option(BitArray)) -> Bool {
  case value {
    None -> True
    Some(bytes) -> byte_aligned(bytes)
  }
}

fn validate_handshake_inputs(
  algorithm: HashAlgorithm,
  pre_shared_key: Option(BitArray),
  shared_secret: BitArray,
  hello_transcript_hash: BitArray,
) -> Result(Nil, Error) {
  case
    byte_aligned(shared_secret)
    && option_is_byte_aligned(pre_shared_key)
    && byte_aligned(hello_transcript_hash)
  {
    False -> Error(crypto.NonByteAligned)
    True -> {
      let digest_length = crypto.hash_length(algorithm)
      case
        bit_array.byte_size(shared_secret) > 0
        && bit_array.byte_size(hello_transcript_hash) == digest_length
      {
        True -> Ok(Nil)
        False -> Error(crypto.InvalidInput)
      }
    }
  }
}

fn validate_secret_and_hash(
  algorithm: HashAlgorithm,
  secret: BitArray,
  transcript_hash: BitArray,
) -> Result(Nil, Error) {
  case byte_aligned(secret) && byte_aligned(transcript_hash) {
    False -> Error(crypto.NonByteAligned)
    True -> {
      let digest_length = crypto.hash_length(algorithm)
      case
        bit_array.byte_size(secret) == digest_length
        && bit_array.byte_size(transcript_hash) == digest_length
      {
        True -> Ok(Nil)
        False -> Error(crypto.InvalidInput)
      }
    }
  }
}

fn byte_aligned(bytes: BitArray) -> Bool {
  bit_array.bit_size(bytes) % 8 == 0
}

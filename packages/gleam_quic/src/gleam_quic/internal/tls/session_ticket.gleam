//// Authenticated stateless TLS tickets and origin-bound client ticket state.

import gleam/bit_array
import gleam/bool
import gleam/option.{type Option, None, Some}
import gleam/result
import gleam_quic/internal/crypto
import gleam_quic/internal/tls/extension
import gleam_quic/internal/tls/hello
import gleam_quic/internal/tls/key_schedule
import gleam_quic/internal/tls/message_body

const format_version = 1

const maximum_lifetime_seconds = 604_800

const quic_maximum_early_data_size = 0xffff_ffff

const u32_modulus = 0x1_0000_0000

const maximum_timestamp = 0x7fff_ffff_ffff_ffff

const associated_data = <<"gleam_quic tls ticket", 1>>

const client_export_version = 1

const client_export_associated_data = <<"gleam_quic client ticket export", 1>>

/// Authenticated server-side state recovered from an opaque ticket.
pub type Claims {
  Claims(
    issued_at_milliseconds: Int,
    lifetime_seconds: Int,
    age_add: Int,
    pre_shared_key: BitArray,
    algorithm: crypto.HashAlgorithm,
    cipher_suite: hello.CipherSuite,
    server_name: String,
    alpn: BitArray,
    quic_version: Int,
    remembered_transport_parameters: BitArray,
    permit_early_data: Bool,
  )
}

/// Client-owned resumption state derived from a NewSessionTicket.
pub type ClientTicket {
  ClientTicket(
    identity: BitArray,
    received_at_milliseconds: Int,
    lifetime_seconds: Int,
    age_add: Int,
    pre_shared_key: BitArray,
    algorithm: crypto.HashAlgorithm,
    cipher_suite: hello.CipherSuite,
    server_name: String,
    alpn: BitArray,
    quic_version: Int,
    remembered_transport_parameters: BitArray,
    permit_early_data: Bool,
  )
}

/// A ticket policy, encoding, authentication, or binding failure.
pub type Error {
  NonByteAligned
  InvalidKey
  InvalidTimestamp
  InvalidLifetime
  InvalidTicket
  InvalidTicketAge
  InvalidCipherSuite
  InvalidOrigin
  OriginMismatch
  Expired
  InvalidEarlyData
  InvalidTransportParameters
  CryptoFailure(crypto.Error)
}

/// Issue an authenticated stateless NewSessionTicket.
pub fn issue(
  ticket_key ticket_key: BitArray,
  issued_at_milliseconds issued_at_milliseconds: Int,
  lifetime_seconds lifetime_seconds: Int,
  resumption_master_secret resumption_master_secret: BitArray,
  algorithm algorithm: crypto.HashAlgorithm,
  cipher_suite cipher_suite: hello.CipherSuite,
  server_name server_name: String,
  alpn alpn: BitArray,
  quic_version quic_version: Int,
  remembered_transport_parameters remembered_transport_parameters: BitArray,
  permit_early_data permit_early_data: Bool,
) -> Result(message_body.NewSessionTicket, Error) {
  use Nil <- result.try(validate_ticket_key(ticket_key))
  use Nil <- result.try(validate_policy(
    issued_at_milliseconds,
    lifetime_seconds,
    algorithm,
    cipher_suite,
    server_name,
    alpn,
    quic_version,
    remembered_transport_parameters,
  ))
  use ticket_nonce <- result.try(crypto.secure_random(8) |> map_crypto_result)
  use age_bytes <- result.try(crypto.secure_random(4) |> map_crypto_result)
  use age_add <- result.try(decode_random_u32(age_bytes))
  use pre_shared_key <- result.try(
    key_schedule.derive_resumption_pre_shared_key(
      algorithm,
      resumption_master_secret,
      ticket_nonce,
    )
    |> map_crypto_result,
  )
  let claims =
    Claims(
      issued_at_milliseconds:,
      lifetime_seconds:,
      age_add:,
      pre_shared_key:,
      algorithm:,
      cipher_suite:,
      server_name:,
      alpn:,
      quic_version:,
      remembered_transport_parameters:,
      permit_early_data:,
    )
  use plaintext <- result.try(encode_claims(claims))
  use nonce <- result.try(crypto.secure_random(12) |> map_crypto_result)
  use protected <- result.try(
    crypto.aes_256_gcm_encrypt(ticket_key, nonce, associated_data, plaintext)
    |> map_crypto_result,
  )
  let opaque_ticket = <<format_version, nonce:bits, protected:bits>>
  let extensions = case
    maximum_early_data_size_for_quic(permit_early_data: permit_early_data)
  {
    None -> []
    Some(value) -> [
      extension.Extension(extension.EarlyData, <<value:size(32)>>),
    ]
  }
  Ok(message_body.NewSessionTicket(
    ticket_lifetime: lifetime_seconds,
    ticket_age_add: age_add,
    ticket_nonce:,
    ticket: opaque_ticket,
    extensions:,
  ))
}

/// Store an authenticated peer's NewSessionTicket in origin-bound client state.
pub fn store(
  new_ticket new_ticket: message_body.NewSessionTicket,
  received_at_milliseconds received_at_milliseconds: Int,
  resumption_master_secret resumption_master_secret: BitArray,
  algorithm algorithm: crypto.HashAlgorithm,
  cipher_suite cipher_suite: hello.CipherSuite,
  server_name server_name: String,
  alpn alpn: BitArray,
  quic_version quic_version: Int,
  remembered_transport_parameters remembered_transport_parameters: BitArray,
) -> Result(ClientTicket, Error) {
  let message_body.NewSessionTicket(
    lifetime,
    age_add,
    nonce,
    identity,
    extensions,
  ) = new_ticket
  use Nil <- result.try(validate_policy(
    received_at_milliseconds,
    lifetime,
    algorithm,
    cipher_suite,
    server_name,
    alpn,
    quic_version,
    remembered_transport_parameters,
  ))
  case
    age_add >= 0 && age_add <= 0xffff_ffff,
    bit_array.bit_size(nonce) % 8 == 0 && bit_array.byte_size(nonce) <= 255,
    bit_array.bit_size(identity) % 8 == 0 && bit_array.byte_size(identity) > 0
  {
    False, _, _ -> Error(InvalidTicketAge)
    _, False, _ -> Error(NonByteAligned)
    _, _, False -> Error(InvalidTicket)
    True, True, True -> {
      use permit_early_data <- result.try(decode_early_data(extensions))
      use pre_shared_key <- result.try(
        key_schedule.derive_resumption_pre_shared_key(
          algorithm,
          resumption_master_secret,
          nonce,
        )
        |> map_crypto_result,
      )
      Ok(ClientTicket(
        identity:,
        received_at_milliseconds:,
        lifetime_seconds: lifetime,
        age_add:,
        pre_shared_key:,
        algorithm:,
        cipher_suite:,
        server_name:,
        alpn:,
        quic_version:,
        remembered_transport_parameters:,
        permit_early_data:,
      ))
    }
  }
}

/// Authenticate and validate one opaque server ticket.
pub fn open(
  ticket_key ticket_key: BitArray,
  opaque_ticket opaque_ticket: BitArray,
  now_milliseconds now_milliseconds: Int,
  expected_server_name expected_server_name: String,
  expected_alpn expected_alpn: BitArray,
  expected_quic_version expected_quic_version: Int,
) -> Result(Claims, Error) {
  use Nil <- result.try(validate_ticket_key(ticket_key))
  use Nil <- result.try(require_byte_aligned(opaque_ticket))
  use plaintext <- result.try(decrypt_ticket(ticket_key, opaque_ticket))
  use claims <- result.try(decode_claims(plaintext))
  use Nil <- result.try(validate_claims_time(claims, now_milliseconds))
  let Claims(
    server_name: server_name,
    alpn: alpn,
    quic_version: quic_version,
    ..,
  ) = claims
  case
    server_name == expected_server_name
    && alpn == expected_alpn
    && quic_version == expected_quic_version
  {
    True -> Ok(claims)
    False -> Error(OriginMismatch)
  }
}

/// Calculate the client's modulo-2^32 obfuscated_ticket_age.
pub fn obfuscated_ticket_age(
  ticket ticket: ClientTicket,
  now_milliseconds now_milliseconds: Int,
) -> Result(Int, Error) {
  let ClientTicket(received_at_milliseconds: received_at, age_add: age_add, ..) =
    ticket
  case now_milliseconds >= received_at {
    False -> Error(InvalidTimestamp)
    True -> Ok({ now_milliseconds - received_at + age_add } % u32_modulus)
  }
}

/// Validate deobfuscated ticket age within a bounded clock/network tolerance.
pub fn ticket_age_is_valid(
  claims claims: Claims,
  obfuscated_age obfuscated_age: Int,
  now_milliseconds now_milliseconds: Int,
  tolerance_milliseconds tolerance_milliseconds: Int,
) -> Bool {
  let Claims(issued_at_milliseconds: issued_at, age_add: age_add, ..) = claims
  case
    obfuscated_age >= 0
    && obfuscated_age < u32_modulus
    && now_milliseconds >= issued_at
    && tolerance_milliseconds >= 0
  {
    False -> False
    True -> {
      let encoded_age = obfuscated_age - age_add
      let deobfuscated_age = case encoded_age < 0 {
        True -> encoded_age + u32_modulus
        False -> encoded_age
      }
      let actual_age = { now_milliseconds - issued_at } % u32_modulus
      absolute_difference(deobfuscated_age, actual_age)
      <= tolerance_milliseconds
    }
  }
}

/// Return whether client state is live and bound to this connection origin.
pub fn is_usable(
  ticket ticket: ClientTicket,
  now_milliseconds now_milliseconds: Int,
  server_name server_name: String,
  alpn alpn: BitArray,
  quic_version quic_version: Int,
) -> Bool {
  let ClientTicket(
    received_at_milliseconds: received_at,
    lifetime_seconds: lifetime,
    server_name: bound_server_name,
    alpn: bound_alpn,
    quic_version: bound_version,
    ..,
  ) = ticket
  now_milliseconds >= received_at
  && now_milliseconds - received_at <= lifetime * 1000
  && server_name == bound_server_name
  && alpn == bound_alpn
  && quic_version == bound_version
}

/// Return whether this ticket explicitly permits QUIC 0-RTT.
pub fn early_data_allowed(ticket ticket: ClientTicket) -> Bool {
  ticket.permit_early_data
}

/// Return the remembered QUIC transport parameters used for 0-RTT checks.
pub fn remembered_parameters(ticket ticket: ClientTicket) -> BitArray {
  ticket.remembered_transport_parameters
}

/// Return the QUIC version identifier cryptographically bound to this ticket.
pub fn quic_version(ticket ticket: ClientTicket) -> Int {
  ticket.quic_version
}

/// Convert an early-data policy to QUIC's sole permitted maximum value.
pub fn maximum_early_data_size_for_quic(
  permit_early_data permit_early_data: Bool,
) -> Option(Int) {
  case permit_early_data {
    True -> Some(quic_maximum_early_data_size)
    False -> None
  }
}

/// Read the effective maximum early-data size from cached client state.
pub fn maximum_early_data_size(ticket ticket: ClientTicket) -> Option(Int) {
  maximum_early_data_size_for_quic(permit_early_data: ticket.permit_early_data)
}

/// Encrypt a versioned client ticket for caller-managed persistence.
///
/// The stored age combines monotonic elapsed time before export with wall
/// time after import, allowing safe process restarts without using wall time
/// for live protocol timers.
pub fn export_client(
  ticket: ClientTicket,
  storage_key: BitArray,
  now_milliseconds: Int,
  unix_milliseconds: Int,
) -> Result(BitArray, Error) {
  use Nil <- result.try(validate_ticket_key(storage_key))
  let ClientTicket(
    identity,
    received_at,
    lifetime,
    age_add,
    pre_shared_key,
    algorithm,
    cipher_suite,
    server_name,
    alpn,
    quic_version,
    remembered_transport_parameters,
    permit_early_data,
  ) = ticket
  let age = now_milliseconds - received_at
  case
    now_milliseconds >= 0
    && unix_milliseconds >= 0
    && now_milliseconds >= received_at
    && age <= lifetime * 1000
    && age <= maximum_timestamp
    && bit_array.bit_size(identity) % 8 == 0
    && bit_array.byte_size(identity) > 0
    && bit_array.byte_size(identity) <= 65_535
  {
    False -> Error(Expired)
    True -> {
      use claims <- result.try(
        encode_claims(Claims(
          0,
          lifetime,
          age_add,
          pre_shared_key,
          algorithm,
          cipher_suite,
          server_name,
          alpn,
          quic_version,
          remembered_transport_parameters,
          permit_early_data,
        )),
      )
      let identity_length = bit_array.byte_size(identity)
      let claims_length = bit_array.byte_size(claims)
      let plaintext = <<
        unix_milliseconds:size(64),
        age:size(64),
        identity_length:size(16),
        identity:bits,
        claims_length:size(32),
        claims:bits,
      >>
      use nonce <- result.try(crypto.secure_random(12) |> map_crypto_result)
      use protected <- result.try(
        crypto.aes_256_gcm_encrypt(
          storage_key,
          nonce,
          client_export_associated_data,
          plaintext,
        )
        |> map_crypto_result,
      )
      Ok(<<client_export_version, nonce:bits, protected:bits>>)
    }
  }
}

/// Authenticate and restore caller-encrypted client ticket state.
pub fn import_client(
  stored: BitArray,
  storage_key: BitArray,
  now_milliseconds: Int,
  unix_milliseconds: Int,
) -> Result(ClientTicket, Error) {
  use Nil <- result.try(validate_ticket_key(storage_key))
  use Nil <- result.try(require_byte_aligned(stored))
  use plaintext <- result.try(decrypt_client_export(storage_key, stored))
  case plaintext {
    <<exported_unix:size(64), age_at_export:size(64), rest:bits>> ->
      restore_client(
        exported_unix,
        age_at_export,
        rest,
        now_milliseconds,
        unix_milliseconds,
      )
    _ -> Error(InvalidTicket)
  }
}

fn restore_client(
  exported_unix: Int,
  age_at_export: Int,
  encoded: BitArray,
  now_milliseconds: Int,
  unix_milliseconds: Int,
) -> Result(ClientTicket, Error) {
  use <- bool.guard(
    when: unix_milliseconds < exported_unix || now_milliseconds < 0,
    return: Error(InvalidTimestamp),
  )
  use #(identity, claims_bytes) <- result.try(decode_client_export(encoded))
  use claims <- result.try(decode_claims(claims_bytes))
  let elapsed = unix_milliseconds - exported_unix
  let age = age_at_export + elapsed
  let Claims(
    _,
    lifetime,
    age_add,
    pre_shared_key,
    algorithm,
    cipher_suite,
    server_name,
    alpn,
    quic_version,
    remembered_transport_parameters,
    permit_early_data,
  ) = claims
  use <- bool.guard(
    when: age > lifetime * 1000 || age > maximum_timestamp,
    return: Error(Expired),
  )
  Ok(ClientTicket(
    identity,
    now_milliseconds - age,
    lifetime,
    age_add,
    pre_shared_key,
    algorithm,
    cipher_suite,
    server_name,
    alpn,
    quic_version,
    remembered_transport_parameters,
    permit_early_data,
  ))
}

/// Return only the non-secret origin binding for internal wrapper validation.
pub fn server_name(ticket: ClientTicket) -> String {
  ticket.server_name
}

fn encode_claims(claims: Claims) -> Result(BitArray, Error) {
  let Claims(
    issued_at,
    lifetime,
    age_add,
    pre_shared_key,
    algorithm,
    cipher_suite,
    server_name,
    alpn,
    quic_version,
    remembered_transport_parameters,
    permit_early_data,
  ) = claims
  use suite <- result.try(cipher_to_wire(cipher_suite, algorithm))
  let name = <<server_name:utf8>>
  let name_length = bit_array.byte_size(name)
  let alpn_length = bit_array.byte_size(alpn)
  let psk_length = bit_array.byte_size(pre_shared_key)
  let parameters_length = bit_array.byte_size(remembered_transport_parameters)
  let flags = case permit_early_data {
    True -> 1
    False -> 0
  }
  Ok(<<
    issued_at:size(64),
    lifetime:size(32),
    age_add:size(32),
    suite:size(16),
    quic_version:size(32),
    flags,
    psk_length,
    pre_shared_key:bits,
    name_length:size(16),
    name:bits,
    alpn_length,
    alpn:bits,
    parameters_length:size(16),
    remembered_transport_parameters:bits,
  >>)
}

fn decode_claims(bytes: BitArray) -> Result(Claims, Error) {
  case bytes {
    <<
      issued_at:size(64),
      lifetime:size(32),
      age_add:size(32),
      suite_identifier:size(16),
      quic_version:size(32),
      flags,
      psk_length,
      rest:bits,
    >> -> {
      use #(pre_shared_key, name_and_rest) <- result.try(take(rest, psk_length))
      case name_and_rest {
        <<name_length:size(16), name_value_and_rest:bits>> -> {
          use #(name, alpn_and_rest) <- result.try(take(
            name_value_and_rest,
            name_length,
          ))
          decode_claims_alpn(
            issued_at,
            lifetime,
            age_add,
            suite_identifier,
            quic_version,
            flags,
            pre_shared_key,
            name,
            alpn_and_rest,
          )
        }
        _ -> Error(InvalidTicket)
      }
    }
    _ -> Error(InvalidTicket)
  }
}

// nolint: deep_nesting -- authenticated nested vectors are decoded exactly once.
fn decode_claims_alpn(
  issued_at: Int,
  lifetime: Int,
  age_add: Int,
  suite_identifier: Int,
  quic_version: Int,
  flags: Int,
  pre_shared_key: BitArray,
  name: BitArray,
  bytes: BitArray,
) -> Result(Claims, Error) {
  case bytes {
    <<alpn_length, alpn_value_and_rest:bits>> -> {
      use #(alpn, parameters_and_rest) <- result.try(take(
        alpn_value_and_rest,
        alpn_length,
      ))
      case parameters_and_rest {
        <<parameters_length:size(16), parameter_value_and_rest:bits>> -> {
          use #(parameters, trailing) <- result.try(take(
            parameter_value_and_rest,
            parameters_length,
          ))
          case
            trailing,
            bit_array.to_string(name),
            cipher_from_wire(suite_identifier)
          {
            <<>>, Ok(server_name), Ok(#(cipher_suite, algorithm)) -> {
              let permit_early_data = flags == 1
              case
                flags == 0 || flags == 1,
                bit_array.byte_size(pre_shared_key)
                == crypto.hash_length(algorithm),
                validate_policy(
                  issued_at,
                  lifetime,
                  algorithm,
                  cipher_suite,
                  server_name,
                  alpn,
                  quic_version,
                  parameters,
                )
              {
                True, True, Ok(Nil) ->
                  Ok(Claims(
                    issued_at_milliseconds: issued_at,
                    lifetime_seconds: lifetime,
                    age_add:,
                    pre_shared_key:,
                    algorithm:,
                    cipher_suite:,
                    server_name:,
                    alpn:,
                    quic_version:,
                    remembered_transport_parameters: parameters,
                    permit_early_data:,
                  ))
                _, _, _ -> Error(InvalidTicket)
              }
            }
            _, _, _ -> Error(InvalidTicket)
          }
        }
        _ -> Error(InvalidTicket)
      }
    }
    _ -> Error(InvalidTicket)
  }
}

fn decode_early_data(
  extensions: List(extension.Extension),
) -> Result(Bool, Error) {
  decode_early_data_items(extensions, False)
}

fn decode_early_data_items(
  extensions: List(extension.Extension),
  found: Bool,
) -> Result(Bool, Error) {
  case extensions {
    [] -> Ok(found)
    [extension.Extension(extension.EarlyData, data), ..rest] ->
      case found, data {
        True, _ -> Error(InvalidEarlyData)
        False, <<value:size(32)>> ->
          case value == quic_maximum_early_data_size {
            True -> decode_early_data_items(rest, True)
            False -> Error(InvalidEarlyData)
          }
        False, _ -> Error(InvalidEarlyData)
      }
    [_, ..rest] -> decode_early_data_items(rest, found)
  }
}

fn validate_policy(
  timestamp: Int,
  lifetime: Int,
  algorithm: crypto.HashAlgorithm,
  cipher_suite: hello.CipherSuite,
  server_name: String,
  alpn: BitArray,
  quic_version: Int,
  remembered_transport_parameters: BitArray,
) -> Result(Nil, Error) {
  use Nil <- result.try(validate_timestamp(timestamp))
  use Nil <- result.try(validate_lifetime(lifetime))
  use _ <- result.try(cipher_to_wire(cipher_suite, algorithm))
  let name = <<server_name:utf8>>
  case
    bit_array.byte_size(name) > 0
    && bit_array.byte_size(name) <= 253
    && bit_array.bit_size(alpn) % 8 == 0
    && bit_array.byte_size(alpn) > 0
    && bit_array.byte_size(alpn) <= 255
    && quic_version >= 0
    && quic_version <= 0xffff_ffff
  {
    False -> Error(InvalidOrigin)
    True ->
      case
        bit_array.bit_size(remembered_transport_parameters) % 8 == 0
        && bit_array.byte_size(remembered_transport_parameters) <= 65_535
      {
        True -> Ok(Nil)
        False -> Error(InvalidTransportParameters)
      }
  }
}

fn validate_timestamp(timestamp: Int) -> Result(Nil, Error) {
  case timestamp >= 0 && timestamp <= maximum_timestamp {
    True -> Ok(Nil)
    False -> Error(InvalidTimestamp)
  }
}

fn validate_lifetime(lifetime: Int) -> Result(Nil, Error) {
  case lifetime > 0 && lifetime <= maximum_lifetime_seconds {
    True -> Ok(Nil)
    False -> Error(InvalidLifetime)
  }
}

fn validate_claims_time(
  claims: Claims,
  now_milliseconds: Int,
) -> Result(Nil, Error) {
  let Claims(issued_at_milliseconds: issued_at, lifetime_seconds: lifetime, ..) =
    claims
  case now_milliseconds >= issued_at {
    False -> Error(InvalidTimestamp)
    True ->
      case now_milliseconds - issued_at <= lifetime * 1000 {
        True -> Ok(Nil)
        False -> Error(Expired)
      }
  }
}

fn validate_ticket_key(ticket_key: BitArray) -> Result(Nil, Error) {
  case bit_array.bit_size(ticket_key) % 8 {
    remainder if remainder != 0 -> Error(NonByteAligned)
    _ ->
      case bit_array.byte_size(ticket_key) == 32 {
        True -> Ok(Nil)
        False -> Error(InvalidKey)
      }
  }
}

fn decrypt_ticket(
  ticket_key: BitArray,
  opaque_ticket: BitArray,
) -> Result(BitArray, Error) {
  case opaque_ticket {
    <<version, nonce:bits-size(96), protected:bits>> ->
      case version == format_version && bit_array.byte_size(protected) >= 16 {
        False -> Error(InvalidTicket)
        True ->
          case
            crypto.aes_256_gcm_decrypt(
              ticket_key,
              nonce,
              associated_data,
              protected,
            )
          {
            Ok(plaintext) -> Ok(plaintext)
            Error(_) -> Error(InvalidTicket)
          }
      }
    _ -> Error(InvalidTicket)
  }
}

fn decrypt_client_export(
  storage_key: BitArray,
  stored: BitArray,
) -> Result(BitArray, Error) {
  case stored {
    <<version, nonce:bits-size(96), protected:bits>> ->
      case
        version == client_export_version && bit_array.byte_size(protected) >= 16
      {
        False -> Error(InvalidTicket)
        True ->
          crypto.aes_256_gcm_decrypt(
            storage_key,
            nonce,
            client_export_associated_data,
            protected,
          )
          |> result.replace_error(InvalidTicket)
      }
    _ -> Error(InvalidTicket)
  }
}

fn decode_client_export(
  bytes: BitArray,
) -> Result(#(BitArray, BitArray), Error) {
  case bytes {
    <<identity_length:size(16), values:bits>> -> {
      use #(identity, claims_and_rest) <- result.try(take(
        values,
        identity_length,
      ))
      decode_client_claims(identity, claims_and_rest)
    }
    _ -> Error(InvalidTicket)
  }
}

fn decode_client_claims(
  identity: BitArray,
  bytes: BitArray,
) -> Result(#(BitArray, BitArray), Error) {
  case bytes {
    <<claims_length:size(32), claims_value_and_rest:bits>> -> {
      use #(claims, trailing) <- result.try(take(
        claims_value_and_rest,
        claims_length,
      ))
      case
        trailing == <<>>
        && bit_array.byte_size(identity) > 0
        && bit_array.byte_size(identity) <= 65_535
      {
        True -> Ok(#(identity, claims))
        False -> Error(InvalidTicket)
      }
    }
    _ -> Error(InvalidTicket)
  }
}

fn decode_random_u32(bytes: BitArray) -> Result(Int, Error) {
  case bytes {
    <<value:size(32)>> -> Ok(value)
    _ -> Error(CryptoFailure(crypto.CryptoUnavailable))
  }
}

fn cipher_to_wire(
  cipher_suite: hello.CipherSuite,
  algorithm: crypto.HashAlgorithm,
) -> Result(Int, Error) {
  case cipher_suite, algorithm {
    hello.Aes128GcmSha256, crypto.Sha256 -> Ok(0x1301)
    hello.Aes256GcmSha384, crypto.Sha384 -> Ok(0x1302)
    hello.Chacha20Poly1305Sha256, crypto.Sha256 -> Ok(0x1303)
    hello.Aes128CcmSha256, crypto.Sha256 -> Ok(0x1304)
    hello.Aes128Ccm8Sha256, crypto.Sha256 -> Ok(0x1305)
    _, _ -> Error(InvalidCipherSuite)
  }
}

fn cipher_from_wire(
  identifier: Int,
) -> Result(#(hello.CipherSuite, crypto.HashAlgorithm), Error) {
  case identifier {
    0x1301 -> Ok(#(hello.Aes128GcmSha256, crypto.Sha256))
    0x1302 -> Ok(#(hello.Aes256GcmSha384, crypto.Sha384))
    0x1303 -> Ok(#(hello.Chacha20Poly1305Sha256, crypto.Sha256))
    0x1304 -> Ok(#(hello.Aes128CcmSha256, crypto.Sha256))
    0x1305 -> Ok(#(hello.Aes128Ccm8Sha256, crypto.Sha256))
    _ -> Error(InvalidCipherSuite)
  }
}

fn take(bytes: BitArray, length: Int) -> Result(#(BitArray, BitArray), Error) {
  case length < 0 || length > bit_array.byte_size(bytes) {
    True -> Error(InvalidTicket)
    False -> {
      let bit_length = length * 8
      case bytes {
        <<prefix:bits-size(bit_length), rest:bits>> -> Ok(#(prefix, rest))
        _ -> Error(InvalidTicket)
      }
    }
  }
}

fn absolute_difference(left: Int, right: Int) -> Int {
  case left >= right {
    True -> left - right
    False -> right - left
  }
}

fn require_byte_aligned(bytes: BitArray) -> Result(Nil, Error) {
  case bit_array.bit_size(bytes) % 8 == 0 {
    True -> Ok(Nil)
    False -> Error(NonByteAligned)
  }
}

fn map_crypto_result(
  value: Result(output, crypto.Error),
) -> Result(output, Error) {
  case value {
    Ok(output) -> Ok(output)
    Error(error) -> Error(CryptoFailure(error))
  }
}

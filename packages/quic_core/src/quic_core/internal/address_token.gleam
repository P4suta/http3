//// Authenticated, expiring Retry and NEW_TOKEN address tokens.

import gleam/bit_array
import gleam/result
import quic_core/internal/crypto
import quic_core/version.{type Version}

const format_version = 3

const associated_data = <<"quic_core address token v3">>

const maximum_timestamp = 9_223_372_036_854_775_807

/// Token purpose determines whether an original destination CID is expected.
pub type Kind {
  Retry
  NewToken
}

/// Authenticated token data returned only after address and expiry checks.
pub type Token {
  Token(
    kind: Kind,
    original_destination_connection_id: BitArray,
    retry_source_connection_id: BitArray,
    issued_at: Int,
  )
}

/// Token format, authentication, binding, or lifetime failure.
pub type Error {
  InvalidInput
  Malformed
  AuthenticationFailed
  AddressMismatch
  VersionMismatch
  Expired
  CryptoUnavailable
}

/// Seal a token with a fresh 96-bit AES-256-GCM nonce.
pub fn seal(
  key: BitArray,
  kind: Kind,
  protocol_version: Version,
  address: BitArray,
  port: Int,
  original_destination_connection_id: BitArray,
  retry_source_connection_id: BitArray,
  issued_at: Int,
) -> Result(BitArray, Error) {
  use nonce <- result.try(crypto.secure_random(12) |> map_crypto_result)
  seal_with_nonce(
    key,
    kind,
    protocol_version,
    address,
    port,
    original_destination_connection_id,
    retry_source_connection_id,
    issued_at,
    nonce,
  )
}

/// Seal with an explicit nonce for deterministic vectors and controlled restore.
pub fn seal_with_nonce(
  key: BitArray,
  kind: Kind,
  protocol_version: Version,
  address: BitArray,
  port: Int,
  original_destination_connection_id: BitArray,
  retry_source_connection_id: BitArray,
  issued_at: Int,
  nonce: BitArray,
) -> Result(BitArray, Error) {
  use Nil <- result.try(validate_inputs(
    key,
    kind,
    protocol_version,
    address,
    port,
    original_destination_connection_id,
    retry_source_connection_id,
    issued_at,
    nonce,
  ))
  let body =
    encode_body(
      kind,
      protocol_version,
      address,
      port,
      original_destination_connection_id,
      retry_source_connection_id,
      issued_at,
    )
  use protected <- result.try(
    crypto.aes_256_gcm_encrypt(key, nonce, associated_data, body)
    |> map_crypto_result,
  )
  Ok(<<nonce:bits, protected:bits>>)
}

/// Authenticate, parse, bind, and expire one opaque address token.
pub fn open(
  key: BitArray,
  token: BitArray,
  expected_protocol_version: Version,
  expected_address: BitArray,
  expected_port: Int,
  now: Int,
  maximum_age: Int,
) -> Result(Token, Error) {
  use Nil <- result.try(validate_open_inputs(
    key,
    token,
    expected_protocol_version,
    expected_address,
    expected_port,
    now,
    maximum_age,
  ))
  let nonce_bits = 12 * 8
  case token {
    <<nonce:bits-size(nonce_bits), protected:bits>> -> {
      use plaintext <- result.try(
        crypto.aes_256_gcm_decrypt(key, nonce, associated_data, protected)
        |> map_crypto_result,
      )
      use decoded <- result.try(decode_body(plaintext))
      validate_decoded(
        decoded,
        expected_protocol_version,
        expected_address,
        expected_port,
        now,
        maximum_age,
      )
    }
    _ -> Error(Malformed)
  }
}

type Decoded {
  Decoded(Kind, Version, BitArray, Int, BitArray, BitArray, Int)
}

fn encode_body(
  kind: Kind,
  protocol_version: Version,
  address: BitArray,
  port: Int,
  original_connection_id: BitArray,
  retry_source_connection_id: BitArray,
  issued_at: Int,
) -> BitArray {
  let address_length = bit_array.byte_size(address)
  let connection_id_length = bit_array.byte_size(original_connection_id)
  let retry_source_length = bit_array.byte_size(retry_source_connection_id)
  let wire_protocol_version = supported_version_to_wire(protocol_version)
  <<
    format_version,
    kind_to_wire(kind),
    wire_protocol_version:size(32),
    issued_at:size(64),
    port:size(16),
    address_length,
    connection_id_length,
    retry_source_length,
    address:bits,
    original_connection_id:bits,
    retry_source_connection_id:bits,
  >>
}

fn decode_body(body: BitArray) -> Result(Decoded, Error) {
  case body {
    <<
      wire_version,
      wire_kind,
      wire_protocol_version:size(32),
      issued_at:size(64),
      port:size(16),
      address_length,
      connection_id_length,
      retry_source_length,
      values:bits,
    >> -> {
      case wire_version == format_version {
        False -> Error(Malformed)
        True -> {
          use protocol_version <- result.try(supported_version_from_wire(
            wire_protocol_version,
          ))
          decode_values(
            values,
            wire_kind,
            protocol_version,
            issued_at,
            port,
            address_length,
            connection_id_length,
            retry_source_length,
          )
        }
      }
    }
    _ -> Error(Malformed)
  }
}

fn decode_values(
  values: BitArray,
  wire_kind: Int,
  protocol_version: Version,
  issued_at: Int,
  port: Int,
  address_length: Int,
  connection_id_length: Int,
  retry_source_length: Int,
) -> Result(Decoded, Error) {
  let address_bits = address_length * 8
  let connection_id_bits = connection_id_length * 8
  let retry_source_bits = retry_source_length * 8
  case values {
    <<
      address:bits-size(address_bits),
      connection_id:bits-size(connection_id_bits),
      retry_source:bits-size(retry_source_bits),
    >> -> {
      use kind <- result.try(kind_from_wire(wire_kind))
      Ok(Decoded(
        kind,
        protocol_version,
        address,
        port,
        connection_id,
        retry_source,
        issued_at,
      ))
    }
    _ -> Error(Malformed)
  }
}

fn validate_decoded(
  decoded: Decoded,
  expected_protocol_version: Version,
  expected_address: BitArray,
  expected_port: Int,
  now: Int,
  maximum_age: Int,
) -> Result(Token, Error) {
  let Decoded(
    kind,
    protocol_version,
    address,
    port,
    connection_id,
    retry_source,
    issued_at,
  ) = decoded
  case valid_connection_ids_for_kind(kind, connection_id, retry_source) {
    False -> Error(Malformed)
    True if protocol_version != expected_protocol_version ->
      Error(VersionMismatch)
    True if address != expected_address -> Error(AddressMismatch)
    True if kind == Retry && port != expected_port -> Error(AddressMismatch)
    True if issued_at > now || now - issued_at > maximum_age -> Error(Expired)
    True -> Ok(Token(kind, connection_id, retry_source, issued_at))
  }
}

fn validate_inputs(
  key: BitArray,
  kind: Kind,
  protocol_version: Version,
  address: BitArray,
  port: Int,
  connection_id: BitArray,
  retry_source_connection_id: BitArray,
  issued_at: Int,
  nonce: BitArray,
) -> Result(Nil, Error) {
  case
    byte_aligned(key)
    && supported_version(protocol_version)
    && valid_address(address)
    && byte_aligned(connection_id)
    && byte_aligned(retry_source_connection_id)
    && byte_aligned(nonce)
    && bit_array.byte_size(key) == 32
    && valid_connection_ids_for_kind(
      kind,
      connection_id,
      retry_source_connection_id,
    )
    && bit_array.byte_size(nonce) == 12
    && port > 0
    && port <= 65_535
    && issued_at >= 0
    && issued_at <= maximum_timestamp
  {
    True -> Ok(Nil)
    False -> Error(InvalidInput)
  }
}

fn validate_open_inputs(
  key: BitArray,
  token: BitArray,
  expected_protocol_version: Version,
  address: BitArray,
  port: Int,
  now: Int,
  maximum_age: Int,
) -> Result(Nil, Error) {
  case
    byte_aligned(key)
    && supported_version(expected_protocol_version)
    && byte_aligned(token)
    && byte_aligned(address)
    && bit_array.byte_size(key) == 32
    && bit_array.byte_size(token) >= 51
    && valid_address(address)
    && port > 0
    && port <= 65_535
    && now >= 0
    && now <= maximum_timestamp
    && maximum_age >= 0
  {
    True -> Ok(Nil)
    False -> Error(InvalidInput)
  }
}

fn kind_to_wire(kind: Kind) -> Int {
  case kind {
    Retry -> 0
    NewToken -> 1
  }
}

fn kind_from_wire(identifier: Int) -> Result(Kind, Error) {
  case identifier {
    0 -> Ok(Retry)
    1 -> Ok(NewToken)
    _ -> Error(Malformed)
  }
}

fn supported_version(protocol_version: Version) -> Bool {
  case protocol_version {
    version.Version1 | version.Version2 -> True
    _ -> False
  }
}

fn supported_version_to_wire(protocol_version: Version) -> Int {
  case protocol_version {
    version.Version1 -> 1
    version.Version2 -> 0x6b33_43cf
    // validate_inputs rejects this before encode_body is reached.
    _ -> 0
  }
}

fn supported_version_from_wire(wire: Int) -> Result(Version, Error) {
  case version.from_wire(wire) {
    Ok(version.Version1) -> Ok(version.Version1)
    Ok(version.Version2) -> Ok(version.Version2)
    _ -> Error(Malformed)
  }
}

fn map_crypto_result(
  value: Result(output, crypto.Error),
) -> Result(output, Error) {
  case value {
    Ok(output) -> Ok(output)
    Error(crypto.AuthenticationFailed) -> Error(AuthenticationFailed)
    Error(crypto.CryptoUnavailable) -> Error(CryptoUnavailable)
    Error(_) -> Error(InvalidInput)
  }
}

fn byte_aligned(bytes: BitArray) -> Bool {
  bit_array.bit_size(bytes) % 8 == 0
}

fn valid_address(address: BitArray) -> Bool {
  byte_aligned(address)
  && { bit_array.byte_size(address) == 4 || bit_array.byte_size(address) == 16 }
}

fn valid_connection_ids_for_kind(
  kind: Kind,
  original_connection_id: BitArray,
  retry_source_connection_id: BitArray,
) -> Bool {
  let original_size = bit_array.byte_size(original_connection_id)
  let retry_source_size = bit_array.byte_size(retry_source_connection_id)
  case kind {
    Retry ->
      byte_aligned(original_connection_id)
      && byte_aligned(retry_source_connection_id)
      && original_size >= 8
      && original_size <= 20
      && retry_source_size >= 8
      && retry_source_size <= 20
    NewToken ->
      byte_aligned(original_connection_id)
      && byte_aligned(retry_source_connection_id)
      && original_size == 0
      && retry_source_size == 0
  }
}

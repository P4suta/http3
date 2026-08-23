//// Stateless reset token derivation and constant-time comparison.

import gleam/bit_array
import gleam/result
import gleam_quic/internal/crypto
import gleam_quic/internal/tls/authentication

/// Reset-token input, runtime, or comparison failure.
pub type Error {
  InvalidSecret
  InvalidConnectionId
  InvalidToken
  CryptoUnavailable
}

/// Derive an unlinkable 16-byte token from a rotating server secret and CID.
pub fn token_for(
  server_secret: BitArray,
  connection_id: BitArray,
) -> Result(BitArray, Error) {
  case valid_secret(server_secret), valid_connection_id(connection_id) {
    False, _ -> Error(InvalidSecret)
    _, False -> Error(InvalidConnectionId)
    _, _ -> {
      use digest <- result.try(
        crypto.hmac(crypto.Sha256, server_secret, <<
          "gleam_quic stateless reset v1",
          connection_id:bits,
        >>)
        |> map_crypto_result,
      )
      take_token(digest)
    }
  }
}

/// Compare a received suffix with a derived token in constant time.
pub fn matches(expected: BitArray, received: BitArray) -> Result(Bool, Error) {
  case
    bit_array.byte_size(expected) == 16 && bit_array.byte_size(received) == 16
  {
    False -> Error(InvalidToken)
    True ->
      authentication.constant_time_equal(expected, received)
      |> map_authentication_result
  }
}

fn take_token(digest: BitArray) -> Result(BitArray, Error) {
  case digest {
    <<token:bits-size(128), _:bits>> -> Ok(token)
    _ -> Error(CryptoUnavailable)
  }
}

fn valid_secret(secret: BitArray) -> Bool {
  bit_array.bit_size(secret) % 8 == 0 && bit_array.byte_size(secret) >= 32
}

fn valid_connection_id(connection_id: BitArray) -> Bool {
  bit_array.bit_size(connection_id) % 8 == 0
  && bit_array.byte_size(connection_id) > 0
  && bit_array.byte_size(connection_id) <= 20
}

fn map_crypto_result(
  value: Result(output, crypto.Error),
) -> Result(output, Error) {
  case value {
    Ok(output) -> Ok(output)
    Error(_) -> Error(CryptoUnavailable)
  }
}

fn map_authentication_result(
  value: Result(output, authentication.Error),
) -> Result(output, Error) {
  case value {
    Ok(output) -> Ok(output)
    Error(_) -> Error(CryptoUnavailable)
  }
}

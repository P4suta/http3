//// Caller-key-encrypted, versioned persistence for origin-bound generic QUIC state.

import gleam/bit_array
import gleam/result
import gleam_quic/internal/crypto
import gleam_quic/internal/tls/session_ticket
import gleam_quic/internal/udp

const format_version = 1

const associated_data = <<"gleam_quic generic ticket store", 1>>

pub type Stored {
  Stored(
    hostname: String,
    port: Int,
    ticket: session_ticket.ClientTicket,
    address_token: BitArray,
  )
}

pub type Error {
  InvalidKey
  InvalidTicket
  Expired
  ClockRollback
  CryptoUnavailable
}

pub fn export(value: Stored, key: BitArray) -> Result(BitArray, Error) {
  export_at(value, key, udp.monotonic_millisecond(), udp.unix_millisecond())
}

pub fn restore(bytes: BitArray, key: BitArray) -> Result(Stored, Error) {
  restore_at(bytes, key, udp.monotonic_millisecond(), udp.unix_millisecond())
}

pub fn export_at(
  value: Stored,
  key: BitArray,
  monotonic_milliseconds: Int,
  unix_milliseconds: Int,
) -> Result(BitArray, Error) {
  let Stored(hostname, port, ticket, address_token) = value
  use Nil <- result.try(validate_key(key))
  let hostname_bytes = <<hostname:utf8>>
  case
    hostname != ""
    && bit_array.byte_size(hostname_bytes) <= 253
    && port > 0
    && port <= 65_535
    && bit_array.bit_size(address_token) % 8 == 0
    && bit_array.byte_size(address_token) <= 65_535
    && session_ticket.server_name(ticket) == hostname
  {
    False -> Error(InvalidTicket)
    True -> {
      use encrypted_ticket <- result.try(
        session_ticket.export_client(
          ticket,
          key,
          monotonic_milliseconds,
          unix_milliseconds,
        )
        |> map_ticket_result,
      )
      let hostname_length = bit_array.byte_size(hostname_bytes)
      let token_length = bit_array.byte_size(address_token)
      let ticket_length = bit_array.byte_size(encrypted_ticket)
      let plaintext = <<
        port:size(16),
        hostname_length:size(16),
        hostname_bytes:bits,
        token_length:size(16),
        address_token:bits,
        ticket_length:size(32),
        encrypted_ticket:bits,
      >>
      use nonce <- result.try(crypto.secure_random(12) |> map_crypto_result)
      use protected <- result.try(
        crypto.aes_256_gcm_encrypt(key, nonce, associated_data, plaintext)
        |> map_crypto_result,
      )
      Ok(<<format_version, nonce:bits, protected:bits>>)
    }
  }
}

pub fn restore_at(
  bytes: BitArray,
  key: BitArray,
  monotonic_milliseconds: Int,
  unix_milliseconds: Int,
) -> Result(Stored, Error) {
  use Nil <- result.try(validate_key(key))
  use plaintext <- result.try(decrypt(bytes, key))
  use #(hostname, port, address_token, encrypted_ticket) <- result.try(decode(
    plaintext,
  ))
  use ticket <- result.try(
    session_ticket.import_client(
      encrypted_ticket,
      key,
      monotonic_milliseconds,
      unix_milliseconds,
    )
    |> map_ticket_result,
  )
  case session_ticket.server_name(ticket) == hostname {
    True -> Ok(Stored(hostname, port, ticket, address_token))
    False -> Error(InvalidTicket)
  }
}

fn validate_key(key: BitArray) -> Result(Nil, Error) {
  case bit_array.bit_size(key) % 8 == 0 && bit_array.byte_size(key) == 32 {
    True -> Ok(Nil)
    False -> Error(InvalidKey)
  }
}

fn decrypt(bytes: BitArray, key: BitArray) -> Result(BitArray, Error) {
  case bytes {
    <<version, nonce:bits-size(96), protected:bits>> ->
      case version == format_version && bit_array.byte_size(protected) >= 16 {
        False -> Error(InvalidTicket)
        True ->
          crypto.aes_256_gcm_decrypt(key, nonce, associated_data, protected)
          |> result.replace_error(InvalidTicket)
      }
    _ -> Error(InvalidTicket)
  }
}

fn decode(
  bytes: BitArray,
) -> Result(#(String, Int, BitArray, BitArray), Error) {
  case bytes {
    <<port:size(16), hostname_length:size(16), values:bits>> -> {
      use #(hostname_bytes, token_and_rest) <- result.try(take(
        values,
        hostname_length,
      ))
      decode_token(port, hostname_bytes, token_and_rest)
    }
    _ -> Error(InvalidTicket)
  }
}

fn decode_token(
  port: Int,
  hostname_bytes: BitArray,
  bytes: BitArray,
) -> Result(#(String, Int, BitArray, BitArray), Error) {
  case bytes {
    <<token_length:size(16), token_value_and_rest:bits>> -> {
      use #(address_token, ticket_and_rest) <- result.try(take(
        token_value_and_rest,
        token_length,
      ))
      decode_ticket(port, hostname_bytes, address_token, ticket_and_rest)
    }
    _ -> Error(InvalidTicket)
  }
}

fn decode_ticket(
  port: Int,
  hostname_bytes: BitArray,
  address_token: BitArray,
  bytes: BitArray,
) -> Result(#(String, Int, BitArray, BitArray), Error) {
  case bytes {
    <<ticket_length:size(32), ticket_value_and_rest:bits>> -> {
      use #(ticket, trailing) <- result.try(take(
        ticket_value_and_rest,
        ticket_length,
      ))
      use hostname <- result.try(
        bit_array.to_string(hostname_bytes)
        |> result.replace_error(InvalidTicket),
      )
      validate_decoded(
        port,
        hostname,
        hostname_bytes,
        address_token,
        ticket,
        trailing,
      )
    }
    _ -> Error(InvalidTicket)
  }
}

fn validate_decoded(
  port: Int,
  hostname: String,
  hostname_bytes: BitArray,
  address_token: BitArray,
  ticket: BitArray,
  trailing: BitArray,
) -> Result(#(String, Int, BitArray, BitArray), Error) {
  case
    trailing == <<>>
    && hostname != ""
    && bit_array.byte_size(hostname_bytes) <= 253
    && port > 0
    && ticket != <<>>
  {
    True -> Ok(#(hostname, port, address_token, ticket))
    False -> Error(InvalidTicket)
  }
}

fn take(bytes: BitArray, length: Int) -> Result(#(BitArray, BitArray), Error) {
  case length < 0 || length > bit_array.byte_size(bytes) {
    True -> Error(InvalidTicket)
    False -> {
      let bits = length * 8
      case bytes {
        <<value:bits-size(bits), rest:bits>> -> Ok(#(value, rest))
        _ -> Error(InvalidTicket)
      }
    }
  }
}

fn map_ticket_result(
  value: Result(output, session_ticket.Error),
) -> Result(output, Error) {
  case value {
    Ok(output) -> Ok(output)
    Error(session_ticket.InvalidKey) -> Error(InvalidKey)
    Error(session_ticket.Expired) -> Error(Expired)
    Error(session_ticket.InvalidTimestamp) -> Error(ClockRollback)
    Error(_) -> Error(InvalidTicket)
  }
}

fn map_crypto_result(
  value: Result(output, crypto.Error),
) -> Result(output, Error) {
  case value {
    Ok(output) -> Ok(output)
    Error(_) -> Error(CryptoUnavailable)
  }
}

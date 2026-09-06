//// Caller-key-encrypted, versioned persistence for origin-bound HTTP/3 state.

import gleam/bit_array
import gleam/result
import http3/internal/clock
import http3/internal/native/client_connection

pub type Stored {
  Stored(
    hostname: String,
    port: Int,
    ticket: client_connection.ResumptionTicket,
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
  export_at(
    value,
    key,
    clock.monotonic_milliseconds(),
    clock.unix_milliseconds(),
  )
}

pub fn restore(bytes: BitArray, key: BitArray) -> Result(Stored, Error) {
  restore_at(
    bytes,
    key,
    clock.monotonic_milliseconds(),
    clock.unix_milliseconds(),
  )
}

fn export_at(
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
    && client_connection.resumption_ticket_server_name(ticket) == hostname
    && client_connection.resumption_ticket_port(ticket) == port
  {
    False -> Error(InvalidTicket)
    True ->
      // `quic_core` owns and authenticates the TLS ticket, origin, and QUIC
      // address token in one bounded envelope. The legacy outer token is
      // deliberately not duplicated into a second ciphertext.
      client_connection.export_stored_resumption_ticket(
        ticket,
        key,
        monotonic_milliseconds,
        unix_milliseconds,
      )
      |> map_ticket_result
  }
}

fn restore_at(
  bytes: BitArray,
  key: BitArray,
  monotonic_milliseconds: Int,
  unix_milliseconds: Int,
) -> Result(Stored, Error) {
  use Nil <- result.try(validate_key(key))
  use ticket <- result.try(
    client_connection.import_stored_resumption_ticket(
      bytes,
      key,
      monotonic_milliseconds,
      unix_milliseconds,
    )
    |> map_ticket_result,
  )
  let hostname = client_connection.resumption_ticket_server_name(ticket)
  let port = client_connection.resumption_ticket_port(ticket)
  Ok(Stored(hostname, port, ticket, <<>>))
}

fn validate_key(key: BitArray) -> Result(Nil, Error) {
  case bit_array.bit_size(key) % 8 == 0 && bit_array.byte_size(key) == 32 {
    True -> Ok(Nil)
    False -> Error(InvalidKey)
  }
}

fn map_ticket_result(
  value: Result(output, client_connection.ResumptionTicketError),
) -> Result(output, Error) {
  case value {
    Ok(output) -> Ok(output)
    Error(client_connection.InvalidResumptionTicketKey) -> Error(InvalidKey)
    Error(client_connection.ExpiredResumptionTicket) -> Error(Expired)
    Error(client_connection.InvalidResumptionTicketTimestamp) ->
      Error(ClockRollback)
    Error(client_connection.ResumptionTicketCryptoUnavailable) ->
      Error(CryptoUnavailable)
    Error(_) -> Error(InvalidTicket)
  }
}

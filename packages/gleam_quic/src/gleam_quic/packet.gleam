//// Version-invariant and pre-decryption QUIC packet parsing.

import gleam/bit_array
import gleam/int
import gleam/list
import gleam/result
import gleam_quic/varint
import gleam_quic/version.{type Version}

/// Fields common to every QUIC long header.
pub type LongHeader {
  LongHeader(
    first_byte: Int,
    version: Version,
    destination_connection_id: BitArray,
    source_connection_id: BitArray,
  )
}

/// A parsed packet whose protected payload has not yet been decrypted.
pub type Packet {
  VersionNegotiation(LongHeader, List(Version))
  UnknownVersion(LongHeader, BitArray)
  Initial(LongHeader, BitArray, BitArray)
  ZeroRtt(LongHeader, BitArray)
  Handshake(LongHeader, BitArray)
  Retry(LongHeader, BitArray, BitArray)
}

/// The invariant portion of a short-header packet.
pub type ShortHeader {
  ShortHeader(Int, BitArray, BitArray)
}

/// A packet header parse failure.
pub type Error {
  NonByteAligned
  NotLongHeader
  NotShortHeader
  Truncated
  InvalidConnectionIdLength(Int)
  InvalidVersionNegotiation
  InvalidRetry
  InvalidPacketType
}

/// Parse one long-header packet from a UDP datagram.
///
/// Length-bearing packets return any following coalesced packet bytes.
/// Version Negotiation, Retry, and unknown-version packets consume the entire
/// datagram because their remainder cannot be split using known semantics.
pub fn parse_long(datagram: BitArray) -> Result(#(Packet, BitArray), Error) {
  case bit_array.bit_size(datagram) % 8 {
    remainder if remainder != 0 -> Error(NonByteAligned)
    _ ->
      case datagram {
        <<first_byte, rest:bits>> ->
          case int.bitwise_and(first_byte, 0x80) {
            0 -> Error(NotLongHeader)
            _ ->
              case rest {
                <<wire_version:size(32), destination_length, ids:bits>> ->
                  parse_connection_ids(
                    first_byte,
                    wire_version,
                    destination_length,
                    ids,
                  )
                _ -> Error(Truncated)
              }
          }
        _ -> Error(Truncated)
      }
  }
}

/// Parse a short header using the destination connection ID length from the
/// connection context. A short-header packet always consumes the datagram.
pub fn parse_short(
  datagram datagram: BitArray,
  destination_connection_id_length destination_connection_id_length: Int,
) -> Result(ShortHeader, Error) {
  case bit_array.bit_size(datagram) % 8 {
    remainder if remainder != 0 -> Error(NonByteAligned)
    _ ->
      case
        destination_connection_id_length < 0
        || destination_connection_id_length > 20
      {
        True ->
          Error(InvalidConnectionIdLength(destination_connection_id_length))
        False ->
          case datagram {
            <<first_byte, rest:bits>> ->
              parse_short_payload(
                first_byte,
                rest,
                destination_connection_id_length,
              )
            _ -> Error(Truncated)
          }
      }
  }
}

fn parse_short_payload(
  first_byte: Int,
  bytes: BitArray,
  destination_connection_id_length: Int,
) -> Result(ShortHeader, Error) {
  case int.bitwise_and(first_byte, 0x80) {
    value if value != 0 -> Error(NotShortHeader)
    _ ->
      case take(bytes, destination_connection_id_length) {
        Ok(#(_, <<>>)) -> Error(Truncated)
        Ok(#(destination, protected_payload)) ->
          Ok(ShortHeader(first_byte, destination, protected_payload))
        Error(error) -> Error(error)
      }
  }
}

fn parse_connection_ids(
  first_byte: Int,
  wire_version: Int,
  destination_length: Int,
  bytes: BitArray,
) -> Result(#(Packet, BitArray), Error) {
  use #(destination, after_destination) <- result.try(take(
    bytes,
    destination_length,
  ))
  use #(source_length, source_and_payload) <- result.try(take_source_length(
    after_destination,
  ))
  use #(source, payload) <- result.try(take(source_and_payload, source_length))
  use parsed_version <- result.try(parse_version(wire_version))
  let header = LongHeader(first_byte, parsed_version, destination, source)
  parse_version_payload(header, destination_length, source_length, payload)
}

fn take_source_length(bytes: BitArray) -> Result(#(Int, BitArray), Error) {
  case bytes {
    <<source_length, rest:bits>> -> Ok(#(source_length, rest))
    _ -> Error(Truncated)
  }
}

fn parse_version(wire_version: Int) -> Result(Version, Error) {
  case version.from_wire(wire_version) {
    Ok(parsed) -> Ok(parsed)
    Error(_) -> Error(InvalidPacketType)
  }
}

fn parse_version_payload(
  header: LongHeader,
  destination_length: Int,
  source_length: Int,
  payload: BitArray,
) -> Result(#(Packet, BitArray), Error) {
  case header.version {
    version.Negotiation -> parse_version_negotiation(header, payload)
    version.Unknown(_) -> Ok(#(UnknownVersion(header, payload), <<>>))
    version.Version1 | version.Version2 ->
      case validate_connection_id_lengths(destination_length, source_length) {
        Error(error) -> Error(error)
        Ok(Nil) -> parse_supported_long_packet(header, payload)
      }
  }
}

fn validate_connection_id_lengths(
  destination_length: Int,
  source_length: Int,
) -> Result(Nil, Error) {
  case destination_length > 20, source_length > 20 {
    True, _ -> Error(InvalidConnectionIdLength(destination_length))
    _, True -> Error(InvalidConnectionIdLength(source_length))
    _, _ -> Ok(Nil)
  }
}

fn parse_version_negotiation(
  header: LongHeader,
  payload: BitArray,
) -> Result(#(Packet, BitArray), Error) {
  case parse_versions(payload, []) {
    Ok([]) | Error(_) -> Error(InvalidVersionNegotiation)
    Ok(versions) -> Ok(#(VersionNegotiation(header, versions), <<>>))
  }
}

fn parse_versions(
  bytes: BitArray,
  reversed: List(Version),
) -> Result(List(Version), Nil) {
  case bytes {
    <<>> -> Ok(list.reverse(reversed))
    <<wire_version:size(32), rest:bits>> -> {
      case version.from_wire(wire_version) {
        Ok(parsed) -> parse_versions(rest, [parsed, ..reversed])
        Error(_) -> Error(Nil)
      }
    }
    _ -> Error(Nil)
  }
}

fn parse_supported_long_packet(
  header: LongHeader,
  payload: BitArray,
) -> Result(#(Packet, BitArray), Error) {
  let type_bits =
    header.first_byte
    |> int.bitwise_shift_right(4)
    |> int.bitwise_and(3)

  case version.long_packet_type(header.version, type_bits) {
    Error(_) -> Error(InvalidPacketType)
    Ok(packet_type) ->
      case packet_type {
        version.Initial -> parse_initial(header, payload)
        version.ZeroRtt -> parse_length_bearing(header, payload, False)
        version.Handshake -> parse_length_bearing(header, payload, True)
        version.Retry -> parse_retry(header, payload)
      }
  }
}

fn parse_initial(
  header: LongHeader,
  payload: BitArray,
) -> Result(#(Packet, BitArray), Error) {
  case varint.decode(payload) {
    Error(_) -> Error(Truncated)
    Ok(#(token_length, after_token_length)) ->
      case take(after_token_length, token_length) {
        Error(error) -> Error(error)
        Ok(#(token, length_and_payload)) ->
          case take_length_bearing_payload(length_and_payload) {
            Error(error) -> Error(error)
            Ok(#(protected_payload, rest)) ->
              Ok(#(Initial(header, token, protected_payload), rest))
          }
      }
  }
}

fn parse_length_bearing(
  header: LongHeader,
  payload: BitArray,
  handshake: Bool,
) -> Result(#(Packet, BitArray), Error) {
  case take_length_bearing_payload(payload) {
    Error(error) -> Error(error)
    Ok(#(protected_payload, rest)) ->
      case handshake {
        True -> Ok(#(Handshake(header, protected_payload), rest))
        False -> Ok(#(ZeroRtt(header, protected_payload), rest))
      }
  }
}

fn take_length_bearing_payload(
  bytes: BitArray,
) -> Result(#(BitArray, BitArray), Error) {
  case varint.decode(bytes) {
    Error(_) -> Error(Truncated)
    Ok(#(payload_length, payload)) -> take(payload, payload_length)
  }
}

fn parse_retry(
  header: LongHeader,
  payload: BitArray,
) -> Result(#(Packet, BitArray), Error) {
  let payload_size = bit_array.byte_size(payload)
  case payload_size <= 16 {
    True -> Error(InvalidRetry)
    False ->
      case take(payload, payload_size - 16) {
        Ok(#(token, integrity_tag)) ->
          Ok(#(Retry(header, token, integrity_tag), <<>>))
        Error(error) -> Error(error)
      }
  }
}

fn take(bytes: BitArray, length: Int) -> Result(#(BitArray, BitArray), Error) {
  case length < 0 || length > bit_array.byte_size(bytes) {
    True -> Error(Truncated)
    False -> {
      let bit_length = length * 8
      case bytes {
        <<prefix:bits-size(bit_length), rest:bits>> -> Ok(#(prefix, rest))
        _ -> Error(Truncated)
      }
    }
  }
}

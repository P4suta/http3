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
  InvalidHeader
}

/// Encode one long-header packet without following coalesced packets.
pub fn encode_long(packet: Packet) -> Result(BitArray, Error) {
  case packet_is_byte_aligned(packet) {
    False -> Error(NonByteAligned)
    True ->
      case packet {
        VersionNegotiation(header, versions) ->
          encode_version_negotiation(header, versions)
        UnknownVersion(header, payload) -> encode_unknown(header, payload)
        Initial(header, token, protected_payload) ->
          encode_initial(header, token, protected_payload)
        ZeroRtt(header, protected_payload) ->
          encode_length_bearing(header, protected_payload, version.ZeroRtt)
        Handshake(header, protected_payload) ->
          encode_length_bearing(header, protected_payload, version.Handshake)
        Retry(header, token, integrity_tag) ->
          encode_retry(header, token, integrity_tag)
      }
  }
}

/// Encode one complete protected short-header packet.
pub fn encode_short(header: ShortHeader) -> Result(BitArray, Error) {
  let ShortHeader(first_byte, destination, protected_payload) = header
  case
    bit_array.bit_size(destination) % 8 == 0
    && bit_array.bit_size(protected_payload) % 8 == 0
  {
    False -> Error(NonByteAligned)
    True ->
      case
        first_byte < 0
        || first_byte > 255
        || int.bitwise_and(first_byte, 0x80) != 0
      {
        True -> Error(NotShortHeader)
        False ->
          case
            bit_array.byte_size(destination) > 20
            || bit_array.byte_size(protected_payload) < 20
          {
            True -> Error(InvalidHeader)
            False ->
              Ok(<<first_byte, destination:bits, protected_payload:bits>>)
          }
      }
  }
}

fn packet_is_byte_aligned(packet: Packet) -> Bool {
  case packet {
    VersionNegotiation(header, _) -> header_is_byte_aligned(header)
    UnknownVersion(header, payload)
    | ZeroRtt(header, payload)
    | Handshake(header, payload) ->
      header_is_byte_aligned(header) && bit_array.bit_size(payload) % 8 == 0
    Initial(header, token, protected_payload)
    | Retry(header, token, protected_payload) ->
      header_is_byte_aligned(header)
      && bit_array.bit_size(token) % 8 == 0
      && bit_array.bit_size(protected_payload) % 8 == 0
  }
}

fn header_is_byte_aligned(header: LongHeader) -> Bool {
  bit_array.bit_size(header.destination_connection_id) % 8 == 0
  && bit_array.bit_size(header.source_connection_id) % 8 == 0
}

fn encode_version_negotiation(
  header: LongHeader,
  versions: List(Version),
) -> Result(BitArray, Error) {
  case header.version, versions {
    version.Negotiation, [] -> Error(InvalidVersionNegotiation)
    version.Negotiation, _ -> {
      use invariant <- result.try(encode_invariant_header(header, 255))
      use encoded_versions <- result.try(encode_versions(versions, <<>>))
      Ok(<<invariant:bits, encoded_versions:bits>>)
    }
    _, _ -> Error(InvalidVersionNegotiation)
  }
}

fn encode_versions(
  versions: List(Version),
  accumulator: BitArray,
) -> Result(BitArray, Error) {
  case versions {
    [] -> Ok(accumulator)
    [version.Negotiation, ..] -> Error(InvalidVersionNegotiation)
    [next, ..rest] ->
      case version.to_wire(next) {
        Error(_) -> Error(InvalidVersionNegotiation)
        Ok(encoded) ->
          encode_versions(rest, <<accumulator:bits, encoded:size(32)>>)
      }
  }
}

fn encode_unknown(
  header: LongHeader,
  payload: BitArray,
) -> Result(BitArray, Error) {
  case header.version {
    version.Unknown(_) -> {
      use invariant <- result.try(encode_invariant_header(header, 255))
      Ok(<<invariant:bits, payload:bits>>)
    }
    _ -> Error(InvalidHeader)
  }
}

fn encode_initial(
  header: LongHeader,
  token: BitArray,
  protected_payload: BitArray,
) -> Result(BitArray, Error) {
  use invariant <- result.try(encode_supported_header(header, version.Initial))
  use token_length <- result.try(encode_length(bit_array.byte_size(token)))
  use payload_length <- result.try(encode_protected_payload_length(
    protected_payload,
  ))
  Ok(<<
    invariant:bits,
    token_length:bits,
    token:bits,
    payload_length:bits,
    protected_payload:bits,
  >>)
}

fn encode_length_bearing(
  header: LongHeader,
  protected_payload: BitArray,
  packet_type: version.LongPacketType,
) -> Result(BitArray, Error) {
  use invariant <- result.try(encode_supported_header(header, packet_type))
  use payload_length <- result.try(encode_protected_payload_length(
    protected_payload,
  ))
  Ok(<<invariant:bits, payload_length:bits, protected_payload:bits>>)
}

fn encode_retry(
  header: LongHeader,
  token: BitArray,
  integrity_tag: BitArray,
) -> Result(BitArray, Error) {
  case
    bit_array.byte_size(token) > 0 && bit_array.byte_size(integrity_tag) == 16
  {
    False -> Error(InvalidRetry)
    True -> {
      use invariant <- result.try(encode_supported_header(header, version.Retry))
      Ok(<<invariant:bits, token:bits, integrity_tag:bits>>)
    }
  }
}

fn encode_supported_header(
  header: LongHeader,
  expected_type: version.LongPacketType,
) -> Result(BitArray, Error) {
  case header.version {
    version.Version1 | version.Version2 -> {
      let type_bits =
        header.first_byte
        |> int.bitwise_shift_right(4)
        |> int.bitwise_and(3)
      case version.long_packet_type(header.version, type_bits) {
        Ok(found) if found == expected_type ->
          encode_invariant_header(header, 20)
        _ -> Error(InvalidPacketType)
      }
    }
    _ -> Error(InvalidPacketType)
  }
}

fn encode_invariant_header(
  header: LongHeader,
  maximum_connection_id_length: Int,
) -> Result(BitArray, Error) {
  let destination_length = bit_array.byte_size(header.destination_connection_id)
  let source_length = bit_array.byte_size(header.source_connection_id)
  case
    header.first_byte < 0
    || header.first_byte > 255
    || int.bitwise_and(header.first_byte, 0x80) == 0
    || destination_length > maximum_connection_id_length
    || source_length > maximum_connection_id_length
  {
    True -> Error(InvalidHeader)
    False ->
      case version.to_wire(header.version) {
        Error(_) -> Error(InvalidHeader)
        Ok(wire_version) ->
          Ok(<<
            header.first_byte,
            wire_version:size(32),
            destination_length,
            header.destination_connection_id:bits,
            source_length,
            header.source_connection_id:bits,
          >>)
      }
  }
}

fn encode_protected_payload_length(
  protected_payload: BitArray,
) -> Result(BitArray, Error) {
  case bit_array.byte_size(protected_payload) < 20 {
    True -> Error(InvalidHeader)
    False -> encode_length(bit_array.byte_size(protected_payload))
  }
}

fn encode_length(length: Int) -> Result(BitArray, Error) {
  case varint.encode(length) {
    Ok(encoded) -> Ok(encoded)
    Error(_) -> Error(InvalidHeader)
  }
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
        Ok(version.Negotiation) -> Error(Nil)
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

//// Complete QUIC long/short packet protection with coalesced decoding.

import gleam/bit_array
import gleam/int
import gleam/option.{type Option}
import gleam/result
import gleam_quic/internal/crypto
import gleam_quic/internal/initial_crypto
import gleam_quic/internal/packet_protection
import gleam_quic/internal/traffic_keys
import gleam_quic/packet_number
import gleam_quic/varint
import gleam_quic/version.{type Version}

/// Protected long-header semantic. Only Initial carries a token field.
pub type LongKind {
  Initial(token: BitArray)
  ZeroRtt
  Handshake
}

/// Initial AES keys or TLS-derived Handshake/0-RTT/1-RTT keys.
pub type PacketKeys {
  InitialPacketKeys(initial_crypto.PacketKeys)
  TrafficPacketKeys(traffic_keys.TrafficKeys)
}

/// One authenticated long-header packet and its coalesced remainder.
pub type DecodedLong {
  DecodedLong(
    kind: LongKind,
    version: Version,
    destination_connection_id: BitArray,
    source_connection_id: BitArray,
    packet_number: Int,
    payload: BitArray,
    rest: BitArray,
  )
}

/// One authenticated short-header packet.
pub type DecodedShort {
  DecodedShort(
    destination_connection_id: BitArray,
    packet_number: Int,
    key_phase: Bool,
    spin: Bool,
    payload: BitArray,
  )
}

type ParsedLong {
  ParsedLong(
    kind: LongKind,
    version: Version,
    destination_connection_id: BitArray,
    source_connection_id: BitArray,
    protected_header_prefix: BitArray,
    protected_packet_number_and_payload: BitArray,
    rest: BitArray,
  )
}

/// A header, packet-number, sample, or authentication failure.
pub type Error {
  NonByteAligned
  InvalidHeader
  Truncated
  UnsupportedVersion
  InvalidPacketNumber
  InsufficientHeaderProtectionSample
  CryptoFailure
  AuthenticationFailed
}

/// Protect one Initial, 0-RTT, or Handshake packet.
pub fn protect_long(
  kind: LongKind,
  version: Version,
  destination_connection_id: BitArray,
  source_connection_id: BitArray,
  packet_number: Int,
  largest_acknowledged: Option(Int),
  plaintext: BitArray,
  keys: PacketKeys,
) -> Result(BitArray, Error) {
  protect_long_with_grease(
    kind,
    version,
    destination_connection_id,
    source_connection_id,
    packet_number,
    largest_acknowledged,
    plaintext,
    keys,
    False,
  )
}

/// Protect one long-header packet and, after negotiation, derive an
/// unpredictable QUIC Bit from secret packet-protection material.
pub fn protect_long_with_grease(
  kind: LongKind,
  version: Version,
  destination_connection_id: BitArray,
  source_connection_id: BitArray,
  packet_number: Int,
  largest_acknowledged: Option(Int),
  plaintext: BitArray,
  keys: PacketKeys,
  grease_quic_bit: Bool,
) -> Result(BitArray, Error) {
  use _ <- result.try(validate_long_inputs(
    kind,
    version,
    destination_connection_id,
    source_connection_id,
    plaintext,
  ))
  use encoded_packet_number <- result.try(encode_packet_number(
    packet_number,
    largest_acknowledged,
  ))
  use fixed_bit <- result.try(select_fixed_bit(
    keys,
    packet_number,
    grease_quic_bit,
  ))
  use header_prefix <- result.try(long_header_prefix(
    kind,
    version,
    destination_connection_id,
    source_connection_id,
    bit_array.byte_size(encoded_packet_number),
    bit_array.byte_size(plaintext) + 16,
    fixed_bit,
  ))
  let header = <<header_prefix:bits, encoded_packet_number:bits>>
  use protected_payload <- result.try(protect_payload(
    keys,
    packet_number,
    header,
    plaintext,
  ))
  protect_complete_header(
    packet_protection.Long,
    header_prefix,
    encoded_packet_number,
    protected_payload,
    keys,
  )
}

/// Parse, remove header protection, reconstruct the packet number, and authenticate one
/// long-header packet while preserving following coalesced bytes.
pub fn unprotect_long(
  datagram: BitArray,
  expected_packet_number: Int,
  keys: PacketKeys,
) -> Result(DecodedLong, Error) {
  unprotect_long_with_grease(datagram, expected_packet_number, keys, False)
}

/// Unprotect a long-header packet while accepting a negotiated zero QUIC Bit.
pub fn unprotect_long_with_grease(
  datagram: BitArray,
  expected_packet_number: Int,
  keys: PacketKeys,
  accept_greased_quic_bit: Bool,
) -> Result(DecodedLong, Error) {
  use parsed <- result.try(parse_long(datagram, accept_greased_quic_bit))
  unprotect_parsed_long(
    parsed,
    expected_packet_number,
    keys,
    accept_greased_quic_bit,
  )
}

/// Inspect a protected long header after the local endpoint advertised QUIC
/// Bit greasing.
pub fn inspect_long_with_grease(
  datagram: BitArray,
  accept_greased_quic_bit: Bool,
) -> Result(#(LongKind, Version), Error) {
  use parsed <- result.try(parse_long(datagram, accept_greased_quic_bit))
  let ParsedLong(kind, version_value, _, _, _, _, _) = parsed
  Ok(#(kind, version_value))
}

/// Protect one complete 1-RTT short-header packet.
pub fn protect_short(
  destination_connection_id: BitArray,
  packet_number: Int,
  largest_acknowledged: Option(Int),
  key_phase: Bool,
  spin: Bool,
  plaintext: BitArray,
  keys: PacketKeys,
) -> Result(BitArray, Error) {
  protect_short_with_grease(
    destination_connection_id,
    packet_number,
    largest_acknowledged,
    key_phase,
    spin,
    plaintext,
    keys,
    False,
  )
}

/// Protect one short-header packet and optionally grease the QUIC Bit.
pub fn protect_short_with_grease(
  destination_connection_id: BitArray,
  packet_number: Int,
  largest_acknowledged: Option(Int),
  key_phase: Bool,
  spin: Bool,
  plaintext: BitArray,
  keys: PacketKeys,
  grease_quic_bit: Bool,
) -> Result(BitArray, Error) {
  use _ <- result.try(validate_short_inputs(
    destination_connection_id,
    plaintext,
  ))
  use encoded_packet_number <- result.try(encode_packet_number(
    packet_number,
    largest_acknowledged,
  ))
  use fixed_bit <- result.try(select_fixed_bit(
    keys,
    packet_number,
    grease_quic_bit,
  ))
  let first_byte =
    short_first_byte(
      bit_array.byte_size(encoded_packet_number),
      key_phase,
      spin,
      fixed_bit,
    )
  let header_prefix = <<first_byte, destination_connection_id:bits>>
  let header = <<header_prefix:bits, encoded_packet_number:bits>>
  use protected_payload <- result.try(protect_payload(
    keys,
    packet_number,
    header,
    plaintext,
  ))
  protect_complete_header(
    packet_protection.Short,
    header_prefix,
    encoded_packet_number,
    protected_payload,
    keys,
  )
}

/// Authenticate and decrypt the short-header packet occupying a datagram.
pub fn unprotect_short(
  datagram: BitArray,
  destination_connection_id_length: Int,
  expected_packet_number: Int,
  keys: PacketKeys,
) -> Result(DecodedShort, Error) {
  unprotect_short_with_grease(
    datagram,
    destination_connection_id_length,
    expected_packet_number,
    keys,
    False,
  )
}

/// Authenticate a short-header packet while accepting a negotiated zero QUIC
/// Bit.
pub fn unprotect_short_with_grease(
  datagram: BitArray,
  destination_connection_id_length: Int,
  expected_packet_number: Int,
  keys: PacketKeys,
  accept_greased_quic_bit: Bool,
) -> Result(DecodedShort, Error) {
  use #(protected_first, destination, protected_payload) <- result.try(
    parse_short(
      datagram,
      destination_connection_id_length,
      accept_greased_quic_bit,
    ),
  )
  use mask <- result.try(header_mask_from_protected_payload(
    keys,
    protected_payload,
  ))
  use unprotected <- result.try(
    packet_protection.unprotect_header(
      packet_protection.Short,
      protected_first,
      protected_payload,
      mask,
    )
    |> map_packet_protection_result,
  )
  let packet_protection.UnprotectedHeader(
    first_byte,
    encoded_packet_number,
    protected_body,
  ) = unprotected
  use _ <- result.try(validate_unprotected_short(
    first_byte,
    accept_greased_quic_bit,
  ))
  use packet_number <- result.try(reconstruct_packet_number(
    encoded_packet_number,
    expected_packet_number,
  ))
  let header = <<first_byte, destination:bits, encoded_packet_number:bits>>
  use plaintext <- result.try(unprotect_payload(
    keys,
    packet_number,
    header,
    protected_body,
  ))
  Ok(DecodedShort(
    destination,
    packet_number,
    int.bitwise_and(first_byte, 0x04) != 0,
    int.bitwise_and(first_byte, 0x20) != 0,
    plaintext,
  ))
}

fn validate_long_inputs(
  kind: LongKind,
  version_value: Version,
  destination: BitArray,
  source: BitArray,
  plaintext: BitArray,
) -> Result(Nil, Error) {
  case
    byte_aligned(destination) && byte_aligned(source) && byte_aligned(plaintext)
  {
    False -> Error(NonByteAligned)
    True -> {
      let token_aligned = case kind {
        Initial(token) -> byte_aligned(token)
        ZeroRtt | Handshake -> True
      }
      case
        !token_aligned
        || bit_array.byte_size(destination) > 20
        || bit_array.byte_size(source) > 20
        || !supported_version(version_value)
      {
        True -> Error(InvalidHeader)
        False -> Ok(Nil)
      }
    }
  }
}

fn validate_short_inputs(
  destination: BitArray,
  plaintext: BitArray,
) -> Result(Nil, Error) {
  case
    byte_aligned(destination)
    && byte_aligned(plaintext)
    && bit_array.byte_size(destination) <= 20
  {
    True -> Ok(Nil)
    False -> Error(InvalidHeader)
  }
}

fn supported_version(version_value: Version) -> Bool {
  version_value == version.Version1 || version_value == version.Version2
}

fn encode_packet_number(
  full: Int,
  largest_acknowledged: Option(Int),
) -> Result(BitArray, Error) {
  case packet_number.encode(full, largest_acknowledged) {
    Ok(encoded) -> Ok(encoded)
    Error(_) -> Error(InvalidPacketNumber)
  }
}

fn long_header_prefix(
  kind: LongKind,
  version_value: Version,
  destination: BitArray,
  source: BitArray,
  packet_number_length: Int,
  protected_body_length: Int,
  fixed_bit: Bool,
) -> Result(BitArray, Error) {
  use packet_type <- result.try(long_packet_type(kind))
  use type_bits <- result.try(
    case version.long_packet_type_bits(version_value, packet_type) {
      Ok(value) -> Ok(value)
      Error(_) -> Error(UnsupportedVersion)
    },
  )
  use wire_version <- result.try(case version.to_wire(version_value) {
    Ok(value) -> Ok(value)
    Error(_) -> Error(UnsupportedVersion)
  })
  use encoded_length <- result.try(
    varint.encode(packet_number_length + protected_body_length)
    |> map_varint_result,
  )
  let first_byte =
    0x80
    |> set_fixed_bit(fixed_bit)
    |> int.bitwise_or(int.bitwise_shift_left(type_bits, 4))
    |> int.bitwise_or(packet_number_length - 1)
  let invariant = <<
    first_byte,
    wire_version:size(32),
    bit_array.byte_size(destination),
    destination:bits,
    bit_array.byte_size(source),
    source:bits,
  >>
  case kind {
    Initial(token) -> {
      use token_length <- result.try(
        varint.encode(bit_array.byte_size(token)) |> map_varint_result,
      )
      Ok(<<
        invariant:bits,
        token_length:bits,
        token:bits,
        encoded_length:bits,
      >>)
    }
    ZeroRtt | Handshake -> Ok(<<invariant:bits, encoded_length:bits>>)
  }
}

fn long_packet_type(kind: LongKind) -> Result(version.LongPacketType, Error) {
  case kind {
    Initial(_) -> Ok(version.Initial)
    ZeroRtt -> Ok(version.ZeroRtt)
    Handshake -> Ok(version.Handshake)
  }
}

fn short_first_byte(
  packet_number_length: Int,
  key_phase: Bool,
  spin: Bool,
  fixed_bit: Bool,
) -> Int {
  let key_phase_bit = case key_phase {
    True -> 0x04
    False -> 0
  }
  let spin_bit = case spin {
    True -> 0x20
    False -> 0
  }
  0
  |> set_fixed_bit(fixed_bit)
  |> int.bitwise_or(key_phase_bit)
  |> int.bitwise_or(spin_bit)
  |> int.bitwise_or(packet_number_length - 1)
}

fn protect_complete_header(
  form: packet_protection.HeaderForm,
  header_prefix: BitArray,
  encoded_packet_number: BitArray,
  protected_payload: BitArray,
  keys: PacketKeys,
) -> Result(BitArray, Error) {
  let protected_packet_number_and_payload = <<
    encoded_packet_number:bits,
    protected_payload:bits,
  >>
  use mask <- result.try(header_mask_from_protected_payload(
    keys,
    protected_packet_number_and_payload,
  ))
  use #(first_byte, prefix_rest) <- result.try(split_first(header_prefix))
  use #(protected_first, protected_packet_number) <- result.try(
    packet_protection.protect_header(
      form,
      first_byte,
      encoded_packet_number,
      mask,
    )
    |> map_packet_protection_result,
  )
  Ok(<<
    protected_first,
    prefix_rest:bits,
    protected_packet_number:bits,
    protected_payload:bits,
  >>)
}

fn header_mask_from_protected_payload(
  keys: PacketKeys,
  protected_packet_number_and_payload: BitArray,
) -> Result(BitArray, Error) {
  use sample <- result.try(take_at(
    protected_packet_number_and_payload,
    4,
    16,
    InsufficientHeaderProtectionSample,
  ))
  case keys {
    InitialPacketKeys(initial) ->
      case initial_crypto.header_protection_mask(initial, sample) {
        Ok(mask) -> Ok(mask)
        Error(_) -> Error(CryptoFailure)
      }
    TrafficPacketKeys(traffic) ->
      case traffic_keys.header_protection_mask(traffic, sample) {
        Ok(mask) -> Ok(mask)
        Error(_) -> Error(CryptoFailure)
      }
  }
}

fn protect_payload(
  keys: PacketKeys,
  packet_number: Int,
  header: BitArray,
  plaintext: BitArray,
) -> Result(BitArray, Error) {
  case keys {
    InitialPacketKeys(initial) ->
      packet_protection.protect_payload(
        initial,
        packet_number,
        header,
        plaintext,
      )
      |> map_packet_protection_result
    TrafficPacketKeys(traffic) ->
      case traffic_keys.protect(traffic, packet_number, header, plaintext) {
        Ok(protected) -> Ok(protected)
        Error(_) -> Error(CryptoFailure)
      }
  }
}

fn unprotect_payload(
  keys: PacketKeys,
  packet_number: Int,
  header: BitArray,
  protected_payload: BitArray,
) -> Result(BitArray, Error) {
  case keys {
    InitialPacketKeys(initial) ->
      packet_protection.unprotect_payload(
        initial,
        packet_number,
        header,
        protected_payload,
      )
      |> map_packet_protection_result
    TrafficPacketKeys(traffic) ->
      case
        traffic_keys.unprotect(
          traffic,
          packet_number,
          header,
          protected_payload,
        )
      {
        Ok(plaintext) -> Ok(plaintext)
        Error(traffic_keys.CryptoFailure(crypto.AuthenticationFailed)) ->
          Error(AuthenticationFailed)
        Error(_) -> Error(CryptoFailure)
      }
  }
}

fn parse_long(
  datagram: BitArray,
  accept_greased_quic_bit: Bool,
) -> Result(ParsedLong, Error) {
  case byte_aligned(datagram) {
    False -> Error(NonByteAligned)
    True -> parse_aligned_long(datagram, accept_greased_quic_bit)
  }
}

fn parse_aligned_long(
  datagram: BitArray,
  accept_greased_quic_bit: Bool,
) -> Result(ParsedLong, Error) {
  case datagram {
    <<first_byte, wire_version:size(32), destination_length, rest:bits>> -> {
      case
        header_form_is_long(first_byte)
        && fixed_bit_is_valid(first_byte, accept_greased_quic_bit)
        && destination_length <= 20
      {
        False -> Error(InvalidHeader)
        True ->
          parse_long_connection_ids(
            datagram,
            first_byte,
            wire_version,
            destination_length,
            rest,
          )
      }
    }
    _ -> Error(Truncated)
  }
}

fn parse_long_connection_ids(
  datagram: BitArray,
  first_byte: Int,
  wire_version: Int,
  destination_length: Int,
  bytes: BitArray,
) -> Result(ParsedLong, Error) {
  use destination_and_rest <- result.try(take(bytes, destination_length))
  let #(destination, after_destination) = destination_and_rest
  case after_destination {
    <<source_length, source_and_body:bits>> if source_length <= 20 -> {
      use source_and_body <- result.try(take(source_and_body, source_length))
      let #(source, body) = source_and_body
      use version_value <- result.try(parse_supported_version(wire_version))
      use kind <- result.try(parse_long_kind(first_byte, version_value))
      parse_long_body(datagram, kind, version_value, destination, source, body)
    }
    <<_, _:bits>> -> Error(InvalidHeader)
    _ -> Error(Truncated)
  }
}

fn parse_supported_version(wire: Int) -> Result(Version, Error) {
  case version.from_wire(wire) {
    Ok(version.Version1) -> Ok(version.Version1)
    Ok(version.Version2) -> Ok(version.Version2)
    Ok(_) | Error(_) -> Error(UnsupportedVersion)
  }
}

fn parse_long_kind(
  first_byte: Int,
  version_value: Version,
) -> Result(LongKind, Error) {
  let type_bits = int.bitwise_and(int.bitwise_shift_right(first_byte, 4), 3)
  case version.long_packet_type(version_value, type_bits) {
    Ok(version.Initial) -> Ok(Initial(<<>>))
    Ok(version.ZeroRtt) -> Ok(ZeroRtt)
    Ok(version.Handshake) -> Ok(Handshake)
    Ok(version.Retry) | Error(_) -> Error(InvalidHeader)
  }
}

fn parse_long_body(
  datagram: BitArray,
  kind: LongKind,
  version_value: Version,
  destination: BitArray,
  source: BitArray,
  body: BitArray,
) -> Result(ParsedLong, Error) {
  case kind {
    Initial(_) -> {
      use #(token_length, after_token_length) <- result.try(decode_varint(body))
      use #(token, length_and_payload) <- result.try(take(
        after_token_length,
        token_length,
      ))
      parse_length_bearing_body(
        datagram,
        Initial(token),
        version_value,
        destination,
        source,
        length_and_payload,
      )
    }
    ZeroRtt | Handshake ->
      parse_length_bearing_body(
        datagram,
        kind,
        version_value,
        destination,
        source,
        body,
      )
  }
}

fn parse_length_bearing_body(
  datagram: BitArray,
  kind: LongKind,
  version_value: Version,
  destination: BitArray,
  source: BitArray,
  length_and_payload: BitArray,
) -> Result(ParsedLong, Error) {
  use #(payload_length, protected_and_rest) <- result.try(decode_varint(
    length_and_payload,
  ))
  use #(protected_payload, rest) <- result.try(take(
    protected_and_rest,
    payload_length,
  ))
  let prefix_length =
    bit_array.byte_size(datagram)
    - bit_array.byte_size(protected_payload)
    - bit_array.byte_size(rest)
  use #(prefix, _) <- result.try(take(datagram, prefix_length))
  Ok(ParsedLong(
    kind,
    version_value,
    destination,
    source,
    prefix,
    protected_payload,
    rest,
  ))
}

fn unprotect_parsed_long(
  parsed: ParsedLong,
  expected_packet_number: Int,
  keys: PacketKeys,
  accept_greased_quic_bit: Bool,
) -> Result(DecodedLong, Error) {
  let ParsedLong(
    kind,
    version_value,
    destination,
    source,
    prefix,
    protected,
    rest,
  ) = parsed
  use mask <- result.try(header_mask_from_protected_payload(keys, protected))
  use #(protected_first, prefix_rest) <- result.try(split_first(prefix))
  use unprotected <- result.try(
    packet_protection.unprotect_header(
      packet_protection.Long,
      protected_first,
      protected,
      mask,
    )
    |> map_packet_protection_result,
  )
  let packet_protection.UnprotectedHeader(
    first_byte,
    encoded_packet_number,
    protected_body,
  ) = unprotected
  use _ <- result.try(validate_unprotected_long(
    first_byte,
    accept_greased_quic_bit,
  ))
  use packet_number <- result.try(reconstruct_packet_number(
    encoded_packet_number,
    expected_packet_number,
  ))
  let header = <<first_byte, prefix_rest:bits, encoded_packet_number:bits>>
  use plaintext <- result.try(unprotect_payload(
    keys,
    packet_number,
    header,
    protected_body,
  ))
  Ok(DecodedLong(
    kind,
    version_value,
    destination,
    source,
    packet_number,
    plaintext,
    rest,
  ))
}

fn parse_short(
  datagram: BitArray,
  destination_length: Int,
  accept_greased_quic_bit: Bool,
) -> Result(#(Int, BitArray, BitArray), Error) {
  case byte_aligned(datagram) {
    False -> Error(NonByteAligned)
    True ->
      parse_aligned_short(datagram, destination_length, accept_greased_quic_bit)
  }
}

fn parse_aligned_short(
  datagram: BitArray,
  destination_length: Int,
  accept_greased_quic_bit: Bool,
) -> Result(#(Int, BitArray, BitArray), Error) {
  case destination_length < 0 || destination_length > 20 {
    True -> Error(InvalidHeader)
    False ->
      parse_short_header(datagram, destination_length, accept_greased_quic_bit)
  }
}

fn parse_short_header(
  datagram: BitArray,
  destination_length: Int,
  accept_greased_quic_bit: Bool,
) -> Result(#(Int, BitArray, BitArray), Error) {
  use #(first_byte, rest) <- result.try(split_first(datagram))
  case
    !header_form_is_long(first_byte)
    && fixed_bit_is_valid(first_byte, accept_greased_quic_bit)
  {
    True -> finish_short_parse(first_byte, rest, destination_length)
    False -> Error(InvalidHeader)
  }
}

fn finish_short_parse(
  first_byte: Int,
  rest: BitArray,
  destination_length: Int,
) -> Result(#(Int, BitArray, BitArray), Error) {
  use #(destination, protected) <- result.try(take(rest, destination_length))
  case protected {
    <<>> -> Error(Truncated)
    _ -> Ok(#(first_byte, destination, protected))
  }
}

fn validate_unprotected_long(
  first_byte: Int,
  accept_greased_quic_bit: Bool,
) -> Result(Nil, Error) {
  case
    header_form_is_long(first_byte)
    && fixed_bit_is_valid(first_byte, accept_greased_quic_bit)
    && int.bitwise_and(first_byte, 0x0c) == 0
  {
    True -> Ok(Nil)
    False -> Error(InvalidHeader)
  }
}

fn validate_unprotected_short(
  first_byte: Int,
  accept_greased_quic_bit: Bool,
) -> Result(Nil, Error) {
  case
    !header_form_is_long(first_byte)
    && fixed_bit_is_valid(first_byte, accept_greased_quic_bit)
    && int.bitwise_and(first_byte, 0x18) == 0
  {
    True -> Ok(Nil)
    False -> Error(InvalidHeader)
  }
}

fn header_form_is_long(first_byte: Int) -> Bool {
  int.bitwise_and(first_byte, 0x80) == 0x80
}

fn fixed_bit_is_valid(first_byte: Int, accept_greased: Bool) -> Bool {
  accept_greased || int.bitwise_and(first_byte, 0x40) == 0x40
}

fn set_fixed_bit(first_byte: Int, fixed: Bool) -> Int {
  case fixed {
    True -> int.bitwise_or(first_byte, 0x40)
    False -> first_byte
  }
}

fn select_fixed_bit(
  keys: PacketKeys,
  packet_number: Int,
  grease: Bool,
) -> Result(Bool, Error) {
  case grease {
    False -> Ok(True)
    True -> {
      let secret = case keys {
        InitialPacketKeys(initial_crypto.PacketKeys(secret, _, _, _)) -> secret
        TrafficPacketKeys(traffic_keys.TrafficKeys(secret: secret, ..)) ->
          secret
      }
      case
        crypto.hmac(crypto.Sha256, secret, <<
          "grease_quic_bit":utf8,
          packet_number:size(64),
        >>)
      {
        Ok(<<first, _:bits>>) -> Ok(int.bitwise_and(first, 1) == 1)
        Ok(_) | Error(_) -> Error(CryptoFailure)
      }
    }
  }
}

fn reconstruct_packet_number(
  encoded: BitArray,
  expected: Int,
) -> Result(Int, Error) {
  use truncated <- result.try(packet_number_integer(encoded))
  case
    packet_number.reconstruct(
      truncated,
      bit_array.byte_size(encoded) * 8,
      expected,
    )
  {
    Ok(full) -> Ok(full)
    Error(_) -> Error(InvalidPacketNumber)
  }
}

fn packet_number_integer(encoded: BitArray) -> Result(Int, Error) {
  case encoded {
    <<value>> -> Ok(value)
    <<value:size(16)>> -> Ok(value)
    <<value:size(24)>> -> Ok(value)
    <<value:size(32)>> -> Ok(value)
    _ -> Error(InvalidPacketNumber)
  }
}

fn decode_varint(bytes: BitArray) -> Result(#(Int, BitArray), Error) {
  case varint.decode(bytes) {
    Ok(decoded) -> Ok(decoded)
    Error(_) -> Error(Truncated)
  }
}

fn map_varint_result(
  value: Result(BitArray, varint.Error),
) -> Result(BitArray, Error) {
  case value {
    Ok(encoded) -> Ok(encoded)
    Error(_) -> Error(InvalidHeader)
  }
}

fn map_packet_protection_result(
  value: Result(value, packet_protection.Error),
) -> Result(value, Error) {
  case value {
    Ok(result_value) -> Ok(result_value)
    Error(packet_protection.NonByteAligned) -> Error(NonByteAligned)
    Error(packet_protection.AuthenticationFailed) -> Error(AuthenticationFailed)
    Error(_) -> Error(CryptoFailure)
  }
}

fn split_first(bytes: BitArray) -> Result(#(Int, BitArray), Error) {
  case bytes {
    <<first, rest:bits>> -> Ok(#(first, rest))
    _ -> Error(Truncated)
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

fn take_at(
  bytes: BitArray,
  offset: Int,
  length: Int,
  error: Error,
) -> Result(BitArray, Error) {
  case
    offset < 0 || length < 0 || offset + length > bit_array.byte_size(bytes)
  {
    True -> Error(error)
    False -> {
      let offset_bits = offset * 8
      let length_bits = length * 8
      case bytes {
        <<_:bits-size(offset_bits), value:bits-size(length_bits), _:bits>> ->
          Ok(value)
        _ -> Error(error)
      }
    }
  }
}

fn byte_aligned(bytes: BitArray) -> Bool {
  bit_array.bit_size(bytes) % 8 == 0
}

//// Bounded HTTP/3 SETTINGS memory used only for a resumed 0-RTT session.
////
//// The wire envelope is fixed-width, versioned, and contains only settings understood by this implementation.
//// Unknown and reserved settings never acquire meaning by being copied into a ticket.

import gleam/int
import http3/internal/varint

const format_version = 1

const qpack_capacity_bit = 1

const maximum_field_section_bit = 2

const qpack_blocked_streams_bit = 4

const connect_protocol_bit = 8

const h3_datagram_bit = 16

const all_known_bits = 31

/// Values and explicit-presence information remembered from one SETTINGS.
pub opaque type Snapshot {
  Snapshot(
    qpack_max_table_capacity: Int,
    maximum_field_section_size: Int,
    qpack_blocked_streams: Int,
    enable_connect_protocol: Bool,
    h3_datagram: Bool,
    present: Int,
  )
}

/// A malformed, non-canonical, or out-of-range remembered-settings envelope.
pub type Error {
  InvalidSnapshot
  InvalidEncoding
}

/// RFC 9114 initial values when no SETTINGS were stored with the ticket.
pub fn defaults() -> Snapshot {
  Snapshot(0, varint.maximum, 0, False, False, 0)
}

/// Construct one validated snapshot from already validated SETTINGS values.
pub fn new(
  qpack_max_table_capacity: Int,
  maximum_field_section_size: Int,
  qpack_blocked_streams: Int,
  enable_connect_protocol: Bool,
  h3_datagram: Bool,
  present_identifiers: List(Int),
) -> Result(Snapshot, Error) {
  let present = presence_mask(present_identifiers, 0)
  let snapshot =
    Snapshot(
      qpack_max_table_capacity,
      maximum_field_section_size,
      qpack_blocked_streams,
      enable_connect_protocol,
      h3_datagram,
      present,
    )
  case valid(snapshot) && omitted_values_are_defaults(snapshot) {
    True -> Ok(snapshot)
    False -> Error(InvalidSnapshot)
  }
}

/// Construct the server's complete advertised-settings ticket context.
///
/// The HTTP/3 sender emits all five understood settings, so all presence bits are retained.
/// GREASE is deliberately excluded from compatibility state.
pub fn advertised(
  qpack_max_table_capacity: Int,
  maximum_field_section_size: Int,
  qpack_blocked_streams: Int,
  enable_connect_protocol: Bool,
  h3_datagram: Bool,
) -> Result(Snapshot, Error) {
  new(
    qpack_max_table_capacity,
    maximum_field_section_size,
    qpack_blocked_streams,
    enable_connect_protocol,
    h3_datagram,
    [1, 6, 7, 8, 0x33],
  )
}

/// Encode a canonical fixed-size ticket context.
pub fn encode(snapshot: Snapshot) -> Result(BitArray, Error) {
  case valid(snapshot) {
    False -> Error(InvalidSnapshot)
    True -> {
      let connect = bool_int(snapshot.enable_connect_protocol)
      let datagram = bool_int(snapshot.h3_datagram)
      Ok(<<
        format_version,
        snapshot.present,
        snapshot.qpack_max_table_capacity:size(64),
        snapshot.maximum_field_section_size:size(64),
        snapshot.qpack_blocked_streams:size(64),
        connect,
        datagram,
      >>)
    }
  }
}

/// Decode only the canonical fixed-size representation.
pub fn decode(bytes: BitArray) -> Result(Snapshot, Error) {
  case bytes {
    <<
      version,
      present,
      qpack_max_table_capacity:size(64),
      maximum_field_section_size:size(64),
      qpack_blocked_streams:size(64),
      connect,
      datagram,
    >> -> {
      let snapshot =
        Snapshot(
          qpack_max_table_capacity,
          maximum_field_section_size,
          qpack_blocked_streams,
          connect == 1,
          datagram == 1,
          present,
        )
      case
        version == format_version
        && { connect == 0 || connect == 1 }
        && { datagram == 0 || datagram == 1 }
        && valid(snapshot)
        && omitted_values_are_defaults(snapshot)
      {
        True -> Ok(snapshot)
        False -> Error(InvalidEncoding)
      }
    }
    _ -> Error(InvalidEncoding)
  }
}

/// Whether current server settings are safe for data produced under remembered settings.
/// Every understood remembered non-default must also be explicit.
pub fn compatible(remembered: Snapshot, current: Snapshot) -> Bool {
  current.qpack_max_table_capacity >= remembered.qpack_max_table_capacity
  && current.maximum_field_section_size >= remembered.maximum_field_section_size
  && current.qpack_blocked_streams >= remembered.qpack_blocked_streams
  && { !remembered.enable_connect_protocol || current.enable_connect_protocol }
  && { !remembered.h3_datagram || current.h3_datagram }
  && remembered_non_defaults_are_present(remembered, current)
}

pub fn qpack_max_table_capacity(snapshot: Snapshot) -> Int {
  snapshot.qpack_max_table_capacity
}

pub fn maximum_field_section_size(snapshot: Snapshot) -> Int {
  snapshot.maximum_field_section_size
}

pub fn qpack_blocked_streams(snapshot: Snapshot) -> Int {
  snapshot.qpack_blocked_streams
}

pub fn enable_connect_protocol(snapshot: Snapshot) -> Bool {
  snapshot.enable_connect_protocol
}

pub fn h3_datagram(snapshot: Snapshot) -> Bool {
  snapshot.h3_datagram
}

fn remembered_non_defaults_are_present(
  remembered: Snapshot,
  current: Snapshot,
) -> Bool {
  { remembered.qpack_max_table_capacity == 0 || is_present(current, 1) }
  && {
    remembered.maximum_field_section_size == varint.maximum
    || is_present(current, 6)
  }
  && { remembered.qpack_blocked_streams == 0 || is_present(current, 7) }
  && { !remembered.enable_connect_protocol || is_present(current, 8) }
  && { !remembered.h3_datagram || is_present(current, 0x33) }
}

fn omitted_values_are_defaults(snapshot: Snapshot) -> Bool {
  { is_present(snapshot, 1) || snapshot.qpack_max_table_capacity == 0 }
  && {
    is_present(snapshot, 6)
    || snapshot.maximum_field_section_size == varint.maximum
  }
  && { is_present(snapshot, 7) || snapshot.qpack_blocked_streams == 0 }
  && { is_present(snapshot, 8) || !snapshot.enable_connect_protocol }
  && { is_present(snapshot, 0x33) || !snapshot.h3_datagram }
}

fn valid(snapshot: Snapshot) -> Bool {
  snapshot.qpack_max_table_capacity >= 0
  && snapshot.qpack_max_table_capacity <= varint.maximum
  && snapshot.maximum_field_section_size >= 0
  && snapshot.maximum_field_section_size <= varint.maximum
  && snapshot.qpack_blocked_streams >= 0
  && snapshot.qpack_blocked_streams <= varint.maximum
  && snapshot.present >= 0
  && snapshot.present <= all_known_bits
}

fn is_present(snapshot: Snapshot, identifier: Int) -> Bool {
  let bit = setting_bit(identifier)
  bit != 0 && int_bit_is_set(snapshot.present, bit)
}

fn presence_mask(identifiers: List(Int), accumulator: Int) -> Int {
  case identifiers {
    [] -> accumulator
    [identifier, ..rest] ->
      presence_mask(rest, int_bit_or(accumulator, setting_bit(identifier)))
  }
}

fn setting_bit(identifier: Int) -> Int {
  case identifier {
    1 -> qpack_capacity_bit
    6 -> maximum_field_section_bit
    7 -> qpack_blocked_streams_bit
    8 -> connect_protocol_bit
    0x33 -> h3_datagram_bit
    _ -> 0
  }
}

fn int_bit_is_set(value: Int, bit: Int) -> Bool {
  int.bitwise_and(value, bit) != 0
}

fn int_bit_or(value: Int, bit: Int) -> Int {
  case bit == 0 || int_bit_is_set(value, bit) {
    True -> value
    False -> int.bitwise_or(value, bit)
  }
}

fn bool_int(value: Bool) -> Int {
  case value {
    True -> 1
    False -> 0
  }
}

//// QUIC version identifiers and version-specific packet type mappings.

import gleam/int

/// A QUIC version identifier carried in a long header.
pub type Version {
  Negotiation
  Version1
  Version2
  Unknown(Int)
}

/// A long-header packet semantic shared by QUIC v1 and v2.
pub type LongPacketType {
  Initial
  ZeroRtt
  Handshake
  Retry
}

/// A version or packet-type conversion failure.
pub type Error {
  OutOfRange
  InvalidPacketType
  UnsupportedVersion(Int)
}

/// Decode a 32-bit QUIC version identifier.
pub fn from_wire(identifier: Int) -> Result(Version, Error) {
  case identifier {
    identifier if identifier < 0 || identifier > 0xffff_ffff -> Error(OutOfRange)
    0 -> Ok(Negotiation)
    1 -> Ok(Version1)
    0x6b33_43cf -> Ok(Version2)
    identifier -> Ok(Unknown(identifier))
  }
}

/// Encode a version identifier as its unsigned 32-bit value.
pub fn to_wire(version: Version) -> Result(Int, Error) {
  case version {
    Negotiation -> Ok(0)
    Version1 -> Ok(1)
    Version2 -> Ok(0x6b33_43cf)
    Unknown(identifier) ->
      case
        identifier > 0
        && identifier <= 0xffff_ffff
        && identifier != 1
        && identifier != 0x6b33_43cf
      {
        True -> Ok(identifier)
        False -> Error(OutOfRange)
      }
  }
}

/// Return whether an identifier follows RFC 9000's reserved-version pattern.
pub fn is_reserved(version: Version) -> Bool {
  case to_wire(version) {
    Ok(identifier) -> int.bitwise_and(identifier, 0x0f0f_0f0f) == 0x0a0a_0a0a
    // nolint: thrown_away_error -- malformed opaque identifiers are not reserved.
    Error(_) -> False
  }
}

/// Interpret the two visible long-header type bits for a supported version.
pub fn long_packet_type(
  version version: Version,
  type_bits type_bits: Int,
) -> Result(LongPacketType, Error) {
  case type_bits < 0 || type_bits > 3 {
    True -> Error(InvalidPacketType)
    False ->
      case version, type_bits {
        Version1, 0 -> Ok(Initial)
        Version1, 1 -> Ok(ZeroRtt)
        Version1, 2 -> Ok(Handshake)
        Version1, 3 -> Ok(Retry)
        Version2, 0 -> Ok(Retry)
        Version2, 1 -> Ok(Initial)
        Version2, 2 -> Ok(ZeroRtt)
        Version2, 3 -> Ok(Handshake)
        Version1, _ | Version2, _ -> Error(InvalidPacketType)
        Negotiation, _ -> Error(UnsupportedVersion(0))
        Unknown(identifier), _ -> Error(UnsupportedVersion(identifier))
      }
  }
}

/// Return the visible long-header type bits for a supported version.
pub fn long_packet_type_bits(
  version version: Version,
  packet_type packet_type: LongPacketType,
) -> Result(Int, Error) {
  case version, packet_type {
    Version1, Initial -> Ok(0)
    Version1, ZeroRtt -> Ok(1)
    Version1, Handshake -> Ok(2)
    Version1, Retry -> Ok(3)
    Version2, Retry -> Ok(0)
    Version2, Initial -> Ok(1)
    Version2, ZeroRtt -> Ok(2)
    Version2, Handshake -> Ok(3)
    Negotiation, _ -> Error(UnsupportedVersion(0))
    Unknown(identifier), _ -> Error(UnsupportedVersion(identifier))
  }
}

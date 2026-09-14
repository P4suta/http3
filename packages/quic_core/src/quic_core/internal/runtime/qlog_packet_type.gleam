//// Strictly redacted pre-decryption QUIC packet classification for qlog.

import quic_core/packet

/// A typed, payload-free classification of public QUIC header shape.
///
/// Parser rejection is retained for tests and internal diagnosis, while
/// `qlog_code` deliberately redacts every rejection to the standard unknown
/// packet type.
pub type Classification {
  OneRttPacket
  InitialPacket
  HandshakePacket
  ZeroRttPacket
  RetryPacket
  VersionNegotiationPacket
  UnknownVersionPacket
  MalformedPacket(packet.Error)
}

/// Classify a datagram using only its public header shape.
///
/// No connection ID, token, version value, packet number, or payload leaves
/// this function. Malformed headers retain only their bounded typed reason.
pub fn classify(datagram: BitArray) -> Classification {
  case datagram {
    <<first, _rest:bits>> if first < 0x80 -> OneRttPacket
    _ ->
      case packet.parse_long(datagram) {
        Ok(#(packet.Initial(_, _, _), _)) -> InitialPacket
        Ok(#(packet.Handshake(_, _), _)) -> HandshakePacket
        Ok(#(packet.ZeroRtt(_, _), _)) -> ZeroRttPacket
        Ok(#(packet.Retry(_, _, _), _)) -> RetryPacket
        Ok(#(packet.VersionNegotiation(_, _), _)) -> VersionNegotiationPacket
        Ok(#(packet.UnknownVersion(_, _), _)) -> UnknownVersionPacket
        Error(error) -> MalformedPacket(error)
      }
  }
}

/// Convert a typed classification to the pinned qlog packet-type code.
///
/// Unknown versions and all parse failures intentionally share code 8 so the
/// live trace cannot reveal rejected header details.
pub fn qlog_code(classification: Classification) -> Int {
  case classification {
    InitialPacket -> 1
    HandshakePacket -> 2
    ZeroRttPacket -> 3
    OneRttPacket -> 4
    RetryPacket -> 5
    VersionNegotiationPacket -> 6
    UnknownVersionPacket | MalformedPacket(_) -> 8
  }
}

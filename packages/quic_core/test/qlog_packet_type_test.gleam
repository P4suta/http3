import quic_core/internal/runtime/qlog_packet_type
import quic_core/packet
import quic_core/version

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn classifies_only_cleartext_packet_shape_test() -> Nil {
  assert qlog_packet_type.classify(<<0x40, 0:160>>)
    == qlog_packet_type.OneRttPacket

  let initial_header =
    packet.LongHeader(0xC0, version.Version1, <<1, 2>>, <<3, 4>>)
  let handshake_header =
    packet.LongHeader(0xE0, version.Version1, <<1, 2>>, <<3, 4>>)
  let assert Ok(initial) =
    packet.encode_long(packet.Initial(initial_header, <<>>, <<0:160>>))
  let assert Ok(handshake) =
    packet.encode_long(packet.Handshake(handshake_header, <<0:160>>))
  assert qlog_packet_type.classify(initial) == qlog_packet_type.InitialPacket
  assert qlog_packet_type.classify(handshake)
    == qlog_packet_type.HandshakePacket
  assert qlog_packet_type.classify(<<>>)
    == qlog_packet_type.MalformedPacket(packet.Truncated)
  assert qlog_packet_type.classify(<<1:size(1)>>)
    == qlog_packet_type.MalformedPacket(packet.NonByteAligned)
}

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn qlog_codes_redact_malformed_and_unknown_version_details_test() -> Nil {
  assert qlog_packet_type.qlog_code(qlog_packet_type.OneRttPacket) == 4
  assert qlog_packet_type.qlog_code(qlog_packet_type.InitialPacket) == 1
  assert qlog_packet_type.qlog_code(qlog_packet_type.HandshakePacket) == 2
  assert qlog_packet_type.qlog_code(qlog_packet_type.ZeroRttPacket) == 3
  assert qlog_packet_type.qlog_code(qlog_packet_type.RetryPacket) == 5
  assert qlog_packet_type.qlog_code(qlog_packet_type.VersionNegotiationPacket)
    == 6
  assert qlog_packet_type.qlog_code(qlog_packet_type.UnknownVersionPacket) == 8
  assert qlog_packet_type.qlog_code(
      qlog_packet_type.MalformedPacket(packet.InvalidConnectionIdLength(20)),
    )
    == 8
}

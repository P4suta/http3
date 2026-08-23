import gleam_quic/packet
import gleam_quic/version

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn parses_version_negotiation_packet_test() -> Nil {
  let datagram = <<
    0x80,
    0:32,
    8,
    0x83,
    0x94,
    0xc8,
    0xf0,
    0x3e,
    0x51,
    0x57,
    0x08,
    4,
    1,
    2,
    3,
    4,
    1:32,
    0x6b33_43cf:32,
    0x1a2a_3a4a:32,
  >>

  let assert Ok(#(parsed, <<>>)) = packet.parse_long(datagram)
  let assert packet.VersionNegotiation(header, versions) = parsed
  assert header.first_byte == 0x80
  assert header.version == version.Negotiation
  assert header.destination_connection_id
    == <<0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08>>
  assert header.source_connection_id == <<1, 2, 3, 4>>
  assert versions
    == [version.Version1, version.Version2, version.Unknown(0x1a2a_3a4a)]
}

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn parses_v1_and_v2_initial_packets_test() -> Nil {
  let v1 = <<0xc0, 1:32, 2, 0xaa, 0xbb, 1, 0xcc, 0, 3, 1, 2, 3, 0xff>>
  let assert Ok(#(packet.Initial(v1_header, token, payload), <<0xff>>)) =
    packet.parse_long(v1)
  assert v1_header.version == version.Version1
  assert token == <<>>
  assert payload == <<1, 2, 3>>

  let v2 = <<0xd0, 0x6b33_43cf:32, 1, 0xaa, 1, 0xbb, 2, 9, 8, 4, 1, 2, 3, 4>>
  let assert Ok(#(packet.Initial(v2_header, v2_token, v2_payload), <<>>)) =
    packet.parse_long(v2)
  assert v2_header.version == version.Version2
  assert v2_token == <<9, 8>>
  assert v2_payload == <<1, 2, 3, 4>>
}

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn parses_v2_retry_and_unknown_version_invariants_test() -> Nil {
  let tag = <<0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15>>
  let retry = <<0xc0, 0x6b33_43cf:32, 1, 0xaa, 1, 0xbb, "token":utf8, tag:bits>>
  let assert Ok(#(packet.Retry(header, token, integrity_tag), <<>>)) =
    packet.parse_long(retry)
  assert header.version == version.Version2
  assert token == <<"token":utf8>>
  assert integrity_tag == tag

  let unknown = <<0xff, 0x0a0a_0a0a:32, 21, 0:size(168), 0, 1, 2, 3>>
  let assert Ok(#(packet.UnknownVersion(unknown_header, <<1, 2, 3>>), <<>>)) =
    packet.parse_long(unknown)
  assert unknown_header.version == version.Unknown(0x0a0a_0a0a)
}

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn parses_short_header_with_contextual_connection_id_length_test() -> Nil {
  let assert Ok(packet.ShortHeader(first, destination, payload)) =
    packet.parse_short(<<0x41, 1, 2, 3, 4, 0xaa, 0xbb>>, 4)
  assert first == 0x41
  assert destination == <<1, 2, 3, 4>>
  assert payload == <<0xaa, 0xbb>>
}

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn rejects_malformed_packet_headers_test() -> Nil {
  assert packet.parse_long(<<0x40, 0, 0, 0, 1>>) == Error(packet.NotLongHeader)
  assert packet.parse_long(<<0x80, 0:32, 0, 0>>)
    == Error(packet.InvalidVersionNegotiation)
  assert packet.parse_long(<<0x80, 0:32, 0, 0, 1, 2, 3>>)
    == Error(packet.InvalidVersionNegotiation)
  assert packet.parse_long(<<0xc0, 1:32, 21, 0:size(168), 0>>)
    == Error(packet.InvalidConnectionIdLength(21))
  assert packet.parse_long(<<0xc0, 1:32, 0, 0, 0, 4, 1, 2>>)
    == Error(packet.Truncated)
  assert packet.parse_long(<<1:size(1)>>) == Error(packet.NonByteAligned)
  assert packet.parse_short(<<0x40, 1>>, 21)
    == Error(packet.InvalidConnectionIdLength(21))
  assert packet.parse_short(<<0x80, 1>>, 0) == Error(packet.NotShortHeader)
}

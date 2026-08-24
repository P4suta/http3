import gleam/bit_array
import gleam/int
import gleam/list
import gleam/option.{None, Some}
import gleam_quic/internal/initial_crypto
import gleam_quic/internal/tls/hello
import gleam_quic/internal/traffic_keys
import gleam_quic/internal/wire_packet
import gleam_quic/version

const destination_connection_id = <<1, 2, 3, 4, 5, 6, 7, 8>>

const source_connection_id = <<9, 10, 11, 12>>

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn protects_coalesces_and_unprotects_long_packets_test() -> Nil {
  let assert Ok(initial) =
    initial_crypto.derive_initial(version.Version1, destination_connection_id)
  let assert Ok(handshake) =
    traffic_keys.from_secret(version.Version1, hello.Aes128GcmSha256, <<3:256>>)
  let assert Ok(initial_packet) =
    wire_packet.protect_long(
      wire_packet.Initial(<<"token">>),
      version.Version1,
      destination_connection_id,
      source_connection_id,
      0,
      None,
      <<1, 0, 0, 0>>,
      wire_packet.InitialPacketKeys(initial.client),
    )
  let assert Ok(handshake_packet) =
    wire_packet.protect_long(
      wire_packet.Handshake,
      version.Version1,
      destination_connection_id,
      source_connection_id,
      0,
      None,
      <<6, 0, 0, 0>>,
      wire_packet.TrafficPacketKeys(handshake),
    )
  let datagram = <<initial_packet:bits, handshake_packet:bits>>

  let assert Ok(wire_packet.DecodedLong(
    wire_packet.Initial(token),
    version.Version1,
    destination,
    source,
    0,
    <<1, 0, 0, 0>>,
    rest,
  )) =
    wire_packet.unprotect_long(
      datagram,
      0,
      wire_packet.InitialPacketKeys(initial.client),
    )
  assert token == <<"token">>
  assert destination == destination_connection_id
  assert source == source_connection_id
  assert rest == handshake_packet

  assert wire_packet.unprotect_long(
      rest,
      0,
      wire_packet.TrafficPacketKeys(handshake),
    )
    == Ok(
      wire_packet.DecodedLong(
        wire_packet.Handshake,
        version.Version1,
        destination_connection_id,
        source_connection_id,
        0,
        <<6, 0, 0, 0>>,
        <<>>,
      ),
    )
}

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn protects_v2_zero_rtt_and_short_header_key_phase_test() -> Nil {
  let assert Ok(keys) =
    traffic_keys.from_secret(version.Version2, hello.Chacha20Poly1305Sha256, <<
      7:256,
    >>)
  let assert Ok(zero_rtt) =
    wire_packet.protect_long(
      wire_packet.ZeroRtt,
      version.Version2,
      destination_connection_id,
      source_connection_id,
      257,
      Some(255),
      <<8, 0, 0>>,
      wire_packet.TrafficPacketKeys(keys),
    )
  assert wire_packet.unprotect_long(
      zero_rtt,
      256,
      wire_packet.TrafficPacketKeys(keys),
    )
    == Ok(
      wire_packet.DecodedLong(
        wire_packet.ZeroRtt,
        version.Version2,
        destination_connection_id,
        source_connection_id,
        257,
        <<8, 0, 0>>,
        <<>>,
      ),
    )

  let assert Ok(short) =
    wire_packet.protect_short(
      destination_connection_id,
      65_537,
      Some(65_535),
      True,
      True,
      <<0x1e, 0, 0>>,
      wire_packet.TrafficPacketKeys(keys),
    )
  assert wire_packet.unprotect_short(
      short,
      bit_array.byte_size(destination_connection_id),
      65_536,
      wire_packet.TrafficPacketKeys(keys),
    )
    == Ok(
      wire_packet.DecodedShort(destination_connection_id, 65_537, True, True, <<
        0x1e,
        0,
        0,
      >>),
    )
}

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn rejects_short_samples_tampering_and_invalid_context_test() -> Nil {
  let assert Ok(keys) =
    traffic_keys.from_secret(version.Version1, hello.Aes128GcmSha256, <<0:256>>)
  assert wire_packet.protect_short(
      <<>>,
      0,
      None,
      False,
      False,
      <<>>,
      wire_packet.TrafficPacketKeys(keys),
    )
    == Error(wire_packet.InsufficientHeaderProtectionSample)

  let assert Ok(packet) =
    wire_packet.protect_short(
      destination_connection_id,
      0,
      None,
      False,
      False,
      <<1, 0, 0, 0, 0, 0, 0, 0>>,
      wire_packet.TrafficPacketKeys(keys),
    )
  let size = bit_array.byte_size(packet)
  let prefix_size = { size - 1 } * 8
  let assert <<prefix:bits-size(prefix_size), last>> = packet
  let tampered = <<prefix:bits, int.bitwise_exclusive_or(last, 1)>>
  assert wire_packet.unprotect_short(
      tampered,
      8,
      0,
      wire_packet.TrafficPacketKeys(keys),
    )
    == Error(wire_packet.AuthenticationFailed)
  assert wire_packet.unprotect_short(
      packet,
      21,
      0,
      wire_packet.TrafficPacketKeys(keys),
    )
    == Error(wire_packet.InvalidHeader)
}

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn rejects_authenticated_reserved_bits_as_a_protocol_violation_test() -> Nil {
  let assert Ok(keys) =
    traffic_keys.from_secret(version.Version1, hello.Aes128GcmSha256, <<4:256>>)
  let assert Ok(reserved) =
    wire_packet.protect_short_with_reserved_bits(
      destination_connection_id,
      0,
      None,
      False,
      False,
      <<1, 2, 3, 4>>,
      wire_packet.TrafficPacketKeys(keys),
      0x08,
    )
  assert wire_packet.unprotect_short(
      reserved,
      bit_array.byte_size(destination_connection_id),
      0,
      wire_packet.TrafficPacketKeys(keys),
    )
    == Error(wire_packet.InvalidReservedBits)
}

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn negotiated_quic_bit_greasing_is_unpredictable_and_authenticated_test() -> Nil {
  let assert Ok(keys) =
    traffic_keys.from_secret(version.Version1, hello.Aes128GcmSha256, <<9:256>>)
  let protected =
    integers(0, 63)
    |> list.map(fn(packet_number) {
      let assert Ok(bytes) =
        wire_packet.protect_short_with_grease(
          destination_connection_id,
          packet_number,
          None,
          False,
          False,
          <<1, 2, 3, 4>>,
          wire_packet.TrafficPacketKeys(keys),
          True,
        )
      #(packet_number, bytes)
    })

  assert list.any(protected, fn(packet) {
    let assert #(_, <<first, _:bits>>) = packet
    int.bitwise_and(first, 0x40) == 0
  })
  assert list.any(protected, fn(packet) {
    let assert #(_, <<first, _:bits>>) = packet
    int.bitwise_and(first, 0x40) == 0x40
  })
  assert list.any(protected, fn(packet) {
    let #(packet_number, bytes) = packet
    let assert <<first, _:bits>> = bytes
    int.bitwise_and(first, 0x40) == 0
    && wire_packet.unprotect_short(
      bytes,
      bit_array.byte_size(destination_connection_id),
      packet_number,
      wire_packet.TrafficPacketKeys(keys),
    )
    == Error(wire_packet.InvalidHeader)
  })

  protected
  |> list.each(fn(packet) {
    let #(packet_number, bytes) = packet
    assert wire_packet.unprotect_short_with_grease(
        bytes,
        bit_array.byte_size(destination_connection_id),
        packet_number,
        wire_packet.TrafficPacketKeys(keys),
        True,
      )
      == Ok(
        wire_packet.DecodedShort(
          destination_connection_id,
          packet_number,
          False,
          False,
          <<1, 2, 3, 4>>,
        ),
      )
  })
}

fn integers(first: Int, last: Int) -> List(Int) {
  case first > last {
    True -> []
    False -> [first, ..integers(first + 1, last)]
  }
}

import gleam/bit_array
import gleeunit/should
import quic_core
import quic_core/internal/ecn
import quic_core/internal/retry_integrity
import quic_core/internal/udp
import quic_core/packet
import quic_core/server
import quic_core/version

@external(erlang, "quic_core_test_ffi", "fixture")
fn fixture(name: String) -> Result(BitArray, Nil)

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn listener_sends_authenticated_retry_over_real_udp_test() -> Nil {
  assert_authenticated_retry(version.Version1, 0xc0)
}

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn listener_keeps_v2_retry_on_the_original_version_over_real_udp_test() -> Nil {
  assert_authenticated_retry(version.Version2, 0xd0)
}

fn assert_authenticated_retry(
  protocol_version: version.Version,
  initial_first_byte: Int,
) -> Nil {
  let certificate = fixture("server.pem") |> should.be_ok
  let private_key = fixture("server-key.pem") |> should.be_ok
  let listener =
    server.new(certificate, private_key, "sample")
    |> should.be_ok
    |> server.with_address_family(quic_core.Ipv4)
    |> server.start
    |> should.be_ok
  let port = server.port(listener) |> should.be_ok

  let loopback = udp.ipv4(127, 0, 0, 1) |> should.be_ok
  let local = udp.endpoint(loopback, 0) |> should.be_ok
  let peer = udp.endpoint(loopback, port) |> should.be_ok
  let socket = udp.open(local) |> should.be_ok
  let original_destination = <<1, 2, 3, 4, 5, 6, 7, 8>>
  let client_source = <<9, 10, 11, 12, 13, 14, 15, 16>>
  let initial =
    packet.Initial(
      packet.LongHeader(
        initial_first_byte,
        protocol_version,
        original_destination,
        client_source,
      ),
      <<>>,
      <<0:size(9600)>>,
    )
    |> packet.encode_long
    |> should.be_ok

  udp.send(socket, peer, initial, ecn.NotEct) |> should.be_ok
  let udp.Datagram(_, response, _) = udp.receive(socket, 1000) |> should.be_ok
  let assert Ok(#(packet.Retry(header, token, tag), <<>>)) =
    packet.parse_long(response)
  assert header.version == protocol_version
  assert header.destination_connection_id == client_source
  assert bit_array.byte_size(header.source_connection_id) == 8
  assert bit_array.byte_size(token) > 0
  assert bit_array.byte_size(tag) == 16
  let without_tag =
    bit_array.slice(response, 0, bit_array.byte_size(response) - 16)
    |> should.be_ok
  retry_integrity.verify(
    protocol_version,
    original_destination,
    without_tag,
    tag,
  )
  |> should.be_ok

  udp.close(socket) |> should.be_ok
  assert server.stop(listener) == Ok(server.Stopped)
}

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn listener_swaps_connection_ids_in_version_negotiation_over_real_udp_test() -> Nil {
  let certificate = fixture("server.pem") |> should.be_ok
  let private_key = fixture("server-key.pem") |> should.be_ok
  let listener =
    server.new(certificate, private_key, "sample")
    |> should.be_ok
    |> server.with_address_family(quic_core.Ipv4)
    |> server.start
    |> should.be_ok
  let port = server.port(listener) |> should.be_ok

  let loopback = udp.ipv4(127, 0, 0, 1) |> should.be_ok
  let local = udp.endpoint(loopback, 0) |> should.be_ok
  let peer = udp.endpoint(loopback, port) |> should.be_ok
  let socket = udp.open(local) |> should.be_ok
  let client_destination = <<1, 2, 3, 4, 5, 6, 7, 8>>
  let client_source = <<9, 10, 11, 12, 13, 14, 15, 16>>
  let unsupported =
    packet.UnknownVersion(
      packet.LongHeader(
        0xff,
        version.Unknown(0xface_b00c),
        client_destination,
        client_source,
      ),
      <<0xde, 0xad, 0xbe, 0xef>>,
    )
    |> packet.encode_long
    |> should.be_ok

  udp.send(socket, peer, unsupported, ecn.NotEct) |> should.be_ok
  let udp.Datagram(_, response, _) = udp.receive(socket, 1000) |> should.be_ok
  let assert Ok(#(packet.VersionNegotiation(header, versions), <<>>)) =
    packet.parse_long(response)
  assert header.destination_connection_id == client_source
  assert header.source_connection_id == client_destination
  assert versions == [version.Version2, version.Version1]

  udp.close(socket) |> should.be_ok
  assert server.stop(listener) == Ok(server.Stopped)
}

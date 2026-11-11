import gleam/bit_array
import gleam/list
import gleam/option.{None}
import gleam/result
import gleeunit/should
import quic_core
import quic_core/frame
import quic_core/internal/ecn
import quic_core/internal/initial_crypto
import quic_core/internal/retry_integrity
import quic_core/internal/udp
import quic_core/internal/wire_packet
import quic_core/packet
import quic_core/server
import quic_core/version

@external(erlang, "quic_core_test_ffi", "fixture")
fn fixture(name: String) -> Result(BitArray, Nil)

type InitialResponseObservation {
  InvalidTokenClose
  RetryObserved
  OtherInitialResponse
}

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
pub fn readable_retry_token_for_another_port_gets_invalid_token_close_test() -> Nil {
  let observation = exercise_retry_erratum_7861(version.Version1)
  assert observation == InvalidTokenClose
}

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn v2_readable_retry_token_for_another_port_gets_invalid_token_close_test() -> Nil {
  let observation = exercise_retry_erratum_7861(version.Version2)
  assert observation == InvalidTokenClose
}

fn exercise_retry_erratum_7861(
  protocol_version: version.Version,
) -> InitialResponseObservation {
  let certificate = fixture("server.pem") |> should.be_ok
  let private_key = fixture("server-key.pem") |> should.be_ok
  let listener =
    server.new(certificate, private_key, "retry-erratum-7861")
    |> should.be_ok
    |> server.with_address_family(quic_core.Ipv4)
    |> server.start
    |> should.be_ok
  let port = server.port(listener) |> should.be_ok

  let loopback = udp.ipv4(127, 0, 0, 1) |> should.be_ok
  let local = udp.endpoint(loopback, 0) |> should.be_ok
  let peer = udp.endpoint(loopback, port) |> should.be_ok
  let first_socket = udp.open(local) |> should.be_ok
  let second_socket = udp.open(local) |> should.be_ok
  let original_destination = <<1, 2, 3, 4, 5, 6, 7, 8>>
  let client_source = <<9, 10, 11, 12, 13, 14, 15, 16>>
  let observation =
    run_retry_erratum_exchange(
      first_socket,
      second_socket,
      peer,
      protocol_version,
      original_destination,
      client_source,
    )

  let first_closed = udp.close(first_socket)
  let second_closed = udp.close(second_socket)
  let stopped = server.stop(listener)
  case first_closed, second_closed, stopped {
    Ok(Nil), Ok(Nil), Ok(server.Stopped) -> observation
    _, _, _ -> OtherInitialResponse
  }
}

fn run_retry_erratum_exchange(
  first_socket: udp.Socket,
  second_socket: udp.Socket,
  peer: udp.Endpoint,
  protocol_version: version.Version,
  original_destination: BitArray,
  client_source: BitArray,
) -> InitialResponseObservation {
  let outcome = {
    let original_keys =
      initial_crypto.derive_initial(protocol_version, original_destination)
      |> result.replace_error(Nil)
    use original_keys <- result.try(original_keys)
    let first_initial =
      wire_packet.protect_long(
        // A foreign implementation's opaque token is unreadable here.
        // Erratum 7861 requires treating it as absent, so this first response is Retry.
        wire_packet.Initial(<<0:size(512)>>),
        protocol_version,
        original_destination,
        client_source,
        0,
        None,
        <<0:size(9600)>>,
        wire_packet.InitialPacketKeys(original_keys.client),
      )
      |> result.replace_error(Nil)
    use first_initial <- result.try(first_initial)

    use Nil <- result.try(
      udp.send(first_socket, peer, first_initial, ecn.NotEct)
      |> result.replace_error(Nil),
    )
    use retry_datagram <- result.try(
      udp.receive(first_socket, 1000) |> result.replace_error(Nil),
    )
    let udp.Datagram(_, retry_bytes, _) = retry_datagram
    use #(token, retry_source) <- result.try(extract_retry_material(retry_bytes))
    let keys =
      initial_crypto.derive_initial(protocol_version, retry_source)
      |> result.replace_error(Nil)
    use keys <- result.try(keys)
    let second_initial =
      wire_packet.protect_long(
        wire_packet.Initial(token),
        protocol_version,
        retry_source,
        client_source,
        0,
        None,
        <<0:size(9600)>>,
        wire_packet.InitialPacketKeys(keys.client),
      )
      |> result.replace_error(Nil)
    use second_initial <- result.try(second_initial)

    // The second socket has a distinct source port.
    // The token remains readable and identifiable as Retry, but cannot validate this transport address.
    use Nil <- result.try(
      udp.send(second_socket, peer, second_initial, ecn.NotEct)
      |> result.replace_error(Nil),
    )
    use response_datagram <- result.try(
      udp.receive(second_socket, 1000) |> result.replace_error(Nil),
    )
    let udp.Datagram(_, response, _) = response_datagram
    Ok(observe_initial_response(
      response,
      keys.server,
      protocol_version,
      client_source,
      retry_source,
    ))
  }
  case outcome {
    Ok(observation) -> observation
    Error(Nil) -> OtherInitialResponse
  }
}

fn extract_retry_material(
  bytes: BitArray,
) -> Result(#(BitArray, BitArray), Nil) {
  case packet.parse_long(bytes) {
    Ok(#(packet.Retry(header, token, _), <<>>)) ->
      Ok(#(token, header.source_connection_id))
    _ -> Error(Nil)
  }
}

fn observe_initial_response(
  bytes: BitArray,
  keys: initial_crypto.PacketKeys,
  expected_version: version.Version,
  expected_destination: BitArray,
  expected_source: BitArray,
) -> InitialResponseObservation {
  case
    wire_packet.unprotect_long(bytes, 0, wire_packet.InitialPacketKeys(keys))
  {
    Ok(wire_packet.DecodedLong(
      wire_packet.Initial(<<>>),
      observed_version,
      destination,
      source,
      0,
      plaintext,
      <<>>,
    )) ->
      case
        observed_version == expected_version,
        destination == expected_destination,
        source == expected_source,
        frame.decode_all(plaintext, frame.default_limits())
      {
        True, True, True, Ok(frames) ->
          case
            list.contains(frames, frame.ConnectionCloseTransport(0x0b, 0, ""))
          {
            True -> InvalidTokenClose
            False -> OtherInitialResponse
          }
        _, _, _, _ -> OtherInitialResponse
      }
    _ ->
      case packet.parse_long(bytes) {
        Ok(#(packet.Retry(_, _, _), <<>>)) -> RetryObserved
        _ -> OtherInitialResponse
      }
  }
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

import gleam/bit_array
import gleam/option.{None, Some}
import gleam_quic
import gleam_quic/client
import gleam_quic/diagnostics
import gleam_quic/server
import gleeunit/should

@external(erlang, "gleam_quic_test_ffi", "fixture")
fn fixture(name: String) -> Result(BitArray, Nil)

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn public_mtls_required_and_optional_round_trip_test() -> Nil {
  let certificate = fixture("server.pem") |> should.be_ok
  let private_key = fixture("server-key.pem") |> should.be_ok
  let ca_certificate = fixture("ca.pem") |> should.be_ok
  let client_certificate = fixture("client.pem") |> should.be_ok
  let client_private_key = fixture("client-key.pem") |> should.be_ok
  let client_authorities =
    server.client_certificate_authorities(client_certificate) |> should.be_ok

  let required_listener =
    server.new(certificate, private_key, "sample")
    |> should.be_ok
    |> server.with_client_authentication(server.Required(client_authorities))
    |> server.with_address_family(gleam_quic.Ipv4)
    |> server.start
    |> should.be_ok
  let required_port = server.port(required_listener) |> should.be_ok
  let authenticated_connection =
    client.new("localhost", required_port, "sample")
    |> should.be_ok
    |> client.with_ca_certificates(ca_certificate)
    |> should.be_ok
    |> client.with_client_certificate(client_certificate, client_private_key)
    |> should.be_ok
    |> client.with_address_family(gleam_quic.Ipv4)
    |> client.connect
    |> should.be_ok
  let authenticated_peer = server.accept(required_listener) |> should.be_ok
  let assert Some(identity) =
    server.client_identity(authenticated_peer) |> should.be_ok
  assert bit_array.byte_size(server.client_identity_fingerprint(identity)) == 32

  let _authenticated_closed = client.close(authenticated_connection)
  let _authenticated_peer_closed = server.close(authenticated_peer)
  assert server.stop(required_listener) == Ok(server.Stopped)

  let optional_listener =
    server.new(certificate, private_key, "sample")
    |> should.be_ok
    |> server.with_client_authentication(server.Optional(client_authorities))
    |> server.with_address_family(gleam_quic.Ipv4)
    |> server.start
    |> should.be_ok
  let optional_port = server.port(optional_listener) |> should.be_ok
  let anonymous_connection =
    client.new("localhost", optional_port, "sample")
    |> should.be_ok
    |> client.with_ca_certificates(ca_certificate)
    |> should.be_ok
    |> client.with_address_family(gleam_quic.Ipv4)
    |> client.connect
    |> should.be_ok
  let anonymous_peer = server.accept(optional_listener) |> should.be_ok
  assert server.client_identity(anonymous_peer) == Ok(None)

  let _anonymous_closed = client.close(anonymous_connection)
  let _anonymous_peer_closed = server.close(anonymous_peer)
  assert server.stop(optional_listener) == Ok(server.Stopped)
  Nil
}

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn generic_quic_public_api_round_trip_over_real_udp_test() -> Nil {
  let certificate = fixture("server.pem") |> should.be_ok
  let private_key = fixture("server-key.pem") |> should.be_ok
  let ca_certificate = fixture("ca.pem") |> should.be_ok

  let listener =
    server.new(certificate, private_key, "sample")
    |> should.be_ok
    |> server.with_application_protocols(["server-only", "shared"])
    |> should.be_ok
    |> server.with_address_family(gleam_quic.Ipv4)
    |> server.start
    |> should.be_ok
  let port = server.port(listener) |> should.be_ok
  let connection =
    client.new("localhost", port, "sample")
    |> should.be_ok
    |> client.with_application_protocols(["client-only", "shared"])
    |> should.be_ok
    |> client.with_address_family(gleam_quic.Ipv4)
    |> client.with_ca_certificates(ca_certificate)
    |> should.be_ok
    |> client.connect
    |> should.be_ok
  let peer = server.accept(listener) |> should.be_ok

  assert client.phase(connection) == Ok(diagnostics.Established)
  assert server.phase(peer) == Ok(diagnostics.Established)
  let diagnostics.ConnectionInfo(
    version,
    protocol,
    cipher,
    congestion,
    early,
    resumed,
  ) = client.connection_info(connection) |> should.be_ok
  assert version == gleam_quic.QuicV1
  assert protocol == "shared"
  assert cipher == diagnostics.Aes128GcmSha256
  assert congestion == gleam_quic.NewReno
  assert early == diagnostics.NotAttempted
  assert resumed == diagnostics.ResumptionNotAttempted
  let diagnostics.ConnectionInfo(
    server_version,
    server_protocol,
    server_cipher,
    _,
    server_early,
    server_resumption,
  ) = server.connection_info(peer) |> should.be_ok
  assert server_version == gleam_quic.QuicV1
  assert server_protocol == "shared"
  assert server_cipher == diagnostics.Aes128GcmSha256
  assert server_early == diagnostics.NotAttempted
  assert server_resumption == diagnostics.FullHandshake

  let stream = client.open_bidirectional(connection) |> should.be_ok
  client.send_and_finish(stream, <<"hello":utf8>>) |> should.be_ok
  let assert server.IncomingStream(peer_stream, server.Bidirectional) =
    server.accept_stream(peer) |> should.be_ok
  assert server.receive(peer_stream, 1024)
    == Ok(server.Data(<<"hello":utf8>>, True))

  server.send_and_finish(peer_stream, <<"world":utf8>>) |> should.be_ok
  assert client.receive(stream, 1024) == Ok(client.Data(<<"world":utf8>>, True))

  let maximum = client.maximum_datagram_size(connection) |> should.be_ok
  assert maximum > 0
  client.send_datagram(connection, <<"client datagram":utf8>>) |> should.be_ok
  assert server.receive_datagram(peer) == Ok(<<"client datagram":utf8>>)
  server.send_datagram(peer, <<"server datagram":utf8>>) |> should.be_ok
  assert client.receive_datagram(connection) == Ok(<<"server datagram":utf8>>)

  client.ping(connection) |> should.be_ok
  client.set_congestion_control(connection, gleam_quic.Cubic) |> should.be_ok
  let diagnostics.ConnectionStats(_, sent, _, sent_bytes, _, _, _, _) =
    client.connection_stats(connection) |> should.be_ok
  assert sent > 0
  assert sent_bytes > 0
  let diagnostics.PathStats(_, _, _, _, window, _, _, _) =
    client.path_stats(connection) |> should.be_ok
  assert window > 0
  let diagnostics.TelemetryStats(dropped, write_errors, queued) =
    client.telemetry_stats(connection) |> should.be_ok
  assert dropped == 0
  assert write_errors == 0
  assert queued >= 0

  assert client.close(connection) == Ok(client.Closed)
  assert client.close(connection) == Ok(client.AlreadyClosed)
  let _server_close = server.close(peer) |> should.be_ok
  assert server.close(peer) == Ok(server.AlreadyClosed)
  assert server.stop(listener) == Ok(server.Stopped)
  assert server.stop(listener) == Ok(server.AlreadyStopped)
}

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn stream_direction_errors_are_typed_test() -> Nil {
  let certificate = fixture("server.pem") |> should.be_ok
  let private_key = fixture("server-key.pem") |> should.be_ok
  let ca_certificate = fixture("ca.pem") |> should.be_ok
  let listener =
    server.new(certificate, private_key, "sample")
    |> should.be_ok
    |> server.with_address_family(gleam_quic.Ipv4)
    |> server.start
    |> should.be_ok
  let port = server.port(listener) |> should.be_ok
  let connection =
    client.new("localhost", port, "sample")
    |> should.be_ok
    |> client.with_address_family(gleam_quic.Ipv4)
    |> client.with_ca_certificates(ca_certificate)
    |> should.be_ok
    |> client.connect
    |> should.be_ok
  let peer = server.accept(listener) |> should.be_ok

  let stream = client.open_unidirectional(connection) |> should.be_ok
  assert client.receive(stream, 1) == Error(client.InvalidDirection)
  client.send_and_finish(stream, <<"one way":utf8>>) |> should.be_ok
  let assert server.IncomingStream(peer_stream, server.Unidirectional) =
    server.accept_stream(peer) |> should.be_ok
  assert server.send(peer_stream, <<"invalid":utf8>>)
    == Error(server.InvalidDirection)
  assert server.receive(peer_stream, 1024)
    == Ok(server.Data(<<"one way":utf8>>, True))

  let _closed = client.close(connection)
  let _stopped = server.stop(listener)
  Nil
}

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn encrypted_ticket_survives_listener_restart_test() -> Nil {
  let certificate = fixture("server.pem") |> should.be_ok
  let private_key = fixture("server-key.pem") |> should.be_ok
  let ca_certificate = fixture("ca.pem") |> should.be_ok
  let ticket_key = server.operational_key(<<1:size(256)>>) |> should.be_ok
  let reset_key = server.operational_key(<<2:size(256)>>) |> should.be_ok
  let address_key = server.operational_key(<<5:size(256)>>) |> should.be_ok
  let ticket_keys = server.key_ring(ticket_key)
  let reset_keys = server.key_ring(reset_key)
  let address_keys = server.key_ring(address_key)
  let operational_keys =
    server.operational_keys(
      ticket: ticket_keys,
      address_token: address_keys,
      stateless_reset: reset_keys,
    )
    |> should.be_ok
  let next_ticket_key = server.operational_key(<<6:size(256)>>) |> should.be_ok
  let next_reset_key = server.operational_key(<<7:size(256)>>) |> should.be_ok
  let next_address_key = server.operational_key(<<8:size(256)>>) |> should.be_ok
  let rotated_ticket_keys =
    server.rotate_key_ring(ticket_keys, next_ticket_key) |> should.be_ok
  let rotated_reset_keys =
    server.rotate_key_ring(reset_keys, next_reset_key) |> should.be_ok
  let rotated_address_keys =
    server.rotate_key_ring(address_keys, next_address_key) |> should.be_ok
  let rotated_operational_keys =
    server.operational_keys(
      ticket: rotated_ticket_keys,
      address_token: rotated_address_keys,
      stateless_reset: rotated_reset_keys,
    )
    |> should.be_ok
  let post_rotation_operational_keys =
    server.operational_keys(
      ticket: rotated_ticket_keys,
      address_token: server.key_ring(next_address_key),
      stateless_reset: rotated_reset_keys,
    )
    |> should.be_ok
  let first_server =
    server.new(certificate, private_key, "sample")
    |> should.be_ok
    |> server.with_address_family(gleam_quic.Ipv4)
    |> server.with_single_node_zero_rtt
    |> server.with_operational_keys(operational_keys)
  let first_listener = server.start(first_server) |> should.be_ok
  let port = server.port(first_listener) |> should.be_ok
  let first_client =
    client.new("localhost", port, "sample")
    |> should.be_ok
    |> client.with_address_family(gleam_quic.Ipv4)
    |> client.with_ca_certificates(ca_certificate)
    |> should.be_ok
  let first_connection = client.connect(first_client) |> should.be_ok
  let first_peer = server.accept(first_listener) |> should.be_ok
  let _initial_ticket =
    client.resumption_ticket(first_connection) |> should.be_ok

  server.reload_operational_keys(first_listener, rotated_operational_keys)
  |> should.be_ok
  server.send_datagram(first_peer, <<"rotation barrier":utf8>>) |> should.be_ok
  assert client.receive_datagram(first_connection)
    == Ok(<<"rotation barrier":utf8>>)

  let ticket = client.resumption_ticket(first_connection) |> should.be_ok
  let storage_key = client.ticket_storage_key(<<3:size(256)>>) |> should.be_ok
  let other_key = client.ticket_storage_key(<<4:size(256)>>) |> should.be_ok
  let stored =
    client.export_resumption_ticket(ticket, storage_key) |> should.be_ok
  assert client.import_resumption_ticket(stored, other_key)
    == Error(client.InvalidStoredTicket)
  let restored =
    client.import_resumption_ticket(stored, storage_key) |> should.be_ok

  let _closed = client.close(first_connection)
  let _peer_closed = server.close(first_peer)
  assert server.stop(first_listener) == Ok(server.Stopped)

  let second_listener =
    first_server
    |> server.with_operational_keys(post_rotation_operational_keys)
    |> server.with_port(port)
    |> should.be_ok
    |> server.start
    |> should.be_ok
  let second_client =
    first_client
    |> client.with_resumption_ticket(restored)
    |> should.be_ok
    |> client.with_zero_rtt
  let second_connection = client.connect(second_client) |> should.be_ok
  let early_stream =
    client.open_bidirectional(second_connection) |> should.be_ok
  client.send_and_finish(early_stream, <<"early":utf8>>) |> should.be_ok
  let second_peer = server.accept(second_listener) |> should.be_ok
  let assert server.IncomingStream(early_peer_stream, server.Bidirectional) =
    server.accept_stream(second_peer) |> should.be_ok
  assert server.receive(early_peer_stream, 1024)
    == Ok(server.Data(<<"early":utf8>>, True))
  let diagnostics.ConnectionInfo(_, _, _, _, early, resumed) =
    client.connection_info(second_connection) |> should.be_ok
  assert early == diagnostics.Accepted
  assert resumed == diagnostics.Resumed
  let diagnostics.ConnectionInfo(_, _, _, _, server_early, server_resumed) =
    server.connection_info(second_peer) |> should.be_ok
  assert server_early == diagnostics.Accepted
  assert server_resumed == diagnostics.Resumed

  let _closed = client.close(second_connection)
  let _peer_closed = server.close(second_peer)
  assert server.stop(second_listener) == Ok(server.Stopped)
}

import gleam/bit_array
import gleam/erlang/process
import gleam/option.{None, Some}
import gleeunit/should
import quic_core
import quic_core/client
import quic_core/diagnostics
import quic_core/failure
import quic_core/server

const sequential_unidirectional_streams = 600

@external(erlang, "quic_core_test_ffi", "fixture")
fn fixture(name: String) -> Result(BitArray, Nil)

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn rsa_pss_certificate_live_round_trip_test() -> Nil {
  credential_round_trip("rsa-pss-server.pem", "rsa-pss-server-key.pem")
}

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn ecdsa_p256_certificate_live_round_trip_test() -> Nil {
  credential_round_trip("ecdsa-p256-server.pem", "ecdsa-p256-server-key.pem")
}

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn ecdsa_p384_certificate_live_round_trip_test() -> Nil {
  credential_round_trip("ecdsa-p384-server.pem", "ecdsa-p384-server-key.pem")
}

fn credential_round_trip(certificate_name: String, key_name: String) -> Nil {
  let certificate = fixture(certificate_name) |> should.be_ok
  let private_key = fixture(key_name) |> should.be_ok
  let listener =
    server.new(certificate, private_key, "credential-matrix")
    |> should.be_ok
    |> server.with_address_family(quic_core.Ipv4)
    |> server.start
    |> should.be_ok
  let port = server.port(listener) |> should.be_ok
  let connection =
    client.new("localhost", port, "credential-matrix")
    |> should.be_ok
    |> client.with_ca_certificates(certificate)
    |> should.be_ok
    |> client.with_address_family(quic_core.Ipv4)
    |> client.connect
    |> should.be_ok
  let peer = server.accept(listener) |> should.be_ok
  assert client.phase(connection) == Ok(diagnostics.Established)
  assert server.phase(peer) == Ok(diagnostics.Established)
  assert client.close(connection) == Ok(client.Closed)
  let _closed = server.close(peer) |> should.be_ok
  assert server.stop(listener) == Ok(server.Stopped)
}

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
    |> server.with_address_family(quic_core.Ipv4)
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
    |> client.with_address_family(quic_core.Ipv4)
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
    |> server.with_address_family(quic_core.Ipv4)
    |> server.start
    |> should.be_ok
  let optional_port = server.port(optional_listener) |> should.be_ok
  let anonymous_connection =
    client.new("localhost", optional_port, "sample")
    |> should.be_ok
    |> client.with_ca_certificates(ca_certificate)
    |> should.be_ok
    |> client.with_address_family(quic_core.Ipv4)
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
    |> server.with_application_protocols([
      "server-preferred",
      "client-preferred",
    ])
    |> should.be_ok
    |> server.with_address_family(quic_core.Ipv4)
    |> server.start
    |> should.be_ok
  let port = server.port(listener) |> should.be_ok
  let connection =
    client.new("localhost", port, "sample")
    |> should.be_ok
    |> client.with_application_protocols([
      "client-preferred",
      "server-preferred",
    ])
    |> should.be_ok
    |> client.with_address_family(quic_core.Ipv4)
    |> client.with_ca_certificates(ca_certificate)
    |> should.be_ok
    |> client.connect
    |> should.be_ok
  let peer = server.accept(listener) |> should.be_ok

  let #(peer_address, peer_port) = server.peer_endpoint(peer) |> should.be_ok
  assert quic_core.ip_address_bytes(peer_address) == <<127, 0, 0, 1>>
  assert peer_port > 0
  let path_mtu = server.path_mtu(peer) |> should.be_ok
  assert path_mtu >= 1200

  assert client.phase(connection) == Ok(diagnostics.Established)
  assert server.phase(peer) == Ok(diagnostics.Established)
  assert client.application_diagnostics(connection) == Ok(None)
  assert server.application_diagnostics(peer) == Ok(None)
  let diagnostics.ConnectionInfo(
    version,
    protocol,
    cipher,
    congestion,
    early,
    resumed,
  ) = client.connection_info(connection) |> should.be_ok
  assert version == quic_core.QuicV1
  assert protocol == "server-preferred"
  assert cipher == diagnostics.Aes128GcmSha256
  assert congestion == quic_core.NewReno
  assert early == diagnostics.NotAttempted
  assert resumed == diagnostics.ResumptionNotAttempted
  assert client.handshake_attempt(connection)
    == Ok(diagnostics.HandshakeAttempt(
      ticket_supplied: False,
      zero_rtt_enabled: False,
      ticket_allows_zero_rtt: False,
      early_data: diagnostics.NotAttempted,
      resumption: diagnostics.ResumptionNotAttempted,
    ))
  let diagnostics.ConnectionInfo(
    server_version,
    server_protocol,
    server_cipher,
    _,
    server_early,
    server_resumption,
  ) = server.connection_info(peer) |> should.be_ok
  assert server_version == quic_core.QuicV1
  assert server_protocol == "server-preferred"
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
  let guaranteed = client.guaranteed_datagram_size(connection) |> should.be_ok
  let peer_guaranteed = server.guaranteed_datagram_size(peer) |> should.be_ok
  assert maximum > 0
  assert guaranteed > 0
  assert guaranteed <= maximum
  assert peer_guaranteed == guaranteed
  client.send_datagram(connection, <<"client datagram":utf8>>) |> should.be_ok
  assert server.receive_datagram(peer) == Ok(<<"client datagram":utf8>>)
  server.send_datagram(peer, <<"server datagram":utf8>>) |> should.be_ok
  assert client.receive_datagram(connection) == Ok(<<"server datagram":utf8>>)

  // This endpoint issues no connection IDs of its own, so a peer connected to
  // it holds no unused identifier to move to and migrates on the one it has.
  // RFC 9000 section 9.5 wants a different identifier for a second local
  // address, and the client takes one whenever the peer supplied it; migration
  // against a peer which does is covered by the interoperability gate.
  assert client.path_validation_in_progress(connection) == Ok(False)
  client.migrate(connection) |> should.be_ok
  assert client.path_validation_in_progress(connection) == Ok(False)
  assert client.guaranteed_datagram_size(connection) == Ok(guaranteed)
  assert server.guaranteed_datagram_size(peer) == Ok(peer_guaranteed)
  let migrated_stream = client.open_bidirectional(connection) |> should.be_ok
  client.send_and_finish(migrated_stream, <<"migrated":utf8>>) |> should.be_ok
  let assert server.IncomingStream(migrated_peer_stream, server.Bidirectional) =
    server.accept_stream(peer) |> should.be_ok
  assert server.receive(migrated_peer_stream, 1024)
    == Ok(server.Data(<<"migrated":utf8>>, True))
  server.send_and_finish(migrated_peer_stream, <<"validated":utf8>>)
  |> should.be_ok
  assert client.receive(migrated_stream, 1024)
    == Ok(client.Data(<<"validated":utf8>>, True))

  client.ping(connection) |> should.be_ok
  client.set_congestion_control(connection, quic_core.Cubic) |> should.be_ok
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
    |> server.with_address_family(quic_core.Ipv4)
    |> server.start
    |> should.be_ok
  let port = server.port(listener) |> should.be_ok
  let connection =
    client.new("localhost", port, "sample")
    |> should.be_ok
    |> client.with_address_family(quic_core.Ipv4)
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

// nolint: unused_exports -- gleeunit discovers public tests by suffix.
pub fn completed_unidirectional_streams_release_runtime_handles_test() -> Nil {
  let certificate = fixture("server.pem") |> should.be_ok
  let private_key = fixture("server-key.pem") |> should.be_ok
  let ca_certificate = fixture("ca.pem") |> should.be_ok
  let listener =
    server.new(certificate, private_key, "unidirectional-lifetime")
    |> should.be_ok
    |> server.with_address_family(quic_core.Ipv4)
    |> server.start
    |> should.be_ok
  let port = server.port(listener) |> should.be_ok
  let connection =
    client.new("localhost", port, "unidirectional-lifetime")
    |> should.be_ok
    |> client.with_address_family(quic_core.Ipv4)
    |> client.with_ca_certificates(ca_certificate)
    |> should.be_ok
    |> client.connect
    |> should.be_ok
  let peer = server.accept(listener) |> should.be_ok

  exchange_client_unidirectional(
    connection,
    peer,
    sequential_unidirectional_streams,
  )
  exchange_server_unidirectional(
    connection,
    peer,
    sequential_unidirectional_streams,
  )

  let diagnostics.ResourceStats(client_handles, _) =
    client.resource_stats(connection) |> should.be_ok
  let diagnostics.ResourceStats(server_handles, _) =
    server.resource_stats(peer) |> should.be_ok
  assert client_handles <= 16
  assert server_handles <= 16

  let _closed = client.close(connection)
  let _server_closed = server.close(peer)
  assert server.stop(listener) == Ok(server.Stopped)
}

fn exchange_client_unidirectional(
  connection: client.Connection,
  peer: server.Connection,
  remaining: Int,
) -> Nil {
  case remaining <= 0 {
    True -> Nil
    False -> {
      let stream = client.open_unidirectional(connection) |> should.be_ok
      client.send_and_finish(stream, <<1>>) |> should.be_ok
      let assert server.IncomingStream(peer_stream, server.Unidirectional) =
        server.accept_stream(peer) |> should.be_ok
      assert server.receive(peer_stream, 1) == Ok(server.Data(<<1>>, True))
      exchange_client_unidirectional(connection, peer, remaining - 1)
    }
  }
}

fn exchange_server_unidirectional(
  connection: client.Connection,
  peer: server.Connection,
  remaining: Int,
) -> Nil {
  case remaining <= 0 {
    True -> Nil
    False -> {
      let stream = server.open_unidirectional(peer) |> should.be_ok
      server.send_and_finish(stream, <<2>>) |> should.be_ok
      let assert client.IncomingStream(peer_stream, client.Unidirectional) =
        client.accept_stream(connection) |> should.be_ok
      assert client.receive(peer_stream, 1) == Ok(client.Data(<<2>>, True))
      exchange_server_unidirectional(connection, peer, remaining - 1)
    }
  }
}

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn stream_ids_stop_sending_and_application_close_are_public_test() -> Nil {
  let certificate = fixture("server.pem") |> should.be_ok
  let private_key = fixture("server-key.pem") |> should.be_ok
  let ca_certificate = fixture("ca.pem") |> should.be_ok
  let listener =
    server.new(certificate, private_key, "sample")
    |> should.be_ok
    |> server.with_address_family(quic_core.Ipv4)
    |> server.start
    |> should.be_ok
  let port = server.port(listener) |> should.be_ok
  let connection =
    client.new("localhost", port, "sample")
    |> should.be_ok
    |> client.with_address_family(quic_core.Ipv4)
    |> client.with_ca_certificates(ca_certificate)
    |> should.be_ok
    |> client.connect
    |> should.be_ok
  let peer = server.accept(listener) |> should.be_ok

  let stream = client.open_bidirectional(connection) |> should.be_ok
  let identifier = client.stream_id(stream)
  assert quic_core.stream_id_value(identifier) == 0
  assert quic_core.stream_initiator(identifier) == quic_core.ClientInitiated
  assert quic_core.stream_direction(identifier) == quic_core.BidirectionalStream
  client.send(stream, <<"request":utf8>>) |> should.be_ok
  let assert server.IncomingStream(peer_stream, server.Bidirectional) =
    server.accept_stream(peer) |> should.be_ok
  assert server.stream_id(peer_stream) == identifier
  assert server.receive(peer_stream, 1024)
    == Ok(server.Data(<<"request":utf8>>, False))

  server.stop_sending(peer_stream, 0x10c) |> should.be_ok
  server.send_and_finish(peer_stream, <<"response":utf8>>) |> should.be_ok
  assert client.receive(stream, 1024)
    == Ok(client.Data(<<"response":utf8>>, True))
  assert client.send(stream, <<"not accepted":utf8>>)
    == Error(client.StreamFinished)

  assert quic_core.application_error_code(-1)
    == Error(quic_core.InvalidApplicationErrorCode(-1))
  let close_code = quic_core.application_error_code(0x1234) |> should.be_ok
  assert server.close_with_code(peer, close_code) == Ok(server.Closed)
  assert client.receive_datagram(connection)
    == Error(client.Failure(failure.Closed(failure.Peer, Some(0x1234))))
  assert server.stop(listener) == Ok(server.Stopped)
}

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn acknowledged_stream_data_survives_peer_connection_close_test() -> Nil {
  let certificate = fixture("server.pem") |> should.be_ok
  let private_key = fixture("server-key.pem") |> should.be_ok
  let ca_certificate = fixture("ca.pem") |> should.be_ok
  let listener =
    server.new(certificate, private_key, "terminal-stream-drain")
    |> should.be_ok
    |> server.with_address_family(quic_core.Ipv4)
    |> server.start
    |> should.be_ok
  let port = server.port(listener) |> should.be_ok
  let connection =
    client.new("localhost", port, "terminal-stream-drain")
    |> should.be_ok
    |> client.with_address_family(quic_core.Ipv4)
    |> client.with_ca_certificates(ca_certificate)
    |> should.be_ok
    |> client.connect
    |> should.be_ok
  let peer = server.accept(listener) |> should.be_ok

  let stream = client.open_bidirectional(connection) |> should.be_ok
  client.send_and_finish(stream, <<"request":utf8>>) |> should.be_ok
  let assert server.IncomingStream(peer_stream, server.Bidirectional) =
    server.accept_stream(peer) |> should.be_ok
  assert server.receive(peer_stream, 1024)
    == Ok(server.Data(<<"request":utf8>>, True))
  server.send_and_finish(peer_stream, <<"response":utf8>>) |> should.be_ok
  assert await_server_send_finished(
      peer_stream,
      diagnostics.monotonic_milliseconds() + 2000,
    )
    == Ok(Nil)

  let close_code = quic_core.application_error_code(0x1234) |> should.be_ok
  assert server.close_with_code(peer, close_code) == Ok(server.Closed)
  // Observe the authenticated connection close first. The stream bytes which
  // preceded it on the wire were already acknowledged and must not be erased
  // merely because the application had not pulled them from the core actor.
  assert client.receive_datagram(connection)
    == Error(client.Failure(failure.Closed(failure.Peer, Some(0x1234))))
  assert client.receive(stream, 1024)
    == Ok(client.Data(<<"response":utf8>>, True))

  assert server.stop(listener) == Ok(server.Stopped)
}

fn await_server_send_finished(
  stream: server.Stream,
  deadline: Int,
) -> Result(Nil, Nil) {
  case server.send_finished(stream), diagnostics.monotonic_milliseconds() {
    Ok(True), _ -> Ok(Nil)
    _, now if now >= deadline -> Error(Nil)
    _, _ -> {
      process.sleep(10)
      await_server_send_finished(stream, deadline)
    }
  }
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
    |> server.with_address_family(quic_core.Ipv4)
    |> server.with_single_node_zero_rtt
    |> server.with_operational_keys(operational_keys)
  let first_listener = server.start(first_server) |> should.be_ok
  let port = server.port(first_listener) |> should.be_ok
  let first_client =
    client.new("localhost", port, "sample")
    |> should.be_ok
    |> client.with_address_family(quic_core.Ipv4)
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
  assert client.handshake_attempt(second_connection)
    == Ok(diagnostics.HandshakeAttempt(
      ticket_supplied: True,
      zero_rtt_enabled: True,
      ticket_allows_zero_rtt: True,
      early_data: diagnostics.Accepted,
      resumption: diagnostics.Resumed,
    ))
  let diagnostics.ConnectionInfo(_, _, _, _, server_early, server_resumed) =
    server.connection_info(second_peer) |> should.be_ok
  assert server_early == diagnostics.Accepted
  assert server_resumed == diagnostics.Resumed

  let _closed = client.close(second_connection)
  let _peer_closed = server.close(second_peer)
  assert server.stop(second_listener) == Ok(server.Stopped)
}

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn v1_ticket_and_token_never_start_a_v2_connection_test() -> Nil {
  let certificate = fixture("server.pem") |> should.be_ok
  let private_key = fixture("server-key.pem") |> should.be_ok
  let ca_certificate = fixture("ca.pem") |> should.be_ok
  let listener =
    server.new(certificate, private_key, "version-bound-ticket")
    |> should.be_ok
    |> server.with_address_family(quic_core.Ipv4)
    |> server.start
    |> should.be_ok
  let port = server.port(listener) |> should.be_ok
  let base_client =
    client.new("localhost", port, "version-bound-ticket")
    |> should.be_ok
    |> client.with_address_family(quic_core.Ipv4)
    |> client.with_ca_certificates(ca_certificate)
    |> should.be_ok

  let first_connection = client.connect(base_client) |> should.be_ok
  let first_peer = server.accept(listener) |> should.be_ok
  let ticket = client.resumption_ticket(first_connection) |> should.be_ok
  let _closed = client.close(first_connection)
  let _peer_closed = server.close(first_peer)

  // The caller's preference cannot relabel authenticated v1 resumption state
  // as v2. The client instead starts the connection on the ticket's bound
  // version; the paired NEW_TOKEN therefore remains on that same version too.
  let resumed_client =
    base_client
    |> client.with_version(quic_core.QuicV2)
    |> client.with_resumption_ticket(ticket)
    |> should.be_ok
  let resumed_connection = client.connect(resumed_client) |> should.be_ok
  let resumed_peer = server.accept(listener) |> should.be_ok
  let diagnostics.ConnectionInfo(negotiated_version, _, _, _, _, resumption) =
    client.connection_info(resumed_connection) |> should.be_ok
  assert negotiated_version == quic_core.QuicV1
  assert resumption == diagnostics.Resumed

  let _closed = client.close(resumed_connection)
  let _peer_closed = server.close(resumed_peer)
  assert server.stop(listener) == Ok(server.Stopped)
}

import gleam/bit_array
import gleam/list
import gleam/option.{None, Some}
import gleam/result
import gleam_quic/internal/connection_state
import gleam_quic/internal/driver
import gleam_quic/internal/ecn
import gleam_quic/internal/packet_space
import gleam_quic/internal/retry_integrity
import gleam_quic/internal/tls/authentication
import gleam_quic/internal/tls/engine
import gleam_quic/internal/tls/extension_value
import gleam_quic/internal/udp
import gleam_quic/internal/wire_packet
import gleam_quic/packet
import gleam_quic/transport_parameter
import gleam_quic/version
import http3/internal/native/connection_state as http3_state
import http3/internal/native/frame
import http3/internal/native/frame_parser
import http3/internal/native/session
import http3/internal/qpack/header.{type Header, Header}

@external(erlang, "gleam_quic_test_ffi", "fixture")
fn fixture(name: String) -> Result(BitArray, Nil)

const original_destination_connection_id = <<1, 2, 3, 4, 5, 6, 7, 8>>

const client_connection_id = <<9, 10, 11, 12, 13, 14, 15, 16>>

const retry_source_connection_id = <<21, 22, 23, 24, 25, 26, 27, 28>>

const maximum_handshake_rounds = 64

/// RFC 9000 section 14.1: the datagram size every path carries, and the size
/// DPLPMTUD falls back to when a larger one turns out not to be sendable.
const minimum_datagram_bytes = 1200

const receive_timeout_milliseconds = 1000

type Peers {
  Peers(client: driver.State, server: driver.State, now_ms: Int)
}

type NetworkError {
  DriverError(driver.Error)
  UdpError(udp.Error)
  UnexpectedPeer
  HandshakeTimeout
}

type SessionPeers {
  SessionPeers(client: session.State, server: session.State, now_ms: Int)
}

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn discards_unauthenticated_packets_without_hiding_protocol_errors_test() -> Nil {
  assert driver.discardable_receive_error(
    driver.ConnectionFailure(connection_state.WirePacketFailure(
      wire_packet.AuthenticationFailed,
    )),
  )
  assert driver.discardable_receive_error(
    driver.ConnectionFailure(connection_state.WirePacketFailure(
      wire_packet.InvalidHeader,
    )),
  )
  assert !driver.discardable_receive_error(driver.ConnectionFailure(
    connection_state.ProtocolViolation,
  ))
}

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn completes_a_protected_quic_handshake_over_datagrams_test() -> Nil {
  let #(client_tls_config, server_tls_config) = tls_configs()
  let assert Ok(client_tls) = engine.start_client(client_tls_config)
  let assert Ok(server_tls) = engine.start_server(server_tls_config)
  let assert Ok(client) =
    driver.start_client(
      connection_state.default_config(connection_state.Client),
      client_tls,
      original_destination_connection_id,
      client_connection_id,
      0,
    )
  let assert Ok(server) =
    driver.start_server(
      connection_state.default_config(connection_state.Server),
      server_tls,
      original_destination_connection_id,
      original_destination_connection_id,
      client_connection_id,
      0,
    )

  assert driver.local_connection_id(client) == client_connection_id
  assert driver.peer_connection_id(client) == original_destination_connection_id
  assert driver.local_connection_id(server)
    == original_destination_connection_id
  assert driver.peer_connection_id(server) == client_connection_id

  let assert Ok(Peers(client, server, _)) =
    drive_handshake(Peers(client, server, 1), maximum_handshake_rounds)
  assert driver.phase(client) == connection_state.Established
  assert driver.phase(server) == connection_state.Established
  assert connection_state.grease_quic_bit_negotiated(driver.connection(client))
  assert connection_state.grease_quic_bit_negotiated(driver.connection(server))
  assert connection_state.can_issue_session_ticket(driver.connection(server))
  assert driver.peer_connection_id(client) == original_destination_connection_id
  assert connection_state.packet_space_discarded(
    driver.connection(client),
    engine.Handshake,
  )

  let #(client, client_events) = driver.take_events(client)
  let #(server, server_events) = driver.take_events(server)
  assert list.contains(client_events, connection_state.HandshakeEstablished)
  assert list.contains(server_events, connection_state.HandshakeEstablished)

  let client = driver.put_connection(client, driver.connection(client))
  let assert Ok(client) =
    driver.update_connection(client, fn(connection) { Ok(connection) })
  let assert Ok(client) = driver.tick(client, 20_000)
  assert driver.phase(client) == connection_state.Established
  assert driver.phase(server) == connection_state.Established
}

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn server_accepts_a_zero_length_initial_peer_connection_id_test() -> Nil {
  let #(_, server_tls_config) = tls_configs()
  let assert Ok(server_tls) = engine.start_server(server_tls_config)
  let assert Ok(server) =
    driver.start_server(
      connection_state.default_config(connection_state.Server),
      server_tls,
      original_destination_connection_id,
      original_destination_connection_id,
      <<>>,
      0,
    )

  assert driver.peer_connection_id(server) == <<>>
}

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn prepares_and_commits_exact_size_live_pmtu_probe_test() -> Nil {
  let #(client_tls_config, server_tls_config) = tls_configs()
  let assert Ok(client_tls) = engine.start_client(client_tls_config)
  let assert Ok(server_tls) = engine.start_server(server_tls_config)
  let assert Ok(client) =
    driver.start_client(
      dont_fragment_config(connection_state.Client),
      client_tls,
      original_destination_connection_id,
      client_connection_id,
      0,
    )
  let assert Ok(server) =
    driver.start_server(
      connection_state.default_config(connection_state.Server),
      server_tls,
      original_destination_connection_id,
      original_destination_connection_id,
      client_connection_id,
      0,
    )
  let assert Ok(Peers(client, _, now)) =
    drive_handshake(Peers(client, server, 1), maximum_handshake_rounds)
  assert !connection_state.pmtu_discovery_complete(driver.connection(client))
  let assert Ok(Some(prepared)) = driver.prepare_pmtu_probe(client, now)
  assert bit_array.byte_size(driver.prepared_bytes(prepared)) == 1300
  let assert Ok(client) = driver.commit_datagram(prepared, now)
  assert driver.prepare_pmtu_probe(client, now + 1) == Ok(None)
}

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn completes_handshake_for_an_ip_literal_without_sni_test() -> Nil {
  let #(client_config, server_config) = tls_configs()
  let client_config = engine.ClientConfig(..client_config, hostname: "::1")
  let assert Ok(client_tls) = engine.start_client(client_config)
  let assert Ok(server_tls) = engine.start_server(server_config)
  let assert Ok(client) =
    driver.start_client(
      connection_state.default_config(connection_state.Client),
      client_tls,
      original_destination_connection_id,
      client_connection_id,
      0,
    )
  let assert Ok(server) =
    driver.start_server(
      connection_state.default_config(connection_state.Server),
      server_tls,
      original_destination_connection_id,
      original_destination_connection_id,
      client_connection_id,
      0,
    )

  let assert Ok(Peers(client, server, _)) =
    drive_handshake(Peers(client, server, 1), maximum_handshake_rounds)
  assert driver.phase(client) == connection_state.Established
  assert driver.phase(server) == connection_state.Established
  assert !connection_state.can_issue_session_ticket(driver.connection(server))
}

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn keeps_coalesced_handshake_progress_when_one_rtt_arrives_early_test() -> Nil {
  let #(client_tls_config, server_tls_config) = tls_configs()
  let assert Ok(client_tls) = engine.start_client(client_tls_config)
  let assert Ok(server_tls) = engine.start_server(server_tls_config)
  let assert Ok(client) =
    driver.start_client(
      connection_state.default_config(connection_state.Client),
      client_tls,
      original_destination_connection_id,
      client_connection_id,
      0,
    )
  let assert Ok(server) =
    driver.start_server(
      connection_state.default_config(connection_state.Server),
      server_tls,
      original_destination_connection_id,
      original_destination_connection_id,
      client_connection_id,
      0,
    )
  let assert Ok(peers) = send_client_datagram(Peers(client, server, 1))
  let Peers(client, server, now_ms) = peers
  let assert Ok(Some(prepared)) = driver.prepare_datagram(server, 1000, now_ms)
  let initial = driver.prepared_bytes(prepared)
  let assert Ok(server) = driver.commit_datagram(prepared, now_ms)
  let early_one_rtt = <<0x40, client_connection_id:bits, 0:160>>
  let assert Ok(client) =
    driver.receive_datagram(
      client,
      <<initial:bits, early_one_rtt:bits>>,
      now_ms,
    )
  let assert Ok(Peers(client, server, _)) =
    drive_handshake(
      Peers(client, server, now_ms + 100),
      maximum_handshake_rounds,
    )
  assert driver.phase(client) == connection_state.Established
  assert driver.phase(server) == connection_state.Established
}

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn completes_quic_v2_protected_handshake_test() -> Nil {
  let #(client_tls_config, server_tls_config) =
    tls_configs_for_version(version.Version2)
  let assert Ok(client_tls) = engine.start_client(client_tls_config)
  let assert Ok(server_tls) = engine.start_server(server_tls_config)
  let client_transport =
    connection_state.Config(
      ..connection_state.default_config(connection_state.Client),
      version: version.Version2,
    )
  let server_transport =
    connection_state.Config(
      ..connection_state.default_config(connection_state.Server),
      version: version.Version2,
    )
  let assert Ok(client) =
    driver.start_client(
      client_transport,
      client_tls,
      original_destination_connection_id,
      client_connection_id,
      0,
    )
  let assert Ok(server) =
    driver.start_server(
      server_transport,
      server_tls,
      original_destination_connection_id,
      original_destination_connection_id,
      client_connection_id,
      0,
    )

  let assert Ok(Peers(client, server, _)) =
    drive_handshake(Peers(client, server, 1), maximum_handshake_rounds)
  assert driver.phase(client) == connection_state.Established
  assert driver.phase(server) == connection_state.Established
}

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn accepts_only_an_eligible_version_negotiation_packet_test() -> Nil {
  let #(client_tls_config, _) = tls_configs()
  let assert Ok(client_tls) = engine.start_client(client_tls_config)
  let assert Ok(client) =
    driver.start_client(
      connection_state.default_config(connection_state.Client),
      client_tls,
      original_destination_connection_id,
      client_connection_id,
      0,
    )
  let assert Ok(datagram) =
    packet.VersionNegotiation(
      packet.LongHeader(
        0x80,
        version.Negotiation,
        client_connection_id,
        original_destination_connection_id,
      ),
      [version.Version2],
    )
    |> packet.encode_long

  assert driver.receive_datagram(client, datagram, 1)
    == Error(driver.VersionNegotiationReceived([version.Version2]))
}

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn ignores_version_negotiation_with_a_wrong_connection_id_test() -> Nil {
  let #(client_tls_config, _) = tls_configs()
  let assert Ok(client_tls) = engine.start_client(client_tls_config)
  let assert Ok(client) =
    driver.start_client(
      connection_state.default_config(connection_state.Client),
      client_tls,
      original_destination_connection_id,
      client_connection_id,
      0,
    )
  let assert Ok(datagram) =
    packet.VersionNegotiation(
      packet.LongHeader(
        0x80,
        version.Negotiation,
        <<0, 0, 0, 0, 0, 0, 0, 0>>,
        original_destination_connection_id,
      ),
      [version.Version2],
    )
    |> packet.encode_long

  assert driver.receive_datagram(client, datagram, 1) |> result.is_ok
}

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn ignores_downgrade_style_version_negotiation_test() -> Nil {
  let #(client_tls_config, _) = tls_configs()
  let assert Ok(client_tls) = engine.start_client(client_tls_config)
  let assert Ok(client) =
    driver.start_client(
      connection_state.default_config(connection_state.Client),
      client_tls,
      original_destination_connection_id,
      client_connection_id,
      0,
    )
  let assert Ok(datagram) =
    packet.VersionNegotiation(
      packet.LongHeader(
        0x80,
        version.Negotiation,
        client_connection_id,
        original_destination_connection_id,
      ),
      [version.Version2, version.Version1],
    )
    |> packet.encode_long

  assert driver.receive_datagram(client, datagram, 1) |> result.is_ok
}

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn retransmits_client_hello_after_initial_packet_loss_test() -> Nil {
  let #(client_tls_config, server_tls_config) = tls_configs()
  let assert Ok(client_tls) = engine.start_client(client_tls_config)
  let assert Ok(server_tls) = engine.start_server(server_tls_config)
  let assert Ok(client) =
    driver.start_client(
      connection_state.default_config(connection_state.Client),
      client_tls,
      original_destination_connection_id,
      client_connection_id,
      0,
    )
  let assert Ok(server) =
    driver.start_server(
      connection_state.default_config(connection_state.Server),
      server_tls,
      original_destination_connection_id,
      original_destination_connection_id,
      client_connection_id,
      0,
    )
  let assert Ok(Some(lost)) = driver.prepare_datagram(client, 1000, 1)
  let assert Ok(client) = driver.commit_datagram(lost, 1)
  let assert Ok(client) = driver.tick(client, 2000)

  let assert Ok(Peers(client, server, _)) =
    drive_handshake(Peers(client, server, 2100), maximum_handshake_rounds)
  assert driver.phase(client) == connection_state.Established
  assert driver.phase(server) == connection_state.Established
}

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn authenticates_retry_and_restarts_initial_keys_test() -> Nil {
  let #(client_tls_config, server_tls_config) = retry_tls_configs()
  let client_tls_config =
    engine.ClientConfig(..client_tls_config, hostname: "::1")
  let assert Ok(client_tls) = engine.start_client(client_tls_config)
  let assert Ok(server_tls) = engine.start_server(server_tls_config)
  let assert Ok(client) =
    driver.start_client(
      connection_state.default_config(connection_state.Client),
      client_tls,
      original_destination_connection_id,
      client_connection_id,
      0,
    )
  let assert Ok(Some(first_initial)) = driver.prepare_datagram(client, 1000, 1)
  let assert Ok(client) = driver.commit_datagram(first_initial, 1)
  let assert Ok(client) =
    driver.receive_datagram(client, invalid_retry_datagram(), 5)
  assert driver.peer_connection_id(client) == original_destination_connection_id
  let assert Ok(client) = driver.receive_datagram(client, retry_datagram(), 10)
  assert driver.peer_connection_id(client) == retry_source_connection_id
  let assert Ok(client) = driver.receive_datagram(client, retry_datagram(), 11)
  assert driver.peer_connection_id(client) == retry_source_connection_id

  let assert Ok(server) =
    driver.start_server(
      connection_state.default_config(connection_state.Server),
      server_tls,
      retry_source_connection_id,
      retry_source_connection_id,
      client_connection_id,
      10,
    )
  let assert Ok(Peers(client, server, _)) =
    drive_handshake(Peers(client, server, 100), maximum_handshake_rounds)
  assert driver.phase(client) == connection_state.Established
  assert driver.phase(server) == connection_state.Established
}

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn cached_address_token_can_fall_back_to_authenticated_retry_test() -> Nil {
  let #(client_tls_config, _) = retry_tls_configs()
  let client_tls_config =
    engine.ClientConfig(..client_tls_config, hostname: "::1")
  let assert Ok(client_tls) = engine.start_client(client_tls_config)
  let assert Ok(client) =
    driver.start_client_with_token(
      connection_state.default_config(connection_state.Client),
      client_tls,
      original_destination_connection_id,
      client_connection_id,
      <<"cached-token":utf8>>,
      0,
    )
  let assert Ok(Some(first_initial)) = driver.prepare_datagram(client, 1000, 1)
  let assert Ok(#(packet.Initial(_, first_token, _), _)) =
    packet.parse_long(driver.prepared_bytes(first_initial))
  assert first_token == <<"cached-token":utf8>>
  let assert Ok(client) = driver.commit_datagram(first_initial, 1)

  let assert Ok(client) = driver.receive_datagram(client, retry_datagram(), 10)
  assert driver.peer_connection_id(client) == retry_source_connection_id
  let assert Ok(Some(retried_initial)) =
    driver.prepare_datagram(client, 1000, 11)
  let assert Ok(#(packet.Initial(_, retry_token, _), _)) =
    packet.parse_long(driver.prepared_bytes(retried_initial))
  assert retry_token == <<"address-token":utf8>>
}

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn pads_initial_and_rejects_wrong_destination_test() -> Nil {
  let #(client_tls_config, server_tls_config) = tls_configs()
  let assert Ok(client_tls) = engine.start_client(client_tls_config)
  let assert Ok(server_tls) = engine.start_server(server_tls_config)
  let assert Ok(client) =
    driver.start_client(
      connection_state.default_config(connection_state.Client),
      client_tls,
      original_destination_connection_id,
      client_connection_id,
      0,
    )
  let server_connection_id = <<17, 18, 19, 20, 21, 22, 23, 24>>
  let wrong_client_connection_id = <<31, 32, 33, 34, 35, 36, 37, 38>>
  let assert Ok(wrong_server) =
    driver.start_server(
      connection_state.default_config(connection_state.Server),
      server_tls,
      original_destination_connection_id,
      server_connection_id,
      wrong_client_connection_id,
      0,
    )
  let assert Ok(Some(prepared)) = driver.prepare_datagram(client, 1000, 1)
  let datagram = driver.prepared_bytes(prepared)
  assert bit_array.byte_size(datagram) == 1200
  let assert Ok(client) = driver.commit_datagram(prepared, 1)
  let assert Ok(wrong_server) =
    driver.receive_datagram(wrong_server, datagram, 1)
  let assert Ok(Some(response)) = driver.prepare_datagram(wrong_server, 1000, 2)
  assert driver.receive_datagram(client, driver.prepared_bytes(response), 2)
    == Error(driver.DestinationConnectionIdMismatch)
}

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn server_accepts_original_destination_alias_before_own_cid_is_known_test() -> Nil {
  let #(client_tls_config, server_tls_config) = tls_configs()
  let assert Ok(client_tls) = engine.start_client(client_tls_config)
  let assert Ok(server_tls) = engine.start_server(server_tls_config)
  let server_connection_id = <<17, 18, 19, 20, 21, 22, 23, 24>>
  let assert Ok(client) =
    driver.start_client(
      connection_state.default_config(connection_state.Client),
      client_tls,
      original_destination_connection_id,
      client_connection_id,
      0,
    )
  let assert Ok(server) =
    driver.start_server(
      connection_state.default_config(connection_state.Server),
      server_tls,
      original_destination_connection_id,
      server_connection_id,
      client_connection_id,
      0,
    )
  let assert Ok(Some(prepared)) = driver.prepare_datagram(client, 1000, 1)
  assert driver.receive_datagram(server, driver.prepared_bytes(prepared), 1)
    |> result.is_ok
}

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn completes_native_quic_handshake_over_real_udp_test() -> Nil {
  let #(client_tls_config, server_tls_config) = tls_configs()
  let assert Ok(client_tls) = engine.start_client(client_tls_config)
  let assert Ok(server_tls) = engine.start_server(server_tls_config)
  let assert Ok(client) =
    driver.start_client(
      connection_state.default_config(connection_state.Client),
      client_tls,
      original_destination_connection_id,
      client_connection_id,
      0,
    )
  let assert Ok(server) =
    driver.start_server(
      connection_state.default_config(connection_state.Server),
      server_tls,
      original_destination_connection_id,
      original_destination_connection_id,
      client_connection_id,
      0,
    )
  let assert Ok(loopback) = udp.ipv4(127, 0, 0, 1)
  let assert Ok(ephemeral) = udp.endpoint(loopback, 0)
  let assert Ok(client_socket) = udp.open(ephemeral)
  let assert Ok(server_socket) = udp.open(ephemeral)
  let assert Ok(client_endpoint) = udp.local_endpoint(client_socket)
  let assert Ok(server_endpoint) = udp.local_endpoint(server_socket)

  let assert Ok(Peers(client, server, _)) =
    drive_udp_handshake(
      Peers(client, server, 1),
      client_socket,
      server_socket,
      client_endpoint,
      server_endpoint,
      maximum_handshake_rounds,
    )
  assert driver.phase(client) == connection_state.Established
  assert driver.phase(server) == connection_state.Established
  assert connection_state.packet_space_discarded(
    driver.connection(client),
    engine.Handshake,
  )
  let assert Ok(Nil) = udp.close(client_socket)
  let assert Ok(Nil) = udp.close(server_socket)
  Nil
}

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn carries_http3_request_response_over_protected_streams_test() -> Nil {
  let #(client_tls_config, server_tls_config) = tls_configs()
  let assert Ok(client_tls) = engine.start_client(client_tls_config)
  let assert Ok(server_tls) = engine.start_server(server_tls_config)
  let assert Ok(client) =
    driver.start_client(
      connection_state.default_config(connection_state.Client),
      client_tls,
      original_destination_connection_id,
      client_connection_id,
      0,
    )
  let assert Ok(server) =
    driver.start_server(
      connection_state.default_config(connection_state.Server),
      server_tls,
      original_destination_connection_id,
      original_destination_connection_id,
      client_connection_id,
      0,
    )
  let assert Ok(Peers(client, server, now_ms)) =
    drive_handshake(Peers(client, server, 1), maximum_handshake_rounds)
  let assert Ok(client) =
    session.start(client, http3_state.default_config(http3_state.Client), False)
  let assert Ok(server) =
    session.start(server, http3_state.default_config(http3_state.Server), False)
  assert session.phase(client) == connection_state.Established
  assert session.phase(server) == connection_state.Established

  let assert Ok(#(client, request_id)) =
    session.open_request(client, streaming_request_headers(), False)
  assert request_id == 0
  let assert Ok(client) = session.send_data(client, request_id, <<"hello ">>)
  let assert Ok(client) = session.send_data(client, request_id, <<"stream">>)
  let assert Ok(client) = session.finish_stream(client, request_id)
  let assert Ok(SessionPeers(client, server, now_ms)) =
    drive_sessions(SessionPeers(client, server, now_ms), 64)
  let #(server, server_events) = session.take_events(server)
  assert has_request_headers(server_events, request_id)
  assert has_data(server_events, request_id, <<"hello ">>)
  assert has_data(server_events, request_id, <<"stream">>)
  assert has_stream_finished(server_events, request_id)

  let assert Ok(server) =
    session.send_response_headers(server, request_id, response_headers(), False)
  let assert Ok(server) = session.send_data(server, request_id, <<"abc">>)
  let assert Ok(server) =
    session.send_trailers(
      server,
      request_id,
      [Header(<<"x-checksum">>, <<"ok">>, False)],
      False,
    )
  let assert Ok(server) = session.finish_stream(server, request_id)
  let assert Ok(SessionPeers(client, server, _)) =
    drive_sessions(SessionPeers(client, server, now_ms), 64)
  let #(client, client_events) = session.take_events(client)
  assert has_response_headers(client_events, request_id)
  assert has_data(client_events, request_id, <<"abc">>)
  assert has_trailers(client_events, request_id)
  assert has_stream_finished(client_events, request_id)
  assert session.phase(client) == connection_state.Established
  assert session.phase(server) == connection_state.Established
}

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn configured_http3_frame_limit_rejects_oversized_peer_settings_test() -> Nil {
  let #(client_tls_config, server_tls_config) = tls_configs()
  let assert Ok(client_tls) = engine.start_client(client_tls_config)
  let assert Ok(server_tls) = engine.start_server(server_tls_config)
  let assert Ok(client) =
    driver.start_client(
      connection_state.default_config(connection_state.Client),
      client_tls,
      original_destination_connection_id,
      client_connection_id,
      0,
    )
  let assert Ok(server) =
    driver.start_server(
      connection_state.default_config(connection_state.Server),
      server_tls,
      original_destination_connection_id,
      original_destination_connection_id,
      client_connection_id,
      0,
    )
  let assert Ok(Peers(client, server, now_ms)) =
    drive_handshake(Peers(client, server, 1), maximum_handshake_rounds)
  let client_config = http3_state.default_config(http3_state.Client)
  let server_defaults = http3_state.default_config(http3_state.Server)
  let server_config =
    http3_state.Config(
      ..server_defaults,
      settings: http3_state.Settings(
        ..server_defaults.settings,
        maximum_field_section_size: 8,
      ),
      maximum_frame_payload_bytes: 8,
    )
  let assert Ok(client) = session.start(client, client_config, False)
  let assert Ok(server) = session.start(server, server_config, False)

  assert drive_sessions(SessionPeers(client, server, now_ms), 8)
    == Error(
      session.FrameParserFailure(
        frame_parser.FrameFailure(frame.PayloadLimitExceeded(8)),
      ),
    )
}

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn keeps_handshake_frames_when_the_socket_refuses_a_datagram_test() -> Nil {
  // `client_connection.flush_driver` hands each prepared handshake datagram
  // to the socket. A socket that answers `udp.MessageTooLarge` has refused a
  // datagram it cannot send whole, which is a path measurement rather than a
  // broken socket: the datagram is never committed, so the frames it carried
  // are still queued, and the path returns to the 1200-byte floor.
  let #(client_tls_config, server_tls_config) = tls_configs()
  let assert Ok(client_tls) = engine.start_client(client_tls_config)
  let assert Ok(server_tls) = engine.start_server(server_tls_config)
  let assert Ok(client) =
    driver.start_client(
      dont_fragment_config(connection_state.Client),
      client_tls,
      original_destination_connection_id,
      client_connection_id,
      0,
    )
  let assert Ok(server) =
    driver.start_server(
      dont_fragment_config(connection_state.Server),
      server_tls,
      original_destination_connection_id,
      original_destination_connection_id,
      client_connection_id,
      0,
    )
  let assert Ok(Some(refused)) = driver.prepare_datagram(client, 1000, 1)
  assert bit_array.byte_size(driver.prepared_bytes(refused))
    == minimum_datagram_bytes
  let assert Ok(client) = driver_after_refused_send(client)
  assert connection_state.path_mtu(driver.connection(client))
    == minimum_datagram_bytes

  // The ClientHello was never committed, so the handshake still completes.
  let assert Ok(Peers(client, server, _)) =
    drive_handshake(Peers(client, server, 1), maximum_handshake_rounds)
  assert driver.phase(client) == connection_state.Established
  assert driver.phase(server) == connection_state.Established
  assert connection_state.path_mtu(driver.connection(client))
    == minimum_datagram_bytes
}

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn keeps_request_data_when_the_socket_refuses_a_datagram_test() -> Nil {
  // The same step over the state `client_connection.flush` holds once the
  // connection is established and DPLPMTUD has confirmed a wider path.
  let #(client_tls_config, server_tls_config) = tls_configs()
  let assert Ok(client_tls) = engine.start_client(client_tls_config)
  let assert Ok(server_tls) = engine.start_server(server_tls_config)
  let assert Ok(client) =
    driver.start_client(
      dont_fragment_config(connection_state.Client),
      client_tls,
      original_destination_connection_id,
      client_connection_id,
      0,
    )
  let assert Ok(server) =
    driver.start_server(
      dont_fragment_config(connection_state.Server),
      server_tls,
      original_destination_connection_id,
      original_destination_connection_id,
      client_connection_id,
      0,
    )
  let assert Ok(Peers(client, server, now_ms)) =
    drive_handshake(Peers(client, server, 1), maximum_handshake_rounds)
  let assert Ok(client) =
    session.start(client, http3_state.default_config(http3_state.Client), False)
  let assert Ok(server) =
    session.start(server, http3_state.default_config(http3_state.Server), False)

  // Confirm a path wider than the floor, the way a live connection does.
  let assert Ok(Some(probe)) = session.prepare_pmtu_probe(client, now_ms)
  let probe_bytes = session.prepared_bytes(probe)
  assert bit_array.byte_size(probe_bytes) > minimum_datagram_bytes
  let assert Ok(client) = session.commit_datagram(probe, ecn.NotEct, now_ms)
  let assert Ok(server) =
    session.receive_datagram(
      server,
      probe_bytes,
      packet_space.NotEct,
      now_ms + 1,
    )
  let assert Ok(SessionPeers(client, server, now_ms)) =
    drive_sessions(SessionPeers(client, server, now_ms + 30), 4)
  assert session.path_mtu(client) > minimum_datagram_bytes

  let assert Ok(#(client, request_id)) =
    session.open_request(client, large_request_headers(), False)
  let assert Ok(client) =
    session.send_data(client, request_id, <<0:size(3000)-unit(8)>>)

  // The flush builds a datagram for the confirmed path and the socket refuses
  // it. The prepared datagram is dropped uncommitted.
  let assert Ok(Some(refused)) = session.prepare_datagram(client, 1000, now_ms)
  assert bit_array.byte_size(session.prepared_bytes(refused))
    > minimum_datagram_bytes
  let assert Ok(client) = session_after_refused_send(client)

  assert session.phase(client) == connection_state.Established
  assert session.path_mtu(client) == minimum_datagram_bytes

  // The request body is still owed and still arrives, inside the floor.
  let assert Ok(SessionPeers(client, server, _)) =
    drive_sessions(SessionPeers(client, server, now_ms), 32)
  let #(_, server_events) = session.take_events(server)
  assert has_request_headers(server_events, request_id)
  assert received_data_bytes(server_events, request_id) == 3000
  assert session.phase(client) == connection_state.Established
  assert session.path_mtu(client) == minimum_datagram_bytes
}

/// Request headers for a body larger than one floor-sized datagram carries.
fn large_request_headers() -> List(Header) {
  [
    Header(<<":method">>, <<"POST">>, False),
    Header(<<":scheme">>, <<"https">>, False),
    Header(<<":authority">>, <<"localhost">>, False),
    Header(<<":path">>, <<"/native">>, False),
    Header(<<"content-length">>, <<"3000">>, False),
  ]
}

/// Total DATA payload bytes one stream delivered.
fn received_data_bytes(events: List(session.Event), stream_id: Int) -> Int {
  list.fold(events, 0, fn(total, event) {
    case event {
      session.Http3Event(http3_state.Data(identifier, bytes))
        if identifier == stream_id
      -> total + bit_array.byte_size(bytes)
      _ -> total
    }
  })
}

/// The step `client_connection.send_prepared_handshake` takes for one refused
/// send.
///
/// The classification is the part under test: only `udp.PathTooSmall` keeps
/// the connection. Were EMSGSIZE folded back into a socket failure - which is
/// what the root client used to do - the flush would return
/// `SocketUnavailable` and this returns `Error(Nil)` in its place, so the test
/// fails instead of quietly asserting an unreachable state.
fn driver_after_refused_send(state: driver.State) -> Result(driver.State, Nil) {
  case udp.classify_send(Error(udp.MessageTooLarge)) {
    udp.PathTooSmall -> Ok(driver.report_pmtu_black_hole(state))
    udp.Delivered | udp.SocketLost -> Error(Nil)
  }
}

/// The same step for `client_connection.send_prepared`, which flushes the
/// established HTTP/3 session rather than the handshake.
fn session_after_refused_send(
  state: session.State,
) -> Result(session.State, Nil) {
  case udp.classify_send(Error(udp.MessageTooLarge)) {
    udp.PathTooSmall -> Ok(session.report_pmtu_black_hole(state))
    udp.Delivered | udp.SocketLost -> Error(Nil)
  }
}

/// A configuration for a socket that carries the Don't-Fragment option, which
/// is what lets DPLPMTUD search above the 1200-byte floor. The fail-closed
/// default is pinned in the core package instead.
fn dont_fragment_config(
  role: connection_state.Role,
) -> connection_state.Config {
  connection_state.Config(
    ..connection_state.default_config(role),
    path_dont_fragment: True,
  )
}

fn drive_handshake(peers: Peers, rounds: Int) -> Result(Peers, driver.Error) {
  case handshake_complete(peers), rounds {
    True, _ -> Ok(peers)
    False, 0 -> Error(driver.InvalidInput)
    False, remaining -> {
      use peers <- result.try(send_client_datagram(peers))
      use peers <- result.try(send_server_datagram(peers))
      drive_handshake(peers, remaining - 1)
    }
  }
}

fn handshake_complete(peers: Peers) -> Bool {
  driver.phase(peers.client) == connection_state.Established
  && driver.phase(peers.server) == connection_state.Established
  && connection_state.packet_space_discarded(
    driver.connection(peers.client),
    engine.Handshake,
  )
}

fn send_client_datagram(peers: Peers) -> Result(Peers, driver.Error) {
  use client <- result.try(driver.tick(peers.client, peers.now_ms))
  use server <- result.try(driver.tick(peers.server, peers.now_ms))
  case driver.prepare_datagram(client, 1000, peers.now_ms) {
    Error(error) -> Error(error)
    Ok(None) -> Ok(Peers(client, server, peers.now_ms + 100))
    Ok(Some(prepared)) -> {
      use client <- result.try(driver.commit_datagram(prepared, peers.now_ms))
      use server <- result.try(driver.receive_datagram(
        server,
        driver.prepared_bytes(prepared),
        peers.now_ms,
      ))
      Ok(Peers(client, server, peers.now_ms + 100))
    }
  }
}

fn send_server_datagram(peers: Peers) -> Result(Peers, driver.Error) {
  use client <- result.try(driver.tick(peers.client, peers.now_ms))
  use server <- result.try(driver.tick(peers.server, peers.now_ms))
  case driver.prepare_datagram(server, 1000, peers.now_ms) {
    Error(error) -> Error(error)
    Ok(None) -> Ok(Peers(client, server, peers.now_ms + 100))
    Ok(Some(prepared)) -> {
      use server <- result.try(driver.commit_datagram(prepared, peers.now_ms))
      use client <- result.try(driver.receive_datagram(
        client,
        driver.prepared_bytes(prepared),
        peers.now_ms,
      ))
      Ok(Peers(client, server, peers.now_ms + 100))
    }
  }
}

fn drive_udp_handshake(
  peers: Peers,
  client_socket: udp.Socket,
  server_socket: udp.Socket,
  client_endpoint: udp.Endpoint,
  server_endpoint: udp.Endpoint,
  rounds: Int,
) -> Result(Peers, NetworkError) {
  case handshake_complete(peers), rounds {
    True, _ -> Ok(peers)
    False, 0 -> Error(HandshakeTimeout)
    False, remaining -> {
      use peers <- result.try(send_client_udp(
        peers,
        client_socket,
        server_socket,
        client_endpoint,
        server_endpoint,
      ))
      use peers <- result.try(send_server_udp(
        peers,
        client_socket,
        server_socket,
        client_endpoint,
        server_endpoint,
      ))
      drive_udp_handshake(
        peers,
        client_socket,
        server_socket,
        client_endpoint,
        server_endpoint,
        remaining - 1,
      )
    }
  }
}

fn send_client_udp(
  peers: Peers,
  client_socket: udp.Socket,
  server_socket: udp.Socket,
  client_endpoint: udp.Endpoint,
  server_endpoint: udp.Endpoint,
) -> Result(Peers, NetworkError) {
  use client <- result.try(
    driver.tick(peers.client, peers.now_ms) |> map_driver,
  )
  use server <- result.try(
    driver.tick(peers.server, peers.now_ms) |> map_driver,
  )
  case driver.prepare_datagram(client, 1000, peers.now_ms) {
    Error(error) -> Error(DriverError(error))
    Ok(None) -> Ok(Peers(client, server, peers.now_ms + 100))
    Ok(Some(prepared)) -> {
      let bytes = driver.prepared_bytes(prepared)
      use Nil <- result.try(
        udp.send(client_socket, server_endpoint, bytes, ecn.NotEct) |> map_udp,
      )
      use client <- result.try(
        driver.commit_datagram_with_ecn(prepared, ecn.NotEct, peers.now_ms)
        |> map_driver,
      )
      use udp.Datagram(peer, received, marking) <- result.try(
        udp.receive(server_socket, receive_timeout_milliseconds) |> map_udp,
      )
      use Nil <- result.try(require_peer(peer, client_endpoint))
      use server <- result.try(
        driver.receive_datagram_with_ecn(
          server,
          received,
          marking,
          peers.now_ms,
        )
        |> map_driver,
      )
      Ok(Peers(client, server, peers.now_ms + 100))
    }
  }
}

fn send_server_udp(
  peers: Peers,
  client_socket: udp.Socket,
  server_socket: udp.Socket,
  client_endpoint: udp.Endpoint,
  server_endpoint: udp.Endpoint,
) -> Result(Peers, NetworkError) {
  use client <- result.try(
    driver.tick(peers.client, peers.now_ms) |> map_driver,
  )
  use server <- result.try(
    driver.tick(peers.server, peers.now_ms) |> map_driver,
  )
  case driver.prepare_datagram(server, 1000, peers.now_ms) {
    Error(error) -> Error(DriverError(error))
    Ok(None) -> Ok(Peers(client, server, peers.now_ms + 100))
    Ok(Some(prepared)) -> {
      let bytes = driver.prepared_bytes(prepared)
      use Nil <- result.try(
        udp.send(server_socket, client_endpoint, bytes, ecn.NotEct) |> map_udp,
      )
      use server <- result.try(
        driver.commit_datagram_with_ecn(prepared, ecn.NotEct, peers.now_ms)
        |> map_driver,
      )
      use udp.Datagram(peer, received, marking) <- result.try(
        udp.receive(client_socket, receive_timeout_milliseconds) |> map_udp,
      )
      use Nil <- result.try(require_peer(peer, server_endpoint))
      use client <- result.try(
        driver.receive_datagram_with_ecn(
          client,
          received,
          marking,
          peers.now_ms,
        )
        |> map_driver,
      )
      Ok(Peers(client, server, peers.now_ms + 100))
    }
  }
}

fn drive_sessions(
  peers: SessionPeers,
  rounds: Int,
) -> Result(SessionPeers, session.Error) {
  case rounds {
    0 -> Ok(peers)
    remaining -> {
      use peers <- result.try(send_client_session(peers))
      use peers <- result.try(send_server_session(peers))
      drive_sessions(peers, remaining - 1)
    }
  }
}

fn send_client_session(
  peers: SessionPeers,
) -> Result(SessionPeers, session.Error) {
  use client <- result.try(session.tick(peers.client, peers.now_ms))
  use server <- result.try(session.tick(peers.server, peers.now_ms))
  case session.prepare_datagram(client, 1000, peers.now_ms) {
    Error(error) -> Error(error)
    Ok(None) -> Ok(SessionPeers(client, server, peers.now_ms + 100))
    Ok(Some(prepared)) -> {
      let bytes = session.prepared_bytes(prepared)
      use client <- result.try(session.commit_datagram(
        prepared,
        ecn.NotEct,
        peers.now_ms,
      ))
      use server <- result.try(session.receive_datagram(
        server,
        bytes,
        packet_space.NotEct,
        peers.now_ms,
      ))
      Ok(SessionPeers(client, server, peers.now_ms + 100))
    }
  }
}

fn send_server_session(
  peers: SessionPeers,
) -> Result(SessionPeers, session.Error) {
  use client <- result.try(session.tick(peers.client, peers.now_ms))
  use server <- result.try(session.tick(peers.server, peers.now_ms))
  case session.prepare_datagram(server, 1000, peers.now_ms) {
    Error(error) -> Error(error)
    Ok(None) -> Ok(SessionPeers(client, server, peers.now_ms + 100))
    Ok(Some(prepared)) -> {
      let bytes = session.prepared_bytes(prepared)
      use server <- result.try(session.commit_datagram(
        prepared,
        ecn.NotEct,
        peers.now_ms,
      ))
      use client <- result.try(session.receive_datagram(
        client,
        bytes,
        packet_space.NotEct,
        peers.now_ms,
      ))
      Ok(SessionPeers(client, server, peers.now_ms + 100))
    }
  }
}

fn require_peer(
  received: udp.Endpoint,
  expected: udp.Endpoint,
) -> Result(Nil, NetworkError) {
  case udp.endpoint_parts(received) == udp.endpoint_parts(expected) {
    True -> Ok(Nil)
    False -> Error(UnexpectedPeer)
  }
}

fn map_driver(
  value: Result(value, driver.Error),
) -> Result(value, NetworkError) {
  case value {
    Ok(output) -> Ok(output)
    Error(error) -> Error(DriverError(error))
  }
}

fn map_udp(value: Result(value, udp.Error)) -> Result(value, NetworkError) {
  case value {
    Ok(output) -> Ok(output)
    Error(error) -> Error(UdpError(error))
  }
}

fn streaming_request_headers() -> List(Header) {
  [
    Header(<<":method">>, <<"POST">>, False),
    Header(<<":scheme">>, <<"https">>, False),
    Header(<<":authority">>, <<"localhost">>, False),
    Header(<<":path">>, <<"/native">>, False),
    Header(<<"content-length">>, <<"12">>, False),
  ]
}

fn response_headers() -> List(Header) {
  [
    Header(<<":status">>, <<"200">>, False),
    Header(<<"content-length">>, <<"3">>, False),
  ]
}

fn has_request_headers(events: List(session.Event), stream_id: Int) -> Bool {
  list.any(events, fn(event) {
    case event {
      session.Http3Event(http3_state.RequestHeaders(identifier, _)) ->
        identifier == stream_id
      _ -> False
    }
  })
}

fn has_response_headers(events: List(session.Event), stream_id: Int) -> Bool {
  list.any(events, fn(event) {
    case event {
      session.Http3Event(http3_state.ResponseHeaders(identifier, _)) ->
        identifier == stream_id
      _ -> False
    }
  })
}

fn has_data(
  events: List(session.Event),
  stream_id: Int,
  expected: BitArray,
) -> Bool {
  list.any(events, fn(event) {
    case event {
      session.Http3Event(http3_state.Data(identifier, bytes)) ->
        identifier == stream_id && bytes == expected
      _ -> False
    }
  })
}

fn has_trailers(events: List(session.Event), stream_id: Int) -> Bool {
  list.any(events, fn(event) {
    case event {
      session.Http3Event(http3_state.Trailers(identifier, _)) ->
        identifier == stream_id
      _ -> False
    }
  })
}

fn has_stream_finished(events: List(session.Event), stream_id: Int) -> Bool {
  list.any(events, fn(event) {
    case event {
      session.Http3Event(http3_state.StreamFinished(identifier)) ->
        identifier == stream_id
      _ -> False
    }
  })
}

fn tls_configs() -> #(engine.ClientConfig, engine.ServerConfig) {
  tls_configs_for_version(version.Version1)
}

fn tls_configs_for_version(
  protocol_version: version.Version,
) -> #(engine.ClientConfig, engine.ServerConfig) {
  let assert Ok(ca_pem) = fixture("ca.pem")
  let assert Ok(server_pem) = fixture("server.pem")
  let assert Ok(key_pem) = fixture("server-key.pem")
  let assert Ok(trust_store) = authentication.trust_store_from_pem(ca_pem)
  let assert Ok(chain) = authentication.certificate_chain_from_pem(server_pem)
  let assert Ok(signing_key) = authentication.signing_key_from_pem(key_pem)
  let shared_parameters = [
    transport_parameter.GreaseQuicBit,
    transport_parameter.VersionInformation(protocol_version, [
      version.Version2,
      version.Version1,
    ]),
    transport_parameter.InitialMaxData(1_048_576),
    transport_parameter.InitialMaxStreamDataBidiLocal(262_144),
    transport_parameter.InitialMaxStreamDataBidiRemote(262_144),
    transport_parameter.InitialMaxStreamDataUni(262_144),
    transport_parameter.InitialMaxStreamsBidi(100),
    transport_parameter.InitialMaxStreamsUni(100),
    transport_parameter.MaxUdpPayloadSize(1400),
    transport_parameter.MaxDatagramFrameSize(1400),
  ]
  #(
    engine.ClientConfig(
      version: protocol_version,
      hostname: "localhost",
      application_protocols: [<<"h3">>],
      transport_parameters: [
        transport_parameter.InitialSourceConnectionId(client_connection_id),
        ..shared_parameters
      ],
      trust_store: trust_store,
      client_credential: None,
      retried: False,
      version_negotiated: False,
    ),
    engine.ServerConfig(
      version: protocol_version,
      application_protocols: [<<"h3">>],
      transport_parameters: [
        transport_parameter.OriginalDestinationConnectionId(
          original_destination_connection_id,
        ),
        transport_parameter.InitialSourceConnectionId(
          original_destination_connection_id,
        ),
        ..shared_parameters
      ],
      certificate_chain: chain,
      signing_key: signing_key,
      signature_scheme: extension_value.Ed25519,
      alternative_credentials: [],
      client_authentication: engine.ClientAuthenticationDisabled,
    ),
  )
}

fn retry_tls_configs() -> #(engine.ClientConfig, engine.ServerConfig) {
  let assert Ok(ca_pem) = fixture("ca.pem")
  let assert Ok(server_pem) = fixture("server.pem")
  let assert Ok(key_pem) = fixture("server-key.pem")
  let assert Ok(trust_store) = authentication.trust_store_from_pem(ca_pem)
  let assert Ok(chain) = authentication.certificate_chain_from_pem(server_pem)
  let assert Ok(signing_key) = authentication.signing_key_from_pem(key_pem)
  let shared_parameters = [
    transport_parameter.GreaseQuicBit,
    transport_parameter.VersionInformation(version.Version1, [
      version.Version2,
      version.Version1,
    ]),
    transport_parameter.InitialMaxData(1_048_576),
    transport_parameter.InitialMaxStreamDataBidiLocal(262_144),
    transport_parameter.InitialMaxStreamDataBidiRemote(262_144),
    transport_parameter.InitialMaxStreamDataUni(262_144),
    transport_parameter.InitialMaxStreamsBidi(100),
    transport_parameter.InitialMaxStreamsUni(100),
    transport_parameter.MaxUdpPayloadSize(1200),
    transport_parameter.MaxDatagramFrameSize(1200),
  ]
  #(
    engine.ClientConfig(
      version: version.Version1,
      hostname: "localhost",
      application_protocols: [<<"h3">>],
      transport_parameters: [
        transport_parameter.InitialSourceConnectionId(client_connection_id),
        ..shared_parameters
      ],
      trust_store: trust_store,
      client_credential: None,
      retried: False,
      version_negotiated: False,
    ),
    engine.ServerConfig(
      version: version.Version1,
      application_protocols: [<<"h3">>],
      transport_parameters: [
        transport_parameter.OriginalDestinationConnectionId(
          original_destination_connection_id,
        ),
        transport_parameter.InitialSourceConnectionId(
          retry_source_connection_id,
        ),
        transport_parameter.RetrySourceConnectionId(retry_source_connection_id),
        ..shared_parameters
      ],
      certificate_chain: chain,
      signing_key: signing_key,
      signature_scheme: extension_value.Ed25519,
      alternative_credentials: [],
      client_authentication: engine.ClientAuthenticationDisabled,
    ),
  )
}

fn retry_datagram() -> BitArray {
  let retry_without_tag = retry_without_tag()
  let assert Ok(tag) =
    retry_integrity.tag(
      version.Version1,
      original_destination_connection_id,
      retry_without_tag,
    )
  <<retry_without_tag:bits, tag:bits>>
}

fn invalid_retry_datagram() -> BitArray {
  <<retry_without_tag():bits, 0:128>>
}

fn retry_without_tag() -> BitArray {
  <<
    0xf0,
    1:32,
    8,
    client_connection_id:bits,
    8,
    retry_source_connection_id:bits,
    "address-token",
  >>
}

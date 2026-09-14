//// Handshake, version negotiation, Retry, and path-MTU behaviour of the
//// packet driver, exercised end to end: two drivers passing datagrams in
//// memory, and one pair over a real loopback UDP socket.

import gleam/bit_array
import gleam/int
import gleam/list
import gleam/option.{type Option, None, Some}
import gleam/result
import quic_core/frame
import quic_core/internal/connection_state
import quic_core/internal/driver
import quic_core/internal/ecn
import quic_core/internal/retry_integrity
import quic_core/internal/tls/authentication
import quic_core/internal/tls/engine
import quic_core/internal/tls/extension
import quic_core/internal/tls/extension_value
import quic_core/internal/tls/handshake
import quic_core/internal/tls/hello
import quic_core/internal/traffic_keys
import quic_core/internal/udp
import quic_core/internal/wire_packet
import quic_core/packet
import quic_core/transport_parameter
import quic_core/version

@external(erlang, "quic_core_test_ffi", "fixture")
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
  GreaseEvidenceMissing(
    client_saw_zero: Bool,
    client_saw_one: Bool,
    server_saw_zero: Bool,
    server_saw_one: Bool,
  )
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
  assert driver.discardable_receive_error(driver.ConnectionFailure(
    connection_state.ConnectionUnavailable,
  ))
  assert !driver.discardable_receive_error(
    driver.ConnectionFailure(connection_state.ProtocolViolation(
      connection_state.ReservedBitsViolation,
    )),
  )
}

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn nonempty_grease_parameter_closes_with_transport_parameter_error_test() -> Nil {
  let #(client_tls_config, server_tls_config) = tls_configs()
  let assert Ok(engine.Step(client_tls, client_actions)) =
    engine.start_client(client_tls_config)
  let malformed_hello =
    nonempty_grease_client_hello(
      sent_at(client_actions, engine.Initial),
      client_tls_config.transport_parameters,
    )
  let client_actions =
    list.map(client_actions, fn(action) {
      case action {
        engine.Send(engine.Initial, _) ->
          engine.Send(engine.Initial, malformed_hello)
        _ -> action
      }
    })
  let assert Ok(server_tls) = engine.start_server(server_tls_config)
  let assert Ok(client) =
    driver.start_client(
      connection_state.default_config(connection_state.Client),
      engine.Step(client_tls, client_actions),
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

  let assert Ok(Some(initial)) = driver.prepare_datagram(client, 1000, 1)
  let assert Ok(client) = driver.commit_datagram(initial, 1)
  let assert Ok(server) =
    driver.receive_datagram(server, driver.prepared_bytes(initial), 1)
  assert driver.phase(server) == connection_state.Closing

  let assert Ok(Some(close)) = driver.prepare_datagram(server, 1000, 2)
  let assert Ok(_server) = driver.commit_datagram(close, 2)
  let assert Ok(client) =
    driver.receive_datagram(client, driver.prepared_bytes(close), 2)
  assert driver.phase(client) == connection_state.Draining
  let #(_, events) = driver.take_events(client)
  assert events == [connection_state.PeerClosed(0x08, "")]
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
pub fn retransmits_client_finished_after_its_first_datagram_is_lost_test() -> Nil {
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

  let assert Ok(peers) =
    drop_first_client_datagram_after_tls_complete(
      Peers(client, server, 1),
      maximum_handshake_rounds,
    )
  assert driver.phase(peers.client) == connection_state.Established
  assert driver.phase(peers.server) == connection_state.Handshaking

  let assert Ok(Some(probe_deadline)) =
    driver.next_deadline(peers.client, peers.now_ms)
  let assert Ok(client) = driver.tick(peers.client, probe_deadline)
  let assert Ok(Some(probe)) =
    driver.prepare_datagram(client, 1000, probe_deadline)
  let assert Ok(_client) = driver.commit_datagram(probe, probe_deadline)
  let assert Ok(server) =
    driver.receive_datagram(
      peers.server,
      driver.prepared_bytes(probe),
      probe_deadline,
    )
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

// RFC 9000 section 8.2.1 expands the datagram carrying a PATH_CHALLENGE to at
// least 1200 bytes, and section 8.2.2 the one carrying its PATH_RESPONSE. The
// expansion proves the path carries a full-size datagram, and it funds the
// reply: a peer answering across a path it has not validated may send only
// three times what it received there, so a challenge sent small leaves it
// unable to send the expanded response, and validation stalls with neither
// endpoint at fault. An independent peer showed exactly that.
// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn expands_a_live_path_validation_datagram_to_the_path_floor_test() -> Nil {
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
  let assert Ok(Peers(client, _, now)) =
    drive_handshake(Peers(client, server, 1), maximum_handshake_rounds)

  let assert Ok(client) =
    driver.update_connection(client, fn(connection) {
      connection_state.begin_path_validation(
        connection,
        <<1, 2, 3, 4, 5, 6, 7, 8>>,
        True,
        now,
      )
    })
  let assert Ok(Some(prepared)) = driver.prepare_datagram(client, 1200, now)
  assert bit_array.byte_size(driver.prepared_bytes(prepared)) == 1200
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
pub fn rejected_unsent_pmtu_probe_reduces_the_next_exact_size_test() -> Nil {
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
  let assert Ok(Some(rejected)) = driver.prepare_pmtu_probe(client, now)
  assert bit_array.byte_size(driver.prepared_bytes(rejected)) == 1300
  let assert Ok(client) = driver.reject_pmtu_probe(rejected)
  let assert Ok(Some(next)) = driver.prepare_pmtu_probe(client, now + 1)
  assert bit_array.byte_size(driver.prepared_bytes(next)) == 1250
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
pub fn server_discards_valid_one_rtt_before_tls_handshake_completion_test() -> Nil {
  let #(_, server_tls_config) = tls_configs()
  let assert Ok(server_tls) = engine.start_server(server_tls_config)
  let assert Ok(keys) =
    traffic_keys.from_secret(version.Version1, hello.Aes128GcmSha256, <<0:256>>)
  let assert Ok(server) =
    driver.start_server(
      connection_state.default_config(connection_state.Server),
      server_tls,
      original_destination_connection_id,
      original_destination_connection_id,
      client_connection_id,
      0,
    )
  let assert Ok(server) =
    driver.update_connection(server, fn(connection) {
      connection_state.apply_tls_actions(connection, [
        engine.InstallReadKeys(engine.OneRtt, keys),
        engine.InstallWriteKeys(engine.OneRtt, keys),
      ])
    })
  assert driver.phase(server) == connection_state.Handshaking

  let assert Ok(sender) =
    connection_state.new(
      connection_state.default_config(connection_state.Client),
      0,
    )
  let assert Ok(sender) =
    connection_state.apply_tls_actions(sender, [
      engine.InstallReadKeys(engine.OneRtt, keys),
      engine.InstallWriteKeys(engine.OneRtt, keys),
      engine.HandshakeComplete,
    ])
  let assert Ok(#(_, early_packet)) =
    connection_state.protect_short_packet(
      sender,
      original_destination_connection_id,
      0,
      False,
      [frame.Stream(0, 0, <<1>>, True)],
      1,
    )

  let assert Ok(server) = driver.receive_datagram(server, early_packet, 1)
  assert driver.phase(server) == connection_state.Handshaking
  let #(_, events) = driver.take_events(server)
  assert events == []
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
pub fn server_ignores_received_version_negotiation_test() -> Nil {
  let #(_, server_tls_config) = tls_configs()
  let assert Ok(server_tls) = engine.start_server(server_tls_config)
  let assert Ok(server) =
    driver.start_server(
      connection_state.default_config(connection_state.Server),
      server_tls,
      original_destination_connection_id,
      original_destination_connection_id,
      client_connection_id,
      0,
    )
  let assert Ok(datagram) =
    packet.VersionNegotiation(
      packet.LongHeader(
        0x80,
        version.Negotiation,
        original_destination_connection_id,
        client_connection_id,
      ),
      [version.Version2],
    )
    |> packet.encode_long

  let assert Ok(server) = driver.receive_datagram(server, datagram, 1)
  assert driver.phase(server) == connection_state.Handshaking
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
pub fn amplification_limited_server_retains_oversized_pto_work_test() -> Nil {
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
  let assert Ok(Peers(_, server, now_ms)) =
    send_client_datagram(Peers(client, server, 1))

  // Drop the complete server flight after committing it. Its 1200-byte
  // Initial plus the Handshake packet consume part of the exact 3x credit
  // granted by the client's only 1200-byte datagram.
  let assert Ok(Some(initial)) = driver.prepare_datagram(server, 1000, now_ms)
  assert bit_array.byte_size(driver.prepared_bytes(initial)) == 1200
  let assert Ok(server) = driver.commit_datagram(initial, now_ms)
  let second_at = now_ms + 100
  let assert Ok(server) = driver.tick(server, second_at)
  let assert Ok(Some(handshake)) =
    driver.prepare_datagram(server, 1000, second_at)
  let handshake_bytes = bit_array.byte_size(driver.prepared_bytes(handshake))
  assert handshake_bytes > 0
  assert handshake_bytes < 1200
  let assert Ok(server) = driver.commit_datagram(handshake, second_at)

  let assert Ok(Some(pto_deadline)) = driver.next_deadline(server, second_at)
  let assert Ok(server) = driver.tick(server, pto_deadline)
  let assert Ok(Some(initial_probe)) =
    driver.prepare_datagram(server, 1000, pto_deadline)
  assert bit_array.byte_size(driver.prepared_bytes(initial_probe)) == 1200
  let assert Ok(server) = driver.commit_datagram(initial_probe, pto_deadline)

  // The reliable Handshake probe remains queued, but its protected datagram
  // is wider than the credit left. That is recoverable peer backpressure, not
  // a connection failure; receiving more bytes will grant it later.
  let retry_at = pto_deadline + 100
  let assert Ok(server) = driver.tick(server, retry_at)
  assert driver.prepare_datagram(server, 1000, retry_at) == Ok(None)
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
  let assert Ok(#(packet.Initial(header, retry_token, _), _)) =
    packet.parse_long(driver.prepared_bytes(retried_initial))
  assert header.version == version.Version1
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
pub fn negotiated_quic_bit_greasing_crosses_live_udp_wire_test() -> Nil {
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

  let assert Ok(peers) =
    drive_udp_handshake(
      Peers(client, server, 1),
      client_socket,
      server_socket,
      client_endpoint,
      server_endpoint,
      maximum_handshake_rounds,
    )
  assert connection_state.grease_quic_bit_negotiated(driver.connection(
    peers.client,
  ))
  assert connection_state.grease_quic_bit_negotiated(driver.connection(
    peers.server,
  ))

  let assert Ok(_) =
    drive_live_greased_packets(
      peers,
      client_socket,
      server_socket,
      client_endpoint,
      server_endpoint,
      64,
      False,
      False,
      False,
      False,
    )
  let assert Ok(Nil) = udp.close(client_socket)
  let assert Ok(Nil) = udp.close(server_socket)
  Nil
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

/// The step a connection owner takes for one refused send.
///
/// The classification is the part under test: only `udp.PathTooSmall` keeps
/// the connection. Were EMSGSIZE folded back into a socket failure, the flush
/// would report a lost socket and this returns `Error(Nil)` in its place, so
/// the test fails instead of quietly asserting an unreachable state.
fn driver_after_refused_send(state: driver.State) -> Result(driver.State, Nil) {
  case udp.classify_send(Error(udp.MessageTooLarge)) {
    udp.PathTooSmall -> Ok(driver.report_pmtu_black_hole(state))
    udp.Delivered | udp.SocketLost -> Error(Nil)
  }
}

/// A configuration for a socket that carries the Don't-Fragment option, which
/// is what lets DPLPMTUD search above the 1200-byte floor. The fail-closed
/// default `connection_state.default_config` pins is covered by
/// `connection_state_test`.
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

/// Advance a valid handshake until the client has processed the server
/// Finished, then commit but deliberately do not deliver the first datagram
/// carrying the client's remaining Handshake work. This models ordinary UDP
/// loss at the exact transition which a covered burst exposed in production.
fn drop_first_client_datagram_after_tls_complete(
  peers: Peers,
  rounds: Int,
) -> Result(Peers, driver.Error) {
  case driver.phase(peers.client), driver.phase(peers.server), rounds {
    connection_state.Established, connection_state.Handshaking, _ -> {
      use client <- result.try(driver.tick(peers.client, peers.now_ms))
      use server <- result.try(driver.tick(peers.server, peers.now_ms))
      use prepared <- result.try(driver.prepare_datagram(
        client,
        1000,
        peers.now_ms,
      ))
      case prepared {
        None -> Error(driver.InvalidInput)
        Some(prepared) -> {
          use client <- result.try(driver.commit_datagram(
            prepared,
            peers.now_ms,
          ))
          Ok(Peers(client, server, peers.now_ms + 100))
        }
      }
    }
    _, _, 0 -> Error(driver.InvalidInput)
    _, _, remaining -> {
      use peers <- result.try(send_client_datagram(peers))
      use peers <- result.try(send_server_datagram(peers))
      drop_first_client_datagram_after_tls_complete(peers, remaining - 1)
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

fn drive_live_greased_packets(
  peers: Peers,
  client_socket: udp.Socket,
  server_socket: udp.Socket,
  client_endpoint: udp.Endpoint,
  server_endpoint: udp.Endpoint,
  rounds: Int,
  client_saw_zero: Bool,
  client_saw_one: Bool,
  server_saw_zero: Bool,
  server_saw_one: Bool,
) -> Result(Peers, NetworkError) {
  case
    client_saw_zero && client_saw_one && server_saw_zero && server_saw_one,
    rounds
  {
    True, _ -> Ok(peers)
    False, 0 ->
      Error(GreaseEvidenceMissing(
        client_saw_zero,
        client_saw_one,
        server_saw_zero,
        server_saw_one,
      ))
    False, remaining -> {
      use client <- result.try(
        driver.update_connection(peers.client, connection_state.queue_ping)
        |> map_driver,
      )
      use #(peers, observed) <- result.try(send_observed_client_udp(
        Peers(client, peers.server, peers.now_ms),
        client_socket,
        server_socket,
        client_endpoint,
        server_endpoint,
      ))
      let #(client_saw_zero, client_saw_one) = case observed {
        None -> #(client_saw_zero, client_saw_one)
        Some(False) -> #(True, client_saw_one)
        Some(True) -> #(client_saw_zero, True)
      }
      use server <- result.try(
        driver.update_connection(peers.server, connection_state.queue_ping)
        |> map_driver,
      )
      use #(peers, observed) <- result.try(send_observed_server_udp(
        Peers(peers.client, server, peers.now_ms),
        client_socket,
        server_socket,
        client_endpoint,
        server_endpoint,
      ))
      let #(server_saw_zero, server_saw_one) = case observed {
        None -> #(server_saw_zero, server_saw_one)
        Some(False) -> #(True, server_saw_one)
        Some(True) -> #(server_saw_zero, True)
      }
      drive_live_greased_packets(
        peers,
        client_socket,
        server_socket,
        client_endpoint,
        server_endpoint,
        remaining - 1,
        client_saw_zero,
        client_saw_one,
        server_saw_zero,
        server_saw_one,
      )
    }
  }
}

fn send_observed_server_udp(
  peers: Peers,
  client_socket: udp.Socket,
  server_socket: udp.Socket,
  client_endpoint: udp.Endpoint,
  server_endpoint: udp.Endpoint,
) -> Result(#(Peers, Option(Bool)), NetworkError) {
  use client <- result.try(
    driver.tick(peers.client, peers.now_ms) |> map_driver,
  )
  use server <- result.try(
    driver.tick(peers.server, peers.now_ms) |> map_driver,
  )
  case driver.prepare_datagram(server, 1000, peers.now_ms) {
    Error(error) -> Error(DriverError(error))
    Ok(None) -> Ok(#(Peers(client, server, peers.now_ms + 100), None))
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
      Ok(#(
        Peers(client, server, peers.now_ms + 100),
        observed_short_quic_bit(received),
      ))
    }
  }
}

fn observed_short_quic_bit(received: BitArray) -> Option(Bool) {
  case received {
    <<first, _:bits>> ->
      case int.bitwise_and(first, 0x80) {
        0 -> Some(int.bitwise_and(first, 0x40) == 0x40)
        _ -> None
      }
    _ -> None
  }
}

fn send_observed_client_udp(
  peers: Peers,
  client_socket: udp.Socket,
  server_socket: udp.Socket,
  client_endpoint: udp.Endpoint,
  server_endpoint: udp.Endpoint,
) -> Result(#(Peers, Option(Bool)), NetworkError) {
  use client <- result.try(
    driver.tick(peers.client, peers.now_ms) |> map_driver,
  )
  use server <- result.try(
    driver.tick(peers.server, peers.now_ms) |> map_driver,
  )
  case driver.prepare_datagram(client, 1000, peers.now_ms) {
    Error(error) -> Error(DriverError(error))
    Ok(None) -> Ok(#(Peers(client, server, peers.now_ms + 100), None))
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
      Ok(#(
        Peers(client, server, peers.now_ms + 100),
        observed_short_quic_bit(received),
      ))
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

fn nonempty_grease_client_hello(
  encoded_hello: BitArray,
  parameters: List(transport_parameter.Parameter),
) -> BitArray {
  let parameters =
    list.filter(parameters, fn(parameter) {
      case parameter {
        transport_parameter.GreaseQuicBit -> False
        _ -> True
      }
    })
  let assert Ok(encoded_parameters) =
    transport_parameter.encode_all(parameters, transport_parameter.Client)
  // RFC 9287 registers 0x2ab2 with a zero-length value. Keep every other
  // parameter canonical and replace only this one with a one-byte value, so
  // the observed failure cannot be attributed to duplicate or malformed
  // neighbouring parameters.
  let invalid_parameters = <<0x6a, 0xb2, 1, 0, encoded_parameters:bits>>
  let assert Ok(handshake.Complete(
    handshake.Message(handshake.ClientHello, body),
    <<>>,
  )) = handshake.decode_next(encoded_hello, handshake.default_limits())
  let assert Ok(hello.ClientHello(random, session, suites, extensions)) =
    hello.decode_client(body, hello.default_limits())
  let extensions =
    list.map(extensions, fn(value) {
      case value {
        extension.Extension(extension.QuicTransportParameters, _) ->
          extension.Extension(
            extension.QuicTransportParameters,
            invalid_parameters,
          )
        _ -> value
      }
    })
  let assert Ok(body) =
    hello.ClientHello(random, session, suites, extensions)
    |> hello.encode_client(hello.default_limits())
  let assert Ok(encoded) =
    handshake.Message(handshake.ClientHello, body)
    |> handshake.encode(0xff_ffff)
  encoded
}

fn sent_at(
  actions: List(engine.Action),
  level: engine.EncryptionLevel,
) -> BitArray {
  let assert [engine.Send(_, bytes)] =
    list.filter(actions, fn(action) {
      case action {
        engine.Send(action_level, _) -> action_level == level
        _ -> False
      }
    })
  bytes
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

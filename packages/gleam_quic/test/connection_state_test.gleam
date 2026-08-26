import gleam/bit_array
import gleam/option.{type Option, None, Some}
import gleam/result
import gleam_quic/frame
import gleam_quic/internal/connection_state
import gleam_quic/internal/ecn
import gleam_quic/internal/key_phase
import gleam_quic/internal/packet_space
import gleam_quic/internal/tls/authentication
import gleam_quic/internal/tls/engine
import gleam_quic/internal/tls/extension_value
import gleam_quic/internal/tls/hello
import gleam_quic/internal/traffic_keys
import gleam_quic/internal/wire_packet
import gleam_quic/stream_id
import gleam_quic/transport_parameter
import gleam_quic/version

@external(erlang, "gleam_quic_test_ffi", "fixture")
fn fixture(name: String) -> Result(BitArray, Nil)

const initial_destination_connection_id = <<1, 2, 3, 4, 5, 6, 7, 8>>

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn applies_tls_actions_keys_parameters_and_crypto_queue_test() -> Nil {
  let assert Ok(connection) =
    connection_state.new(
      connection_state.default_config(connection_state.Client),
      0,
    )
  let assert Ok(keys) = test_keys()
  let actions = [
    engine.InstallWriteKeys(engine.Handshake, keys),
    engine.InstallReadKeys(engine.Handshake, keys),
    engine.Send(engine.Handshake, <<"server flight">>),
    engine.PeerTransportParameters(peer_parameters()),
    engine.EarlyDataAccepted,
    engine.HandshakeComplete,
    engine.DiscardKeys(engine.Initial),
  ]
  let assert Ok(connection) =
    connection_state.apply_tls_actions(connection, actions)
  assert connection_state.keys_available(
    connection,
    engine.Handshake,
    connection_state.Read,
  )
  assert connection_state.keys_available(
    connection,
    engine.Handshake,
    connection_state.Write,
  )
  assert connection_state.packet_space_discarded(connection, engine.Initial)
  assert connection_state.phase(connection) == connection_state.Established

  let assert Ok(connection_state.PacketPrepared(
    connection,
    engine.Handshake,
    0,
    [frame.Crypto(0, <<"server flight">>)],
  )) = connection_state.prepare_packet(connection, engine.Handshake, 1200, 1)
  let assert Ok(connection) =
    connection_state.commit_packet(
      connection,
      engine.Handshake,
      0,
      [frame.Crypto(0, <<"server flight">>)],
      100,
      ecn.Ect0,
      1,
    )
  assert connection_state.bytes_in_flight(connection) == 100

  let #(connection, events) = connection_state.take_events(connection)
  assert events
    == [
      connection_state.PeerParametersApplied,
      connection_state.EarlyDataWasAccepted,
      connection_state.HandshakeEstablished,
    ]
  let #(_, no_events) = connection_state.take_events(connection)
  assert no_events == []
}

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn opens_receives_and_reads_flow_controlled_streams_test() -> Nil {
  let assert Ok(connection) = established(connection_state.Server)
  let assert Ok(connection) =
    connection_state.record_datagram_received(connection, 1200, 10)
  let assert Ok(connection) =
    connection_state.receive_packet(
      connection,
      engine.OneRtt,
      0,
      [frame.Stream(0, 0, <<"hello">>, True)],
      packet_space.Ect0,
      10,
    )
  let #(connection, events) = connection_state.take_events(connection)
  assert events
    == [connection_state.StreamOpened(0), connection_state.StreamReadable(0)]
  let assert Ok(#(connection, read)) =
    connection_state.read_stream(connection, 0, 16)
  assert connection_state.read_data(read) == Some(#(<<"hello">>, True))

  let assert Ok(connection_state.PacketPrepared(
    prepared,
    engine.OneRtt,
    0,
    response_frames,
  )) = connection_state.prepare_packet(connection, engine.OneRtt, 1200, 35)
  assert list_contains_ack(response_frames)
  assert connection_state.connection_counters(prepared)
    == connection_state.ConnectionCounters(0, 0, 0)
  let assert Ok(committed) =
    connection_state.commit_packet(
      prepared,
      engine.OneRtt,
      0,
      response_frames,
      64,
      ecn.NotEct,
      35,
    )
  assert connection_state.connection_counters(committed)
    == connection_state.ConnectionCounters(1, 0, 0)
}

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn removes_terminal_streams_and_replenishes_peer_concurrency_test() -> Nil {
  let assert Ok(connection) = established(connection_state.Server)
  let assert Ok(connection_state.PacketPrepared(
    connection,
    engine.OneRtt,
    _,
    [frame.HandshakeDone],
  )) = connection_state.prepare_packet(connection, engine.OneRtt, 1200, 1)
  let assert Ok(connection) =
    connection_state.receive_packet(
      connection,
      engine.OneRtt,
      0,
      [frame.Stream(2, 0, <<"done">>, True)],
      packet_space.NotEct,
      10,
    )
  assert connection_state.active_stream_count(connection) == 1

  let assert Ok(#(connection, read)) =
    connection_state.read_stream(connection, 2, 16)
  assert connection_state.read_data(read) == Some(#(<<"done">>, True))
  assert connection_state.active_stream_count(connection) == 0

  let assert Ok(connection_state.PacketPrepared(
    connection,
    engine.OneRtt,
    _,
    frames,
  )) = connection_state.prepare_packet(connection, engine.OneRtt, 1200, 20)
  assert contains_max_streams(frames, frame.Unidirectional, 101)

  let assert Ok(connection) =
    connection_state.receive_packet(
      connection,
      engine.OneRtt,
      1,
      [frame.Stream(2, 0, <<"done">>, True)],
      packet_space.NotEct,
      21,
    )
  assert connection_state.active_stream_count(connection) == 0
}

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn sends_streams_round_robin_and_recovers_congestion_credit_test() -> Nil {
  let assert Ok(connection) = established(connection_state.Client)
  let assert Ok(#(connection, first_id)) =
    connection_state.open_stream(connection, stream_id.Bidirectional)
  let assert Ok(#(connection, second_id)) =
    connection_state.open_stream(connection, stream_id.Bidirectional)
  assert #(first_id, second_id) == #(0, 4)
  let assert Ok(connection) =
    connection_state.queue_stream(connection, first_id, <<"one">>, True)
  let assert Ok(connection) =
    connection_state.queue_stream(connection, second_id, <<"two">>, True)

  let assert Ok(connection_state.PacketPrepared(
    connection,
    engine.OneRtt,
    0,
    [first_frame],
  )) = connection_state.prepare_packet(connection, engine.OneRtt, 1200, 1)
  assert first_frame == frame.Stream(0, 0, <<"one">>, True)
  let assert Ok(connection) =
    connection_state.commit_packet(
      connection,
      engine.OneRtt,
      0,
      [first_frame],
      1200,
      ecn.Ect0,
      1,
    )
  assert connection_state.bytes_in_flight(connection) == 1200

  let assert Ok(connection_state.PacketPrepared(
    connection,
    engine.OneRtt,
    1,
    [second_frame],
  )) = connection_state.prepare_packet(connection, engine.OneRtt, 1200, 2)
  assert second_frame == frame.Stream(4, 0, <<"two">>, True)
  let assert Ok(connection) =
    connection_state.commit_packet(
      connection,
      engine.OneRtt,
      1,
      [second_frame],
      1200,
      ecn.Ect0,
      2,
    )

  let assert Ok(connection) =
    connection_state.record_datagram_received(connection, 80, 20)
  let assert Ok(connection) =
    connection_state.receive_packet(
      connection,
      engine.OneRtt,
      0,
      [frame.Ack(frame.Acknowledgement(0, [frame.AckRange(0, 1)], None))],
      packet_space.NotEct,
      20,
    )
  assert connection_state.bytes_in_flight(connection) == 0
  assert connection_state.congestion_window(connection) > 12_000
}

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn counts_only_ack_eliciting_packets_declared_lost_test() -> Nil {
  let assert Ok(connection) = established(connection_state.Client)
  let assert Ok(connection) =
    connection_state.commit_packet(
      connection,
      engine.OneRtt,
      0,
      [frame.Ping],
      100,
      ecn.NotEct,
      1,
    )
  let assert Ok(connection) =
    connection_state.commit_packet(
      connection,
      engine.OneRtt,
      1,
      [frame.Ping],
      100,
      ecn.NotEct,
      2,
    )
  let assert Ok(connection) =
    connection_state.commit_packet(
      connection,
      engine.OneRtt,
      2,
      [frame.Ping],
      100,
      ecn.NotEct,
      3,
    )
  let assert Ok(connection) =
    connection_state.commit_packet(
      connection,
      engine.OneRtt,
      3,
      [frame.Ping],
      100,
      ecn.NotEct,
      4,
    )
  let assert Ok(connection) =
    connection_state.record_datagram_received(connection, 64, 5)
  let assert Ok(connection) =
    connection_state.receive_packet(
      connection,
      engine.OneRtt,
      0,
      [frame.Ack(frame.Acknowledgement(0, [frame.AckRange(3, 3)], None))],
      packet_space.NotEct,
      5,
    )
  assert connection_state.connection_counters(connection)
    == connection_state.ConnectionCounters(0, 3, 0)
}

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn aborts_both_directions_of_a_bidirectional_stream_test() -> Nil {
  let assert Ok(connection) = established(connection_state.Client)
  let assert Ok(#(connection, identifier)) =
    connection_state.open_stream(connection, stream_id.Bidirectional)
  let assert Ok(connection) =
    connection_state.queue_stream(
      connection,
      identifier,
      <<"discard me">>,
      False,
    )

  let assert Ok(connection) =
    connection_state.abort_stream(connection, identifier, 0x10c)
  assert connection_state.stream_buffered_send_bytes(connection, identifier)
    == Ok(0)

  let assert Ok(connection_state.PacketPrepared(
    connection,
    engine.OneRtt,
    0,
    [reset],
  )) = connection_state.prepare_packet(connection, engine.OneRtt, 1200, 1)
  assert reset == frame.ResetStream(identifier, 0x10c, 0)
  let assert Ok(connection_state.PacketPrepared(_, engine.OneRtt, 0, [stop])) =
    connection_state.prepare_packet(connection, engine.OneRtt, 1200, 1)
  assert stop == frame.StopSending(identifier, 0x10c)
}

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn enforces_connection_send_credit_without_consuming_stream_data_test() -> Nil {
  let assert Ok(connection) =
    connection_state.new(
      connection_state.default_config(connection_state.Client),
      0,
    )
  let assert Ok(keys) = test_keys()
  let assert Ok(connection) =
    connection_state.apply_tls_actions(connection, [
      engine.InstallWriteKeys(engine.OneRtt, keys),
      engine.InstallReadKeys(engine.OneRtt, keys),
      engine.PeerTransportParameters([
        transport_parameter.InitialMaxData(0),
        transport_parameter.InitialMaxStreamDataBidiRemote(1024),
        transport_parameter.InitialMaxStreamsBidi(1),
      ]),
      engine.HandshakeComplete,
    ])
  let assert Ok(#(connection, identifier)) =
    connection_state.open_stream(connection, stream_id.Bidirectional)
  let assert Ok(connection) =
    connection_state.queue_stream(connection, identifier, <<"held">>, True)
  let assert Ok(connection_state.PacketPrepared(
    connection,
    engine.OneRtt,
    0,
    [frame.DataBlocked(0)],
  )) = connection_state.prepare_packet(connection, engine.OneRtt, 1200, 1)

  let assert Ok(connection) =
    connection_state.receive_packet(
      connection,
      engine.OneRtt,
      0,
      [frame.MaxData(4)],
      packet_space.NotEct,
      2,
    )
  let assert Ok(connection_state.PacketPrepared(
    _,
    engine.OneRtt,
    0,
    [frame.Stream(0, 0, <<"held">>, True)],
  )) = connection_state.prepare_packet(connection, engine.OneRtt, 1200, 2)
  Nil
}

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn enforces_server_amplification_and_key_availability_test() -> Nil {
  let assert Ok(connection) =
    connection_state.new(
      connection_state.default_config(connection_state.Server),
      0,
    )
  let assert Ok(keys) = test_keys()
  let assert Ok(connection) =
    connection_state.apply_tls_actions(connection, [
      engine.InstallWriteKeys(engine.Handshake, keys),
    ])
  assert connection_state.commit_packet(
      connection,
      engine.Handshake,
      0,
      [frame.Ping],
      1200,
      ecn.NotEct,
      0,
    )
    == Error(connection_state.AmplificationLimited)

  let assert Ok(connection) =
    connection_state.record_datagram_received(connection, 400, 1)
  let assert Ok(connection) =
    connection_state.commit_packet(
      connection,
      engine.Handshake,
      0,
      [frame.Ping],
      1200,
      ecn.NotEct,
      1,
    )
  assert connection_state.bytes_in_flight(connection) == 1200

  assert connection_state.receive_packet(
      connection,
      engine.OneRtt,
      0,
      [frame.Ping],
      packet_space.NotEct,
      2,
    )
    == Error(connection_state.MissingReadKeys(engine.OneRtt))
}

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn derives_initial_keys_and_processes_coalesced_wire_packets_test() -> Nil {
  let assert Ok(keys) = test_keys()
  let assert Ok(client) =
    connection_state.new(
      connection_state.default_config(connection_state.Client),
      0,
    )
  let assert Ok(client) =
    connection_state.install_initial_keys(
      client,
      initial_destination_connection_id,
    )
  let assert Ok(client) =
    connection_state.apply_tls_actions(client, [
      engine.InstallWriteKeys(engine.Handshake, keys),
      engine.InstallReadKeys(engine.Handshake, keys),
    ])
  assert connection_state.keys_available(
    client,
    engine.Initial,
    connection_state.Write,
  )
  assert connection_state.apply_tls_actions(client, [
      engine.InstallWriteKeys(engine.Initial, keys),
    ])
    == Error(connection_state.InvalidConfiguration)

  let assert Ok(server) =
    connection_state.new(
      connection_state.default_config(connection_state.Server),
      0,
    )
  let assert Ok(server) =
    connection_state.install_initial_keys(
      server,
      initial_destination_connection_id,
    )
  let assert Ok(server) =
    connection_state.apply_tls_actions(server, [
      engine.InstallWriteKeys(engine.Handshake, keys),
      engine.InstallReadKeys(engine.Handshake, keys),
    ])

  let assert Ok(initial_packet) =
    connection_state.protect_long_packet(
      client,
      wire_packet.Initial(<<>>),
      initial_destination_connection_id,
      <<9, 10, 11, 12>>,
      0,
      [frame.Ping],
    )
  let assert Ok(handshake_packet) =
    connection_state.protect_long_packet(
      client,
      wire_packet.Handshake,
      initial_destination_connection_id,
      <<9, 10, 11, 12>>,
      0,
      [frame.Ping],
    )
  let datagram = <<initial_packet:bits, handshake_packet:bits>>
  let assert Ok(server) =
    connection_state.record_datagram_received(
      server,
      bit_array.byte_size(datagram),
      1,
    )
  let assert Ok(connection_state.LongPacketReceipt(
    server,
    destination,
    source,
    rest,
  )) =
    connection_state.receive_protected_long_packet(
      server,
      datagram,
      packet_space.NotEct,
      1,
    )
  assert destination == initial_destination_connection_id
  assert source == <<9, 10, 11, 12>>
  assert rest == handshake_packet
  assert connection_state.connection_counters(server)
    == connection_state.ConnectionCounters(0, 0, 1)
  let assert Ok(connection_state.LongPacketReceipt(server, _, _, <<>>)) =
    connection_state.receive_protected_long_packet(
      server,
      rest,
      packet_space.NotEct,
      1,
    )
  assert connection_state.connection_counters(server)
    == connection_state.ConnectionCounters(0, 0, 1)
  let assert Ok(connection_state.PacketPrepared(
    _,
    engine.Initial,
    0,
    initial_ack,
  )) = connection_state.prepare_packet(server, engine.Initial, 1200, 1)
  assert list_contains_ack(initial_ack)
  let assert Ok(connection_state.PacketPrepared(
    _,
    engine.Handshake,
    0,
    handshake_ack,
  )) = connection_state.prepare_packet(server, engine.Handshake, 1200, 1)
  assert list_contains_ack(handshake_ack)
}

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn protects_and_processes_short_header_stream_packet_test() -> Nil {
  let assert Ok(client) = established(connection_state.Client)
  let assert Ok(server) = established(connection_state.Server)
  let assert Ok(#(_, packet)) =
    connection_state.protect_short_packet(
      client,
      initial_destination_connection_id,
      0,
      True,
      [frame.Stream(0, 0, <<"wire">>, True)],
      1,
    )
  let assert Ok(server) =
    connection_state.record_datagram_received(
      server,
      bit_array.byte_size(packet),
      1,
    )
  let assert Ok(connection_state.ShortPacketReceipt(
    server,
    destination,
    False,
    True,
  )) =
    connection_state.receive_protected_short_packet(
      server,
      packet,
      8,
      packet_space.NotEct,
      1,
    )
  assert destination == initial_destination_connection_id
  let #(_, events) = connection_state.take_events(server)
  assert events
    == [connection_state.StreamOpened(0), connection_state.StreamReadable(0)]
}

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn updates_one_rtt_keys_on_wire_and_unlocks_after_ack_test() -> Nil {
  let assert Ok(sender) = established(connection_state.Server)
  let assert Ok(receiver) = established(connection_state.Server)
  let assert Ok(sender) = connection_state.initiate_key_update(sender, 100)
  let assert Ok(#(sender, packet)) =
    connection_state.protect_short_packet(
      sender,
      initial_destination_connection_id,
      0,
      False,
      [frame.Ping],
      100,
    )
  assert connection_state.initiate_key_update(sender, 101)
    == Error(connection_state.KeyUpdateFailure(key_phase.UpdateNotAcknowledged))
  let assert Ok(receiver) =
    connection_state.record_datagram_received(
      receiver,
      bit_array.byte_size(packet),
      100,
    )
  let assert Ok(connection_state.ShortPacketReceipt(_, _, True, False)) =
    connection_state.receive_protected_short_packet(
      receiver,
      packet,
      8,
      packet_space.NotEct,
      100,
    )

  let assert Ok(sender) =
    connection_state.commit_packet(
      sender,
      engine.OneRtt,
      0,
      [frame.Ping],
      bit_array.byte_size(packet),
      ecn.NotEct,
      100,
    )
  let assert Ok(sender) =
    connection_state.receive_packet(
      sender,
      engine.OneRtt,
      0,
      [frame.Ack(frame.Acknowledgement(0, [frame.AckRange(0, 0)], None))],
      packet_space.NotEct,
      101,
    )
  let assert Ok(_) = connection_state.initiate_key_update(sender, 100_000)
  Nil
}

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn validates_rebinding_and_enforces_active_migration_policy_test() -> Nil {
  let challenge = <<1, 2, 3, 4, 5, 6, 7, 8>>
  let assert Ok(connection) = established(connection_state.Client)
  let assert Ok(connection) =
    connection_state.apply_tls_actions(connection, [
      engine.PeerTransportParameters([
        transport_parameter.DisableActiveMigration,
      ]),
    ])
  assert connection_state.begin_path_validation(connection, challenge, True, 10)
    == Error(connection_state.ActiveMigrationDisabled)
  let assert Ok(connection) =
    connection_state.begin_path_validation(connection, challenge, False, 10)
  let assert Ok(connection_state.PacketPrepared(
    connection,
    engine.OneRtt,
    0,
    [frame.PathChallenge(challenge)],
  )) = connection_state.prepare_packet(connection, engine.OneRtt, 1200, 10)
  let assert Ok(connection) =
    connection_state.receive_packet(
      connection,
      engine.OneRtt,
      0,
      [frame.PathResponse(challenge)],
      packet_space.NotEct,
      11,
    )
  let #(_, events) = connection_state.take_events(connection)
  assert events
    == [connection_state.PeerParametersApplied, connection_state.PathValidated]

  let assert Ok(timeout) = established(connection_state.Server)
  let assert Ok(timeout) =
    connection_state.begin_path_validation(timeout, challenge, False, 10)
  let assert Ok(timeout) = connection_state.tick(timeout, 10_000)
  let #(_, events) = connection_state.take_events(timeout)
  assert events == [connection_state.PathValidationFailed]
}

// RFC 9000 section 21.9 and reported erratum 8875 permit load shedding when
// excessive PATH_CHALLENGE traffic is an attack. Repeated challenges must not
// grow the pending PATH_RESPONSE queue, and distinct challenges are bounded.
// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn bounds_and_coalesces_path_challenge_responses_test() -> Nil {
  let duplicate = <<0, 1, 2, 3, 4, 5, 6, 7>>
  let assert Ok(connection) = established(connection_state.Server)
  let assert Ok(connection) =
    connection_state.receive_packet(
      connection,
      engine.OneRtt,
      0,
      repeated_path_challenges(duplicate, 128, []),
      packet_space.NotEct,
      1,
    )
  let assert Ok(connection_state.PacketPrepared(
    connection,
    engine.OneRtt,
    _,
    [frame.HandshakeDone],
  )) = connection_state.prepare_packet(connection, engine.OneRtt, 1200, 1)
  let assert Ok(connection_state.PacketPrepared(
    _,
    engine.OneRtt,
    _,
    [frame.PathResponse(response)],
  )) = connection_state.prepare_packet(connection, engine.OneRtt, 1200, 1)
  assert response == duplicate

  let assert Ok(connection) = established(connection_state.Server)
  assert connection_state.receive_packet(
      connection,
      engine.OneRtt,
      0,
      distinct_path_challenges(65, []),
      packet_space.NotEct,
      1,
    )
    == Error(connection_state.ProtocolViolation)
}

fn repeated_path_challenges(
  challenge: BitArray,
  remaining: Int,
  frames: List(frame.Frame),
) -> List(frame.Frame) {
  case remaining {
    0 -> frames
    _ ->
      repeated_path_challenges(challenge, remaining - 1, [
        frame.PathChallenge(challenge),
        ..frames
      ])
  }
}

fn distinct_path_challenges(
  remaining: Int,
  frames: List(frame.Frame),
) -> List(frame.Frame) {
  case remaining {
    0 -> frames
    value ->
      distinct_path_challenges(value - 1, [
        frame.PathChallenge(<<value:64>>),
        ..frames
      ])
  }
}

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn rotates_peer_connection_ids_and_surfaces_local_retirement_test() -> Nil {
  let replacement = <<11, 12, 13, 14, 15, 16, 17, 18>>
  let assert Ok(connection) = established(connection_state.Client)
  let assert Ok(connection) =
    connection_state.initialize_peer_connection_id(
      connection,
      initial_destination_connection_id,
      <<0:128>>,
    )
  let assert Ok(connection) =
    connection_state.receive_packet(
      connection,
      engine.OneRtt,
      0,
      [
        frame.NewConnectionId(1, 1, replacement, <<1:128>>),
        frame.RetireConnectionId(7),
      ],
      packet_space.NotEct,
      1,
    )
  assert connection_state.current_peer_connection_id(connection)
    == Ok(replacement)
  let #(_, events) = connection_state.take_events(connection)
  assert events
    == [
      connection_state.PeerConnectionIdAvailable(1, replacement),
      connection_state.LocalConnectionIdRetirementRequested(7),
    ]
  let assert Ok(connection_state.PacketPrepared(
    _,
    engine.OneRtt,
    0,
    [frame.RetireConnectionId(0)],
  )) = connection_state.prepare_packet(connection, engine.OneRtt, 1200, 1)
  Nil
}

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn recognizes_only_active_stateless_reset_tokens_test() -> Nil {
  let reset_token = <<7:128>>
  let assert Ok(connection) = established(connection_state.Client)
  let assert Ok(connection) =
    connection_state.initialize_peer_connection_id(
      connection,
      initial_destination_connection_id,
      reset_token,
    )
  let assert Ok(#(connection, False)) =
    connection_state.handle_stateless_reset_candidate(
      connection,
      <<1, 2, 3, 4, 5, 8:128>>,
      10,
    )
  let assert Ok(#(connection, True)) =
    connection_state.handle_stateless_reset_candidate(
      connection,
      <<1, 2, 3, 4, 5, reset_token:bits>>,
      10,
    )
  assert connection_state.phase(connection) == connection_state.Draining
  let #(_, events) = connection_state.take_events(connection)
  assert events == [connection_state.StatelessResetReceived]
}

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn confirms_recovery_tracked_pmtu_probes_and_handles_black_holes_test() -> Nil {
  let assert Ok(connection) = established(connection_state.Client)
  let assert Ok(connection) =
    connection_state.apply_tls_actions(connection, [
      engine.PeerTransportParameters([
        transport_parameter.MaxUdpPayloadSize(1400),
      ]),
    ])
  assert connection_state.path_mtu(connection) == 1200
  let assert Ok(#(connection, 1300)) =
    connection_state.start_pmtu_probe(connection)
  let assert Ok(connection) =
    connection_state.commit_packet(
      connection,
      engine.OneRtt,
      0,
      [frame.Ping, frame.Padding(1)],
      1300,
      ecn.NotEct,
      10,
    )
  let assert Ok(connection) =
    connection_state.receive_packet(
      connection,
      engine.OneRtt,
      0,
      [frame.Ack(frame.Acknowledgement(0, [frame.AckRange(0, 0)], None))],
      packet_space.NotEct,
      20,
    )
  assert connection_state.path_mtu(connection) == 1300
  let connection = connection_state.report_pmtu_black_hole(connection)
  assert connection_state.path_mtu(connection) == 1200
}

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn omitted_peer_udp_payload_parameter_uses_rfc_default_test() -> Nil {
  let config = connection_state.default_config(connection_state.Client)
  let assert Ok(connection) = connection_state.new(config, 0)
  let assert Ok(keys) = test_keys()
  let assert Ok(connection) =
    connection_state.apply_tls_actions(connection, [
      engine.InstallWriteKeys(engine.OneRtt, keys),
      engine.InstallReadKeys(engine.OneRtt, keys),
      engine.HandshakeComplete,
    ])
  assert connection_state.commit_packet(
      connection,
      engine.OneRtt,
      0,
      [frame.Ping],
      1300,
      ecn.NotEct,
      1,
    )
    |> result.is_ok
}

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn sends_stream_data_in_zero_rtt_and_requeues_it_on_rejection_test() -> Nil {
  let assert Ok(connection) =
    connection_state.new(
      connection_state.default_config(connection_state.Client),
      0,
    )
  let assert Ok(keys) = test_keys()
  let assert Ok(connection) =
    connection_state.apply_tls_actions(connection, [
      engine.PeerTransportParameters(peer_parameters()),
      engine.InstallWriteKeys(engine.ZeroRtt, keys),
    ])
  assert connection_state.can_send_early_data(connection)
  let assert Ok(#(connection, 0)) =
    connection_state.open_stream(connection, stream_id.Bidirectional)
  let assert Ok(connection) =
    connection_state.queue_stream(connection, 0, <<"early">>, True)
  let assert Ok(connection_state.PacketPrepared(
    connection,
    engine.ZeroRtt,
    0,
    [early_frame],
  )) = connection_state.prepare_packet(connection, engine.ZeroRtt, 1200, 1)
  assert early_frame == frame.Stream(0, 0, <<"early">>, True)
  let assert Ok(connection) =
    connection_state.commit_packet(
      connection,
      engine.ZeroRtt,
      0,
      [early_frame],
      100,
      ecn.NotEct,
      1,
    )
  assert connection_state.bytes_in_flight(connection) == 100
  assert connection_state.next_application_packet_number(connection) == 1

  let assert Ok(connection) =
    connection_state.apply_tls_actions(connection, [engine.EarlyDataRejected])
  assert connection_state.bytes_in_flight(connection) == 0
  assert connection_state.next_application_packet_number(connection) == 1
  assert !connection_state.can_send_early_data(connection)

  let assert Ok(connection) =
    connection_state.apply_tls_actions(connection, [
      engine.InstallWriteKeys(engine.OneRtt, keys),
      engine.InstallReadKeys(engine.OneRtt, keys),
      engine.HandshakeComplete,
    ])
  let assert Ok(connection_state.PacketPrepared(
    _,
    engine.OneRtt,
    1,
    [retransmitted],
  )) = connection_state.prepare_packet(connection, engine.OneRtt, 1200, 2)
  assert retransmitted == early_frame
}

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn queues_negotiated_datagrams_and_reports_tokens_distinctly_test() -> Nil {
  let assert Ok(connection) = established(connection_state.Client)
  let assert Ok(connection) =
    connection_state.apply_tls_actions(connection, [
      engine.PeerTransportParameters([
        transport_parameter.MaxDatagramFrameSize(4),
      ]),
    ])
  let assert Ok(connection) = connection_state.queue_datagram(connection, <<1>>)
  assert connection_state.queue_datagram(connection, <<1, 2, 3>>)
    == Error(connection_state.DatagramTooLarge(4))
  let assert Ok(connection_state.PacketPrepared(
    connection,
    engine.OneRtt,
    0,
    [frame.Datagram(<<1>>)],
  )) = connection_state.prepare_packet(connection, engine.OneRtt, 1200, 1)
  let assert Ok(connection) =
    connection_state.receive_packet(
      connection,
      engine.OneRtt,
      0,
      [frame.NewToken(<<9>>), frame.Datagram(<<2>>)],
      packet_space.NotEct,
      1,
    )
  let #(_, events) = connection_state.take_events(connection)
  assert events
    == [
      connection_state.PeerParametersApplied,
      connection_state.NewTokenReceived(<<9>>),
      connection_state.DatagramReceived(<<2>>),
    ]
}

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn only_established_servers_can_queue_bounded_new_tokens_test() -> Nil {
  let assert Ok(server) = established(connection_state.Server)
  let assert Ok(server) =
    connection_state.queue_new_token(server, <<"address-token":utf8>>)
  let assert Ok(connection_state.PacketPrepared(
    server,
    engine.OneRtt,
    0,
    [frame.HandshakeDone],
  )) = connection_state.prepare_packet(server, engine.OneRtt, 1200, 1)
  let assert Ok(connection_state.PacketPrepared(
    _,
    engine.OneRtt,
    0,
    [frame.NewToken(<<"address-token":utf8>>)],
  )) = connection_state.prepare_packet(server, engine.OneRtt, 1200, 1)

  let assert Ok(client) = established(connection_state.Client)
  assert connection_state.queue_new_token(client, <<"address-token":utf8>>)
    == Error(connection_state.ConnectionUnavailable)
  assert connection_state.queue_new_token(server, <<>>)
    == Error(connection_state.InvalidInput)
}

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn closes_idles_and_converges_deterministically_test() -> Nil {
  let assert Ok(connection) = established(connection_state.Client)
  let assert Ok(connection) =
    connection_state.close(connection, 0x100, "done", 10)
  assert connection_state.phase(connection) == connection_state.Closing
  let assert Ok(connection_state.PacketPrepared(
    connection,
    engine.OneRtt,
    0,
    [frame.ConnectionCloseApplication(0x100, "done")],
  )) = connection_state.prepare_packet(connection, engine.OneRtt, 1200, 10)
  let assert Ok(connection) = connection_state.tick(connection, 3010)
  assert connection_state.phase(connection) == connection_state.Closed

  let assert Ok(idle) =
    connection_state.new(
      connection_state.default_config(connection_state.Client),
      0,
    )
  assert connection_state.next_deadline(idle, 0) == Ok(Some(30_000))
  let assert Ok(idle) = connection_state.tick(idle, 30_000)
  assert connection_state.phase(idle) == connection_state.Closed
  assert connection_state.next_deadline(idle, 30_000) == Ok(None)
}

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn owns_tls_handshake_and_post_handshake_ticket_end_to_end_test() -> Nil {
  let #(client_config, server_config) = tls_configs()
  let assert Ok(client_step) = engine.start_client(client_config)
  let assert Ok(server_tls) = engine.start_server(server_config)

  let assert Ok(client) =
    connection_state.new(
      connection_state.default_config(connection_state.Client),
      0,
    )
  let assert Ok(client) =
    connection_state.install_initial_keys(
      client,
      initial_destination_connection_id,
    )
  let assert Ok(client) =
    connection_state.attach_client_tls(client, client_step)

  let assert Ok(server) =
    connection_state.new(
      connection_state.default_config(connection_state.Server),
      0,
    )
  let assert Ok(server) =
    connection_state.install_initial_keys(
      server,
      initial_destination_connection_id,
    )
  let assert Ok(server) = connection_state.attach_server_tls(server, server_tls)

  let assert Ok(connection_state.PacketPrepared(
    client,
    engine.Initial,
    _,
    client_initial_frames,
  )) = connection_state.prepare_packet(client, engine.Initial, 1200, 1)
  let assert Some(client_hello) = crypto_data(client_initial_frames)
  let assert Ok(server) =
    connection_state.receive_packet(
      server,
      engine.Initial,
      0,
      [frame.Crypto(0, client_hello)],
      packet_space.NotEct,
      1,
    )

  let assert Ok(connection_state.PacketPrepared(
    server,
    engine.Initial,
    _,
    server_initial_frames,
  )) = connection_state.prepare_packet(server, engine.Initial, 1200, 2)
  let assert Some(server_hello) = crypto_data(server_initial_frames)
  let assert Ok(client) =
    connection_state.receive_packet(
      client,
      engine.Initial,
      0,
      [frame.Crypto(0, server_hello)],
      packet_space.NotEct,
      2,
    )

  let assert Ok(connection_state.PacketPrepared(
    server,
    engine.Handshake,
    _,
    server_handshake_frames,
  )) = connection_state.prepare_packet(server, engine.Handshake, 65_000, 3)
  let assert Some(server_flight) = crypto_data(server_handshake_frames)
  let assert Ok(client) =
    connection_state.receive_packet(
      client,
      engine.Handshake,
      0,
      [frame.Crypto(0, server_flight)],
      packet_space.NotEct,
      3,
    )
  assert connection_state.phase(client) == connection_state.Established

  let assert Ok(connection_state.PacketPrepared(
    client,
    engine.Handshake,
    _,
    client_handshake_frames,
  )) = connection_state.prepare_packet(client, engine.Handshake, 1200, 4)
  let assert Some(client_finished) = crypto_data(client_handshake_frames)
  let assert Ok(server) =
    connection_state.receive_packet(
      server,
      engine.Handshake,
      0,
      [frame.Crypto(0, client_finished)],
      packet_space.NotEct,
      4,
    )
  assert connection_state.phase(server) == connection_state.Established

  let assert Ok(connection_state.PacketPrepared(
    server,
    engine.OneRtt,
    _,
    [frame.HandshakeDone],
  )) = connection_state.prepare_packet(server, engine.OneRtt, 1200, 5)

  let assert Ok(server) =
    connection_state.issue_session_ticket(server, <<7:256>>, 5, 60, True)
  let assert Ok(connection_state.PacketPrepared(
    _,
    engine.OneRtt,
    _,
    ticket_frames,
  )) = connection_state.prepare_packet(server, engine.OneRtt, 1200, 5)
  let assert Some(ticket) = crypto_data(ticket_frames)
  let assert Ok(client) =
    connection_state.receive_packet(
      client,
      engine.OneRtt,
      0,
      [frame.Crypto(0, ticket)],
      packet_space.NotEct,
      5,
    )
  let #(_, events) = connection_state.take_events(client)
  assert contains_session_ticket(events)
}

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn wakes_a_pacing_limited_connection_at_the_release_time_test() -> Nil {
  let #(connection, stream) = pacer_bound_connection()

  // Sending resumes until the pacer, not the congestion window, refuses.
  let #(connection, limited) = flush_datagrams(connection, 100, 32)
  let assert Error(connection_state.PacingLimited(release)) = limited
  assert release > 100
  let assert Ok(buffered) =
    connection_state.stream_buffered_send_bytes(connection, stream)
  assert buffered > 0

  // The owner must wake itself exactly when the pacer releases the next
  // packet, not at the far later idle or probe timeout.
  let assert Ok(Some(deadline)) =
    connection_state.next_deadline(connection, 100)
  assert deadline == release

  // The wake is only worth arming if flushing at it actually sends.
  let in_flight = connection_state.bytes_in_flight(connection)
  let #(connection, resumed) = flush_datagrams(connection, deadline, 1)
  assert resumed == Ok(Nil)
  assert connection_state.bytes_in_flight(connection) == in_flight + 1200
}

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn arms_the_pacing_wake_for_a_datagram_larger_than_the_last_test() -> Nil {
  let #(connection, _) = pacer_bound_connection()
  let #(connection, limited) = flush_datagrams(connection, 100, 32)
  let assert Error(connection_state.PacingLimited(release)) = limited

  // A short datagram spends less than the pacer refills, so the wake it arms
  // has to cover the next full-sized datagram rather than its own size.
  let #(connection, short) = flush_sized_datagrams(connection, 300, release, 1)
  assert short == Ok(Nil)
  let #(_, refused) = flush_datagrams(connection, release, 1)
  let assert Error(connection_state.PacingLimited(full_release)) = refused
  assert full_release > release

  let assert Ok(Some(deadline)) =
    connection_state.next_deadline(connection, release)
  assert deadline == full_release

  let in_flight = connection_state.bytes_in_flight(connection)
  let #(connection, resumed) = flush_datagrams(connection, deadline, 1)
  assert resumed == Ok(Nil)
  assert connection_state.bytes_in_flight(connection) == in_flight + 1200
}

/// Establish a connection whose congestion window outruns the pacer's burst,
/// with enough stream data queued to keep every flush send-limited by pacing.
fn pacer_bound_connection() -> #(connection_state.State, Int) {
  let assert Ok(connection) = established(connection_state.Client)
  let assert Ok(#(connection, stream)) =
    connection_state.open_stream(connection, stream_id.Bidirectional)
  let assert Ok(connection) =
    connection_state.queue_stream(
      connection,
      stream,
      <<0:size(64_000)-unit(8)>>,
      False,
    )

  // The initial burst and the initial congestion window are both ten
  // full-sized datagrams, so time zero releases exactly ten packets.
  let #(connection, opening_burst) = flush_datagrams(connection, 0, 10)
  assert opening_burst == Ok(Nil)
  assert connection_state.bytes_in_flight(connection) == 12_000

  // One round trip later the peer acknowledges the burst: the congestion
  // window grows well beyond one burst while the pacer refills at most one.
  let assert Ok(connection) =
    connection_state.record_datagram_received(connection, 80, 100)
  let assert Ok(connection) =
    connection_state.receive_packet(
      connection,
      engine.OneRtt,
      0,
      [frame.Ack(frame.Acknowledgement(0, [frame.AckRange(0, 9)], None))],
      packet_space.NotEct,
      100,
    )
  assert connection_state.bytes_in_flight(connection) == 0
  assert connection_state.congestion_window(connection) > 13_200
  #(connection, stream)
}

fn established(
  role: connection_state.Role,
) -> Result(connection_state.State, connection_state.Error) {
  let assert Ok(connection) =
    connection_state.new(connection_state.default_config(role), 0)
  let assert Ok(keys) = test_keys()
  let assert Ok(connection) =
    connection_state.apply_tls_actions(connection, [
      engine.InstallWriteKeys(engine.OneRtt, keys),
      engine.InstallReadKeys(engine.OneRtt, keys),
      engine.PeerTransportParameters(peer_parameters()),
      engine.HandshakeComplete,
    ])
  let #(connection, _) = connection_state.take_events(connection)
  Ok(connection)
}

fn peer_parameters() -> List(transport_parameter.Parameter) {
  [
    transport_parameter.InitialMaxData(1_048_576),
    transport_parameter.InitialMaxStreamDataBidiLocal(262_144),
    transport_parameter.InitialMaxStreamDataBidiRemote(262_144),
    transport_parameter.InitialMaxStreamDataUni(262_144),
    transport_parameter.InitialMaxStreamsBidi(100),
    transport_parameter.InitialMaxStreamsUni(100),
    transport_parameter.MaxUdpPayloadSize(65_527),
    transport_parameter.AckDelayExponent(3),
    transport_parameter.MaxAckDelay(25),
    transport_parameter.MaxDatagramFrameSize(65_535),
  ]
}

fn test_keys() -> Result(traffic_keys.TrafficKeys, traffic_keys.Error) {
  traffic_keys.from_secret(version.Version1, hello.Aes128GcmSha256, <<0:256>>)
}

fn tls_configs() -> #(engine.ClientConfig, engine.ServerConfig) {
  let assert Ok(ca_pem) = fixture("ca.pem")
  let assert Ok(server_pem) = fixture("server.pem")
  let assert Ok(key_pem) = fixture("server-key.pem")
  let assert Ok(trust_store) = authentication.trust_store_from_pem(ca_pem)
  let assert Ok(chain) = authentication.certificate_chain_from_pem(server_pem)
  let assert Ok(signing_key) = authentication.signing_key_from_pem(key_pem)
  #(
    engine.ClientConfig(
      version: version.Version1,
      hostname: "localhost",
      application_protocols: [<<"h3">>],
      transport_parameters: [
        transport_parameter.InitialSourceConnectionId(<<1>>),
        transport_parameter.MaxUdpPayloadSize(1200),
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
        transport_parameter.OriginalDestinationConnectionId(<<9>>),
        transport_parameter.InitialSourceConnectionId(<<2>>),
        transport_parameter.MaxUdpPayloadSize(1200),
        transport_parameter.MaxDatagramFrameSize(1200),
      ],
      certificate_chain: chain,
      signing_key: signing_key,
      signature_scheme: extension_value.Ed25519,
      alternative_credentials: [],
      client_authentication: engine.ClientAuthenticationDisabled,
    ),
  )
}

fn crypto_data(frames: List(frame.Frame)) -> Option(BitArray) {
  case frames {
    [] -> None
    [frame.Crypto(_, data), ..] -> Some(data)
    [_, ..rest] -> crypto_data(rest)
  }
}

fn contains_session_ticket(events: List(connection_state.Event)) -> Bool {
  case events {
    [] -> False
    [connection_state.SessionTicketStored(_), ..] -> True
    [_, ..rest] -> contains_session_ticket(rest)
  }
}

fn list_contains_ack(frames: List(frame.Frame)) -> Bool {
  case frames {
    [] -> False
    [frame.Ack(_), ..] -> True
    [_, ..rest] -> list_contains_ack(rest)
  }
}

fn contains_max_streams(
  frames: List(frame.Frame),
  direction: frame.StreamDirection,
  maximum: Int,
) -> Bool {
  case frames {
    [] -> False
    [frame.MaxStreams(value_direction, value), ..]
      if value_direction == direction && value == maximum
    -> True
    [_, ..rest] -> contains_max_streams(rest, direction, maximum)
  }
}

fn flush_datagrams(
  connection: connection_state.State,
  now_milliseconds: Int,
  budget: Int,
) -> #(connection_state.State, Result(Nil, connection_state.Error)) {
  flush_sized_datagrams(connection, 1200, now_milliseconds, budget)
}

fn flush_sized_datagrams(
  connection: connection_state.State,
  datagram_bytes: Int,
  now_milliseconds: Int,
  budget: Int,
) -> #(connection_state.State, Result(Nil, connection_state.Error)) {
  case budget <= 0 {
    True -> #(connection, Ok(Nil))
    False ->
      case
        connection_state.prepare_packet(
          connection,
          engine.OneRtt,
          datagram_bytes,
          now_milliseconds,
        )
      {
        Ok(connection_state.PacketPrepared(prepared, _, number, frames)) ->
          case
            connection_state.validate_send_budget(
              prepared,
              frames,
              datagram_bytes,
              now_milliseconds,
            )
          {
            Error(reason) -> #(connection, Error(reason))
            Ok(Nil) -> {
              let assert Ok(sent) =
                connection_state.commit_packet(
                  prepared,
                  engine.OneRtt,
                  number,
                  frames,
                  datagram_bytes,
                  ecn.Ect0,
                  now_milliseconds,
                )
              flush_sized_datagrams(
                sent,
                datagram_bytes,
                now_milliseconds,
                budget - 1,
              )
            }
          }
        _ -> #(connection, Ok(Nil))
      }
  }
}

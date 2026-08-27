import gleam/bit_array
import gleam/list
import gleam/option.{type Option, None, Some}
import gleam/result
import gleam/string
import gleam_quic/frame
import gleam_quic/internal/connection_state
import gleam_quic/internal/ecn
import gleam_quic/internal/key_phase
import gleam_quic/internal/packet_space
import gleam_quic/internal/runtime/budget
import gleam_quic/internal/tls/authentication
import gleam_quic/internal/tls/engine
import gleam_quic/internal/tls/extension_value
import gleam_quic/internal/tls/hello
import gleam_quic/internal/traffic_keys
import gleam_quic/internal/wire_packet
import gleam_quic/stream_id
import gleam_quic/transport_parameter
import gleam_quic/varint
import gleam_quic/version

@external(erlang, "gleam_quic_test_ffi", "fixture")
fn fixture(name: String) -> Result(BitArray, Nil)

const initial_destination_connection_id = <<1, 2, 3, 4, 5, 6, 7, 8>>

/// RFC 9000 section 17.2: twenty bytes is the longest connection ID version 1
/// allows, and therefore the largest short header a packet can carry.
const maximum_destination_connection_id = <<
  1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20,
>>

/// A packet number far enough above the largest acknowledged one to force the
/// four-byte encoding. Together with a twenty-byte destination connection ID
/// it is the widest short header QUIC version 1 can put on a packet.
const widest_packet_number = 16_777_216

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
pub fn ignores_a_new_token_no_initial_can_repeat_test() -> Nil {
  // A NEW_TOKEN is only worth keeping if a later connection can repeat it in
  // an Initial that still fits the 1200-byte floor. The server chooses the
  // width, so one past that budget is dropped on arrival rather than stored
  // and refused at the start of the next connection.
  let budget = connection_state.maximum_initial_token_bytes()
  let assert Ok(connection) = established(connection_state.Client)
  let assert Ok(connection) =
    connection_state.receive_packet(
      connection,
      engine.OneRtt,
      0,
      [frame.NewToken(<<0:size(budget + 1)-unit(8)>>)],
      packet_space.NotEct,
      1,
    )
  let #(connection, events) = connection_state.take_events(connection)
  assert events == []

  // The widest token an Initial can still repeat is kept.
  let usable = <<0:size(budget)-unit(8)>>
  let assert Ok(connection) =
    connection_state.receive_packet(
      connection,
      engine.OneRtt,
      1,
      [frame.NewToken(usable)],
      packet_space.NotEct,
      2,
    )
  let #(_, events) = connection_state.take_events(connection)
  assert events == [connection_state.NewTokenReceived(usable)]
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

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn rearms_the_pacing_wake_after_the_window_shrinks_test() -> Nil {
  // A long round trip puts the pacing release far enough ahead that a
  // congestion event can land between the refusal and the wake.
  let #(connection, _) = pacer_bound_connection_after(1000)
  let #(connection, limited) = flush_datagrams(connection, 1000, 32)
  let assert Error(connection_state.PacingLimited(early_release)) = limited
  assert early_release > 1000
  let assert Ok(Some(armed)) = connection_state.next_deadline(connection, 1000)
  assert armed == early_release

  // The peer acknowledges only the last of the ten packets just sent, so the
  // seven below the reordering threshold are declared lost and the congestion
  // window halves: the pacer now refills at half the rate the refusal assumed.
  let window = connection_state.congestion_window(connection)
  let assert Ok(connection) =
    connection_state.record_datagram_received(connection, 80, 1010)
  let assert Ok(connection) =
    connection_state.receive_packet(
      connection,
      engine.OneRtt,
      1,
      [frame.Ack(frame.Acknowledgement(0, [frame.AckRange(19, 19)], None))],
      packet_space.NotEct,
      1010,
    )
  assert connection_state.congestion_window(connection) < window

  // At the release the earlier refusal named, the pacer still refuses, and it
  // names a strictly later one.
  let #(connection, refused) = flush_datagrams(connection, early_release, 1)
  let assert Error(connection_state.PacingLimited(release)) = refused
  assert release > early_release

  // The owner must wake at the release the pacer would honour now, not fall
  // back to the far later recovery or idle deadline.
  let assert Ok(Some(deadline)) =
    connection_state.next_deadline(connection, early_release)
  assert deadline == release

  let in_flight = connection_state.bytes_in_flight(connection)
  let #(connection, resumed) = flush_datagrams(connection, deadline, 1)
  assert resumed == Ok(Nil)
  assert connection_state.bytes_in_flight(connection) == in_flight + 1200
}

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn skips_the_pacing_wake_without_pending_output_test() -> Nil {
  let assert Ok(connection) = established(connection_state.Client)
  let assert Ok(#(connection, stream)) =
    connection_state.open_stream(connection, stream_id.Bidirectional)
  let assert Ok(connection) =
    connection_state.queue_stream(
      connection,
      stream,
      <<0:size(11_000)-unit(8)>>,
      True,
    )

  // The opening burst is ten datagrams wide and carries more than the queued
  // bytes, so it takes every one of them and the FIN while spending the
  // pacer's tokens. The connection is left with bytes in flight and nothing a
  // stream poll would emit. Those unacknowledged bytes are still counted as
  // buffered, which is exactly why a byte count cannot stand in for pending
  // output.
  let #(connection, drained) = flush_datagrams(connection, 0, 10)
  assert drained == Ok(Nil)
  assert connection_state.stream_buffered_send_bytes(connection, stream)
    == Ok(11_000)

  // The pacer really is refusing at this instant: the same state with one byte
  // queued on a second stream arms the release the pacer owes.
  let assert Ok(#(waiting, other)) =
    connection_state.open_stream(connection, stream_id.Bidirectional)
  let assert Ok(waiting) =
    connection_state.queue_stream(waiting, other, <<0>>, False)
  let assert Ok(Some(release)) = connection_state.next_deadline(waiting, 0)
  assert release > 0

  // With nothing to send, no pacing wake is armed at all: the owner is left
  // with the far later deadline the burst in flight already owes it.
  let assert Ok(Some(deadline)) = connection_state.next_deadline(connection, 0)
  assert deadline > release
}

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn sizes_stream_frames_from_the_validated_path_mtu_test() -> Nil {
  let connection = validated_path_connection()

  let assert Ok(#(connection, stream)) =
    connection_state.open_stream(connection, stream_id.Bidirectional)
  let assert Ok(connection) =
    connection_state.queue_stream(
      connection,
      stream,
      <<0:size(64_000)-unit(8)>>,
      False,
    )

  // The send path asks for the pre-validation floor, but the validated path is
  // what one datagram carries: a 9000-byte path has to place close to 9000
  // bytes of stream data in the packet rather than the floor's 1200.
  let assert Ok(connection_state.PacketPrepared(
    _,
    engine.OneRtt,
    _,
    [frame.Stream(0, 0, data, False)],
  )) = connection_state.prepare_packet(connection, engine.OneRtt, 1200, 30)
  assert bit_array.byte_size(data) > 8000
}

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn paces_datagrams_the_validated_path_carries_test() -> Nil {
  // The pacer-bound fixture leaves a congestion window wide enough for one
  // path-sized datagram and stream data still queued behind it.
  let #(connection, _) = pacer_bound_connection()
  let assert Ok(connection) =
    connection_state.apply_tls_actions(connection, [
      engine.PeerTransportParameters([
        transport_parameter.MaxUdpPayloadSize(31_567),
      ]),
    ])
  let assert Ok(#(connection, 16_384)) =
    connection_state.start_pmtu_probe(connection)
  let number = connection_state.next_application_packet_number(connection)

  // The pacer's burst has to scale with the path. Fixed at ten 1200-byte
  // datagrams it cannot hold one 16_384-byte datagram at all, so the pacer
  // refuses the reservation as invalid input rather than releasing or delaying
  // it: neither the probe that proves the path nor any datagram sized from it
  // can be sent, and the pacing wake `next_deadline` asks about for a
  // path-sized datagram is dropped for exactly the same reason.
  let probed =
    connection_state.commit_packet(
      connection,
      engine.OneRtt,
      number,
      [frame.Ping, frame.Padding(1)],
      16_384,
      ecn.NotEct,
      100,
    )
  assert probed |> result.map(connection_state.bytes_in_flight) == Ok(16_384)

  let assert Ok(connection) = probed
  let assert Ok(connection) =
    connection_state.receive_packet(
      connection,
      engine.OneRtt,
      1,
      [
        frame.Ack(frame.Acknowledgement(
          0,
          [frame.AckRange(number, number)],
          None,
        )),
      ],
      packet_space.NotEct,
      200,
    )
  assert connection_state.path_mtu(connection) == 16_384

  // A datagram sized from the validated path is now ordinary output, so the
  // send budget has to admit it instead of rejecting it out of hand.
  let assert Ok(connection_state.PacketPrepared(prepared, _, _, frames)) =
    connection_state.prepare_packet(connection, engine.OneRtt, 16_384, 210)
  assert connection_state.validate_send_budget(
      prepared,
      engine.OneRtt,
      frames,
      16_384,
      210,
    )
    == Ok(Nil)
}

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn floors_the_congestion_window_at_the_validated_path_test() -> Nil {
  // DPLPMTUD has proved the path carries 9000-byte datagrams, so that is the
  // size ordinary output is now built at.
  let connection = validated_path_connection()

  // Two congestion events, each halving the window: the peer acknowledges only
  // the newest packet of a flight, so every packet below the reordering
  // threshold is declared lost.
  let connection = loses_a_flight(connection, 1, 1, 30)
  let connection = loses_a_flight(connection, 11, 2, 60)

  // RFC 9002 section 7.2 floors the window at two maximum-sized datagrams. A
  // controller still holding the 1200-byte pre-validation size floors it at
  // 2400 - less than the single datagram this path carries - so path-sized
  // output and the DPLPMTUD probes that keep the path confirmed both stall
  // until the window regrows. The controller's maximum datagram size has to
  // follow the validated path.
  assert connection_state.congestion_window(connection) >= 18_000
  assert connection_state.validate_send_budget(
      connection,
      engine.OneRtt,
      [frame.Ping],
      9000,
      70,
    )
    == Ok(Nil)
}

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn full_recovery_ledger_backpressures_before_transmission_test() -> Nil {
  let config =
    connection_state.Config(
      ..connection_state.default_config(connection_state.Client),
      maximum_outstanding_packets: 1,
      path_dont_fragment: True,
    )
  let assert Ok(connection) = established_with_config(config)
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

  // The next ack-eliciting packet must remain queued until the peer frees a
  // ledger entry. This refusal happens during preflight, before the caller
  // hands the datagram to UDP.
  assert connection_state.validate_send_budget(
      connection,
      engine.OneRtt,
      [frame.Ping],
      100,
      1000,
    )
    == Error(connection_state.RecoveryLimited)

  // ACK-only output is not retained, so it remains available to make the
  // progress that can free the peer's own recovery state.
  assert connection_state.validate_send_budget(
      connection,
      engine.OneRtt,
      [frame.Ack(frame.Acknowledgement(0, [frame.AckRange(0, 0)], None))],
      100,
      1000,
    )
    == Ok(Nil)

  let assert Ok(connection) =
    connection_state.receive_packet(
      connection,
      engine.OneRtt,
      0,
      [frame.Ack(frame.Acknowledgement(0, [frame.AckRange(0, 0)], None))],
      packet_space.NotEct,
      1000,
    )
  assert connection_state.validate_send_budget(
      connection,
      engine.OneRtt,
      [frame.Ping],
      100,
      1000,
    )
    == Ok(Nil)
}

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn sizes_a_switched_controller_from_the_validated_path_test() -> Nil {
  let connection = validated_path_connection()

  // A controller installed mid-connection starts on the path this connection
  // is sending on, not on the configured max_udp_payload_size ceiling: ten
  // 9000-byte datagrams bound the window it opens with.
  let assert Ok(connection) =
    connection_state.set_congestion_algorithm(
      connection,
      connection_state.Cubic,
    )
  assert connection_state.congestion_window(connection) == 18_000

  // And its reductions keep RFC 9002 section 7.2's floor of two path-sized
  // datagrams.
  let connection = loses_a_flight(connection, 1, 1, 30)
  assert connection_state.congestion_window(connection) >= 18_000
}

/// Commit a flight of ten small packets and let the peer acknowledge only the
/// newest, so every packet below the reordering threshold is declared lost and
/// the congestion window halves once.
fn loses_a_flight(
  connection: connection_state.State,
  first_packet_number: Int,
  peer_packet_number: Int,
  now_milliseconds: Int,
) -> connection_state.State {
  let newest = first_packet_number + 9
  let connection =
    commits_small_packets(connection, first_packet_number, 10, now_milliseconds)
  let assert Ok(connection) =
    acknowledges_application_packets(
      connection,
      peer_packet_number,
      frame.AckRange(newest, newest),
      now_milliseconds + 10,
    )
  connection
}

/// Commit `count` consecutive 100-byte ack-eliciting packets at one instant.
fn commits_small_packets(
  connection: connection_state.State,
  packet_number: Int,
  count: Int,
  now_milliseconds: Int,
) -> connection_state.State {
  case count <= 0 {
    True -> connection
    False -> {
      let assert Ok(connection) =
        connection_state.commit_packet(
          connection,
          engine.OneRtt,
          packet_number,
          [frame.Ping],
          100,
          ecn.NotEct,
          now_milliseconds,
        )
      commits_small_packets(
        connection,
        packet_number + 1,
        count - 1,
        now_milliseconds,
      )
    }
  }
}

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn keeps_a_coalesced_ack_inside_the_validated_path_test() -> Nil {
  let connection = validated_path_connection()

  // A peer that drops or reorders alternate packet numbers keeps the full
  // retained range set alive, and every retained range costs two more varints
  // in the ACK this packet coalesces ahead of its stream data.
  let connection = receives_alternate_packets(connection, 256)
  let assert Ok(#(connection, stream)) =
    connection_state.open_stream(connection, stream_id.Bidirectional)
  let assert Ok(connection) =
    connection_state.queue_stream(
      connection,
      stream,
      <<0:size(64_000)-unit(8)>>,
      False,
    )

  let assert Ok(connection_state.PacketPrepared(prepared, _, number, frames)) =
    connection_state.prepare_packet(connection, engine.OneRtt, 1000, 40)
  let assert [frame.Ack(frame.Acknowledgement(_, ranges, _)), frame.Stream(..)] =
    frames
  assert list.length(ranges) == 256

  // The whole datagram - ACK, stream frame, header, and AEAD tag - still fits
  // the path DPLPMTUD validated, which is never above the peer's advertised
  // max_udp_payload_size. The header is sized by the peer's destination
  // connection ID, so the longest one QUIC version 1 allows has to fit too.
  assert protected_datagram_bytes(
      prepared,
      initial_destination_connection_id,
      number,
      frames,
    )
    <= connection_state.path_mtu(prepared)
  assert protected_datagram_bytes(
      prepared,
      maximum_destination_connection_id,
      widest_packet_number,
      frames,
    )
    <= connection_state.path_mtu(prepared)

  // Stream data is budgeted against the widest header a STREAM frame can
  // write, which leaves slack the bound above cannot see: it stays satisfied
  // even when the header cost is guessed several bytes low. A QUIC DATAGRAM
  // frame is sized to the byte, so one queued with no acknowledgement owed
  // fills the path exactly and pins that cost.
  let filled = queues_a_full_datagram(validated_path_connection())
  let assert Ok(connection_state.PacketPrepared(filled, _, _, datagram_frames)) =
    connection_state.prepare_packet(filled, engine.OneRtt, 1000, 40)
  let bytes =
    protected_datagram_bytes(
      filled,
      maximum_destination_connection_id,
      widest_packet_number,
      datagram_frames,
    )
  assert bytes <= connection_state.path_mtu(filled)
  assert bytes >= connection_state.path_mtu(filled) - 8
}

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn keeps_the_path_at_the_floor_by_default_test() -> Nil {
  // The default configuration says nothing about the socket it will be sent
  // on, so it assumes the Don't-Fragment option is absent and stays on the
  // 1200-byte floor. Every runtime passes the option its socket actually got;
  // a connection built without that answer never grows a path it cannot prove.
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
      engine.PeerTransportParameters(peer_parameters()),
      engine.HandshakeComplete,
    ])
  let #(connection, _) = connection_state.take_events(connection)
  assert connection_state.path_mtu(connection) == 1200

  let floored = case connection_state.start_pmtu_probe(connection) {
    // nolint: thrown_away_error -- refusing to probe is one correct answer.
    Error(_) -> connection
    Ok(#(probing, size)) -> acknowledges_probe(probing, size)
  }
  assert connection_state.path_mtu(floored) == 1200
}

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn keeps_the_path_at_the_floor_without_dont_fragment_test() -> Nil {
  // A socket the kernel would not give the Don't-Fragment option to can have
  // an oversized probe fragmented locally, delivered, and acknowledged. RFC
  // 8899 section 3 lets an acknowledged probe raise the path only when it
  // could not have been fragmented, so a connection told the flag is inactive
  // stays on the 1200-byte floor however large a probe the peer acknowledges.
  let assert Ok(connection) =
    connection_state.new(
      connection_state.Config(
        ..connection_state.default_config(connection_state.Client),
        path_dont_fragment: False,
      ),
      0,
    )
  let assert Ok(keys) = test_keys()
  let assert Ok(connection) =
    connection_state.apply_tls_actions(connection, [
      engine.InstallWriteKeys(engine.OneRtt, keys),
      engine.InstallReadKeys(engine.OneRtt, keys),
      engine.PeerTransportParameters(peer_parameters()),
      engine.HandshakeComplete,
    ])
  let #(connection, _) = connection_state.take_events(connection)
  assert connection_state.path_mtu(connection) == 1200

  // Either no probe is scheduled at all, or one is scheduled and its
  // acknowledgement proves nothing. Both leave the path on the floor.
  let floored = case connection_state.start_pmtu_probe(connection) {
    // nolint: thrown_away_error -- refusing to probe is one correct answer.
    Error(_) -> connection
    Ok(#(probing, size)) -> acknowledges_probe(probing, size)
  }
  assert connection_state.path_mtu(floored) == 1200
}

/// Commit one padded `size`-byte probe and have the peer acknowledge it.
fn acknowledges_probe(
  connection: connection_state.State,
  size: Int,
) -> connection_state.State {
  let number = connection_state.next_application_packet_number(connection)
  let assert Ok(connection) =
    connection_state.commit_packet(
      connection,
      engine.OneRtt,
      number,
      [frame.Ping, frame.Padding(1)],
      size,
      ecn.NotEct,
      10,
    )
  let assert Ok(connection) =
    connection_state.receive_packet(
      connection,
      engine.OneRtt,
      0,
      [
        frame.Ack(frame.Acknowledgement(
          0,
          [frame.AckRange(number, number)],
          None,
        )),
      ],
      packet_space.NotEct,
      20,
    )
  connection
}

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn keeps_a_handshake_packet_inside_the_smallest_path_test() -> Nil {
  let assert Ok(keys) = test_keys()
  let assert Ok(connection) =
    connection_state.new(
      connection_state.default_config(connection_state.Client),
      0,
    )
  let assert Ok(connection) =
    connection_state.apply_tls_actions(connection, [
      engine.InstallWriteKeys(engine.Handshake, keys),
      engine.Send(engine.Handshake, <<0:size(1500)-unit(8)>>),
    ])

  // Nothing has been validated above the 1200-byte floor every path carries,
  // and RFC 9000 section 14.1 lets no datagram exceed it before it has.
  assert connection_state.path_mtu(connection) == 1200

  // The caller asks for the whole flight in one packet. A long-header packet
  // is built from the same queue as every other level, so the budget has to be
  // measured against the path rather than trusted.
  let assert Ok(connection_state.PacketPrepared(prepared, _, number, frames)) =
    connection_state.prepare_packet(connection, engine.Handshake, 65_000, 1)
  let assert Ok(packet) =
    connection_state.protect_long_packet(
      prepared,
      wire_packet.Handshake,
      maximum_destination_connection_id,
      maximum_destination_connection_id,
      number,
      frames,
    )
  assert bit_array.byte_size(packet) <= connection_state.path_mtu(prepared)
}

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn keeps_an_acknowledgement_only_packet_inside_the_smallest_path_test() -> Nil {
  let assert Ok(connection) = established(connection_state.Client)
  assert connection_state.path_mtu(connection) == 1200

  // A peer that drops every other block of packet numbers keeps the full
  // retained range set alive, and a widely scattered set makes every gap
  // varint four bytes. The acknowledgement alone then outgrows the floor,
  // and an ACK-only packet carries no other frame for the send path to
  // measure it beside.
  let connection = receives_scattered_packets(connection, 256)
  let assert Ok(connection_state.PacketPrepared(prepared, _, _, frames)) =
    connection_state.prepare_packet(connection, engine.OneRtt, 1000, 40)
  let assert [frame.Ack(frame.Acknowledgement(_, ranges, _))] = frames

  // RFC 9000 section 13.2.4 lets an acknowledgement carry a subset of the
  // ranges its sender retains. All 256 do not fit the floor, so the oldest
  // stay retained for a later packet while the newest - the ones the peer's
  // loss detection needs - go out now, largest received packet number first.
  assert list.length(ranges) < 256
  assert list.length(ranges) > 200
  let assert [frame.AckRange(_, largest), ..] = ranges
  assert largest == 256 * 1_048_576
  assert protected_datagram_bytes(
      prepared,
      maximum_destination_connection_id,
      widest_packet_number,
      frames,
    )
    <= connection_state.path_mtu(prepared)
}

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn keeps_an_initial_packet_with_a_token_inside_the_smallest_path_test() -> Nil {
  // A server-issued address-validation token rides in every Initial its
  // client sends (RFC 9000 section 8.1.2), on top of the long header and the
  // AEAD tag. It is the one part of a packet's overhead the peer chooses, so
  // it is the part a budget computed without it under-counts by.
  let token = <<0:size(700)-unit(8)>>
  let assert Ok(connection) =
    connection_state.new(
      connection_state.default_config(connection_state.Client),
      0,
    )
  let assert Ok(connection) =
    connection_state.install_initial_keys(
      connection,
      initial_destination_connection_id,
    )
  let assert Ok(connection) =
    connection_state.apply_tls_actions(connection, [
      engine.Send(engine.Initial, <<0:size(1500)-unit(8)>>),
    ])
  let connection =
    connection_state.set_initial_token_bytes(
      connection,
      bit_array.byte_size(token),
    )
  assert connection_state.path_mtu(connection) == 1200

  let assert Ok(connection_state.PacketPrepared(prepared, _, number, frames)) =
    connection_state.prepare_packet(connection, engine.Initial, 1000, 1)
  let assert Ok(packet) =
    connection_state.protect_long_packet(
      prepared,
      wire_packet.Initial(token),
      maximum_destination_connection_id,
      maximum_destination_connection_id,
      number,
      frames,
    )

  // The handshake still advances: the token narrows the payload rather than
  // silencing the packet.
  let assert Some(_) = crypto_data(frames)
  assert bit_array.byte_size(packet) <= connection_state.path_mtu(prepared)
}

/// Receive `count` ack-eliciting packets spaced far enough apart that every
/// retained range encodes its gap as a four-byte varint.
fn receives_scattered_packets(
  connection: connection_state.State,
  count: Int,
) -> connection_state.State {
  list.index_fold(list.repeat(Nil, count), connection, fn(connection, _, index) {
    let assert Ok(connection) =
      connection_state.receive_packet(
        connection,
        engine.OneRtt,
        { index + 1 } * 1_048_576,
        [frame.Ping],
        packet_space.NotEct,
        30,
      )
    connection
  })
}

/// Protect one 1-RTT packet and report the size of the datagram that goes on
/// the wire, header protection and AEAD tag included.
fn protected_datagram_bytes(
  connection: connection_state.State,
  destination_connection_id: BitArray,
  packet_number: Int,
  frames: List(frame.Frame),
) -> Int {
  let assert Ok(#(_, datagram)) =
    connection_state.protect_short_packet(
      connection,
      destination_connection_id,
      packet_number,
      False,
      frames,
      40,
    )
  bit_array.byte_size(datagram)
}

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn decodes_a_path_sized_packet_past_the_default_frame_budget_test() -> Nil {
  let assert Ok(sender) = established(connection_state.Client)
  let assert Ok(receiver) = established(connection_state.Server)

  // PADDING costs one decoding unit per byte, so a DPLPMTUD probe blows the
  // 4096-unit default long before its two frames are decoded.
  let receiver =
    receives_short_packet(sender, receiver, 0, [frame.Ping, frame.Padding(8000)])

  // The relaxation is one unit per packet byte, not per frame, so it also has
  // to admit a packet whose bytes are all distinct frames. No frame encodes in
  // less than one byte, so this is the tightest bound that admits both.
  let receiver =
    receives_short_packet(sender, receiver, 1, list.repeat(frame.Ping, 8000))

  // Both packets were decoded and both are ack-eliciting, so the receiver owes
  // one acknowledgement covering the pair.
  let assert Ok(connection_state.PacketPrepared(_, _, _, frames)) =
    connection_state.prepare_packet(receiver, engine.OneRtt, 1000, 2)
  let assert [frame.Ack(frame.Acknowledgement(_, ranges, _)), ..] = frames
  assert ranges == [frame.AckRange(0, 1)]
}

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn bounds_long_header_frames_at_the_default_budget_test() -> Nil {
  let assert Ok(keys) = test_keys()
  let assert Ok(client) =
    connection_state.new(
      connection_state.default_config(connection_state.Client),
      0,
    )
  let assert Ok(client) =
    connection_state.apply_tls_actions(client, [
      engine.InstallWriteKeys(engine.Handshake, keys),
      engine.InstallReadKeys(engine.Handshake, keys),
    ])
  let assert Ok(server) =
    connection_state.new(
      connection_state.default_config(connection_state.Server),
      0,
    )
  let assert Ok(server) =
    connection_state.apply_tls_actions(server, [
      engine.InstallWriteKeys(engine.Handshake, keys),
      engine.InstallReadKeys(engine.Handshake, keys),
    ])

  // A long-header packet is unauthenticated work: Initial keys are derivable
  // from a connection ID any off-path sender can observe, and the same decode
  // path serves Handshake and 0-RTT. Advertising a large max_udp_payload_size
  // must not let one buy more decoding than the fixed default budget, however
  // many frames its plaintext holds.
  let assert Ok(packet) =
    connection_state.protect_long_packet(
      client,
      wire_packet.Handshake,
      initial_destination_connection_id,
      <<9, 10, 11, 12>>,
      0,
      list.repeat(frame.Ping, 4097),
    )
  assert connection_state.receive_protected_long_packet(
      server,
      packet,
      packet_space.NotEct,
      1,
    )
    == Error(connection_state.FrameCodecFailure(frame.FrameLimitExceeded(4096)))
}

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn keeps_acknowledging_behind_a_full_datagram_queue_test() -> Nil {
  let connection = validated_path_connection()

  // A peer sending a steady ack-eliciting stream on alternate packet numbers
  // keeps the full retained range set alive, so the acknowledgement owed here
  // is as large as this endpoint ever builds.
  let connection = receives_alternate_packets(connection, 256)

  // The application writes back-to-back datagrams sized by the public
  // `maximum_datagram_data_size`. A QUIC DATAGRAM frame cannot be split (RFC
  // 9221 section 3), so if it were sized without room for that acknowledgement
  // no ACK could leave this endpoint until the queue drained - unbounded delay
  // where RFC 9000 section 13.2.1 allows max_ack_delay, and spurious probe
  // timeouts at the peer.
  let connection = queues_a_full_datagram(connection)
  let connection = queues_a_full_datagram(connection)

  let assert Ok(connection_state.PacketPrepared(prepared, _, _, frames)) =
    connection_state.prepare_packet(connection, engine.OneRtt, 1000, 40)
  let assert [frame.Ack(_), frame.Datagram(_)] = frames

  // Both fit, and the finished datagram still fits the path with the widest
  // short header QUIC version 1 allows.
  assert protected_datagram_bytes(
      prepared,
      maximum_destination_connection_id,
      widest_packet_number,
      frames,
    )
    <= connection_state.path_mtu(prepared)

  // The second datagram follows immediately rather than being displaced by the
  // acknowledgement that shared the first packet.
  let assert Ok(connection_state.PacketPrepared(_, _, _, [frame.Datagram(_)])) =
    connection_state.prepare_packet(prepared, engine.OneRtt, 1000, 40)
  Nil
}

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn sends_an_acknowledgement_a_queued_datagram_crowds_out_test() -> Nil {
  let connection = validated_path_connection()

  // No acknowledgement is scheduled yet, so this datagram is sized to fill the
  // path exactly.
  let connection = queues_a_full_datagram(connection)

  // The peer's traffic arrives after that frame was built, so the
  // acknowledgement now due no longer fits beside it. The indivisible datagram
  // is the one that waits: an acknowledgement withheld until an application
  // queue drains has no bound at all, where RFC 9000 section 13.2.1 allows
  // max_ack_delay.
  let connection = receives_alternate_packets(connection, 4)
  let assert Ok(connection_state.PacketPrepared(prepared, _, _, frames)) =
    connection_state.prepare_packet(connection, engine.OneRtt, 1000, 40)
  let assert [frame.Ack(_)] = frames

  // The datagram is delayed by one packet, not dropped.
  let assert Ok(connection_state.PacketPrepared(_, _, _, [frame.Datagram(_)])) =
    connection_state.prepare_packet(prepared, engine.OneRtt, 1000, 40)
  Nil
}

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn keeps_an_early_datagram_inside_the_pre_validation_floor_test() -> Nil {
  let connection = zero_rtt_connection()

  // A 0-RTT datagram rides a long header - version, both connection IDs, and a
  // length field - which is far wider than the short header an established
  // connection writes. Sizing it against the short header puts it past the
  // 1200-byte floor every path is required to carry.
  let connection = queues_a_full_datagram(connection)
  let assert Ok(connection_state.PacketPrepared(prepared, _, _, frames)) =
    connection_state.prepare_packet(connection, engine.ZeroRtt, 1200, 10)
  let assert [frame.Datagram(_)] = frames
  let assert Ok(packet) =
    connection_state.protect_long_packet(
      prepared,
      wire_packet.ZeroRtt,
      maximum_destination_connection_id,
      maximum_destination_connection_id,
      widest_packet_number,
      frames,
    )
  assert bit_array.byte_size(packet) <= connection_state.path_mtu(prepared)
}

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn bounds_a_close_reason_to_the_smallest_path_test() -> Nil {
  let assert Ok(connection) = established(connection_state.Client)

  // CONNECTION_CLOSE cannot be split and cannot be dropped, so a caller's
  // reason phrase has to be bounded where it enters the connection rather than
  // becoming an oversized datagram on the 1200-byte floor.
  let assert Ok(connection) =
    connection_state.close(connection, 7, string.repeat("reason ", 1000), 10)
  let assert Ok(connection_state.PacketPrepared(prepared, _, _, frames)) =
    connection_state.prepare_packet(connection, engine.OneRtt, 1000, 10)
  let assert [frame.ConnectionCloseApplication(7, reason)] = frames
  assert string.starts_with(reason, "reason ")
  assert protected_datagram_bytes(
      prepared,
      maximum_destination_connection_id,
      widest_packet_number,
      frames,
    )
    <= connection_state.path_mtu(prepared)
}

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn bounds_a_new_token_to_the_smallest_path_test() -> Nil {
  let assert Ok(server) = established(connection_state.Server)

  // NEW_TOKEN is indivisible and reliable, so a token too large for the
  // 1200-byte floor is refused at the door instead of being emitted as an
  // oversized datagram once a black hole resets the path.
  assert connection_state.queue_new_token(server, <<0:size(1200)-unit(8)>>)
    == Error(connection_state.InvalidInput)

  let assert Ok(server) =
    connection_state.queue_new_token(server, <<0:size(1024)-unit(8)>>)

  // HANDSHAKE_DONE was queued when the handshake completed and leaves in the
  // packet ahead of the token.
  let assert Ok(connection_state.PacketPrepared(
    server,
    _,
    _,
    [frame.HandshakeDone],
  )) = connection_state.prepare_packet(server, engine.OneRtt, 1000, 10)
  let assert Ok(connection_state.PacketPrepared(prepared, _, _, frames)) =
    connection_state.prepare_packet(server, engine.OneRtt, 1000, 10)
  let assert [frame.NewToken(_)] = frames
  assert protected_datagram_bytes(
      prepared,
      maximum_destination_connection_id,
      widest_packet_number,
      frames,
    )
    <= connection_state.path_mtu(prepared)
}

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn drops_a_datagram_the_path_no_longer_carries_test() -> Nil {
  let connection = queues_a_full_datagram(validated_path_connection())

  // The path collapses back to the 1200-byte floor while the datagram is still
  // queued. It cannot be split and it must not go out oversized, so RFC 9221
  // section 5 lets it be dropped instead.
  let connection = connection_state.report_pmtu_black_hole(connection)
  assert connection_state.path_mtu(connection) == 1200
  let assert Ok(connection_state.NoPacket(connection)) =
    connection_state.prepare_packet(connection, engine.OneRtt, 1000, 40)

  // A datagram sized for the smaller path is still carried, and still fits.
  let connection = queues_a_full_datagram(connection)
  let assert Ok(connection_state.PacketPrepared(prepared, _, _, frames)) =
    connection_state.prepare_packet(connection, engine.OneRtt, 1000, 40)
  let assert [frame.Datagram(_)] = frames
  assert protected_datagram_bytes(
      prepared,
      maximum_destination_connection_id,
      widest_packet_number,
      frames,
    )
    <= connection_state.path_mtu(prepared)
}

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn arms_the_pacing_wake_for_a_path_sized_datagram_test() -> Nil {
  let connection = wide_path_connection()

  // Nothing is waiting to be sent, so the only deadline owed is the far later
  // idle timeout.
  let assert Ok(Some(idle)) = connection_state.next_deadline(connection, 10_001)

  let assert Ok(#(waiting, stream)) =
    connection_state.open_stream(connection, stream_id.Bidirectional)
  let assert Ok(waiting) =
    connection_state.queue_stream(
      waiting,
      stream,
      <<0:size(16_384)-unit(8)>>,
      False,
    )

  // The pacer is holding fewer tokens than one datagram of the validated path,
  // so a send really is paced at this instant.
  let #(_, limited) = flush_sized_datagrams(waiting, 16_384, 10_001, 1)
  let assert Error(connection_state.PacingLimited(release)) = limited
  assert release > 10_001

  // The owner has to wake at that release rather than at the idle deadline. A
  // burst fixed at ten 1200-byte datagrams cannot hold a 16_384-byte one at
  // all, so the pacer refused the question and no pacing wake was armed.
  let assert Ok(Some(deadline)) =
    connection_state.next_deadline(waiting, 10_001)
  assert deadline == release
  assert deadline < idle

  // The wake is only worth arming if flushing at it actually sends.
  let #(sent, resumed) = flush_sized_datagrams(waiting, 16_384, deadline, 1)
  assert resumed == Ok(Nil)
  assert connection_state.bytes_in_flight(sent) == 16_384
}

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn paces_a_small_write_by_the_datagram_it_produces_test() -> Nil {
  let connection = wide_path_connection()
  let assert Ok(#(waiting, stream)) =
    connection_state.open_stream(connection, stream_id.Bidirectional)
  let assert Ok(waiting) =
    connection_state.queue_stream(
      waiting,
      stream,
      <<0:size(16_384)-unit(8)>>,
      False,
    )
  let #(_, limited) = flush_sized_datagrams(waiting, 16_384, 10_001, 1)
  let assert Error(connection_state.PacingLimited(release)) = limited

  // One queued byte on the same wide path produces a datagram of a few dozen
  // bytes, not a path-sized one. The send path commits the datagram it built,
  // so the pacer releases that small one long before the tokens a
  // 16_384-byte datagram needs have accrued.
  let assert Ok(#(small, identifier)) =
    connection_state.open_stream(connection, stream_id.Bidirectional)
  let assert Ok(small) =
    connection_state.queue_stream(small, identifier, <<0>>, False)
  let #(sent, resumed) = flush_sized_datagrams(small, 60, 10_001, 1)
  assert resumed == Ok(Nil)
  assert connection_state.bytes_in_flight(sent) == 60

  // Arming the wake for a path-sized datagram would have slept through that
  // sendable instant.
  let assert Ok(Some(deadline)) = connection_state.next_deadline(small, 10_001)
  assert deadline != release
}

/// Queue the largest QUIC DATAGRAM the current path and the peer's frame limit
/// allow.
fn queues_a_full_datagram(
  connection: connection_state.State,
) -> connection_state.State {
  let assert Ok(payload) =
    connection_state.maximum_datagram_data_size(connection)
  let assert Ok(connection) =
    connection_state.queue_datagram(connection, <<0:size(payload)-unit(8)>>)
  connection
}

/// Receive `count` ack-eliciting packets on alternate packet numbers so every
/// retained ACK range stays alive.
fn receives_alternate_packets(
  connection: connection_state.State,
  count: Int,
) -> connection_state.State {
  list.index_fold(list.repeat(Nil, count), connection, fn(connection, _, index) {
    let assert Ok(connection) =
      connection_state.receive_packet(
        connection,
        engine.OneRtt,
        { index + 1 } * 2,
        [frame.Ping],
        packet_space.NotEct,
        30,
      )
    connection
  })
}

/// Drive DPLPMTUD to a validated 16_384-byte path while leaving the pacer
/// holding less than one datagram of that size.
///
/// The token bucket refills at 1.25 congestion windows per round trip, so the
/// first round trip is deliberately long: it grows the window past the probe
/// allowance a 16_384-byte probe needs, and the probe is then acknowledged one
/// millisecond after it was sent, before the bucket it emptied has refilled.
fn wide_path_connection() -> connection_state.State {
  let assert Ok(connection) = established(connection_state.Client)
  let assert Ok(connection) =
    connection_state.apply_tls_actions(connection, [
      engine.PeerTransportParameters([
        transport_parameter.MaxUdpPayloadSize(31_567),
      ]),
    ])
  let assert Ok(#(connection, stream)) =
    connection_state.open_stream(connection, stream_id.Bidirectional)
  let assert Ok(connection) =
    connection_state.queue_stream(
      connection,
      stream,
      <<0:size(11_000)-unit(8)>>,
      True,
    )

  // The opening burst spends every one of the pacer's tokens and carries all
  // the queued bytes and the FIN, so nothing is left pending behind it.
  let #(connection, opening) = flush_datagrams(connection, 0, 10)
  assert opening == Ok(Nil)
  let assert Ok(connection) =
    acknowledges_application_packets(
      connection,
      0,
      frame.AckRange(0, 9),
      10_000,
    )

  // The peer's authenticated ceiling puts the first probe midpoint exactly on
  // 16_384, and the grown window leaves room to send it.
  let assert Ok(#(connection, 16_384)) =
    connection_state.start_pmtu_probe(connection)
  let number = connection_state.next_application_packet_number(connection)
  let assert Ok(connection) =
    connection_state.commit_packet(
      connection,
      engine.OneRtt,
      number,
      [frame.Ping, frame.Padding(1)],
      16_384,
      ecn.NotEct,
      10_000,
    )
  let assert Ok(connection) =
    acknowledges_application_packets(
      connection,
      1,
      frame.AckRange(number, number),
      10_001,
    )
  assert connection_state.path_mtu(connection) == 16_384
  connection
}

/// Deliver one ACK-only packet from the peer covering `range`.
fn acknowledges_application_packets(
  connection: connection_state.State,
  packet_number: Int,
  range: frame.AckRange,
  now_milliseconds: Int,
) -> Result(connection_state.State, connection_state.Error) {
  let assert Ok(connection) =
    connection_state.record_datagram_received(connection, 80, now_milliseconds)
  connection_state.receive_packet(
    connection,
    engine.OneRtt,
    packet_number,
    [frame.Ack(frame.Acknowledgement(0, [range], None))],
    packet_space.NotEct,
    now_milliseconds,
  )
}

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn abandons_a_lost_pmtu_probe_without_a_congestion_response_test() -> Nil {
  let assert Ok(connection) = established(connection_state.Client)
  let assert Ok(#(connection, 9000)) =
    connection_state.start_pmtu_probe(connection)
  let connection =
    send_probe_then_lose_it(connection, [frame.Ping, frame.Padding(1)])

  // RFC 9002 section 3: a probe is deliberately larger than the confirmed
  // path, so losing one is not evidence of congestion. Its 9000 bytes leave
  // flight - only the two unacknowledged 100-byte packets remain - and the
  // window keeps the size the acknowledgement grew it to.
  assert connection_state.bytes_in_flight(connection) == 200
  assert connection_state.congestion_window(connection) >= 12_000
  assert connection_state.path_mtu(connection) == 1200
}

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn keeps_the_congestion_response_for_a_same_sized_pto_probe_test() -> Nil {
  let assert Ok(connection) = established(connection_state.Client)
  let assert Ok(#(connection, 9000)) =
    connection_state.start_pmtu_probe(connection)

  // A PTO probe carries retransmitted frames beside its PING. Losing one is an
  // ordinary loss even when its size happens to match the outstanding
  // DPLPMTUD probe, so the window still halves.
  let connection =
    send_probe_then_lose_it(connection, [
      frame.Ping,
      frame.Stream(0, 0, <<0:size(8000)-unit(8)>>, False),
    ])
  assert connection_state.bytes_in_flight(connection) == 200
  assert connection_state.congestion_window(connection) < 12_000
}

/// Drive DPLPMTUD to a validated 9000-byte path. The peer's authenticated
/// ceiling puts the first probe midpoint exactly on 9000, and acknowledging
/// that probe is what makes the size usable.
fn validated_path_connection() -> connection_state.State {
  let assert Ok(connection) = established(connection_state.Client)
  let assert Ok(connection) =
    connection_state.apply_tls_actions(connection, [
      engine.PeerTransportParameters([
        transport_parameter.MaxUdpPayloadSize(16_800),
      ]),
    ])
  let assert Ok(#(connection, 9000)) =
    connection_state.start_pmtu_probe(connection)
  let assert Ok(connection) =
    connection_state.commit_packet(
      connection,
      engine.OneRtt,
      0,
      [frame.Ping, frame.Padding(1)],
      9000,
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
  assert connection_state.path_mtu(connection) == 9000
  connection
}

/// A client that has installed 0-RTT write keys and learned the peer's
/// remembered transport parameters, but has not completed the handshake. Its
/// path is still the pre-validation floor every path is required to carry.
fn zero_rtt_connection() -> connection_state.State {
  let assert Ok(keys) = test_keys()
  let assert Ok(connection) =
    connection_state.new(
      connection_state.default_config(connection_state.Client),
      0,
    )
  let assert Ok(connection) =
    connection_state.apply_tls_actions(connection, [
      engine.InstallWriteKeys(engine.ZeroRtt, keys),
      engine.PeerTransportParameters(peer_parameters()),
    ])
  let #(connection, _) = connection_state.take_events(connection)
  assert connection_state.path_mtu(connection) == 1200
  connection
}

/// Protect one short packet from `sender` and feed it to `receiver`.
fn receives_short_packet(
  sender: connection_state.State,
  receiver: connection_state.State,
  packet_number: Int,
  frames: List(frame.Frame),
) -> connection_state.State {
  let assert Ok(#(_, packet)) =
    connection_state.protect_short_packet(
      sender,
      initial_destination_connection_id,
      packet_number,
      False,
      frames,
      1,
    )
  let assert Ok(receiver) =
    connection_state.record_datagram_received(
      receiver,
      bit_array.byte_size(packet),
      1,
    )
  let assert Ok(connection_state.ShortPacketReceipt(receiver, _, _, _)) =
    connection_state.receive_protected_short_packet(
      receiver,
      packet,
      8,
      packet_space.NotEct,
      1,
    )
  receiver
}

/// Send `frames` as a 9000-byte packet, then acknowledge three later packets
/// so the packet threshold declares it lost.
fn send_probe_then_lose_it(
  connection: connection_state.State,
  frames: List(frame.Frame),
) -> connection_state.State {
  let assert Ok(connection) =
    connection_state.commit_packet(
      connection,
      engine.OneRtt,
      0,
      frames,
      9000,
      ecn.NotEct,
      10,
    )
  let connection =
    list.index_fold(list.repeat(Nil, 3), connection, fn(connection, _, index) {
      let assert Ok(connection) =
        connection_state.commit_packet(
          connection,
          engine.OneRtt,
          index + 1,
          [frame.Ping],
          100,
          ecn.NotEct,
          10,
        )
      connection
    })
  let assert Ok(connection) =
    connection_state.receive_packet(
      connection,
      engine.OneRtt,
      0,
      [frame.Ack(frame.Acknowledgement(0, [frame.AckRange(3, 3)], None))],
      packet_space.NotEct,
      20,
    )
  connection
}

/// Establish a connection whose congestion window outruns the pacer's burst,
/// with enough stream data queued to keep every flush send-limited by pacing.
fn pacer_bound_connection() -> #(connection_state.State, Int) {
  pacer_bound_connection_after(100)
}

/// The same pacer-bound connection, with the opening burst acknowledged after a
/// caller-chosen round trip so the pacing release can be placed far enough
/// ahead to leave room for a congestion event before the wake.
fn pacer_bound_connection_after(
  round_trip_milliseconds: Int,
) -> #(connection_state.State, Int) {
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
    connection_state.record_datagram_received(
      connection,
      80,
      round_trip_milliseconds,
    )
  let assert Ok(connection) =
    connection_state.receive_packet(
      connection,
      engine.OneRtt,
      0,
      [frame.Ack(frame.Acknowledgement(0, [frame.AckRange(0, 9)], None))],
      packet_space.NotEct,
      round_trip_milliseconds,
    )
  assert connection_state.bytes_in_flight(connection) == 0
  assert connection_state.congestion_window(connection) > 13_200
  #(connection, stream)
}

/// One established connection on a socket that carries the Don't-Fragment
/// option, which is what lets DPLPMTUD search above the 1200-byte floor. The
/// fail-closed default is pinned by
/// `keeps_the_path_at_the_floor_by_default_test` instead.
fn established(
  role: connection_state.Role,
) -> Result(connection_state.State, connection_state.Error) {
  established_with_config(
    connection_state.Config(
      ..connection_state.default_config(role),
      path_dont_fragment: True,
    ),
  )
}

fn established_with_config(
  config: connection_state.Config,
) -> Result(connection_state.State, connection_state.Error) {
  let assert Ok(connection) = connection_state.new(config, 0)
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
              engine.OneRtt,
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

/// A memory grant wide enough that nothing in these tests is held by it.
const ample_memory_grant = 16_777_216

/// One round of the credit test: small enough that several rounds fit inside
/// the grant, large enough that the window updates during them.
const credit_chunk_bytes = 4096

const credit_rounds = 12

/// The grant the credit test runs under, and it is not a number this test
/// chose: it is exactly what a listener charges to admit one connection, so
/// the bound asserted below is the bound a shipped server actually runs
/// against rather than one arranged to be easy to meet.
fn admission_grant_bytes() -> Int {
  budget.admission_quanta() * budget.quantum()
}

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn a_refused_connection_stops_inviting_the_peer_to_open_streams_test() -> Nil {
  let assert Ok(connection) = established(connection_state.Server)
  let assert Ok(connection_state.PacketPrepared(
    connection,
    engine.OneRtt,
    _,
    [frame.HandshakeDone],
  )) = connection_state.prepare_packet(connection, engine.OneRtt, 1200, 1)

  // The endpoint has no memory left for this connection.
  let #(connection, _held) =
    connection_state.apply_memory_grant(connection, 0, True)
  assert connection_state.credit_growth_held(connection) == True

  // A peer using the allowance this endpoint already advertised is served
  // exactly as before. It is never punished for credit we handed it.
  let assert Ok(connection) =
    connection_state.receive_packet(
      connection,
      engine.OneRtt,
      0,
      [frame.Stream(2, 0, <<"done">>, True)],
      packet_space.NotEct,
      10,
    )
  let assert Ok(#(connection, read)) =
    connection_state.read_stream(connection, 2, 16)
  assert connection_state.read_data(read) == Some(#(<<"done">>, True))
  assert connection_state.active_stream_count(connection) == 0
  assert connection_state.phase(connection) == connection_state.Established

  // What is withheld is the invitation to open another one: the allowance the
  // closed stream freed is not advertised, and it does not grow.
  let #(connection, held) = prepared_frames(connection, 20)
  assert contains_max_streams(held, frame.Unidirectional, 101) == False
  assert connection_state.advertised_stream_limit(
      connection,
      stream_id.Unidirectional,
    )
    == 100

  // The moment the endpoint has room again the withheld allowance is stated,
  // without the peer having to send anything to prompt it.
  let #(connection, _released) =
    connection_state.apply_memory_grant(connection, ample_memory_grant, False)
  assert connection_state.credit_growth_held(connection) == False
  let #(connection, released) = prepared_frames(connection, 30)
  assert contains_max_streams(released, frame.Unidirectional, 101)
  assert connection_state.advertised_stream_limit(
      connection,
      stream_id.Unidirectional,
    )
    == 101
}

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn advertised_receive_credit_stays_inside_the_memory_grant_test() -> Nil {
  let assert Ok(connection) = granted_connection()
  let opening = connection_state.advertised_max_data(connection)

  // The credit a server promises in its handshake, before it has asked its
  // endpoint for a single byte of room, is credit the admission charge has
  // already funded. A server that advertised more than this would be
  // over-committed by the difference on every connection it ever admitted.
  assert opening == budget.initial_receive_credit()
  assert connection_state.outstanding_receive_credit(connection)
    <= admission_grant_bytes()

  // The peer sends and the application reads, round after round, with the
  // grant re-applied each turn exactly as the connection actor re-applies it.
  let connection = exchange_within_grant(connection, 0, 10, credit_rounds)

  // The window really did open -- so the bound below is a bound on growth that
  // happened, not on growth that never started -- and it never opened past the
  // room the grant funds.
  assert connection_state.advertised_max_data(connection) > opening
  assert connection_state.outstanding_receive_credit(connection)
    <= admission_grant_bytes()
  assert connection_state.retained_bytes(connection) <= admission_grant_bytes()
}

/// One peer send and one application read per round, checking after each that
/// neither the credit advertised nor the memory held has left the grant.
fn exchange_within_grant(
  connection: connection_state.State,
  offset: Int,
  now: Int,
  remaining: Int,
) -> connection_state.State {
  case remaining <= 0 {
    True -> connection
    False -> {
      let #(connection, _held) =
        connection_state.apply_memory_grant(
          connection,
          admission_grant_bytes(),
          False,
        )
      let connection = case
        offset + credit_chunk_bytes
        <= connection_state.advertised_max_data(connection)
      {
        False -> connection
        True -> send_and_read_chunk(connection, offset, now)
      }
      // The two standing bounds, checked every round rather than only at the
      // end: a peer that keeps filling every window it is offered still cannot
      // take this connection past what its endpoint granted.
      assert connection_state.outstanding_receive_credit(connection)
        <= admission_grant_bytes()
      assert connection_state.retained_bytes(connection)
        <= admission_grant_bytes()
      exchange_within_grant(
        connection,
        smallest_offset(connection, offset),
        now + 1,
        remaining - 1,
      )
    }
  }
}

fn smallest_offset(connection: connection_state.State, offset: Int) -> Int {
  case
    offset + credit_chunk_bytes
    <= connection_state.advertised_max_data(connection)
  {
    False -> offset
    True -> offset + credit_chunk_bytes
  }
}

fn send_and_read_chunk(
  connection: connection_state.State,
  offset: Int,
  now: Int,
) -> connection_state.State {
  let assert Ok(connection) =
    connection_state.receive_packet(
      connection,
      engine.OneRtt,
      now,
      [frame.Stream(2, offset, credit_chunk(), False)],
      packet_space.NotEct,
      now,
    )
  let assert Ok(#(connection, _read)) =
    connection_state.read_stream(connection, 2, credit_chunk_bytes)
  connection
}

fn credit_chunk() -> BitArray {
  <<0:size(credit_chunk_bytes)-unit(8)>>
}

/// An established server configured the way `server_transport` configures a
/// shipped listener's connections: the connection-level receive credit it
/// opens with is the credit its endpoint charged admission for, and the window
/// it widens by is the step it asks its endpoint for room in.
fn granted_connection() -> Result(
  connection_state.State,
  connection_state.Error,
) {
  let assert Ok(connection) =
    connection_state.new(
      connection_state.Config(
        ..connection_state.default_config(connection_state.Server),
        path_dont_fragment: True,
        initial_receive_data: budget.initial_receive_credit(),
        receive_data_window: budget.growth_step(),
      ),
      0,
    )
  let assert Ok(keys) = test_keys()
  let assert Ok(connection) =
    connection_state.apply_tls_actions(connection, [
      engine.InstallWriteKeys(engine.OneRtt, keys),
      engine.InstallReadKeys(engine.OneRtt, keys),
      engine.PeerTransportParameters(peer_parameters()),
      engine.HandshakeComplete,
    ])
  let #(connection, _events) = connection_state.take_events(connection)
  Ok(connection)
}

/// The 1-RTT frames this connection has to send now, if it has any at all.
fn prepared_frames(
  connection: connection_state.State,
  now: Int,
) -> #(connection_state.State, List(frame.Frame)) {
  let assert Ok(prepared) =
    connection_state.prepare_packet(connection, engine.OneRtt, 1200, now)
  case prepared {
    connection_state.PacketPrepared(connection, _level, _number, frames) -> #(
      connection,
      frames,
    )
    connection_state.NoPacket(connection) -> #(connection, [])
  }
}

/// A stream receive window narrow enough that one chunk crosses the half-window
/// deadband, so a single read is enough to make a MAX_STREAM_DATA increase due.
const narrow_stream_window_bytes = 4096

/// Connection-level receive credit wide enough that nothing in the restatement
/// test is bounded by it: what that test is about is the per-stream frames.
const narrow_connection_window_bytes = 65_536

/// How many 1-RTT packets a restatement is allowed to need. The queue emits one
/// queued frame per packet, and the whole point of the test is that only a
/// handful of frames are owed, so this is a bound rather than an expectation.
const restatement_packet_bound = 24

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn a_lifted_refusal_restates_only_the_credit_it_withheld_test() -> Nil {
  let assert Ok(connection) = narrow_window_connection()
  let #(connection, _handshake) =
    drained_frames(connection, 1, restatement_packet_bound)

  // A locally-opened unidirectional stream. This endpoint can only send on it,
  // and RFC 9000 section 19.10 makes MAX_STREAM_DATA for a stream the peer
  // cannot send on a STREAM_STATE_ERROR the peer must close the connection on.
  let assert Ok(#(connection, send_only)) =
    connection_state.open_stream(connection, stream_id.Unidirectional)

  // One peer-opened bidirectional stream this endpoint goes on to read from,
  // and one peer-opened unidirectional stream it never touches.
  let assert Ok(connection) =
    connection_state.receive_packet(
      connection,
      engine.OneRtt,
      0,
      [
        frame.Stream(0, 0, narrow_chunk(), False),
        frame.Stream(2, 0, narrow_chunk(), False),
      ],
      packet_space.NotEct,
      10,
    )

  // The endpoint has no memory left for this connection, so credit growth is
  // held down from here until it has room again.
  let #(connection, _held) =
    connection_state.apply_memory_grant(connection, 0, True)
  assert connection_state.credit_growth_held(connection) == True

  // Reading a whole window off the bidirectional stream would ordinarily raise
  // that stream's limit. While the hold binds, the increase is withheld.
  let assert Ok(#(connection, _read)) =
    connection_state.read_stream(connection, 0, narrow_stream_window_bytes)
  let #(connection, withheld) =
    drained_frames(connection, 20, restatement_packet_bound)
  assert list.any(withheld, is_max_stream_data(_, 0)) == False

  // The moment the endpoint has room again, what was withheld is stated.
  let #(connection, _released) =
    connection_state.apply_memory_grant(connection, ample_memory_grant, False)
  let #(_connection, restated) =
    drained_frames(connection, 30, restatement_packet_bound)

  // Exactly the stream whose increase was withheld, exactly once.
  assert list.count(restated, is_max_stream_data(_, 0)) == 1
  // Never the send-only stream: this endpoint has no receive credit to state
  // for it, and stating any would be a protocol violation.
  assert list.any(restated, is_max_stream_data(_, send_only)) == False
  // And never a stream whose increase was never withheld in the first place.
  assert list.any(restated, is_max_stream_data(_, 2)) == False
}

fn is_max_stream_data(value: frame.Frame, identifier: Int) -> Bool {
  case value {
    frame.MaxStreamData(stream, _maximum) -> stream == identifier
    _ -> False
  }
}

fn narrow_chunk() -> BitArray {
  <<0:size(narrow_stream_window_bytes)-unit(8)>>
}

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn default_receive_offsets_do_not_cap_stream_lifetime_test() -> Nil {
  let connection_state.Config(
    maximum_receive_data:,
    maximum_receive_stream_data:,
    maximum_stream_final_size:,
    ..,
  ) = connection_state.default_config(connection_state.Server)
  assert maximum_receive_data == varint.maximum
  assert maximum_receive_stream_data == varint.maximum
  assert maximum_stream_final_size == varint.maximum
}

/// An established server whose receive windows are narrow enough that a single
/// read crosses the deadband, so what a credit hold withholds is visible in one
/// exchange rather than after a megabyte of them.
fn narrow_window_connection() -> Result(
  connection_state.State,
  connection_state.Error,
) {
  let assert Ok(connection) =
    connection_state.new(
      connection_state.Config(
        ..connection_state.default_config(connection_state.Server),
        path_dont_fragment: True,
        initial_receive_data: narrow_connection_window_bytes,
        receive_data_window: narrow_connection_window_bytes,
        initial_receive_stream_data: narrow_stream_window_bytes,
        receive_stream_window: narrow_stream_window_bytes,
        maximum_receive_stream_data: narrow_connection_window_bytes,
      ),
      0,
    )
  let assert Ok(keys) = test_keys()
  let assert Ok(connection) =
    connection_state.apply_tls_actions(connection, [
      engine.InstallWriteKeys(engine.OneRtt, keys),
      engine.InstallReadKeys(engine.OneRtt, keys),
      engine.PeerTransportParameters(peer_parameters()),
      engine.HandshakeComplete,
    ])
  let #(connection, _events) = connection_state.take_events(connection)
  Ok(connection)
}

/// Every 1-RTT frame this connection has to send now, drained over at most
/// `packets` prepared packets so the wait is bounded whatever it owes.
fn drained_frames(
  connection: connection_state.State,
  now: Int,
  packets: Int,
) -> #(connection_state.State, List(frame.Frame)) {
  drain_frames(connection, now, packets, [])
}

fn drain_frames(
  connection: connection_state.State,
  now: Int,
  packets: Int,
  seen: List(frame.Frame),
) -> #(connection_state.State, List(frame.Frame)) {
  case packets <= 0 {
    True -> #(connection, list.reverse(seen))
    False ->
      case prepared_frames(connection, now) {
        #(connection, []) -> #(connection, list.reverse(seen))
        #(connection, frames) ->
          drain_frames(
            connection,
            now,
            packets - 1,
            list.fold(frames, seen, fn(seen, value) { [value, ..seen] }),
          )
      }
  }
}

/// Connection-level receive credit one peer stream can fill exactly, so the
/// peer can be driven to no credit at all inside a single exchange.
const shut_window_bytes = 8192

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn a_lifted_refusal_restates_the_connection_limit_test() -> Nil {
  let assert Ok(connection) = shut_window_connection()
  let #(connection, _handshake) =
    drained_frames(connection, 1, restatement_packet_bound)
  let opening = connection_state.advertised_max_data(connection)
  assert opening == shut_window_bytes

  // The endpoint has no memory left for this connection, so its advertised
  // credit is held to what the peer has already read off.
  let #(connection, _held) =
    connection_state.apply_memory_grant(connection, 0, True)
  assert connection_state.credit_growth_held(connection) == True

  // The peer spends every byte of connection-level credit it holds, and the
  // application reads all of it. Under the hold none of it is handed back, so
  // the peer is left with no credit whatsoever.
  let assert Ok(connection) =
    connection_state.receive_packet(
      connection,
      engine.OneRtt,
      0,
      [frame.Stream(0, 0, shut_window_chunk(), False)],
      packet_space.NotEct,
      10,
    )
  let assert Ok(#(connection, _read)) =
    connection_state.read_stream(connection, 0, shut_window_bytes)
  let #(connection, withheld) =
    drained_frames(connection, 20, restatement_packet_bound)
  assert list.any(withheld, is_max_data) == False
  assert connection_state.advertised_max_data(connection) == opening
  assert connection_state.outstanding_receive_credit(connection) == 0

  // The lift has to hand that room on by itself. The peer cannot send, so
  // nothing will arrive to prompt this endpoint; the application has read
  // everything there was, so it will not read again. A connection-level limit
  // that only the next read can raise is a limit never raised, and a
  // connection that waits for it is a connection stalled to its idle timeout.
  let #(connection, _released) =
    connection_state.apply_memory_grant(connection, ample_memory_grant, False)
  let #(connection, restated) =
    drained_frames(connection, 30, restatement_packet_bound)
  assert list.any(restated, is_max_data) == True
  assert connection_state.advertised_max_data(connection) > opening
  assert connection_state.outstanding_receive_credit(connection) > 0
}

fn is_max_data(value: frame.Frame) -> Bool {
  case value {
    frame.MaxData(_maximum) -> True
    _ -> False
  }
}

fn shut_window_chunk() -> BitArray {
  <<0:size(shut_window_bytes)-unit(8)>>
}

/// An established server whose connection-level receive credit is narrow
/// enough for one peer stream to spend all of it in a single packet, so the
/// state a lifted refusal has to recover from -- a peer holding no credit at
/// all -- is reachable without a megabyte of traffic.
fn shut_window_connection() -> Result(
  connection_state.State,
  connection_state.Error,
) {
  let assert Ok(connection) =
    connection_state.new(
      connection_state.Config(
        ..connection_state.default_config(connection_state.Server),
        path_dont_fragment: True,
        initial_receive_data: shut_window_bytes,
        receive_data_window: shut_window_bytes,
        initial_receive_stream_data: shut_window_bytes,
        receive_stream_window: shut_window_bytes,
        maximum_receive_stream_data: narrow_connection_window_bytes,
      ),
      0,
    )
  let assert Ok(keys) = test_keys()
  let assert Ok(connection) =
    connection_state.apply_tls_actions(connection, [
      engine.InstallWriteKeys(engine.OneRtt, keys),
      engine.InstallReadKeys(engine.OneRtt, keys),
      engine.PeerTransportParameters(peer_parameters()),
      engine.HandshakeComplete,
    ])
  let #(connection, _events) = connection_state.take_events(connection)
  Ok(connection)
}

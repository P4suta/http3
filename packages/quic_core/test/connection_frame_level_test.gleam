import gleam/bit_array
import gleam/list
import gleam/option.{None, Some}
import gleam/result
import quic_core/frame
import quic_core/internal/connection_state
import quic_core/internal/packet_space
import quic_core/internal/tls/engine
import quic_core/internal/tls/hello
import quic_core/internal/traffic_keys
import quic_core/internal/wire_packet
import quic_core/version

const destination = <<1, 2, 3, 4, 5, 6, 7, 8>>

const source = <<11, 12, 13, 14, 15, 16, 17, 18>>

const spare = <<21, 22, 23, 24, 25, 26, 27, 28>>

fn endpoints(
  protocol: version.Version,
) -> #(connection_state.State, connection_state.State) {
  let assert Ok(client) =
    connection_state.new(
      connection_state.Config(
        ..connection_state.default_config(connection_state.Client),
        version: protocol,
      ),
      0,
    )
  let assert Ok(server) =
    connection_state.new(
      connection_state.Config(
        ..connection_state.default_config(connection_state.Server),
        version: protocol,
      ),
      0,
    )
  let assert Ok(client) =
    connection_state.install_initial_keys(client, destination)
  let assert Ok(server) =
    connection_state.install_initial_keys(server, destination)
  let assert Ok(keys) =
    traffic_keys.from_secret(protocol, hello.Aes128GcmSha256, <<0x51:256>>)
  let assert Ok(client) =
    connection_state.apply_tls_actions(client, [
      engine.InstallWriteKeys(engine.Handshake, keys),
      engine.InstallWriteKeys(engine.ZeroRtt, keys),
    ])
  let assert Ok(server) =
    connection_state.apply_tls_actions(server, [
      engine.InstallReadKeys(engine.Handshake, keys),
      engine.InstallReadKeys(engine.ZeroRtt, keys),
      engine.InstallWriteKeys(engine.OneRtt, keys),
    ])
  let assert Ok(server) =
    connection_state.initialize_peer_connection_id(server, source, <<0x41:128>>)
  #(client, server)
}

fn receive_wire(
  server: connection_state.State,
  datagram: BitArray,
) -> connection_state.State {
  let assert Ok(connection_state.LongPacketReceipt(server, _, _, <<>>)) =
    connection_state.receive_protected_long_packet(
      server,
      datagram,
      packet_space.NotEct,
      1,
    )
  server
}

fn exchange(
  protocol: version.Version,
  frames: List(frame.Frame),
) -> connection_state.State {
  let #(client, server) = endpoints(protocol)
  let assert Ok(datagram) =
    connection_state.protect_long_packet(
      client,
      wire_packet.ZeroRtt,
      destination,
      source,
      0,
      frames,
    )
  receive_wire(server, datagram)
}

// RFC9000§12.4/Table3 permits these frames in0RTT.
// The observed postcondition goes through AEAD authentication, frame decoding and actual connection state.
// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn authenticated_zero_rtt_can_supply_a_spare_connection_id_test() -> Nil {
  [version.Version1, version.Version2]
  |> list.each(fn(protocol) {
    let server =
      exchange(protocol, [frame.NewConnectionId(1, 0, spare, <<0x71:128>>)])
    assert connection_state.local_transport_failure_code(server) == None
    assert connection_state.phase(server) == connection_state.Handshaking
    assert connection_state.rotate_peer_connection_id(server)
      |> result.map(fn(pair) {
        let #(rotated, _) = pair
        connection_state.current_peer_connection_id(rotated)
        |> result.map(fn(identifier) { identifier == spare })
      })
      == Ok(Ok(True))
  })
}

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn authenticated_zero_rtt_path_challenge_queues_a_one_rtt_response_test() -> Nil {
  [version.Version1, version.Version2]
  |> list.each(fn(protocol) {
    let challenge = <<0x53:64>>
    let server = exchange(protocol, [frame.PathChallenge(challenge)])
    assert connection_state.local_transport_failure_code(server) == None
    let assert Ok(connection_state.PacketPrepared(_, _, _, frames)) =
      connection_state.prepare_packet(server, engine.OneRtt, 1200, 2)
    assert list.any(frames, fn(value) {
      case value {
        frame.PathResponse(data) -> data == challenge
        _ -> False
      }
    })
  })
}

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn authenticated_zero_rtt_transport_close_enters_draining_without_local_error_test() -> Nil {
  [version.Version1, version.Version2]
  |> list.each(fn(protocol) {
    let server = exchange(protocol, [frame.ConnectionCloseTransport(0, 0, "")])
    assert connection_state.phase(server) == connection_state.Draining
    assert connection_state.local_transport_failure_code(server) == None
    let #(_, events) = connection_state.take_events(server)
    assert list.any(events, fn(event) {
      case event {
        connection_state.PeerTransportClosed(0, "") -> True
        _ -> False
      }
    })
    assert connection_state.prepare_packet(server, engine.OneRtt, 1200, 2)
      |> result.map(fn(_) { Nil })
      == Error(connection_state.ConnectionUnavailable)
    let assert Ok(server) = connection_state.tick(server, 3001)
    assert connection_state.phase(server) == connection_state.Closed
  })
}

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn unauthenticated_zero_rtt_cannot_trigger_a_protocol_close_test() -> Nil {
  let #(client, server) = endpoints(version.Version1)
  let assert Ok(datagram) =
    connection_state.protect_long_packet(
      client,
      wire_packet.ZeroRtt,
      destination,
      source,
      0,
      [frame.Padding(32), frame.Crypto(0, <<>>)],
    )
  // Alter the AEAD tag outside the header-protection sample.
  // The same frame has a fatal authenticated outcome, but a forgery must only be discarded.
  let prefix_bits = bit_array.bit_size(datagram) - 1
  let assert <<prefix:bits-size(prefix_bits), last:size(1)>> = datagram
  let changed = case last {
    0 -> 1
    _ -> 0
  }
  assert connection_state.receive_protected_long_packet(
      server,
      <<prefix:bits, changed:size(1)>>,
      packet_space.NotEct,
      1,
    )
    |> result.map(fn(_) { Nil })
    == Error(connection_state.WirePacketFailure(
      wire_packet.AuthenticationFailed,
    ))
  assert connection_state.local_transport_failure_code(server) == None
  assert connection_state.phase(server) == connection_state.Handshaking
  let authenticated = receive_wire(server, datagram)
  assert connection_state.local_transport_failure_code(authenticated)
    == Some(0x0a)
}

fn zero_rtt_forbidden() -> List(#(frame.Frame, connection_state.FrameKind)) {
  [
    #(
      frame.Ack(frame.Acknowledgement(0, [frame.AckRange(0, 0)], None)),
      connection_state.AckFrame,
    ),
    #(frame.Crypto(0, <<>>), connection_state.CryptoFrame),
    #(frame.NewToken(<<1>>), connection_state.NewTokenFrame),
    #(frame.PathResponse(<<0:64>>), connection_state.PathResponseFrame),
    #(frame.HandshakeDone, connection_state.HandshakeDoneFrame),
    // §12.5 permits this refusal even though Table3 marks application space.
    #(frame.RetireConnectionId(0), connection_state.RetireConnectionIdFrame),
  ]
}

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn forbidden_zero_rtt_frames_close_with_protocol_violation_after_authentication_test() -> Nil {
  zero_rtt_forbidden()
  |> list.each(fn(entry) {
    let #(value, kind) = entry
    let server = exchange(version.Version1, [value])
    assert connection_state.local_transport_failure_code(server) == Some(0x0a)
    assert connection_state.phase(server) == connection_state.Closing
    let #(_, events) = connection_state.take_events(server)
    assert list.any(events, fn(event) {
      case event {
        connection_state.LocalTransportFailure(
          connection_state.FrameAtWrongEncryptionLevel(engine.ZeroRtt, actual),
          0x0a,
        ) -> actual == kind
        _ -> False
      }
    })
  })
}

fn application_only() -> List(#(frame.Frame, connection_state.FrameKind)) {
  [
    #(frame.ResetStream(0, 0, 0), connection_state.ResetStreamFrame),
    #(frame.StopSending(0, 0), connection_state.StopSendingFrame),
    #(frame.NewToken(<<1>>), connection_state.NewTokenFrame),
    #(frame.Stream(0, 0, <<1>>, False), connection_state.StreamFrame),
    #(frame.MaxData(1), connection_state.MaxDataFrame),
    #(frame.MaxStreamData(0, 1), connection_state.MaxStreamDataFrame),
    #(
      frame.MaxStreams(frame.Bidirectional, 1),
      connection_state.MaxStreamsFrame,
    ),
    #(frame.DataBlocked(1), connection_state.DataBlockedFrame),
    #(frame.StreamDataBlocked(0, 1), connection_state.StreamDataBlockedFrame),
    #(
      frame.StreamsBlocked(frame.Unidirectional, 1),
      connection_state.StreamsBlockedFrame,
    ),
    #(
      frame.NewConnectionId(1, 0, spare, <<0x71:128>>),
      connection_state.NewConnectionIdFrame,
    ),
    #(frame.RetireConnectionId(0), connection_state.RetireConnectionIdFrame),
    #(frame.PathChallenge(<<0:64>>), connection_state.PathChallengeFrame),
    #(frame.PathResponse(<<0:64>>), connection_state.PathResponseFrame),
    #(
      frame.ConnectionCloseApplication(0, ""),
      connection_state.ConnectionCloseApplicationFrame,
    ),
    #(frame.HandshakeDone, connection_state.HandshakeDoneFrame),
    #(frame.Datagram(<<1>>), connection_state.DatagramFrame),
  ]
}

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn initial_and_handshake_reject_every_application_frame_before_state_effects_test() -> Nil {
  let #(_, server) = endpoints(version.Version1)
  [engine.Initial, engine.Handshake]
  |> list.each(fn(level) {
    application_only()
    |> list.each(fn(entry) {
      let #(value, kind) = entry
      assert connection_state.receive_packet(
          server,
          level,
          0,
          [frame.Padding(1), frame.Ping, value],
          packet_space.NotEct,
          1,
        )
        |> result.map(fn(_) { Nil })
        == Error(connection_state.FrameAtWrongEncryptionLevel(level, kind))
    })
  })
  assert connection_state.active_stream_count(server) == 0
  assert connection_state.local_transport_failure_code(server) == None
}

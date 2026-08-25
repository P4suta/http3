//// Socket-independent generic QUIC connection runtime.

import gleam/bit_array
import gleam/option.{type Option}
import gleam/result
import gleam_quic/internal/connection_state as transport
import gleam_quic/internal/driver
import gleam_quic/internal/ecn
import gleam_quic/internal/packet_space
import gleam_quic/internal/stream_state
import gleam_quic/internal/tls/anti_replay
import gleam_quic/internal/tls/authentication
import gleam_quic/internal/tls/hello
import gleam_quic/internal/tls/resumption
import gleam_quic/internal/udp
import gleam_quic/stream_id

/// Socket-independent state for one fixed peer path.
pub opaque type State {
  State(
    peer: udp.Endpoint,
    quic: driver.State,
    packets_received: Int,
    packets_sent: Int,
    bytes_received: Int,
    bytes_sent: Int,
    flushes: Int,
  )
}

/// A protected datagram awaiting a confirmed UDP send.
pub opaque type PreparedDatagram {
  PreparedDatagram(state: State, prepared: driver.PreparedDatagram)
}

/// One bounded read from a QUIC stream.
pub type Read {
  Pending
  Data(bytes: BitArray, finished: Bool)
  Reset(application_error_code: Int)
  Finished
}

/// Runtime-owned packet and byte counters.
pub type Stats {
  Stats(Int, Int, Int, Int, Int, Int, Int, Int)
}

/// Construct runtime state around an initialized driver.
pub fn new(peer: udp.Endpoint, quic: driver.State) -> State {
  State(peer, quic, 0, 0, 0, 0, 0)
}

/// Current authenticated peer path.
pub fn peer(state: State) -> udp.Endpoint {
  state.peer
}

/// Adopt an authenticated replacement path.
pub fn with_peer(state: State, peer: udp.Endpoint) -> State {
  State(..state, peer: peer)
}

/// Connection ID used by a server router for short-header packets.
pub fn local_connection_id(state: State) -> BitArray {
  driver.local_connection_id(state.quic)
}

/// Stable lifecycle phase.
pub fn phase(state: State) -> transport.Phase {
  driver.phase(state.quic)
}

/// Whether TLS has installed authenticated 1-RTT keys.
pub fn established(state: State) -> Bool {
  phase(state) == transport.Established
}

/// Whether this client connection resumed an offered TLS session.
pub fn resumed(state: State) -> Bool {
  transport.client_resumed(driver.connection(state.quic))
}

/// Authenticated ALPN selection, when the TLS handshake has completed.
pub fn application_protocol(state: State) -> Option(BitArray) {
  transport.application_protocol(driver.connection(state.quic))
}

/// Authenticated cipher selection, when the TLS handshake has completed.
pub fn cipher_suite(state: State) -> Option(hello.CipherSuite) {
  transport.cipher_suite(driver.connection(state.quic))
}

/// Whether this server connection selected a valid resumption ticket.
pub fn server_resumed(state: State) -> Bool {
  transport.server_resumed(driver.connection(state.quic))
}

/// Return the verified client identity without exposing TLS state.
pub fn server_client_identity(
  state: State,
) -> Option(authentication.VerifiedPeer) {
  transport.server_client_identity(driver.connection(state.quic))
}

/// Whether this server connection accepted replay-guarded early data.
pub fn server_early_data_accepted(state: State) -> Bool {
  transport.server_early_data_accepted(driver.connection(state.quic))
}

/// Whether this server peer offered early data.
pub fn server_early_data_attempted(state: State) -> Bool {
  transport.server_early_data_attempted(driver.connection(state.quic))
}

/// Pull and clear ordered transport events.
pub fn take_events(state: State) -> #(State, List(transport.Event)) {
  let #(quic, events) = driver.take_events(state.quic)
  #(State(..state, quic: quic), events)
}

/// Authenticate one datagram received on this connection's routed path.
pub fn receive_datagram(
  state: State,
  datagram: BitArray,
  marking: packet_space.ReceivedCodepoint,
  now: Int,
) -> Result(State, driver.Error) {
  use quic <- result.try(driver.receive_datagram_with_ecn(
    state.quic,
    datagram,
    marking,
    now,
  ))
  Ok(
    State(
      ..state,
      quic: quic,
      packets_received: state.packets_received + 1,
      bytes_received: state.bytes_received + bit_array.byte_size(datagram),
    ),
  )
}

/// Advance all protocol timers.
pub fn tick(state: State, now: Int) -> Result(State, driver.Error) {
  driver.tick(state.quic, now)
  |> result.map(fn(quic) { State(..state, quic: quic) })
}

/// Return the earliest protocol timer deadline.
pub fn next_deadline(
  state: State,
  now: Int,
) -> Result(Option(Int), driver.Error) {
  driver.next_deadline(state.quic, now)
}

/// Protect at most one bounded UDP datagram.
pub fn prepare_datagram(
  state: State,
  maximum_frame_data_bytes: Int,
  now: Int,
) -> Result(Option(PreparedDatagram), driver.Error) {
  driver.prepare_datagram(state.quic, maximum_frame_data_bytes, now)
  |> result.map(fn(prepared) {
    case prepared {
      option.None -> option.None
      option.Some(value) -> option.Some(PreparedDatagram(state, value))
    }
  })
}

/// Bytes for one UDP send.
pub fn prepared_bytes(prepared: PreparedDatagram) -> BitArray {
  driver.prepared_bytes(prepared.prepared)
}

/// Commit a datagram after UDP reports a successful send.
pub fn commit_datagram(
  prepared: PreparedDatagram,
  marking: ecn.Codepoint,
  now: Int,
) -> Result(State, driver.Error) {
  let size = bit_array.byte_size(prepared_bytes(prepared))
  driver.commit_datagram_with_ecn(prepared.prepared, marking, now)
  |> result.map(fn(quic) {
    State(
      ..prepared.state,
      quic: quic,
      packets_sent: prepared.state.packets_sent + 1,
      bytes_sent: prepared.state.bytes_sent + size,
      flushes: prepared.state.flushes + 1,
    )
  })
}

/// Open the next locally initiated stream.
pub fn open_stream(
  state: State,
  direction: stream_id.Direction,
) -> Result(#(State, Int), driver.Error) {
  transport.open_stream(driver.connection(state.quic), direction)
  |> result.map(fn(opened) {
    let #(connection, identifier) = opened
    #(
      State(..state, quic: driver.put_connection(state.quic, connection)),
      identifier,
    )
  })
  |> result.map_error(driver.ConnectionFailure)
}

/// Queue bounded bytes and an optional FIN on a stream's send direction.
pub fn send(
  state: State,
  identifier: Int,
  bytes: BitArray,
  finish: Bool,
) -> Result(State, driver.Error) {
  driver.update_connection(state.quic, fn(connection) {
    transport.queue_stream(connection, identifier, bytes, finish)
  })
  |> result.map(fn(quic) { State(..state, quic: quic) })
}

/// Return bytes currently retained for this stream's send direction.
pub fn buffered_send_bytes(
  state: State,
  identifier: Int,
) -> Result(Int, driver.Error) {
  transport.stream_buffered_send_bytes(
    driver.connection(state.quic),
    identifier,
  )
  |> result.map_error(driver.ConnectionFailure)
}

/// Pull one bounded stream read and replenish flow-control credit.
pub fn read(
  state: State,
  identifier: Int,
  maximum_bytes: Int,
) -> Result(#(State, Read), driver.Error) {
  transport.read_stream(
    driver.connection(state.quic),
    identifier,
    maximum_bytes,
  )
  |> result.map(fn(output) {
    let #(connection, outcome) = output
    let read = case outcome {
      stream_state.ReadPending(_) -> Pending
      stream_state.ReadData(_, bytes, finished, _) -> Data(bytes, finished)
      stream_state.ReadReset(_, code, _, _) -> Reset(code)
      stream_state.ReadFinished(_) -> Finished
    }
    #(State(..state, quic: driver.put_connection(state.quic, connection)), read)
  })
  |> result.map_error(driver.ConnectionFailure)
}

/// Abort every locally usable direction of one stream.
pub fn reset(
  state: State,
  identifier: Int,
  application_error_code: Int,
) -> Result(State, driver.Error) {
  driver.update_connection(state.quic, fn(connection) {
    transport.abort_stream(connection, identifier, application_error_code)
  })
  |> result.map(fn(quic) { State(..state, quic: quic) })
}

/// Largest raw QUIC Datagram payload on the current path.
pub fn maximum_datagram_size(state: State) -> Result(Int, driver.Error) {
  transport.maximum_datagram_data_size(driver.connection(state.quic))
  |> result.map_error(driver.ConnectionFailure)
}

/// Queue one negotiated QUIC Datagram.
pub fn send_datagram(
  state: State,
  payload: BitArray,
) -> Result(State, driver.Error) {
  driver.update_connection(state.quic, fn(connection) {
    transport.queue_datagram(connection, payload)
  })
  |> result.map(fn(quic) { State(..state, quic: quic) })
}

/// Queue one ack-eliciting PING.
pub fn ping(state: State) -> Result(State, driver.Error) {
  driver.update_connection(state.quic, transport.queue_ping)
  |> result.map(fn(quic) { State(..state, quic: quic) })
}

/// Queue one authenticated NEW_TOKEN frame on an established connection.
pub fn queue_new_token(
  state: State,
  token: BitArray,
) -> Result(State, driver.Error) {
  driver.update_connection(state.quic, fn(connection) {
    transport.queue_new_token(connection, token)
  })
  |> result.map(fn(quic) { State(..state, quic: quic) })
}

/// Change the live congestion controller.
pub fn set_congestion_control(
  state: State,
  algorithm: transport.CongestionAlgorithm,
) -> Result(State, driver.Error) {
  driver.update_connection(state.quic, fn(connection) {
    transport.set_congestion_algorithm(connection, algorithm)
  })
  |> result.map(fn(quic) { State(..state, quic: quic) })
}

/// Begin validation of a candidate peer path.
pub fn begin_path_validation(
  state: State,
  challenge: BitArray,
  active_migration: Bool,
  now: Int,
) -> Result(State, driver.Error) {
  driver.update_connection(state.quic, fn(connection) {
    transport.begin_path_validation(
      connection,
      challenge,
      active_migration,
      now,
    )
  })
  |> result.map(fn(quic) { State(..state, quic: quic) })
}

/// Whether the peer permits active path migration.
pub fn active_migration_available(state: State) -> Bool {
  transport.active_migration_available(driver.connection(state.quic))
}

/// Whether candidate-path validation is pending.
pub fn path_validation_in_progress(state: State) -> Bool {
  transport.path_validation_in_progress(driver.connection(state.quic))
}

/// Current non-fragmenting QUIC UDP payload size.
pub fn path_mtu(state: State) -> Int {
  transport.path_mtu(driver.connection(state.quic))
}

/// Whether DPLPMTUD has reached this path's current ceiling.
pub fn pmtu_discovery_complete(state: State) -> Bool {
  transport.pmtu_discovery_complete(driver.connection(state.quic))
}

/// Prepare one exact-size DPLPMTUD probe.
pub fn prepare_pmtu_probe(
  state: State,
  now: Int,
) -> Result(Option(PreparedDatagram), driver.Error) {
  driver.prepare_pmtu_probe(state.quic, now)
  |> result.map(fn(prepared) {
    case prepared {
      option.None -> option.None
      option.Some(value) -> option.Some(PreparedDatagram(state, value))
    }
  })
}

/// Snapshot path diagnostics.
pub fn path_stats(state: State) -> transport.PathSnapshot {
  transport.path_snapshot(driver.connection(state.quic))
}

/// Snapshot runtime-owned counters.
pub fn stats(state: State) -> Stats {
  let transport.ConnectionCounters(acks, retransmissions, coalesced) =
    transport.connection_counters(driver.connection(state.quic))
  Stats(
    state.packets_received,
    state.packets_sent,
    state.bytes_received,
    state.bytes_sent,
    acks,
    retransmissions,
    state.flushes,
    coalesced,
  )
}

/// Return the server replay cache selected during TLS resumption.
pub fn server_replay_cache(state: State) -> Option(anti_replay.Cache) {
  transport.server_replay_cache(driver.connection(state.quic))
}

/// Whether established server TLS can issue a NewSessionTicket.
pub fn can_issue_session_ticket(state: State) -> Bool {
  transport.can_issue_session_ticket(driver.connection(state.quic))
}

/// Refresh server-side resumption/replay policy while handshaking.
pub fn refresh_server_resumption_policy(
  state: State,
  policy: resumption.ServerPolicy,
) -> Result(State, driver.Error) {
  case phase(state) {
    transport.Handshaking ->
      driver.update_connection(state.quic, fn(connection) {
        transport.refresh_server_resumption_policy(connection, policy)
      })
      |> result.map(fn(quic) { State(..state, quic: quic) })
    _ -> Ok(state)
  }
}

/// Issue one TLS session ticket from an established server connection.
pub fn issue_session_ticket(
  state: State,
  ticket_key: BitArray,
  now: Int,
  lifetime_seconds: Int,
  permit_early_data: Bool,
) -> Result(State, driver.Error) {
  driver.update_connection(state.quic, fn(connection) {
    transport.issue_session_ticket(
      connection,
      ticket_key,
      now,
      lifetime_seconds,
      permit_early_data,
    )
  })
  |> result.map(fn(quic) { State(..state, quic: quic) })
}

/// Best-effort application close transition.
pub fn close(
  state: State,
  application_error_code: Int,
  reason: String,
  now: Int,
) -> State {
  case
    driver.update_connection(state.quic, fn(connection) {
      transport.close(connection, application_error_code, reason, now)
    })
  {
    Ok(quic) -> State(..state, quic: quic)
    Error(_) -> state
  }
}

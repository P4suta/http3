//// Pure datagram driver joining QUIC packet protection to connection state.

import gleam/bit_array
import gleam/int
import gleam/list
import gleam/option.{type Option, None, Some}
import gleam/result
import gleam_quic/frame
import gleam_quic/internal/connection_state
import gleam_quic/internal/ecn
import gleam_quic/internal/packet_space
import gleam_quic/internal/pmtu
import gleam_quic/internal/retry_integrity
import gleam_quic/internal/tls/engine
import gleam_quic/internal/wire_packet
import gleam_quic/packet
import gleam_quic/version.{type Version}

const minimum_initial_datagram_bytes = 1200

const maximum_padding_adjustments = 8

/// Stable endpoint role.
pub type Role {
  Client
  Server
}

/// QUIC connection state plus packet-routing identifiers. Addresses and UDP
/// sockets deliberately remain outside this value.
pub opaque type State {
  State(
    role: Role,
    version: Version,
    connection: connection_state.State,
    local_connection_id: BitArray,
    peer_connection_id: BitArray,
    original_destination_connection_id: BitArray,
    initial_token: BitArray,
    server_packet_received: Bool,
    retry_received: Bool,
  )
}

/// A protected datagram whose frames have left their queues but have not yet
/// been committed to recovery, congestion, pacing, or amplification state.
pub opaque type PreparedDatagram {
  PreparedDatagram(
    state: State,
    level: engine.EncryptionLevel,
    packet_number: Int,
    frames: List(frame.Frame),
    bytes: BitArray,
  )
}

/// Invalid identifiers, unsupported special packets, or core transition
/// failure.
pub type Error {
  InvalidInput
  DestinationConnectionIdMismatch
  VersionNegotiationReceived(List(Version))
  PacketFailure(packet.Error)
  ConnectionFailure(connection_state.Error)
  /// An authenticated Retry carried an address-validation token wider than
  /// `budget_bytes`, the widest one this endpoint can repeat in an Initial
  /// that still fits the 1200-byte floor.
  ///
  /// This is a local limit, not a peer fault: RFC 9000 places no upper bound
  /// on a Retry token, and the budget is computed by charging every Initial
  /// header field its widest encoding, so a token a little past it might well
  /// have fitted the header this connection actually writes. It is reported
  /// apart from `ConnectionFailure` so a log or qlog never attributes it to
  /// the server as a protocol violation.
  RetryTokenTooLarge(token_bytes: Int, budget_bytes: Int)
}

/// Return whether a receive failure occurred before packet authentication and
/// therefore must be silently discarded instead of closing the connection.
pub fn discardable_receive_error(error: Error) -> Bool {
  case error {
    InvalidInput | DestinationConnectionIdMismatch | PacketFailure(_) -> True
    ConnectionFailure(connection_state.MissingReadKeys(_))
    | ConnectionFailure(connection_state.MissingWriteKeys(_))
    | ConnectionFailure(connection_state.WirePacketFailure(
        wire_packet.AuthenticationFailed,
      ))
    | ConnectionFailure(connection_state.WirePacketFailure(
        wire_packet.InvalidHeader,
      ))
    | ConnectionFailure(connection_state.WirePacketFailure(
        wire_packet.Truncated,
      ))
    | ConnectionFailure(connection_state.WirePacketFailure(
        wire_packet.InsufficientHeaderProtectionSample,
      )) -> True
    _ -> False
  }
}

/// Start a client after TLS has emitted its first ClientHello actions.
pub fn start_client(
  config: connection_state.Config,
  tls: engine.Step(engine.Client),
  original_destination_connection_id: BitArray,
  local_connection_id: BitArray,
  now_ms: Int,
) -> Result(State, Error) {
  start_client_with_token(
    config,
    tls,
    original_destination_connection_id,
    local_connection_id,
    <<>>,
    now_ms,
  )
}

/// Start a client with one cached server-issued address-validation token.
pub fn start_client_with_token(
  config: connection_state.Config,
  tls: engine.Step(engine.Client),
  original_destination_connection_id: BitArray,
  local_connection_id: BitArray,
  initial_token: BitArray,
  now_ms: Int,
) -> Result(State, Error) {
  use _ <- result.try(validate_connection_id(original_destination_connection_id))
  use _ <- result.try(validate_connection_id(local_connection_id))
  // A cached token only saves a round trip. One this endpoint cannot repeat
  // inside an Initial that still fits the 1200-byte floor is dropped and the
  // connection starts without it; the server is free to answer with a Retry
  // carrying a token of its own choosing.
  let initial_token = case carryable_initial_token(initial_token) {
    True -> initial_token
    False -> <<>>
  }
  use connection <- result.try(
    connection_state.new(config, now_ms) |> map_connection_result,
  )
  use connection <- result.try(
    connection_state.install_initial_keys(
      connection,
      original_destination_connection_id,
    )
    |> map_connection_result,
  )
  use connection <- result.try(
    connection_state.attach_client_tls(connection, tls)
    |> map_connection_result,
  )
  Ok(record_initial_token(
    State(
      Client,
      config.version,
      connection,
      local_connection_id,
      original_destination_connection_id,
      original_destination_connection_id,
      <<>>,
      False,
      False,
    ),
    initial_token,
  ))
}

/// Record the address-validation token every Initial this endpoint sends will
/// carry, on the driver that writes it and on the connection that budgets an
/// Initial payload around it.
///
/// The two have to move together. `protect_long` writes `initial_token` into
/// every Initial, and `connection_state` subtracts its width from what one
/// Initial may carry, so a token recorded in only one of them builds a
/// datagram past the 1200-byte floor - which is exactly what a server-chosen
/// Retry token would have done. Every change of `initial_token` goes through
/// here; both constructors start from the empty token a fresh connection
/// already budgets for.
fn record_initial_token(state: State, token: BitArray) -> State {
  State(
    ..state,
    initial_token: token,
    connection: connection_state.set_initial_token_bytes(
      state.connection,
      bit_array.byte_size(token),
    ),
  )
}

/// Start a server for one accepted client Initial packet.
pub fn start_server(
  config: connection_state.Config,
  tls: engine.Server,
  original_destination_connection_id: BitArray,
  local_connection_id: BitArray,
  peer_connection_id: BitArray,
  now_ms: Int,
) -> Result(State, Error) {
  use _ <- result.try(validate_connection_id(original_destination_connection_id))
  use _ <- result.try(validate_connection_id(local_connection_id))
  use _ <- result.try(validate_initial_peer_connection_id(peer_connection_id))
  use connection <- result.try(
    connection_state.new(config, now_ms) |> map_connection_result,
  )
  use connection <- result.try(
    connection_state.install_initial_keys(
      connection,
      original_destination_connection_id,
    )
    |> map_connection_result,
  )
  use connection <- result.try(
    connection_state.attach_server_tls(connection, tls)
    |> map_connection_result,
  )
  use connection <- result.try(
    connection_state.observe_peer_initial_connection_id(
      connection,
      peer_connection_id,
    )
    |> map_connection_result,
  )
  Ok(State(
    Server,
    config.version,
    connection,
    local_connection_id,
    peer_connection_id,
    original_destination_connection_id,
    <<>>,
    False,
    False,
  ))
}

/// Return the connection ID used to route incoming short-header packets.
pub fn local_connection_id(state: State) -> BitArray {
  state.local_connection_id
}

/// Return the current peer destination connection ID.
pub fn peer_connection_id(state: State) -> BitArray {
  state.peer_connection_id
}

/// Return stable connection progress.
pub fn phase(state: State) -> connection_state.Phase {
  connection_state.phase(state.connection)
}

/// Pull and clear core transport events.
pub fn take_events(state: State) -> #(State, List(connection_state.Event)) {
  let #(connection, events) = connection_state.take_events(state.connection)
  #(State(..state, connection: connection), events)
}

/// Poll packet spaces in encryption order and protect at most one datagram.
/// The caller must either commit the returned value after UDP send succeeds or
/// discard it and retain its original `State`.
pub fn prepare_datagram(
  state: State,
  maximum_frame_data_bytes: Int,
  now_ms: Int,
) -> Result(Option(PreparedDatagram), Error) {
  case maximum_frame_data_bytes > 0 && now_ms >= 0 {
    False -> Error(InvalidInput)
    True ->
      prepare_levels(
        state,
        [
          engine.Initial,
          engine.Handshake,
          engine.ZeroRtt,
          engine.OneRtt,
        ],
        maximum_frame_data_bytes,
        now_ms,
      )
  }
}

/// Prepare one exact-size DPLPMTUD probe on an established path.
///
/// `None` means a probe is already outstanding or discovery has reached its
/// current ceiling. The caller commits the returned datagram only after UDP
/// reports a successful send, exactly like `prepare_datagram`.
pub fn prepare_pmtu_probe(
  state: State,
  now_ms: Int,
) -> Result(Option(PreparedDatagram), Error) {
  case connection_state.start_pmtu_probe(state.connection) {
    Error(connection_state.PmtuFailure(pmtu.ProbeAlreadyOutstanding))
    | Error(connection_state.PmtuFailure(pmtu.NoLargerProbe)) -> Ok(None)
    Error(error) -> Error(ConnectionFailure(error))
    Ok(#(connection, target_size)) -> {
      let state = State(..state, connection: connection)
      let packet_number =
        connection_state.next_application_packet_number(connection)
      protect_pmtu_probe(
        state,
        packet_number,
        target_size,
        int.max(target_size - 64, 1),
        maximum_padding_adjustments,
        now_ms,
      )
    }
  }
}

/// Reset the confirmed path size to the 1200-byte floor and clear any
/// outstanding probe.
///
/// A datagram the local stack refuses as too large is exactly the signal RFC
/// 8899 section 4.3 calls a black hole: with Don't-Fragment set the kernel
/// will not split it, so the size this connection believed the path carried is
/// not a size it can send at all. Recovering is a path measurement, not a
/// socket failure, so the connection keeps running from the floor.
pub fn report_pmtu_black_hole(state: State) -> State {
  State(
    ..state,
    connection: connection_state.report_pmtu_black_hole(state.connection),
  )
}

/// Bytes to pass to one UDP send operation.
pub fn prepared_bytes(prepared: PreparedDatagram) -> BitArray {
  prepared.bytes
}

/// Commit a datagram only after the runtime reports a successful UDP send.
pub fn commit_datagram(
  prepared: PreparedDatagram,
  now_ms: Int,
) -> Result(State, Error) {
  commit_datagram_with_ecn(prepared, ecn.NotEct, now_ms)
}

/// Commit a successfully sent datagram with its actual IP ECN marking.
pub fn commit_datagram_with_ecn(
  prepared: PreparedDatagram,
  codepoint: ecn.Codepoint,
  now_ms: Int,
) -> Result(State, Error) {
  use connection <- result.try(
    connection_state.commit_packet(
      prepared.state.connection,
      prepared.level,
      prepared.packet_number,
      prepared.frames,
      bit_array.byte_size(prepared.bytes),
      codepoint,
      now_ms,
    )
    |> map_connection_result,
  )
  Ok(State(..prepared.state, connection: connection))
}

/// Authenticate every packet in one UDP datagram. Datagram amplification
/// credit is applied exactly once even when long-header packets are coalesced.
pub fn receive_datagram(
  state: State,
  datagram: BitArray,
  now_ms: Int,
) -> Result(State, Error) {
  receive_datagram_with_ecn(state, datagram, packet_space.NotEct, now_ms)
}

/// Authenticate one datagram and retain its observed IP ECN marking for ACKs.
pub fn receive_datagram_with_ecn(
  state: State,
  datagram: BitArray,
  codepoint: packet_space.ReceivedCodepoint,
  now_ms: Int,
) -> Result(State, Error) {
  case
    bit_array.bit_size(datagram) % 8 == 0
    && bit_array.byte_size(datagram) > 0
    && now_ms >= 0
  {
    False -> Error(InvalidInput)
    True -> {
      use connection <- result.try(
        connection_state.record_datagram_received(
          state.connection,
          bit_array.byte_size(datagram),
          now_ms,
        )
        |> map_connection_result,
      )
      receive_packets(
        State(..state, connection: connection),
        datagram,
        codepoint,
        now_ms,
      )
    }
  }
}

/// Advance recovery, validation, idle, close, and drain timers.
pub fn tick(state: State, now_ms: Int) -> Result(State, Error) {
  use connection <- result.try(
    connection_state.tick(state.connection, now_ms) |> map_connection_result,
  )
  Ok(State(..state, connection: connection))
}

/// Return the earliest QUIC timer deadline for an event-driven runtime.
pub fn next_deadline(state: State, now_ms: Int) -> Result(Option(Int), Error) {
  connection_state.next_deadline(state.connection, now_ms)
  |> map_connection_result
}

/// Apply a transport operation while preserving routing state.
pub fn update_connection(
  state: State,
  update: fn(connection_state.State) ->
    Result(connection_state.State, connection_state.Error),
) -> Result(State, Error) {
  use connection <- result.try(
    update(state.connection) |> map_connection_result,
  )
  Ok(State(..state, connection: connection))
}

/// Inspect the core connection for HTTP/3 stream orchestration.
pub fn connection(state: State) -> connection_state.State {
  state.connection
}

/// Replace the core connection after a typed HTTP/3 transport operation.
pub fn put_connection(
  state: State,
  connection: connection_state.State,
) -> State {
  State(..state, connection: connection)
}

fn prepare_levels(
  state: State,
  levels: List(engine.EncryptionLevel),
  maximum_frame_data_bytes: Int,
  now_ms: Int,
) -> Result(Option(PreparedDatagram), Error) {
  case levels {
    [] -> Ok(None)
    [level, ..rest] ->
      case
        connection_state.prepare_packet(
          state.connection,
          level,
          maximum_frame_data_bytes,
          now_ms,
        )
      {
        Error(connection_state.SpaceUnavailable)
        | Error(connection_state.MissingWriteKeys(_)) ->
          prepare_levels(state, rest, maximum_frame_data_bytes, now_ms)
        Error(error) -> Error(ConnectionFailure(error))
        Ok(connection_state.NoPacket(connection)) ->
          prepare_levels(
            State(..state, connection: connection),
            rest,
            maximum_frame_data_bytes,
            now_ms,
          )
        Ok(connection_state.PacketPrepared(connection, _, packet_number, frames)) ->
          case
            protect_prepared(
              State(..state, connection: connection),
              level,
              packet_number,
              frames,
              now_ms,
            )
          {
            Error(ConnectionFailure(connection_state.MissingWriteKeys(_))) ->
              prepare_levels(state, rest, maximum_frame_data_bytes, now_ms)
            outcome -> outcome
          }
      }
  }
}

fn protect_prepared(
  state: State,
  level: engine.EncryptionLevel,
  packet_number: Int,
  frames: List(frame.Frame),
  now_ms: Int,
) -> Result(Option(PreparedDatagram), Error) {
  case level {
    engine.Initial ->
      protect_padded_initial(
        state,
        packet_number,
        frames,
        0,
        maximum_padding_adjustments,
        now_ms,
      )
    engine.Handshake | engine.ZeroRtt -> {
      use bytes <- result.try(protect_long(state, level, packet_number, frames))
      make_prepared(state, level, packet_number, frames, bytes, now_ms)
    }
    engine.OneRtt -> {
      use #(connection, bytes) <- result.try(
        connection_state.protect_short_packet(
          state.connection,
          state.peer_connection_id,
          packet_number,
          False,
          frames,
          now_ms,
        )
        |> map_connection_result,
      )
      make_prepared(
        State(..state, connection: connection),
        level,
        packet_number,
        frames,
        bytes,
        now_ms,
      )
    }
  }
}

fn protect_padded_initial(
  state: State,
  packet_number: Int,
  frames: List(frame.Frame),
  padding: Int,
  attempts: Int,
  now_ms: Int,
) -> Result(Option(PreparedDatagram), Error) {
  let padded_frames = case padding > 0 {
    True -> list.append(frames, [frame.Padding(padding)])
    False -> frames
  }
  use bytes <- result.try(protect_long(
    state,
    engine.Initial,
    packet_number,
    padded_frames,
  ))
  let size = bit_array.byte_size(bytes)
  case size, attempts {
    value, _ if value == minimum_initial_datagram_bytes ->
      make_prepared(
        state,
        engine.Initial,
        packet_number,
        padded_frames,
        bytes,
        now_ms,
      )
    _, 0 -> Error(InvalidInput)
    value, _ -> {
      let adjusted = padding + minimum_initial_datagram_bytes - value
      case adjusted < 0 {
        True -> Error(InvalidInput)
        False ->
          protect_padded_initial(
            state,
            packet_number,
            frames,
            adjusted,
            attempts - 1,
            now_ms,
          )
      }
    }
  }
}

fn protect_pmtu_probe(
  state: State,
  packet_number: Int,
  target_size: Int,
  padding: Int,
  attempts: Int,
  now_ms: Int,
) -> Result(Option(PreparedDatagram), Error) {
  let frames = [frame.Ping, frame.Padding(padding)]
  use #(connection, bytes) <- result.try(
    connection_state.protect_short_packet(
      state.connection,
      state.peer_connection_id,
      packet_number,
      False,
      frames,
      now_ms,
    )
    |> map_connection_result,
  )
  let size = bit_array.byte_size(bytes)
  case size, attempts {
    value, _ if value == target_size ->
      make_prepared(
        State(..state, connection: connection),
        engine.OneRtt,
        packet_number,
        frames,
        bytes,
        now_ms,
      )
    _, 0 -> Error(InvalidInput)
    value, _ -> {
      let adjusted = padding + target_size - value
      case adjusted < 1 {
        True -> Error(InvalidInput)
        False ->
          protect_pmtu_probe(
            state,
            packet_number,
            target_size,
            adjusted,
            attempts - 1,
            now_ms,
          )
      }
    }
  }
}

fn make_prepared(
  state: State,
  level: engine.EncryptionLevel,
  packet_number: Int,
  frames: List(frame.Frame),
  bytes: BitArray,
  now_ms: Int,
) -> Result(Option(PreparedDatagram), Error) {
  use Nil <- result.try(
    connection_state.validate_send_budget(
      state.connection,
      level,
      frames,
      bit_array.byte_size(bytes),
      now_ms,
    )
    |> map_connection_result,
  )
  Ok(Some(PreparedDatagram(state, level, packet_number, frames, bytes)))
}

fn protect_long(
  state: State,
  level: engine.EncryptionLevel,
  packet_number: Int,
  frames: List(frame.Frame),
) -> Result(BitArray, Error) {
  let kind = case level {
    engine.Initial -> wire_packet.Initial(state.initial_token)
    engine.Handshake -> wire_packet.Handshake
    engine.ZeroRtt -> wire_packet.ZeroRtt
    engine.OneRtt -> wire_packet.Handshake
  }
  connection_state.protect_long_packet(
    state.connection,
    kind,
    state.peer_connection_id,
    state.local_connection_id,
    packet_number,
    frames,
  )
  |> map_connection_result
}

fn receive_packets(
  state: State,
  datagram: BitArray,
  codepoint: packet_space.ReceivedCodepoint,
  now_ms: Int,
) -> Result(State, Error) {
  case datagram {
    <<>> -> Ok(state)
    <<first, _rest:bits>> ->
      case int.bitwise_and(first, 0x80) != 0 {
        True -> receive_long_packet(state, datagram, codepoint, now_ms)
        False -> receive_short_packet(state, datagram, codepoint, now_ms)
      }
    _ -> Error(InvalidInput)
  }
}

fn receive_long_packet(
  state: State,
  datagram: BitArray,
  codepoint: packet_space.ReceivedCodepoint,
  now_ms: Int,
) -> Result(State, Error) {
  use #(invariant, _) <- result.try(
    packet.parse_long(datagram) |> map_packet_result,
  )
  case invariant {
    packet.VersionNegotiation(header, versions) ->
      receive_version_negotiation(state, header, versions)
    packet.Retry(header, token, integrity_tag) ->
      receive_retry(state, datagram, header, token, integrity_tag, now_ms)
    packet.UnknownVersion(_, _) -> Error(InvalidInput)
    packet.Initial(header, _, _)
    | packet.ZeroRtt(header, _)
    | packet.Handshake(header, _) -> {
      let packet.LongHeader(_, packet_version, _, _) = header
      receive_supported_long_packet(
        state,
        datagram,
        packet_version,
        codepoint,
        now_ms,
      )
    }
  }
}

fn receive_supported_long_packet(
  original_state: State,
  datagram: BitArray,
  packet_version: Version,
  codepoint: packet_space.ReceivedCodepoint,
  now_ms: Int,
) -> Result(State, Error) {
  case prepare_compatible_version(original_state, packet_version) {
    Error(error) -> Error(error)
    Ok(None) -> Ok(original_state)
    Ok(Some(state)) -> {
      use receipt <- result.try(
        connection_state.receive_protected_long_packet(
          state.connection,
          datagram,
          codepoint,
          now_ms,
        )
        |> map_connection_result,
      )
      let connection_state.LongPacketReceipt(
        connection,
        destination,
        source,
        remaining,
      ) = receipt
      use _ <- result.try(require_destination(state, destination))
      let peer_connection_id = case state.role, source {
        Client, <<>> -> state.peer_connection_id
        Client, value -> value
        Server, _ -> state.peer_connection_id
      }
      let connection = case state.role, state.server_packet_received, source {
        Client, False, value if value != <<>> ->
          connection_state.observe_peer_initial_connection_id(connection, value)
          |> map_connection_result
        _, _, _ -> Ok(connection)
      }
      use connection <- result.try(connection)
      let server_packet_received = case state.role {
        Client -> True
        Server -> state.server_packet_received
      }
      let authenticated =
        State(
          ..state,
          connection: connection,
          peer_connection_id: peer_connection_id,
          server_packet_received: server_packet_received,
        )
      case receive_packets(authenticated, remaining, codepoint, now_ms) {
        Ok(next) -> Ok(next)
        Error(error) ->
          case discardable_receive_error(error) {
            True -> Ok(authenticated)
            False -> Error(error)
          }
      }
    }
  }
}

fn prepare_compatible_version(
  state: State,
  packet_version: Version,
) -> Result(Option(State), Error) {
  case packet_version == state.version, state.role {
    True, _ -> Ok(Some(state))
    False, Server -> Ok(None)
    False, Client ->
      case
        connection_state.negotiate_compatible_version(
          state.connection,
          packet_version,
          state.peer_connection_id,
        )
      {
        Ok(connection) ->
          Ok(Some(
            State(..state, version: packet_version, connection: connection),
          ))
        // nolint: thrown_away_error -- discard unauthenticated alternate versions.
        Error(_) -> Ok(None)
      }
  }
}

fn receive_version_negotiation(
  state: State,
  header: packet.LongHeader,
  versions: List(Version),
) -> Result(State, Error) {
  let packet.LongHeader(_, _, destination, source) = header
  case
    state.role == Client
    && !state.server_packet_received
    && destination == state.local_connection_id
    && source == state.original_destination_connection_id
    && !list.contains(versions, state.version)
  {
    True -> Error(VersionNegotiationReceived(versions))
    False -> Ok(state)
  }
}

fn receive_retry(
  state: State,
  datagram: BitArray,
  header: packet.LongHeader,
  token: BitArray,
  integrity_tag: BitArray,
  now_ms: Int,
) -> Result(State, Error) {
  let packet.LongHeader(_, packet_version, destination, source) = header
  case
    state.role == Client
    && !state.server_packet_received
    && !state.retry_received
    && packet_version == state.version
    && destination == state.local_connection_id
    && source != state.original_destination_connection_id
  {
    False -> Ok(state)
    True -> {
      use retry_without_tag <- result.try(split_retry_tag(datagram))
      let carryable_token = carryable_initial_token(token)
      case
        retry_integrity.verify(
          state.version,
          state.original_destination_connection_id,
          retry_without_tag,
          integrity_tag,
        )
      {
        // nolint: thrown_away_error -- RFC 9000 requires silent Retry discard.
        Error(_) -> Ok(state)
        // The Retry is authenticated and the server picked a token no Initial
        // can repeat inside the 1200-byte floor. Dropping the token would get
        // the next Initial rejected and sending it would build a datagram no
        // path is known to carry, so the attempt ends here with a typed
        // failure instead of stalling until the idle timeout. The check is
        // deliberately after the integrity tag: a forged Retry must not be
        // able to end a connection.
        Ok(Nil) if !carryable_token ->
          Error(RetryTokenTooLarge(
            bit_array.byte_size(token),
            connection_state.maximum_initial_token_bytes(),
          ))
        Ok(Nil) -> {
          use connection <- result.try(
            connection_state.process_retry(state.connection, source, now_ms)
            |> map_connection_result,
          )
          use connection <- result.try(
            connection_state.observe_peer_initial_connection_id(
              connection,
              source,
            )
            |> map_connection_result,
          )
          Ok(record_initial_token(
            State(
              ..state,
              connection: connection,
              peer_connection_id: source,
              server_packet_received: True,
              retry_received: True,
            ),
            token,
          ))
        }
      }
    }
  }
}

fn split_retry_tag(datagram: BitArray) -> Result(BitArray, Error) {
  let prefix_bits = bit_array.bit_size(datagram) - 128
  case prefix_bits > 0 {
    False -> Error(InvalidInput)
    True ->
      case datagram {
        <<prefix:bits-size(prefix_bits), _:bits-size(128)>> -> Ok(prefix)
        _ -> Error(InvalidInput)
      }
  }
}

fn receive_short_packet(
  state: State,
  datagram: BitArray,
  codepoint: packet_space.ReceivedCodepoint,
  now_ms: Int,
) -> Result(State, Error) {
  case
    connection_state.receive_protected_short_packet(
      state.connection,
      datagram,
      bit_array.byte_size(state.local_connection_id),
      codepoint,
      now_ms,
    )
  {
    // A peer can coalesce or reorder 1-RTT before this endpoint installs both
    // application directions. Discard that packet without rolling back the
    // authenticated Initial/Handshake packets already processed.
    Error(connection_state.MissingReadKeys(_))
    | Error(connection_state.MissingWriteKeys(_)) -> Ok(state)
    Error(error) -> Error(ConnectionFailure(error))
    Ok(receipt) -> {
      let connection_state.ShortPacketReceipt(connection, destination, _, _) =
        receipt
      use _ <- result.try(require_destination(state, destination))
      Ok(State(..state, connection: connection))
    }
  }
}

fn require_destination(
  state: State,
  destination: BitArray,
) -> Result(Nil, Error) {
  // Before a client receives the server's first Initial it continues to use
  // the original destination connection ID that it selected. A server is
  // therefore required to route both that temporary alias and its own source
  // connection ID during the handshake (RFC 9000 sections 7.2 and 17.2.2).
  let original_server_initial =
    state.role == Server
    && connection_state.phase(state.connection) == connection_state.Handshaking
    && destination == state.original_destination_connection_id
  case destination == state.local_connection_id || original_server_initial {
    True -> Ok(Nil)
    False -> Error(DestinationConnectionIdMismatch)
  }
}

fn validate_connection_id(value: BitArray) -> Result(Nil, Error) {
  let size = bit_array.byte_size(value)
  case bit_array.bit_size(value) % 8 == 0 && size >= 8 && size <= 20 {
    True -> Ok(Nil)
    False -> Error(InvalidInput)
  }
}

fn validate_initial_peer_connection_id(value: BitArray) -> Result(Nil, Error) {
  let size = bit_array.byte_size(value)
  case bit_array.bit_size(value) % 8 == 0 && size <= 20 {
    True -> Ok(Nil)
    False -> Error(InvalidInput)
  }
}

/// Whether a token is whole bytes and narrow enough to ride an Initial that
/// still fits the 1200-byte floor, which is the only size every path carries
/// before DPLPMTUD has confirmed more.
///
/// `connection_state.maximum_initial_token_bytes` owns the width: it is the
/// same budget the send path subtracts from an Initial's payload, so checking
/// every token against it here is what makes that budget a real ceiling.
fn carryable_initial_token(value: BitArray) -> Bool {
  bit_array.bit_size(value) % 8 == 0
  && bit_array.byte_size(value)
  <= connection_state.maximum_initial_token_bytes()
}

fn map_connection_result(
  value: Result(value, connection_state.Error),
) -> Result(value, Error) {
  case value {
    Ok(updated) -> Ok(updated)
    Error(error) -> Error(ConnectionFailure(error))
  }
}

fn map_packet_result(
  value: Result(value, packet.Error),
) -> Result(value, Error) {
  case value {
    Ok(decoded) -> Ok(decoded)
    Error(error) -> Error(PacketFailure(error))
  }
}

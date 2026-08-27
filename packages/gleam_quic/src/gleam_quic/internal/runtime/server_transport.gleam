//// One generic QUIC server connection over a listener-owned UDP socket.

import gleam/bit_array
import gleam/int
import gleam/option.{type Option}
import gleam/result
import gleam_quic/internal/connection_state as transport
import gleam_quic/internal/driver
import gleam_quic/internal/ecn
import gleam_quic/internal/packet_space
import gleam_quic/internal/runtime/budget
import gleam_quic/internal/runtime/connection
import gleam_quic/internal/stateless_reset
import gleam_quic/internal/tls/anti_replay
import gleam_quic/internal/tls/authentication
import gleam_quic/internal/tls/engine
import gleam_quic/internal/tls/extension_value
import gleam_quic/internal/tls/hello
import gleam_quic/internal/tls/resumption
import gleam_quic/internal/udp
import gleam_quic/stream_id
import gleam_quic/transport_parameter
import gleam_quic/version.{type Version}

// RFC 9000 section 18.2: max_udp_payload_size is a limit on what this endpoint
// is willing to receive, and its default is 65_527. Sending stays governed by
// DPLPMTUD, which starts at the 1200-byte floor and probes every larger size.
const maximum_udp_payload_size = 65_527

const session_ticket_lifetime_seconds = 86_400

/// Fixed credentials, ALPN policy, operational keys, and transport bounds.
pub type Config {
  Config(
    certificate_chain: List(BitArray),
    signing_key: authentication.SigningKey,
    signature_scheme: extension_value.SignatureScheme,
    alternative_credentials: List(engine.ServerCredential),
    client_authentication: engine.ClientAuthentication,
    application_protocols: List(BitArray),
    ticket_key: BitArray,
    stateless_reset_key: BitArray,
    allow_zero_rtt: Bool,
    idle_timeout_milliseconds: Int,
    congestion_control: transport.CongestionAlgorithm,
    bidirectional_stream_limit: Int,
    unidirectional_stream_limit: Int,
    stream_buffer_limit: Int,
    datagram_limit: Int,
    path_dont_fragment: Bool,
  )
}

/// State for one peer path and server-selected connection ID.
pub opaque type State {
  State(config: Config, connection: connection.State, ticket_issued: Bool)
}

/// A protected datagram awaiting listener send confirmation.
pub opaque type PreparedDatagram {
  PreparedDatagram(state: State, prepared: connection.PreparedDatagram)
}

/// TLS, transport, stateless-reset, or input failure.
pub type Error {
  InvalidInput
  TlsFailure(engine.Error)
  DriverFailure(driver.Error)
  StatelessResetFailure(stateless_reset.Error)
}

/// Authenticate a first client Initial and create routed server state.
pub fn accept_initial(
  config config: Config,
  protocol_version protocol_version: Version,
  original_destination_connection_id original_destination_connection_id: BitArray,
  local_connection_id local_connection_id: BitArray,
  peer_connection_id peer_connection_id: BitArray,
  retry_source_connection_id retry_source_connection_id: Option(BitArray),
  peer peer: udp.Endpoint,
  datagram datagram: BitArray,
  marking marking: packet_space.ReceivedCodepoint,
  now now: Int,
  resumption_policy resumption_policy: resumption.ServerPolicy,
) -> Result(State, Error) {
  use Nil <- result.try(validate_initial_inputs(
    config,
    original_destination_connection_id,
    local_connection_id,
    peer_connection_id,
    retry_source_connection_id,
    datagram,
    now,
  ))
  use reset_token <- result.try(
    stateless_reset.token_for(config.stateless_reset_key, local_connection_id)
    |> result.map_error(StatelessResetFailure),
  )
  let tls_config =
    engine.ServerConfig(
      version: protocol_version,
      application_protocols: config.application_protocols,
      transport_parameters: server_transport_parameters(
        protocol_version,
        original_destination_connection_id,
        local_connection_id,
        retry_source_connection_id,
        config.idle_timeout_milliseconds,
        config.bidirectional_stream_limit,
        config.unidirectional_stream_limit,
        config.datagram_limit,
        reset_token,
      ),
      certificate_chain: config.certificate_chain,
      signing_key: config.signing_key,
      signature_scheme: config.signature_scheme,
      alternative_credentials: config.alternative_credentials,
      client_authentication: config.client_authentication,
    )
  let resumption_policy = case retry_source_connection_id {
    option.Some(_) -> resumption.reject_early_data(resumption_policy)
    option.None -> resumption_policy
  }
  use tls <- result.try(
    engine.start_server_with_resumption(tls_config, resumption_policy)
    |> result.map_error(TlsFailure),
  )
  use quic <- result.try(
    driver.start_server(
      server_transport_config(config, protocol_version),
      tls,
      case retry_source_connection_id {
        option.Some(_) -> local_connection_id
        option.None -> original_destination_connection_id
      },
      local_connection_id,
      peer_connection_id,
      now,
    )
    |> result.map_error(DriverFailure),
  )
  receive_datagram(
    State(config, connection.new(peer, quic), False),
    datagram,
    marking,
    now,
    resumption_policy,
  )
}

/// Current authenticated peer path.
pub fn peer(state: State) -> udp.Endpoint {
  connection.peer(state.connection)
}

/// Adopt an authenticated replacement peer path.
pub fn with_peer(state: State, peer: udp.Endpoint) -> State {
  State(..state, connection: connection.with_peer(state.connection, peer))
}

/// Router connection ID.
pub fn local_connection_id(state: State) -> BitArray {
  connection.local_connection_id(state.connection)
}

/// Stable lifecycle phase.
pub fn phase(state: State) -> transport.Phase {
  connection.phase(state.connection)
}

/// Hold this connection's advertised receive credit inside the endpoint memory
/// it has been granted, and report every byte it keeps resident.
pub fn apply_memory_grant(
  state: State,
  granted_bytes: Int,
  refused: Bool,
) -> #(State, Int) {
  let #(inner, retained) =
    connection.apply_memory_grant(state.connection, granted_bytes, refused)
  #(State(..state, connection: inner), retained)
}

/// Whether authenticated 1-RTT keys are installed.
pub fn established(state: State) -> Bool {
  connection.established(state.connection)
}

/// Authenticated ALPN selection, when the TLS handshake has completed.
pub fn application_protocol(state: State) -> Option(BitArray) {
  connection.application_protocol(state.connection)
}

/// Authenticated cipher selection, when the TLS handshake has completed.
pub fn cipher_suite(state: State) -> Option(hello.CipherSuite) {
  connection.cipher_suite(state.connection)
}

/// Whether this connection authenticated with a resumption ticket.
pub fn resumed(state: State) -> Bool {
  connection.server_resumed(state.connection)
}

/// Return the path- and signature-verified client identity, when configured.
pub fn client_identity(state: State) -> Option(authentication.VerifiedPeer) {
  connection.server_client_identity(state.connection)
}

/// Whether replay-guarded early data was accepted on this connection.
pub fn early_data_accepted(state: State) -> Bool {
  connection.server_early_data_accepted(state.connection)
}

/// Whether the authenticated peer offered early data.
pub fn early_data_attempted(state: State) -> Bool {
  connection.server_early_data_attempted(state.connection)
}

/// Refresh replay state and authenticate one datagram.
pub fn receive_datagram(
  state: State,
  datagram: BitArray,
  marking: packet_space.ReceivedCodepoint,
  now: Int,
  resumption_policy: resumption.ServerPolicy,
) -> Result(State, Error) {
  use connection <- result.try(
    connection.refresh_server_resumption_policy(
      state.connection,
      resumption_policy,
    )
    |> result.map_error(DriverFailure),
  )
  use connection <- result.try(
    connection.receive_datagram(connection, datagram, marking, now)
    |> result.map_error(DriverFailure),
  )
  Ok(State(..state, connection: connection))
}

/// Advance protocol timers.
pub fn tick(state: State, now: Int) -> Result(State, Error) {
  connection.tick(state.connection, now)
  |> result.map(fn(connection) { State(..state, connection: connection) })
  |> result.map_error(DriverFailure)
}

/// Queue one session ticket after address-token work has been queued.
pub fn issue_session_ticket_if_ready(
  state: State,
  now: Int,
) -> Result(State, Error) {
  maybe_issue_ticket(state, now)
}

/// Earliest protocol deadline.
pub fn next_deadline(state: State, now: Int) -> Result(Option(Int), Error) {
  connection.next_deadline(state.connection, now)
  |> result.map_error(DriverFailure)
}

/// Pull and clear ordered transport events.
pub fn take_events(state: State) -> #(State, List(transport.Event)) {
  let #(connection, events) = connection.take_events(state.connection)
  #(State(..state, connection: connection), events)
}

/// Protect at most one bounded datagram.
pub fn prepare_datagram(
  state: State,
  maximum_frame_data_bytes: Int,
  now: Int,
) -> Result(Option(PreparedDatagram), Error) {
  connection.prepare_datagram(state.connection, maximum_frame_data_bytes, now)
  |> result.map(fn(value) {
    case value {
      option.None -> option.None
      option.Some(prepared) -> option.Some(PreparedDatagram(state, prepared))
    }
  })
  |> result.map_error(DriverFailure)
}

pub fn prepared_bytes(prepared: PreparedDatagram) -> BitArray {
  connection.prepared_bytes(prepared.prepared)
}

/// Commit one confirmed UDP send.
pub fn commit_datagram(
  prepared: PreparedDatagram,
  marking: ecn.Codepoint,
  now: Int,
) -> Result(State, Error) {
  connection.commit_datagram(prepared.prepared, marking, now)
  |> result.map(fn(connection) {
    State(..prepared.state, connection: connection)
  })
  |> result.map_error(DriverFailure)
}

pub fn open_stream(
  state: State,
  direction: stream_id.Direction,
) -> Result(#(State, Int), Error) {
  connection.open_stream(state.connection, direction)
  |> result.map(fn(output) {
    let #(connection, identifier) = output
    #(State(..state, connection: connection), identifier)
  })
  |> result.map_error(DriverFailure)
}

pub fn send(
  state: State,
  identifier: Int,
  bytes: BitArray,
  finish: Bool,
) -> Result(State, Error) {
  connection.send(state.connection, identifier, bytes, finish)
  |> result.map(fn(connection) { State(..state, connection: connection) })
  |> result.map_error(DriverFailure)
}

pub fn buffered_send_bytes(
  state: State,
  identifier: Int,
) -> Result(Int, Error) {
  connection.buffered_send_bytes(state.connection, identifier)
  |> result.map_error(DriverFailure)
}

pub fn read(
  state: State,
  identifier: Int,
  maximum_bytes: Int,
) -> Result(#(State, connection.Read), Error) {
  connection.read(state.connection, identifier, maximum_bytes)
  |> result.map(fn(output) {
    let #(connection, read) = output
    #(State(..state, connection: connection), read)
  })
  |> result.map_error(DriverFailure)
}

pub fn reset(
  state: State,
  identifier: Int,
  application_error_code: Int,
) -> Result(State, Error) {
  connection.reset(state.connection, identifier, application_error_code)
  |> result.map(fn(connection) { State(..state, connection: connection) })
  |> result.map_error(DriverFailure)
}

pub fn send_datagram(state: State, payload: BitArray) -> Result(State, Error) {
  connection.send_datagram(state.connection, payload)
  |> result.map(fn(connection) { State(..state, connection: connection) })
  |> result.map_error(DriverFailure)
}

pub fn maximum_datagram_size(state: State) -> Result(Int, Error) {
  connection.maximum_datagram_size(state.connection)
  |> result.map_error(DriverFailure)
}

pub fn ping(state: State) -> Result(State, Error) {
  connection.ping(state.connection)
  |> result.map(fn(connection) { State(..state, connection: connection) })
  |> result.map_error(DriverFailure)
}

/// Queue one authenticated NEW_TOKEN frame on an established connection.
pub fn queue_new_token(state: State, token: BitArray) -> Result(State, Error) {
  connection.queue_new_token(state.connection, token)
  |> result.map(fn(next) { State(..state, connection: next) })
  |> result.map_error(DriverFailure)
}

pub fn set_congestion_control(
  state: State,
  algorithm: transport.CongestionAlgorithm,
) -> Result(State, Error) {
  connection.set_congestion_control(state.connection, algorithm)
  |> result.map(fn(connection) { State(..state, connection: connection) })
  |> result.map_error(DriverFailure)
}

pub fn begin_path_validation(
  state: State,
  challenge: BitArray,
  now: Int,
) -> Result(State, Error) {
  connection.begin_path_validation(state.connection, challenge, False, now)
  |> result.map(fn(connection) { State(..state, connection: connection) })
  |> result.map_error(DriverFailure)
}

pub fn path_validation_in_progress(state: State) -> Bool {
  connection.path_validation_in_progress(state.connection)
}

pub fn path_mtu(state: State) -> Int {
  connection.path_mtu(state.connection)
}

pub fn pmtu_discovery_complete(state: State) -> Bool {
  connection.pmtu_discovery_complete(state.connection)
}

/// Return the path to the 1200-byte floor after the local stack refused a
/// datagram this connection believed the path carried.
pub fn report_pmtu_black_hole(state: State) -> State {
  State(
    ..state,
    connection: connection.report_pmtu_black_hole(state.connection),
  )
}

pub fn prepare_pmtu_probe(
  state: State,
  now: Int,
) -> Result(Option(PreparedDatagram), Error) {
  connection.prepare_pmtu_probe(state.connection, now)
  |> result.map(fn(value) {
    case value {
      option.None -> option.None
      option.Some(prepared) -> option.Some(PreparedDatagram(state, prepared))
    }
  })
  |> result.map_error(DriverFailure)
}

pub fn path_stats(state: State) -> transport.PathSnapshot {
  connection.path_stats(state.connection)
}

pub fn stats(state: State) -> connection.Stats {
  connection.stats(state.connection)
}

pub fn replay_cache(state: State) -> Option(anti_replay.Cache) {
  connection.server_replay_cache(state.connection)
}

pub fn close(state: State, code: Int, reason: String, now: Int) -> State {
  State(
    ..state,
    connection: connection.close(state.connection, code, reason, now),
  )
}

fn maybe_issue_ticket(state: State, now: Int) -> Result(State, Error) {
  case
    state.ticket_issued,
    connection.can_issue_session_ticket(state.connection)
  {
    True, _ | _, False -> Ok(state)
    False, True ->
      connection.issue_session_ticket(
        state.connection,
        state.config.ticket_key,
        now,
        session_ticket_lifetime_seconds,
        state.config.allow_zero_rtt,
      )
      |> result.map(fn(connection) {
        State(..state, connection: connection, ticket_issued: True)
      })
      |> result.map_error(DriverFailure)
  }
}

fn server_transport_config(
  config: Config,
  version: Version,
) -> transport.Config {
  let defaults = transport.default_config(transport.Server)
  transport.Config(
    ..defaults,
    version: version,
    path_dont_fragment: config.path_dont_fragment,
    congestion_algorithm: config.congestion_control,
    idle_timeout_milliseconds: config.idle_timeout_milliseconds,
    maximum_peer_streams_bidirectional: config.bidirectional_stream_limit,
    maximum_peer_streams_unidirectional: config.unidirectional_stream_limit,
    maximum_stream_receive_buffer: config.stream_buffer_limit,
    maximum_stream_send_buffer: config.stream_buffer_limit,
    // The connection-level receive credit this server opens with is the credit
    // its endpoint charged admission for, and no more. Everything above it is
    // granted before it is advertised.
    initial_receive_data: budget.initial_receive_credit(),
    receive_data_window: budget.growth_step(),
    maximum_total_streams: config.bidirectional_stream_limit
      + config.unidirectional_stream_limit,
    maximum_udp_payload_size: maximum_udp_payload_size,
    maximum_datagram_frame_size: int.min(
      config.datagram_limit,
      maximum_udp_payload_size,
    ),
  )
}

fn server_transport_parameters(
  protocol_version: Version,
  original_destination_connection_id: BitArray,
  local_connection_id: BitArray,
  retry_source_connection_id: Option(BitArray),
  idle_timeout_milliseconds: Int,
  bidirectional_stream_limit: Int,
  unidirectional_stream_limit: Int,
  datagram_limit: Int,
  reset_token: BitArray,
) -> List(transport_parameter.Parameter) {
  let parameters = [
    transport_parameter.GreaseQuicBit,
    transport_parameter.VersionInformation(protocol_version, [
      version.Version2,
      version.Version1,
    ]),
    transport_parameter.OriginalDestinationConnectionId(
      original_destination_connection_id,
    ),
    transport_parameter.InitialSourceConnectionId(local_connection_id),
    transport_parameter.StatelessResetToken(reset_token),
    transport_parameter.MaxIdleTimeout(idle_timeout_milliseconds),
    transport_parameter.MaxUdpPayloadSize(maximum_udp_payload_size),
    // Grant-before-growth starts here. This is the only receive credit a
    // server promises before it has asked its endpoint for room, so it is the
    // credit the endpoint's admission charge has to fund, and the two are the
    // same constant. A connection that wants a wider window asks for one on
    // its first turn and advertises it as soon as the grant lands.
    transport_parameter.InitialMaxData(budget.initial_receive_credit()),
    transport_parameter.InitialMaxStreamDataBidiLocal(262_144),
    transport_parameter.InitialMaxStreamDataBidiRemote(262_144),
    transport_parameter.InitialMaxStreamDataUni(262_144),
    transport_parameter.InitialMaxStreamsBidi(bidirectional_stream_limit),
    transport_parameter.InitialMaxStreamsUni(unidirectional_stream_limit),
    transport_parameter.ActiveConnectionIdLimit(4),
    transport_parameter.MaxDatagramFrameSize(int.min(
      datagram_limit,
      maximum_udp_payload_size,
    )),
  ]
  case retry_source_connection_id {
    option.Some(connection_id) -> [
      transport_parameter.RetrySourceConnectionId(connection_id),
      ..parameters
    ]
    option.None -> parameters
  }
}

fn validate_initial_inputs(
  config: Config,
  original_destination_connection_id: BitArray,
  local_connection_id: BitArray,
  peer_connection_id: BitArray,
  retry_source_connection_id: Option(BitArray),
  datagram: BitArray,
  now: Int,
) -> Result(Nil, Error) {
  let valid_routing_id = fn(value) {
    let size = bit_array.byte_size(value)
    bit_array.bit_size(value) % 8 == 0 && size >= 8 && size <= 20
  }
  let valid_peer_id = fn(value) {
    bit_array.bit_size(value) % 8 == 0 && bit_array.byte_size(value) <= 20
  }
  case
    config.certificate_chain != []
    && config.application_protocols != []
    && bit_array.byte_size(config.ticket_key) == 32
    && bit_array.byte_size(config.stateless_reset_key) == 32
    && config.bidirectional_stream_limit > 0
    && config.unidirectional_stream_limit > 0
    && config.stream_buffer_limit > 0
    && config.datagram_limit > 0
    && valid_routing_id(original_destination_connection_id)
    && valid_routing_id(local_connection_id)
    && valid_peer_id(peer_connection_id)
    && case retry_source_connection_id {
      option.Some(value) ->
        value == local_connection_id && valid_routing_id(value)
      option.None -> True
    }
    && bit_array.byte_size(datagram) >= 1200
    && now >= 0
  {
    True -> Ok(Nil)
    False -> Error(InvalidInput)
  }
}

//// One native HTTP/3 server connection over a listener-owned UDP socket.

import gleam/bit_array
import gleam/int
import gleam/option.{type Option, None, Some}
import gleam/result
import gleam_quic/internal/connection_state as transport
import gleam_quic/internal/driver
import gleam_quic/internal/ecn
import gleam_quic/internal/http3/connection_state as http3_state
import gleam_quic/internal/http3/drain
import gleam_quic/internal/http3/session
import gleam_quic/internal/packet_space
import gleam_quic/internal/qpack/header.{type Header}
import gleam_quic/internal/tls/anti_replay
import gleam_quic/internal/tls/authentication
import gleam_quic/internal/tls/engine
import gleam_quic/internal/tls/extension_value
import gleam_quic/internal/tls/resumption
import gleam_quic/internal/udp
import gleam_quic/transport_parameter
import gleam_quic/version.{type Version}

// A 1452-byte UDP payload fits a 1500-byte IPv6 path without IP
// fragmentation. DPLPMTUD starts at 1200 and confirms every larger size.
const maximum_datagram_frame_bytes = 1452

const session_ticket_lifetime_seconds = 86_400

/// Fixed credentials and bounds inherited from the listener.
pub type Config {
  Config(
    certificate_chain: List(BitArray),
    signing_key: authentication.SigningKey,
    signature_scheme: extension_value.SignatureScheme,
    alternative_credentials: List(engine.ServerCredential),
    ticket_key: BitArray,
    http_datagrams: Bool,
    maximum_body_bytes: Int,
  )
}

/// Stable connection-level early-data outcome.
pub type EarlyDataStatus {
  NotAttempted
  Pending
  Accepted
  Rejected
}

/// Runtime traffic counters owned above the pure transport core.
pub type Stats {
  Stats(
    packets_received: Int,
    packets_sent: Int,
    data_received: Int,
    data_sent: Int,
    acknowledgements_sent: Int,
    retransmissions: Int,
    flushes: Int,
    packets_coalesced: Int,
  )
}

/// A handshaking driver or an established HTTP/3 session.
type Protocol {
  Handshaking(driver.State)
  Established(session.State)
}

/// State for one peer address and one server-selected connection ID.
pub opaque type State {
  State(
    config: Config,
    peer: udp.Endpoint,
    original_destination_connection_id: BitArray,
    local_connection_id: BitArray,
    protocol: Protocol,
    ticket_issued: Bool,
    early_data_status: EarlyDataStatus,
    packets_received: Int,
    packets_sent: Int,
    data_received: Int,
    data_sent: Int,
    flushes: Int,
  )
}

/// A protected datagram awaiting listener UDP-send confirmation.
pub opaque type PreparedDatagram {
  DriverDatagram(State, driver.PreparedDatagram)
  SessionDatagram(State, session.PreparedDatagram)
}

/// Credential, TLS, QUIC, HTTP/3, or state transition failure.
pub type Error {
  InvalidInput
  TlsFailure(engine.Error)
  DriverFailure(driver.Error)
  SessionFailure(session.Error)
}

/// Authenticate the first client Initial and create a routed server state.
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
  now_ms now_ms: Int,
  resumption_policy resumption_policy: resumption.ServerPolicy,
) -> Result(State, Error) {
  use Nil <- result.try(validate_initial_inputs(
    config,
    original_destination_connection_id,
    local_connection_id,
    peer_connection_id,
    retry_source_connection_id,
    datagram,
    now_ms,
  ))
  let tls_config =
    engine.ServerConfig(
      version: protocol_version,
      application_protocols: [<<"h3">>],
      transport_parameters: server_transport_parameters(
        protocol_version,
        original_destination_connection_id,
        local_connection_id,
        retry_source_connection_id,
        config.http_datagrams,
      ),
      certificate_chain: config.certificate_chain,
      signing_key: config.signing_key,
      signature_scheme: config.signature_scheme,
      alternative_credentials: config.alternative_credentials,
    )
  let resumption_policy = case retry_source_connection_id {
    Some(_) -> resumption.reject_early_data(resumption_policy)
    None -> resumption_policy
  }
  use tls <- result.try(
    engine.start_server_with_resumption(tls_config, resumption_policy)
    |> result.map_error(TlsFailure),
  )
  use quic <- result.try(
    driver.start_server(
      server_transport_config(
        protocol_version,
        config.http_datagrams,
        config.maximum_body_bytes,
      ),
      tls,
      case retry_source_connection_id {
        Some(_) -> local_connection_id
        None -> original_destination_connection_id
      },
      local_connection_id,
      peer_connection_id,
      now_ms,
    )
    |> result.map_error(DriverFailure),
  )
  let state =
    State(
      config,
      peer,
      original_destination_connection_id,
      local_connection_id,
      Handshaking(quic),
      False,
      NotAttempted,
      0,
      0,
      0,
      0,
      0,
    )
  receive_datagram(
    state: state,
    datagram: datagram,
    marking: marking,
    now_ms: now_ms,
    resumption_policy: resumption_policy,
  )
}

/// Return the current peer endpoint.
pub fn peer(state: State) -> udp.Endpoint {
  state.peer
}

/// Return whether TLS has promoted this transport to an HTTP/3 session.
pub fn is_established(state: State) -> Bool {
  case state.protocol {
    Handshaking(_) -> False
    Established(_) -> True
  }
}

/// Adopt a newly authenticated peer endpoint after NAT rebinding or migration.
pub fn with_peer(state: State, peer: udp.Endpoint) -> State {
  State(..state, peer: peer)
}

/// Validate one authenticated candidate peer address before adopting it.
pub fn begin_path_validation(
  state: State,
  challenge: BitArray,
  now_ms: Int,
) -> Result(State, Error) {
  case state.protocol {
    Handshaking(_) -> Error(InvalidInput)
    Established(http3) ->
      session.begin_path_validation(http3, challenge, now_ms)
      |> result.map(fn(next) { State(..state, protocol: Established(next)) })
      |> result.map_error(SessionFailure)
  }
}

/// Refresh replay state, authenticate a datagram, and promote to HTTP/3 once
/// the TLS handshake is established.
pub fn receive_datagram(
  state state: State,
  datagram datagram: BitArray,
  marking marking: packet_space.ReceivedCodepoint,
  now_ms now_ms: Int,
  resumption_policy resumption_policy: resumption.ServerPolicy,
) -> Result(State, Error) {
  let received = bit_array.byte_size(datagram)
  case state.protocol {
    Handshaking(quic) -> {
      use quic <- result.try(
        refresh_driver_policy(quic, resumption_policy)
        |> result.map_error(DriverFailure),
      )
      use quic <- result.try(
        driver.receive_datagram_with_ecn(quic, datagram, marking, now_ms)
        |> result.map_error(DriverFailure),
      )
      promote(
        State(
          ..state,
          protocol: Handshaking(quic),
          packets_received: state.packets_received + 1,
          data_received: state.data_received + received,
        ),
        now_ms,
      )
    }
    Established(http3) -> {
      use http3 <- result.try(
        session.receive_datagram(http3, datagram, marking, now_ms)
        |> result.map_error(SessionFailure),
      )
      Ok(
        State(
          ..state,
          protocol: Established(http3),
          packets_received: state.packets_received + 1,
          data_received: state.data_received + received,
        ),
      )
    }
  }
}

/// Advance loss, PTO, idle, validation, close, and drain timers.
pub fn tick(state: State, now_ms: Int) -> Result(State, Error) {
  case state.protocol {
    Handshaking(quic) -> {
      use quic <- result.try(
        driver.tick(quic, now_ms) |> result.map_error(DriverFailure),
      )
      promote(State(..state, protocol: Handshaking(quic)), now_ms)
    }
    Established(http3) ->
      session.tick(http3, now_ms)
      |> result.map(fn(http3) { State(..state, protocol: Established(http3)) })
      |> result.map_error(SessionFailure)
  }
}

/// Queue one QUIC PING on an established connection.
pub fn ping(state: State) -> Result(State, Error) {
  use http3 <- result.try(require_session(state))
  session.ping(http3)
  |> result.map(fn(http3) { State(..state, protocol: Established(http3)) })
  |> result.map_error(SessionFailure)
}

/// Queue one authenticated NEW_TOKEN frame on an established connection.
pub fn queue_new_token(state: State, token: BitArray) -> Result(State, Error) {
  use http3 <- result.try(require_session(state))
  session.queue_new_token(http3, token)
  |> result.map(fn(http3) { State(..state, protocol: Established(http3)) })
  |> result.map_error(SessionFailure)
}

/// Protect at most one datagram without committing transport accounting.
pub fn prepare_datagram(
  state: State,
  maximum_frame_data_bytes: Int,
  now_ms: Int,
) -> Result(Option(PreparedDatagram), Error) {
  case state.protocol {
    Handshaking(quic) ->
      driver.prepare_datagram(quic, maximum_frame_data_bytes, now_ms)
      |> result.map(fn(prepared) {
        option.map(prepared, fn(value) { DriverDatagram(state, value) })
      })
      |> result.map_error(DriverFailure)
    Established(http3) ->
      session.prepare_datagram(http3, maximum_frame_data_bytes, now_ms)
      |> result.map(fn(prepared) {
        option.map(prepared, fn(value) { SessionDatagram(state, value) })
      })
      |> result.map_error(SessionFailure)
  }
}

/// Bytes for the listener's one UDP send operation.
pub fn prepared_bytes(prepared: PreparedDatagram) -> BitArray {
  case prepared {
    DriverDatagram(_, value) -> driver.prepared_bytes(value)
    SessionDatagram(_, value) -> session.prepared_bytes(value)
  }
}

/// Commit a successfully sent datagram and update runtime counters.
pub fn commit_datagram(
  prepared: PreparedDatagram,
  marking: ecn.Codepoint,
  now_ms: Int,
) -> Result(State, Error) {
  let bytes = bit_array.byte_size(prepared_bytes(prepared))
  case prepared {
    DriverDatagram(state, value) ->
      driver.commit_datagram_with_ecn(value, marking, now_ms)
      |> result.map(fn(quic) {
        State(
          ..state,
          protocol: Handshaking(quic),
          packets_sent: state.packets_sent + 1,
          data_sent: state.data_sent + bytes,
          flushes: state.flushes + 1,
        )
      })
      |> result.map_error(DriverFailure)
    SessionDatagram(state, value) ->
      session.commit_datagram(value, marking, now_ms)
      |> result.map(fn(http3) {
        State(
          ..state,
          protocol: Established(http3),
          packets_sent: state.packets_sent + 1,
          data_sent: state.data_sent + bytes,
          flushes: state.flushes + 1,
        )
      })
      |> result.map_error(SessionFailure)
  }
}

/// Pull and clear ordered HTTP/3 and transport events.
pub fn take_events(state: State) -> #(State, List(session.Event)) {
  case state.protocol {
    Handshaking(_) -> #(state, [])
    Established(http3) -> {
      let #(http3, events) = session.take_events(http3)
      let status = event_early_data_status(events, state.early_data_status)
      #(
        State(..state, protocol: Established(http3), early_data_status: status),
        events,
      )
    }
  }
}

/// Queue response HEADERS on an accepted request stream.
pub fn send_response_headers(
  state: State,
  stream_id: Int,
  headers: List(Header),
) -> Result(State, Error) {
  use http3 <- result.try(require_session(state))
  session.send_response_headers(http3, stream_id, headers, False)
  |> result.map(fn(http3) { State(..state, protocol: Established(http3)) })
  |> result.map_error(SessionFailure)
}

/// Queue one response DATA frame.
pub fn send_data(
  state: State,
  stream_id: Int,
  bytes: BitArray,
) -> Result(State, Error) {
  use http3 <- result.try(require_session(state))
  session.send_data(http3, stream_id, bytes)
  |> result.map(fn(http3) { State(..state, protocol: Established(http3)) })
  |> result.map_error(SessionFailure)
}

/// Queue response trailers.
pub fn send_trailers(
  state: State,
  stream_id: Int,
  headers: List(Header),
) -> Result(State, Error) {
  use http3 <- result.try(require_session(state))
  session.send_trailers(http3, stream_id, headers, False)
  |> result.map(fn(http3) { State(..state, protocol: Established(http3)) })
  |> result.map_error(SessionFailure)
}

/// Validate response framing and queue QUIC FIN.
pub fn finish_stream(state: State, stream_id: Int) -> Result(State, Error) {
  use http3 <- result.try(require_session(state))
  session.finish_stream(http3, stream_id)
  |> result.map(fn(http3) { State(..state, protocol: Established(http3)) })
  |> result.map_error(SessionFailure)
}

/// Promise one server push and open its unidirectional response stream.
pub fn promise_push(
  state: State,
  request_stream_id: Int,
  headers: List(Header),
  now_ms: Int,
) -> Result(#(State, Int, Int), Error) {
  use http3 <- result.try(require_session(state))
  session.promise_push(http3, request_stream_id, headers, now_ms)
  |> result.map(fn(output) {
    let #(http3, push_id, push_stream_id) = output
    #(State(..state, protocol: Established(http3)), push_id, push_stream_id)
  })
  |> result.map_error(SessionFailure)
}

/// Queue pushed response HEADERS.
pub fn send_push_response_headers(
  state: State,
  stream_id: Int,
  headers: List(Header),
) -> Result(State, Error) {
  use http3 <- result.try(require_session(state))
  session.send_push_response_headers(http3, stream_id, headers)
  |> result.map(fn(http3) { State(..state, protocol: Established(http3)) })
  |> result.map_error(SessionFailure)
}

/// Queue pushed response DATA.
pub fn send_push_data(
  state: State,
  stream_id: Int,
  bytes: BitArray,
) -> Result(State, Error) {
  use http3 <- result.try(require_session(state))
  session.send_push_data(http3, stream_id, bytes)
  |> result.map(fn(http3) { State(..state, protocol: Established(http3)) })
  |> result.map_error(SessionFailure)
}

/// Queue pushed response trailers.
pub fn send_push_trailers(
  state: State,
  stream_id: Int,
  headers: List(Header),
) -> Result(State, Error) {
  use http3 <- result.try(require_session(state))
  session.send_push_trailers(http3, stream_id, headers)
  |> result.map(fn(http3) { State(..state, protocol: Established(http3)) })
  |> result.map_error(SessionFailure)
}

/// Finish one pushed response stream.
pub fn finish_push(state: State, stream_id: Int) -> Result(State, Error) {
  use http3 <- result.try(require_session(state))
  session.finish_push(http3, stream_id)
  |> result.map(fn(http3) { State(..state, protocol: Established(http3)) })
  |> result.map_error(SessionFailure)
}

/// Abort both directions of one request stream.
pub fn abort_stream(
  state: State,
  stream_id: Int,
  application_error_code: Int,
) -> Result(State, Error) {
  use http3 <- result.try(require_session(state))
  session.abort_stream(http3, stream_id, application_error_code)
  |> result.map(fn(http3) { State(..state, protocol: Established(http3)) })
  |> result.map_error(SessionFailure)
}

/// Queue the initial maximum-cutoff GOAWAY for graceful drain.
pub fn start_drain(state: State, now_ms: Int) -> Result(State, Error) {
  use http3 <- result.try(require_session(state))
  session.start_drain(http3, now_ms)
  |> result.map(fn(http3) { State(..state, protocol: Established(http3)) })
  |> result.map_error(SessionFailure)
}

/// Queue the final GOAWAY cutoff and return newly rejected stream IDs.
pub fn refine_drain(
  state: State,
  identifier: Int,
) -> Result(#(State, List(Int)), Error) {
  use http3 <- result.try(require_session(state))
  session.refine_drain(http3, identifier)
  |> result.map(fn(output) {
    let #(http3, rejected) = output
    #(State(..state, protocol: Established(http3)), rejected)
  })
  |> result.map_error(SessionFailure)
}

/// Advance the fixed drain deadline and return streams that must be aborted.
pub fn on_drain_timer(
  state: State,
  now_ms: Int,
) -> Result(#(State, List(Int)), Error) {
  use http3 <- result.try(require_session(state))
  session.on_drain_timer(http3, now_ms)
  |> result.map(fn(output) {
    let #(http3, cancelled) = output
    #(State(..state, protocol: Established(http3)), cancelled)
  })
  |> result.map_error(SessionFailure)
}

/// Return the current graceful-drain phase.
pub fn drain_phase(state: State) -> drain.Phase {
  case state.protocol {
    Handshaking(_) -> drain.Open
    Established(http3) -> session.drain_phase(http3)
  }
}

/// Mark a completed HTTP/3 graceful drain closed before QUIC shutdown.
pub fn close_drained(state: State) -> Result(State, Error) {
  use http3 <- result.try(require_session(state))
  session.close_drained(http3)
  |> result.map(fn(http3) { State(..state, protocol: Established(http3)) })
  |> result.map_error(SessionFailure)
}

/// Return negotiated HTTP Datagram support.
pub fn datagrams_available(state: State) -> Bool {
  case state.protocol {
    Established(http3) -> session.datagrams_available(http3)
    Handshaking(_) -> False
  }
}

/// Return the largest HTTP Datagram payload for one request stream.
pub fn maximum_http_datagram_size(
  state: State,
  stream_id: Int,
) -> Result(Int, Error) {
  use http3 <- result.try(require_session(state))
  session.maximum_http_datagram_size(http3, stream_id)
  |> result.map_error(SessionFailure)
}

/// Queue one HTTP Datagram associated with a request stream.
pub fn send_http_datagram(
  state: State,
  stream_id: Int,
  payload: BitArray,
) -> Result(State, Error) {
  use http3 <- result.try(require_session(state))
  session.send_http_datagram(http3, stream_id, payload)
  |> result.map(fn(http3) { State(..state, protocol: Established(http3)) })
  |> result.map_error(SessionFailure)
}

/// Return the server-side early-data status.
pub fn early_data_status(state: State) -> EarlyDataStatus {
  state.early_data_status
}

/// Return the listener-global replay cache after a completed resumed hello.
pub fn replay_cache(state: State) -> Option(anti_replay.Cache) {
  case state.protocol {
    Handshaking(quic) -> transport.server_replay_cache(driver.connection(quic))
    Established(http3) -> session.server_replay_cache(http3)
  }
}

/// Snapshot bounded path diagnostics.
pub fn path_snapshot(state: State) -> Option(transport.PathSnapshot) {
  case state.protocol {
    Handshaking(_) -> None
    Established(http3) -> Some(session.path_snapshot(http3))
  }
}

/// Return the current non-fragmenting QUIC UDP payload size when established.
pub fn path_mtu(state: State) -> Option(Int) {
  case state.protocol {
    Handshaking(_) -> None
    Established(http3) -> Some(session.path_mtu(http3))
  }
}

/// Return whether live DPLPMTUD is complete for an established path.
pub fn pmtu_discovery_complete(state: State) -> Bool {
  case state.protocol {
    Handshaking(_) -> False
    Established(http3) -> session.pmtu_discovery_complete(http3)
  }
}

/// Return whether candidate-path authentication is still in progress.
pub fn path_validation_in_progress(state: State) -> Bool {
  case state.protocol {
    Handshaking(_) -> False
    Established(http3) -> session.path_validation_in_progress(http3)
  }
}

/// Prepare one exact-size DPLPMTUD probe on an established path.
pub fn prepare_pmtu_probe(
  state: State,
  now_ms: Int,
) -> Result(Option(PreparedDatagram), Error) {
  use http3 <- result.try(require_session(state))
  session.prepare_pmtu_probe(http3, now_ms)
  |> result.map(fn(prepared) {
    option.map(prepared, fn(value) { SessionDatagram(state, value) })
  })
  |> result.map_error(SessionFailure)
}

/// Snapshot listener-owned packet and byte counters.
pub fn stats(state: State) -> Stats {
  let counters = case state.protocol {
    Handshaking(quic) -> transport.connection_counters(driver.connection(quic))
    Established(http3) -> session.connection_counters(http3)
  }
  let transport.ConnectionCounters(acks, retransmissions, coalesced) = counters
  Stats(
    state.packets_received,
    state.packets_sent,
    state.data_received,
    state.data_sent,
    acks,
    retransmissions,
    state.flushes,
    coalesced,
  )
}

/// Best-effort application close; the listener retains the socket.
pub fn close(state: State, code: Int, reason: String, now_ms: Int) -> State {
  case state.protocol {
    Handshaking(quic) ->
      case
        driver.update_connection(quic, fn(connection) {
          transport.close(connection, code, reason, now_ms)
        })
      {
        Ok(quic) -> State(..state, protocol: Handshaking(quic))
        Error(_) -> state
      }
    Established(http3) ->
      case session.close(http3, code, reason, now_ms) {
        Ok(http3) -> State(..state, protocol: Established(http3))
        Error(_) -> state
      }
  }
}

fn promote(state: State, now_ms: Int) -> Result(State, Error) {
  case state.protocol {
    Established(_) -> Ok(state)
    Handshaking(quic) ->
      case driver.phase(quic) {
        transport.Established -> establish_http3(state, quic, now_ms)
        _ -> Ok(state)
      }
  }
}

fn establish_http3(
  state: State,
  quic: driver.State,
  now_ms: Int,
) -> Result(State, Error) {
  let connection = driver.connection(quic)
  let can_issue_ticket = transport.can_issue_session_ticket(connection)
  let datagrams =
    state.config.http_datagrams
    && transport.maximum_datagram_data_size(connection) |> result.is_ok
  use http3 <- result.try(
    session.start(quic, server_http3_config(state.config), datagrams)
    |> result.map_error(SessionFailure),
  )
  use #(http3, ticket_issued) <- result.try(issue_initial_session_ticket(
    http3,
    can_issue_ticket,
    state.config,
    now_ms,
  ))
  Ok(State(..state, protocol: Established(http3), ticket_issued: ticket_issued))
}

fn issue_initial_session_ticket(
  http3: session.State,
  can_issue_ticket: Bool,
  config: Config,
  now_ms: Int,
) -> Result(#(session.State, Bool), Error) {
  case can_issue_ticket {
    False -> Ok(#(http3, False))
    True ->
      session.issue_session_ticket(
        http3,
        config.ticket_key,
        now_ms,
        session_ticket_lifetime_seconds,
        True,
      )
      |> result.map(fn(http3) { #(http3, True) })
      |> result.map_error(SessionFailure)
  }
}

fn refresh_driver_policy(
  quic: driver.State,
  policy: resumption.ServerPolicy,
) -> Result(driver.State, driver.Error) {
  case driver.phase(quic) {
    transport.Handshaking ->
      driver.update_connection(quic, fn(connection) {
        transport.refresh_server_resumption_policy(connection, policy)
      })
    _ -> Ok(quic)
  }
}

fn require_session(state: State) -> Result(session.State, Error) {
  case state.protocol {
    Established(http3) -> Ok(http3)
    Handshaking(_) -> Error(InvalidInput)
  }
}

fn event_early_data_status(
  events: List(session.Event),
  current: EarlyDataStatus,
) -> EarlyDataStatus {
  case events {
    [] -> current
    [session.TransportEvent(transport.EarlyDataWasAccepted), ..] -> Accepted
    [session.TransportEvent(transport.EarlyDataWasRejected), ..] -> Rejected
    [_, ..rest] -> event_early_data_status(rest, current)
  }
}

fn server_transport_config(
  protocol_version: Version,
  http_datagrams: Bool,
  maximum_body_bytes: Int,
) -> transport.Config {
  let config = transport.default_config(transport.Server)
  transport.Config(
    ..config,
    version: protocol_version,
    maximum_stream_final_size: int.max(
      config.maximum_stream_final_size,
      maximum_body_bytes + 1_048_576,
    ),
    maximum_udp_payload_size: maximum_datagram_frame_bytes,
    grease_quic_bit: True,
    maximum_datagram_frame_size: case http_datagrams {
      True -> maximum_datagram_frame_bytes
      False -> 0
    },
  )
}

fn server_transport_parameters(
  protocol_version: Version,
  original_destination_connection_id: BitArray,
  local_connection_id: BitArray,
  retry_source_connection_id: Option(BitArray),
  http_datagrams: Bool,
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
    transport_parameter.MaxIdleTimeout(30_000),
    transport_parameter.MaxUdpPayloadSize(maximum_datagram_frame_bytes),
    transport_parameter.InitialMaxData(1_048_576),
    transport_parameter.InitialMaxStreamDataBidiLocal(262_144),
    transport_parameter.InitialMaxStreamDataBidiRemote(262_144),
    transport_parameter.InitialMaxStreamDataUni(262_144),
    transport_parameter.InitialMaxStreamsBidi(100),
    transport_parameter.InitialMaxStreamsUni(100),
    transport_parameter.ActiveConnectionIdLimit(4),
  ]
  let parameters = case retry_source_connection_id {
    Some(connection_id) -> [
      transport_parameter.RetrySourceConnectionId(connection_id),
      ..parameters
    ]
    None -> parameters
  }
  case http_datagrams {
    True -> [
      transport_parameter.MaxDatagramFrameSize(maximum_datagram_frame_bytes),
      ..parameters
    ]
    False -> parameters
  }
}

fn server_http3_config(config: Config) -> http3_state.Config {
  let defaults = http3_state.default_config(http3_state.Server)
  let settings =
    http3_state.Settings(
      ..defaults.settings,
      h3_datagram: config.http_datagrams,
    )
  http3_state.Config(
    ..defaults,
    settings: settings,
    maximum_body_bytes: config.maximum_body_bytes,
  )
}

fn validate_initial_inputs(
  config: Config,
  original_destination_connection_id: BitArray,
  local_connection_id: BitArray,
  peer_connection_id: BitArray,
  retry_source_connection_id: Option(BitArray),
  datagram: BitArray,
  now_ms: Int,
) -> Result(Nil, Error) {
  let valid_routing_id = fn(value) {
    let size = bit_array.byte_size(value)
    bit_array.bit_size(value) % 8 == 0 && size >= 8 && size <= 20
  }
  let valid_initial_peer_id = fn(value) {
    bit_array.bit_size(value) % 8 == 0 && bit_array.byte_size(value) <= 20
  }
  case
    config.certificate_chain != []
    && bit_array.byte_size(config.ticket_key) == 32
    && config.maximum_body_bytes > 0
    && valid_routing_id(original_destination_connection_id)
    && valid_routing_id(local_connection_id)
    && valid_initial_peer_id(peer_connection_id)
    && case retry_source_connection_id {
      Some(value) -> value == local_connection_id && valid_routing_id(value)
      None -> True
    }
    && bit_array.byte_size(datagram) >= 1200
    && now_ms >= 0
  {
    True -> Ok(Nil)
    False -> Error(InvalidInput)
  }
}

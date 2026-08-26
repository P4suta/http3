//// One reusable generic QUIC client connection and its UDP pump.

import gleam/bit_array
import gleam/dynamic.{type Dynamic}
import gleam/erlang/process.{type Pid, type Subject}
import gleam/int
import gleam/list
import gleam/option.{type Option, None, Some}
import gleam/result
import gleam_quic.{type AddressFamily, DualStack, Ipv4, Ipv6}
import gleam_quic/internal/connection_state as transport
import gleam_quic/internal/crypto
import gleam_quic/internal/driver
import gleam_quic/internal/ecn
import gleam_quic/internal/process_label
import gleam_quic/internal/runtime/connection
import gleam_quic/internal/tls/authentication
import gleam_quic/internal/tls/engine
import gleam_quic/internal/tls/hello
import gleam_quic/internal/tls/session_ticket
import gleam_quic/internal/udp
import gleam_quic/stream_id
import gleam_quic/transport_parameter
import gleam_quic/version.{type Version}

const maximum_packets_per_flush = 64

// Pre-validation floor for one packet's frame payload. The send path widens it
// to whatever DPLPMTUD has validated for the current path.
const maximum_frame_data_bytes = 1000

const connection_id_bytes = 8

const connection_attempt_delay_milliseconds = 250

// RFC 9000 section 18.2: max_udp_payload_size is a limit on what this endpoint
// is willing to receive, and its default is 65_527. Sending stays governed by
// DPLPMTUD, which starts at the 1200-byte floor and probes every larger size.
const maximum_udp_payload_size = 65_527

/// Validated client transport policy.
pub type Config {
  Config(
    hostname: String,
    port: Int,
    address_family: AddressFamily,
    dns_timeout_milliseconds: Int,
    connect_timeout_milliseconds: Int,
    handshake_timeout_milliseconds: Int,
    total_timeout_milliseconds: Int,
    idle_timeout_milliseconds: Int,
    trust_store: authentication.TrustStore,
    client_credential: Option(engine.ClientCredential),
    application_protocols: List(BitArray),
    resumption_ticket: Option(session_ticket.ClientTicket),
    allow_zero_rtt: Bool,
    address_token: BitArray,
    version: Version,
    congestion_control: transport.CongestionAlgorithm,
    bidirectional_stream_limit: Int,
    unidirectional_stream_limit: Int,
    stream_buffer_limit: Int,
    datagram_limit: Int,
  )
}

/// A socket, current path, and generic QUIC connection state.
pub opaque type State {
  State(
    socket: udp.Socket,
    connection: connection.State,
    previous_socket: Option(udp.Socket),
    version: Version,
    application_protocol: BitArray,
  )
}

/// Resolution, socket, TLS, QUIC, timeout, or migration failure.
pub type Error {
  InvalidInput
  ResolutionFailed
  SocketUnavailable
  DnsTimeout
  ConnectTimeout
  HandshakeTimeout
  TotalTimeout
  TlsHandshakeFailed
  QuicFailure(driver.Error)
  PeerClosed
  MigrationUnavailable
  VersionNegotiationReceived(List(Version))
  VersionNegotiationFailed
}

type CandidateDecision {
  Select(Subject(Result(State, Error)))
  Cancel
}

type CandidateMessage {
  CandidateReady(Pid, Subject(CandidateDecision))
  CandidateFailed(Error)
}

/// Resolve, race, authenticate, and establish one generic QUIC connection.
pub fn connect(config: Config) -> Result(State, Error) {
  use Nil <- result.try(validate(config))
  let deadline = udp.monotonic_millisecond() + config.total_timeout_milliseconds
  use addresses <- result.try(
    case
      udp.resolve_with_timeout(
        config.hostname,
        udp_address_family(config.address_family),
        int.min(
          config.dns_timeout_milliseconds,
          config.total_timeout_milliseconds,
        ),
      )
    {
      Ok(addresses) -> Ok(addresses)
      Error(udp.Timeout) -> Error(DnsTimeout)
      Error(_) -> Error(ResolutionFailed)
    },
  )
  connect_addresses(config, addresses, deadline, None)
}

/// Pull and clear ordered transport events.
pub fn take_events(state: State) -> #(State, List(transport.Event)) {
  let #(next, events) = connection.take_events(state.connection)
  #(settle_migration(State(..state, connection: next), events), events)
}

/// Advance protocol timers and flush bounded output.
pub fn drive(state: State) -> Result(State, Error) {
  let now = udp.monotonic_millisecond()
  use next <- result.try(
    connection.tick(state.connection, now) |> result.map_error(QuicFailure),
  )
  flush(State(..state, connection: next), now, maximum_packets_per_flush)
}

/// Return the earliest protocol deadline for an event-driven owner.
pub fn next_deadline(state: State, now: Int) -> Result(Option(Int), Error) {
  connection.next_deadline(state.connection, now)
  |> result.map_error(QuicFailure)
}

/// Arm the current and candidate-path sockets for one mailbox delivery each.
pub fn activate_once(state: State) -> Result(Nil, Error) {
  use Nil <- result.try(
    udp.activate_once(state.socket) |> result.replace_error(SocketUnavailable),
  )
  case state.previous_socket {
    None -> Ok(Nil)
    Some(socket) ->
      udp.activate_once(socket) |> result.replace_error(SocketUnavailable)
  }
}

/// Consume one active-mode datagram from either live path.
pub fn receive_active(state: State, message: Dynamic) -> Result(State, Error) {
  case udp.receive_active(state.socket, message) {
    Ok(datagram) -> process_received_datagram(state, datagram)
    Error(udp.InvalidInput) ->
      case state.previous_socket {
        None -> Error(InvalidInput)
        Some(socket) ->
          udp.receive_active(socket, message)
          |> result.replace_error(InvalidInput)
          |> result.try(process_received_datagram(state, _))
      }
    Error(_) -> Error(SocketUnavailable)
  }
}

/// Open one locally initiated bidirectional or unidirectional stream.
pub fn open_stream(
  state: State,
  direction: stream_id.Direction,
) -> Result(#(State, Int), Error) {
  connection.open_stream(state.connection, direction)
  |> result.map(fn(opened) {
    let #(next, identifier) = opened
    #(State(..state, connection: next), identifier)
  })
  |> result.map_error(QuicFailure)
}

/// Queue bytes and an optional stream FIN.
pub fn send(
  state: State,
  identifier: Int,
  bytes: BitArray,
  finish: Bool,
) -> Result(State, Error) {
  connection.send(state.connection, identifier, bytes, finish)
  |> result.map(fn(next) { State(..state, connection: next) })
  |> result.map_error(QuicFailure)
}

/// Return retained send bytes for synchronous backpressure.
pub fn buffered_send_bytes(
  state: State,
  identifier: Int,
) -> Result(Int, Error) {
  connection.buffered_send_bytes(state.connection, identifier)
  |> result.map_error(QuicFailure)
}

/// Pull one bounded stream read.
pub fn read(
  state: State,
  identifier: Int,
  maximum_bytes: Int,
) -> Result(#(State, connection.Read), Error) {
  connection.read(state.connection, identifier, maximum_bytes)
  |> result.map(fn(output) {
    let #(next, read) = output
    #(State(..state, connection: next), read)
  })
  |> result.map_error(QuicFailure)
}

/// Abort every locally usable stream direction.
pub fn reset(
  state: State,
  identifier: Int,
  application_error_code: Int,
) -> Result(State, Error) {
  connection.reset(state.connection, identifier, application_error_code)
  |> result.map(fn(next) { State(..state, connection: next) })
  |> result.map_error(QuicFailure)
}

/// Queue one negotiated QUIC Datagram.
pub fn send_datagram(state: State, payload: BitArray) -> Result(State, Error) {
  connection.send_datagram(state.connection, payload)
  |> result.map(fn(next) { State(..state, connection: next) })
  |> result.map_error(QuicFailure)
}

/// Largest raw QUIC Datagram payload on the current path.
pub fn maximum_datagram_size(state: State) -> Result(Int, Error) {
  connection.maximum_datagram_size(state.connection)
  |> result.map_error(QuicFailure)
}

/// Queue one ack-eliciting PING.
pub fn ping(state: State) -> Result(State, Error) {
  connection.ping(state.connection)
  |> result.map(fn(next) { State(..state, connection: next) })
  |> result.map_error(QuicFailure)
}

/// Change the live congestion controller.
pub fn set_congestion_control(
  state: State,
  algorithm: transport.CongestionAlgorithm,
) -> Result(State, Error) {
  connection.set_congestion_control(state.connection, algorithm)
  |> result.map(fn(next) { State(..state, connection: next) })
  |> result.map_error(QuicFailure)
}

/// Begin migration from a fresh local UDP path.
pub fn migrate(state: State) -> Result(State, Error) {
  case
    state.previous_socket,
    connection.active_migration_available(state.connection)
  {
    Some(_), _ | _, False -> Error(MigrationUnavailable)
    None, True -> {
      use challenge <- result.try(
        crypto.secure_random(8) |> result.replace_error(MigrationUnavailable),
      )
      use socket <- result.try(
        open_for_peer(connection.peer(state.connection))
        |> result.replace_error(MigrationUnavailable),
      )
      case
        connection.begin_path_validation(
          state.connection,
          challenge,
          True,
          udp.monotonic_millisecond(),
        )
      {
        Error(_) -> {
          let _ = udp.close(socket)
          Error(MigrationUnavailable)
        }
        Ok(next) ->
          Ok(
            State(
              ..state,
              socket: socket,
              connection: next,
              previous_socket: Some(state.socket),
            ),
          )
      }
    }
  }
}

/// Current path diagnostics.
pub fn path_stats(state: State) -> transport.PathSnapshot {
  connection.path_stats(state.connection)
}

/// Runtime-owned counters.
pub fn stats(state: State) -> connection.Stats {
  connection.stats(state.connection)
}

/// Current non-fragmenting QUIC UDP payload size.
pub fn path_mtu(state: State) -> Int {
  connection.path_mtu(state.connection)
}

/// Whether DPLPMTUD has reached the current ceiling.
pub fn pmtu_discovery_complete(state: State) -> Bool {
  connection.pmtu_discovery_complete(state.connection)
}

/// Whether candidate path validation is in progress.
pub fn path_validation_in_progress(state: State) -> Bool {
  connection.path_validation_in_progress(state.connection)
}

/// Send and commit at most one DPLPMTUD probe.
pub fn probe_path_mtu(state: State, now: Int) -> Result(State, Error) {
  case connection.prepare_pmtu_probe(state.connection, now) {
    Error(error) -> Error(QuicFailure(error))
    Ok(None) -> Ok(state)
    Ok(Some(prepared)) -> {
      let bytes = connection.prepared_bytes(prepared)
      use Nil <- result.try(
        udp.send(
          state.socket,
          connection.peer(state.connection),
          bytes,
          ecn.NotEct,
        )
        |> result.replace_error(SocketUnavailable),
      )
      connection.commit_datagram(prepared, ecn.NotEct, now)
      |> result.map(fn(next) { State(..state, connection: next) })
      |> result.map_error(QuicFailure)
    }
  }
}

/// Negotiated wire version retained without exposing TLS state.
pub fn version(state: State) -> Version {
  state.version
}

/// Negotiated application protocol retained without exposing TLS state.
pub fn application_protocol(state: State) -> BitArray {
  case connection.application_protocol(state.connection) {
    Some(protocol) -> protocol
    None -> state.application_protocol
  }
}

/// Negotiated cipher retained without exposing TLS keys or state.
pub fn cipher_suite(state: State) -> Option(hello.CipherSuite) {
  connection.cipher_suite(state.connection)
}

/// Whether the connection resumed the caller-supplied session.
pub fn resumed(state: State) -> Bool {
  connection.resumed(state.connection)
}

/// Stable connection lifecycle.
pub fn phase(state: State) -> transport.Phase {
  connection.phase(state.connection)
}

/// Best-effort application close followed by unconditional socket cleanup.
pub fn close(state: State, application_error_code: Int, reason: String) -> Nil {
  let now = udp.monotonic_millisecond()
  let closing =
    connection.close(state.connection, application_error_code, reason, now)
  let state = State(..state, connection: closing)
  let _ = flush(state, now, 4)
  let _ = udp.close(state.socket)
  case state.previous_socket {
    Some(socket) -> {
      let _ = udp.close(socket)
      Nil
    }
    None -> Nil
  }
}

fn settle_migration(state: State, events: List(transport.Event)) -> State {
  case state.previous_socket {
    None -> state
    Some(previous_socket) -> {
      let validated = list.contains(events, transport.PathValidated)
      let failed = list.contains(events, transport.PathValidationFailed)
      case validated, failed {
        True, _ -> {
          let _ = udp.close(previous_socket)
          State(..state, previous_socket: None)
        }
        False, True -> {
          let _ = udp.close(state.socket)
          State(..state, socket: previous_socket, previous_socket: None)
        }
        False, False -> state
      }
    }
  }
}

fn connect_addresses(
  config: Config,
  addresses: List(udp.Address),
  deadline: Int,
  last_error: Option(Error),
) -> Result(State, Error) {
  case addresses, remaining_milliseconds(deadline) {
    _, remaining if remaining <= 0 -> Error(TotalTimeout)
    [], _ -> Error(option_error(last_error, SocketUnavailable))
    [address], _ -> connect_address(config, address, deadline, False)
    [_, _, ..], _ -> race_addresses(config, addresses, deadline)
  }
}

fn race_addresses(
  config: Config,
  addresses: List(udp.Address),
  deadline: Int,
) -> Result(State, Error) {
  let results = process.new_subject()
  let owner = process.self()
  let candidates =
    spawn_candidates(config, addresses, deadline, owner, results, 0, [])
  await_candidate(results, candidates, list.length(candidates), deadline, None)
}

fn spawn_candidates(
  config: Config,
  addresses: List(udp.Address),
  deadline: Int,
  owner: Pid,
  results: Subject(CandidateMessage),
  index: Int,
  reversed: List(Pid),
) -> List(Pid) {
  case addresses {
    [] -> list.reverse(reversed)
    [address, ..rest] -> {
      let candidate =
        process.spawn_unlinked(fn() {
          process_label.set(process_label.ConnectCandidate)
          process.sleep(index * connection_attempt_delay_milliseconds)
          run_candidate(config, address, deadline, owner, results)
        })
      spawn_candidates(config, rest, deadline, owner, results, index + 1, [
        candidate,
        ..reversed
      ])
    }
  }
}

fn run_candidate(
  config: Config,
  address: udp.Address,
  deadline: Int,
  owner: Pid,
  results: Subject(CandidateMessage),
) -> Nil {
  case connect_address(config, address, deadline, True) {
    Error(error) -> process.send(results, CandidateFailed(error))
    Ok(state) -> offer_candidate(state, deadline, owner, results)
  }
}

fn offer_candidate(
  state: State,
  deadline: Int,
  owner: Pid,
  results: Subject(CandidateMessage),
) -> Nil {
  let decision = process.new_subject()
  process.send(results, CandidateReady(process.self(), decision))
  case
    process.receive(
      decision,
      within: int.max(0, remaining_milliseconds(deadline)),
    )
  {
    Ok(Select(completion)) -> transfer_candidate(state, owner, completion)
    Ok(Cancel) | Error(Nil) -> discard_state(state)
  }
}

fn transfer_candidate(
  state: State,
  owner: Pid,
  completion: Subject(Result(State, Error)),
) -> Nil {
  case udp.transfer_owner(state.socket, owner) {
    Ok(Nil) -> process.send(completion, Ok(state))
    Error(_) -> {
      discard_state(state)
      process.send(completion, Error(SocketUnavailable))
    }
  }
}

fn await_candidate(
  results: Subject(CandidateMessage),
  candidates: List(Pid),
  remaining_candidates: Int,
  deadline: Int,
  last_error: Option(Error),
) -> Result(State, Error) {
  case remaining_candidates, remaining_milliseconds(deadline) {
    0, _ -> Error(option_error(last_error, SocketUnavailable))
    _, remaining if remaining <= 0 -> {
      cancel_candidates(candidates, None)
      Error(option_error(last_error, TotalTimeout))
    }
    _, remaining ->
      case process.receive(results, within: remaining) {
        Error(Nil) -> {
          cancel_candidates(candidates, None)
          Error(option_error(last_error, TotalTimeout))
        }
        Ok(CandidateFailed(error)) ->
          await_candidate(
            results,
            candidates,
            remaining_candidates - 1,
            deadline,
            prefer_candidate_error(last_error, error),
          )
        Ok(CandidateReady(candidate, decision)) ->
          select_candidate(candidate, decision, candidates, deadline)
      }
  }
}

fn select_candidate(
  candidate: Pid,
  decision: Subject(CandidateDecision),
  candidates: List(Pid),
  deadline: Int,
) -> Result(State, Error) {
  let completion = process.new_subject()
  process.send(decision, Select(completion))
  case
    process.receive(
      completion,
      within: int.max(0, remaining_milliseconds(deadline)),
    )
  {
    Ok(Ok(state)) -> {
      cancel_candidates(candidates, Some(candidate))
      Ok(state)
    }
    Ok(Error(error)) -> {
      cancel_candidates(candidates, None)
      Error(error)
    }
    Error(Nil) -> {
      cancel_candidates(candidates, None)
      Error(TotalTimeout)
    }
  }
}

fn prefer_candidate_error(
  current: Option(Error),
  incoming: Error,
) -> Option(Error) {
  case current {
    None -> Some(incoming)
    Some(error) ->
      case
        candidate_error_priority(incoming) > candidate_error_priority(error)
      {
        True -> Some(incoming)
        False -> current
      }
  }
}

fn candidate_error_priority(error: Error) -> Int {
  case error {
    TlsHandshakeFailed -> 100
    VersionNegotiationFailed | VersionNegotiationReceived(_) -> 90
    QuicFailure(_) | PeerClosed -> 80
    HandshakeTimeout -> 60
    ConnectTimeout -> 50
    DnsTimeout | ResolutionFailed -> 40
    SocketUnavailable -> 30
    TotalTimeout -> 20
    MigrationUnavailable | InvalidInput -> 10
  }
}

fn cancel_candidates(candidates: List(Pid), winner: Option(Pid)) -> Nil {
  list.each(candidates, fn(candidate) {
    case winner {
      Some(selected) if selected == candidate -> Nil
      _ -> process.kill(candidate)
    }
  })
}

fn discard_state(state: State) -> Nil {
  let _ = udp.close(state.socket)
  case state.previous_socket {
    Some(socket) -> {
      let _ = udp.close(socket)
      Nil
    }
    None -> Nil
  }
}

fn connect_address(
  config: Config,
  address: udp.Address,
  deadline: Int,
  confirm_reachability: Bool,
) -> Result(State, Error) {
  use peer <- result.try(
    udp.endpoint(address, config.port) |> result.replace_error(InvalidInput),
  )
  use socket <- result.try(
    open_for_address(address) |> result.replace_error(SocketUnavailable),
  )
  let connect_deadline =
    int.min(
      deadline,
      udp.monotonic_millisecond() + config.connect_timeout_milliseconds,
    )
  let outcome = case remaining_milliseconds(connect_deadline) <= 0 {
    True -> Error(ConnectTimeout)
    False ->
      case establish(config, socket, peer, deadline) {
        Error(error) -> Error(error)
        Ok(state) -> {
          let should_confirm = case config.resumption_ticket {
            Some(ticket) ->
              config.allow_zero_rtt
              && session_ticket.early_data_allowed(ticket)
              && confirm_reachability
            None -> False
          }
          case should_confirm {
            True ->
              confirm_resumption_candidate(
                state,
                int.min(
                  deadline,
                  udp.monotonic_millisecond()
                    + config.handshake_timeout_milliseconds,
                ),
              )
            False -> Ok(state)
          }
        }
      }
  }
  case outcome {
    Ok(state) -> Ok(state)
    Error(error) -> {
      let _ = udp.close(socket)
      Error(error)
    }
  }
}

fn confirm_resumption_candidate(
  state: State,
  deadline: Int,
) -> Result(State, Error) {
  let connection.Stats(received, _, _, _, _, _, _, _) = stats(state)
  case received > 0, remaining_milliseconds(deadline) {
    True, _ -> Ok(state)
    False, remaining if remaining <= 0 -> Error(HandshakeTimeout)
    False, _ -> {
      use state <- result.try(pump_until(state, deadline))
      confirm_resumption_candidate(state, deadline)
    }
  }
}

fn establish(
  config: Config,
  socket: udp.Socket,
  peer: udp.Endpoint,
  deadline: Int,
) -> Result(State, Error) {
  use selected <- result.try(initial_connection_version(config))
  establish_version(
    config,
    socket,
    peer,
    int.min(
      deadline,
      udp.monotonic_millisecond() + config.handshake_timeout_milliseconds,
    ),
    selected,
    [],
  )
}

fn initial_connection_version(config: Config) -> Result(Version, Error) {
  case config.resumption_ticket {
    None -> Ok(config.version)
    Some(ticket) ->
      case version.from_wire(session_ticket.quic_version(ticket)) {
        Ok(version.Version1) -> Ok(version.Version1)
        Ok(version.Version2) -> Ok(version.Version2)
        _ -> Error(TlsHandshakeFailed)
      }
  }
}

fn establish_version(
  config: Config,
  socket: udp.Socket,
  peer: udp.Endpoint,
  deadline: Int,
  selected_version: Version,
  attempted_versions: List(Version),
) -> Result(State, Error) {
  use original_destination_connection_id <- result.try(random_connection_id())
  use local_connection_id <- result.try(random_connection_id())
  let tls_config =
    engine.ClientConfig(
      version: selected_version,
      hostname: config.hostname,
      application_protocols: config.application_protocols,
      transport_parameters: client_transport_parameters(
        local_connection_id,
        config.datagram_limit,
        selected_version,
        config.resumption_ticket == None,
        config.idle_timeout_milliseconds,
        config.bidirectional_stream_limit,
        config.unidirectional_stream_limit,
      ),
      trust_store: config.trust_store,
      client_credential: config.client_credential,
      retried: False,
      version_negotiated: attempted_versions != [],
    )
  let now = udp.monotonic_millisecond()
  use tls <- result.try(
    case config.resumption_ticket {
      None -> engine.start_client(tls_config)
      Some(ticket) ->
        engine.start_client_resuming(
          tls_config,
          ticket,
          now,
          config.allow_zero_rtt && session_ticket.early_data_allowed(ticket),
        )
    }
    |> result.replace_error(TlsHandshakeFailed),
  )
  use quic <- result.try(
    driver.start_client_with_token(
      client_transport_config(config, selected_version),
      tls,
      original_destination_connection_id,
      local_connection_id,
      config.address_token,
      now,
    )
    |> result.map_error(QuicFailure),
  )
  let state =
    State(
      socket,
      connection.new(peer, quic),
      None,
      selected_version,
      first_protocol(config.application_protocols),
    )
  let early_data = case config.resumption_ticket {
    Some(ticket) ->
      config.allow_zero_rtt && session_ticket.early_data_allowed(ticket)
    None -> False
  }
  case early_data {
    True -> Ok(state)
    False ->
      complete_handshake(
        config,
        state,
        deadline,
        selected_version,
        attempted_versions,
      )
  }
}

fn complete_handshake(
  config: Config,
  state: State,
  deadline: Int,
  selected_version: Version,
  attempted_versions: List(Version),
) -> Result(State, Error) {
  case handshake(state, deadline, attempted_versions != []) {
    Error(VersionNegotiationReceived(offered)) ->
      case
        select_compatible_version(selected_version, offered, [
          selected_version,
          ..attempted_versions
        ])
      {
        Error(_) -> Error(VersionNegotiationFailed)
        Ok(next_version) ->
          establish_version(
            case config.resumption_ticket {
              Some(_) -> Config(..config, resumption_ticket: None)
              None -> config
            },
            state.socket,
            connection.peer(state.connection),
            deadline,
            next_version,
            [selected_version, ..attempted_versions],
          )
      }
    outcome -> outcome
  }
}

fn handshake(
  state: State,
  deadline: Int,
  ignore_version_negotiation: Bool,
) -> Result(State, Error) {
  case phase(state), remaining_milliseconds(deadline) {
    transport.Established, _ -> Ok(state)
    transport.Closed, _ -> Error(PeerClosed)
    _, remaining if remaining <= 0 -> Error(HandshakeTimeout)
    _, _ -> {
      use state <- result.try(drive(state))
      let now = udp.monotonic_millisecond()
      use protocol_deadline <- result.try(next_deadline(state, now))
      use state <- result.try(receive_passive(
        state,
        wait_milliseconds(deadline, protocol_deadline, now),
        ignore_version_negotiation,
      ))
      handshake(state, deadline, ignore_version_negotiation)
    }
  }
}

fn pump_until(state: State, total_deadline: Int) -> Result(State, Error) {
  use state <- result.try(drive(state))
  let now = udp.monotonic_millisecond()
  use protocol_deadline <- result.try(next_deadline(state, now))
  receive_passive(
    state,
    wait_milliseconds(total_deadline, protocol_deadline, now),
    True,
  )
}

fn receive_passive(
  state: State,
  timeout: Int,
  ignore_version_negotiation: Bool,
) -> Result(State, Error) {
  case udp.receive(state.socket, timeout) {
    Error(udp.Timeout) -> Ok(state)
    Error(_) -> Error(SocketUnavailable)
    Ok(udp.Datagram(peer, bytes, marking)) ->
      case same_endpoint(peer, connection.peer(state.connection)) {
        False -> Ok(state)
        True ->
          case
            connection.receive_datagram(
              state.connection,
              bytes,
              marking,
              udp.monotonic_millisecond(),
            )
          {
            Ok(next) -> Ok(State(..state, connection: next))
            Error(driver.VersionNegotiationReceived(versions)) ->
              case ignore_version_negotiation {
                True -> Ok(state)
                False -> Error(VersionNegotiationReceived(versions))
              }
            Error(error) -> discard_or_fail(state, error)
          }
      }
  }
}

fn flush(
  state: State,
  now: Int,
  remaining_packets: Int,
) -> Result(State, Error) {
  case remaining_packets {
    0 -> Ok(state)
    _ ->
      case
        connection.prepare_datagram(
          state.connection,
          maximum_frame_data_bytes,
          now,
        )
      {
        Error(driver.ConnectionFailure(transport.PacingLimited(_)))
        | Error(driver.ConnectionFailure(transport.CongestionLimited)) ->
          Ok(state)
        Error(error) -> Error(QuicFailure(error))
        Ok(None) -> Ok(state)
        Ok(Some(prepared)) -> {
          use Nil <- result.try(
            udp.send(
              state.socket,
              connection.peer(state.connection),
              connection.prepared_bytes(prepared),
              ecn.NotEct,
            )
            |> result.replace_error(SocketUnavailable),
          )
          use next <- result.try(
            connection.commit_datagram(prepared, ecn.NotEct, now)
            |> result.map_error(QuicFailure),
          )
          flush(State(..state, connection: next), now, remaining_packets - 1)
        }
      }
  }
}

fn process_received_datagram(
  state: State,
  datagram: udp.Datagram,
) -> Result(State, Error) {
  let udp.Datagram(peer, bytes, marking) = datagram
  case same_endpoint(peer, connection.peer(state.connection)) {
    False -> Ok(state)
    True ->
      case
        connection.receive_datagram(
          state.connection,
          bytes,
          marking,
          udp.monotonic_millisecond(),
        )
      {
        Ok(next) -> Ok(State(..state, connection: next))
        Error(error) -> discard_or_fail(state, error)
      }
  }
}

fn client_transport_config(
  config: Config,
  selected: Version,
) -> transport.Config {
  let defaults = transport.default_config(transport.Client)
  transport.Config(
    ..defaults,
    version: selected,
    congestion_algorithm: config.congestion_control,
    idle_timeout_milliseconds: config.idle_timeout_milliseconds,
    maximum_peer_streams_bidirectional: config.bidirectional_stream_limit,
    maximum_peer_streams_unidirectional: config.unidirectional_stream_limit,
    maximum_stream_receive_buffer: config.stream_buffer_limit,
    maximum_stream_send_buffer: config.stream_buffer_limit,
    maximum_total_streams: config.bidirectional_stream_limit
      + config.unidirectional_stream_limit,
    maximum_udp_payload_size: maximum_udp_payload_size,
    maximum_datagram_frame_size: int.min(
      config.datagram_limit,
      maximum_udp_payload_size,
    ),
  )
}

fn client_transport_parameters(
  local_connection_id: BitArray,
  datagram_limit: Int,
  selected_version: Version,
  advertise_compatible_versions: Bool,
  idle_timeout_milliseconds: Int,
  bidirectional_stream_limit: Int,
  unidirectional_stream_limit: Int,
) -> List(transport_parameter.Parameter) {
  let available_versions = case advertise_compatible_versions {
    True -> [version.Version2, version.Version1]
    False -> [selected_version]
  }
  [
    transport_parameter.GreaseQuicBit,
    transport_parameter.MaxIdleTimeout(idle_timeout_milliseconds),
    transport_parameter.MaxUdpPayloadSize(maximum_udp_payload_size),
    transport_parameter.InitialMaxData(1_048_576),
    transport_parameter.InitialMaxStreamDataBidiLocal(262_144),
    transport_parameter.InitialMaxStreamDataBidiRemote(262_144),
    transport_parameter.InitialMaxStreamDataUni(262_144),
    transport_parameter.InitialMaxStreamsBidi(bidirectional_stream_limit),
    transport_parameter.InitialMaxStreamsUni(unidirectional_stream_limit),
    transport_parameter.ActiveConnectionIdLimit(4),
    transport_parameter.InitialSourceConnectionId(local_connection_id),
    transport_parameter.VersionInformation(selected_version, available_versions),
    transport_parameter.MaxDatagramFrameSize(int.min(
      datagram_limit,
      maximum_udp_payload_size,
    )),
  ]
}

fn random_connection_id() -> Result(BitArray, Error) {
  crypto.secure_random(connection_id_bytes)
  |> result.replace_error(TlsHandshakeFailed)
}

fn open_for_address(address: udp.Address) -> Result(udp.Socket, udp.Error) {
  case bit_array.byte_size(udp.address_bytes(address)) {
    4 -> {
      use wildcard <- result.try(udp.ipv4(0, 0, 0, 0))
      use endpoint <- result.try(udp.endpoint(wildcard, 0))
      udp.open(endpoint)
    }
    16 -> {
      use wildcard <- result.try(udp.ipv6(0, 0, 0, 0, 0, 0, 0, 0))
      use endpoint <- result.try(udp.endpoint(wildcard, 0))
      udp.open(endpoint)
    }
    _ -> Error(udp.InvalidInput)
  }
}

fn open_for_peer(peer: udp.Endpoint) -> Result(udp.Socket, udp.Error) {
  let #(bytes, _) = udp.endpoint_parts(peer)
  use address <- result.try(udp.address_from_bytes(bytes))
  open_for_address(address)
}

fn udp_address_family(address_family: AddressFamily) -> udp.AddressFamily {
  case address_family {
    Ipv4 -> udp.Ipv4
    Ipv6 -> udp.Ipv6
    DualStack -> udp.Any
  }
}

fn wait_milliseconds(
  total_deadline: Int,
  protocol_deadline: Option(Int),
  now: Int,
) -> Int {
  let target = case protocol_deadline {
    Some(deadline) if deadline < total_deadline -> deadline
    _ -> total_deadline
  }
  int.max(0, target - now)
}

fn remaining_milliseconds(deadline: Int) -> Int {
  deadline - udp.monotonic_millisecond()
}

fn same_endpoint(left: udp.Endpoint, right: udp.Endpoint) -> Bool {
  udp.endpoint_parts(left) == udp.endpoint_parts(right)
}

fn option_error(value: Option(Error), fallback: Error) -> Error {
  case value {
    Some(error) -> error
    None -> fallback
  }
}

fn discard_or_fail(state: State, error: driver.Error) -> Result(State, Error) {
  case driver.discardable_receive_error(error) {
    True -> Ok(state)
    False ->
      case error {
        driver.ConnectionFailure(transport.TlsFailure(_)) ->
          Error(TlsHandshakeFailed)
        _ -> Error(QuicFailure(error))
      }
  }
}

fn first_protocol(protocols: List(BitArray)) -> BitArray {
  case protocols {
    [protocol, ..] -> protocol
    [] -> <<>>
  }
}

fn validate(config: Config) -> Result(Nil, Error) {
  case
    config.hostname != ""
    && config.port > 0
    && config.port <= 65_535
    && config.dns_timeout_milliseconds > 0
    && config.connect_timeout_milliseconds > 0
    && config.handshake_timeout_milliseconds > 0
    && config.total_timeout_milliseconds > 0
    && config.idle_timeout_milliseconds > 0
    && valid_protocols(config.application_protocols)
    && config.bidirectional_stream_limit > 0
    && config.unidirectional_stream_limit > 0
    && config.stream_buffer_limit > 0
    && config.datagram_limit > 0
    && {
      config.version == version.Version1 || config.version == version.Version2
    }
  {
    True -> Ok(Nil)
    False -> Error(InvalidInput)
  }
}

fn valid_protocols(protocols: List(BitArray)) -> Bool {
  case protocols {
    [] -> False
    [protocol, ..rest] -> {
      let size = bit_array.byte_size(protocol)
      bit_array.bit_size(protocol) % 8 == 0
      && size > 0
      && size <= 255
      && valid_protocols_tail(rest)
    }
  }
}

fn valid_protocols_tail(protocols: List(BitArray)) -> Bool {
  case protocols {
    [] -> True
    [protocol, ..rest] -> {
      let size = bit_array.byte_size(protocol)
      bit_array.bit_size(protocol) % 8 == 0
      && size > 0
      && size <= 255
      && valid_protocols_tail(rest)
    }
  }
}

fn select_compatible_version(
  current: Version,
  offered: List(Version),
  attempted: List(Version),
) -> Result(Version, Nil) {
  [version.Version2, version.Version1]
  |> list.find(fn(candidate) {
    candidate != current
    && list.contains(offered, candidate)
    && !list.contains(attempted, candidate)
  })
}

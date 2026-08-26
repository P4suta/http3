//// One reusable native HTTP/3 client connection and its UDP pump.

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
import gleam_quic/internal/tls/authentication
import gleam_quic/internal/tls/engine
import gleam_quic/internal/tls/session_ticket
import gleam_quic/internal/udp
import gleam_quic/transport_parameter
import gleam_quic/version.{type Version}
import http3/internal/native/connection_state as http3_state
import http3/internal/native/session
import http3/internal/process_label
import http3/internal/qpack/header.{type Header}

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

/// Connection policy after public input validation.
pub type Config {
  Config(
    hostname: String,
    port: Int,
    address_family: AddressFamily,
    dns_timeout_milliseconds: Int,
    connect_timeout_milliseconds: Int,
    handshake_timeout_milliseconds: Int,
    timeout_milliseconds: Int,
    idle_timeout_milliseconds: Int,
    trust_store: authentication.TrustStore,
    http_datagrams: Bool,
    resumption_ticket: Option(session_ticket.ClientTicket),
    address_token: BitArray,
    maximum_pushes: Int,
    quic_version: Version,
    bidirectional_stream_limit: Int,
    unidirectional_stream_limit: Int,
    frame_limit: Int,
    datagram_limit: Int,
    qpack_table_limit: Int,
    qpack_blocked_stream_limit: Int,
  )
}

/// A socket, fixed peer endpoint, and established HTTP/3 session.
pub opaque type State {
  State(
    socket: udp.Socket,
    peer: udp.Endpoint,
    session: session.State,
    previous_socket: Option(udp.Socket),
    packets_received: Int,
    packets_sent: Int,
    data_received: Int,
    data_sent: Int,
    flushes: Int,
  )
}

/// Runtime traffic counters owned by one connection actor.
pub type Stats {
  Stats(
    packets_received: Int,
    packets_sent: Int,
    data_received: Int,
    data_sent: Int,
    acknowledgements_sent: Int,
    retransmissions: Int,
    batch_flushes: Int,
    packets_coalesced: Int,
  )
}

/// Stable reusable-connection failures.
pub type Error {
  InvalidInput
  ResolutionFailed
  SocketUnavailable
  DnsTimeout
  ConnectTimeout
  HandshakeTimeout
  OperationTimeout
  TotalTimeout
  TlsHandshakeFailed
  QuicTransportFailed(operation: String, error: driver.Error)
  Http3OperationFailed(operation: String, error: session.Error)
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

/// Resolve, authenticate, and establish one reusable connection.
pub fn connect(config: Config) -> Result(State, Error) {
  case validate(config) {
    Error(error) -> Error(error)
    Ok(Nil) -> {
      let deadline = udp.monotonic_millisecond() + config.timeout_milliseconds
      use addresses <- result.try(
        case
          udp.resolve_with_timeout(
            config.hostname,
            udp_address_family(config.address_family),
            int.min(
              config.dns_timeout_milliseconds,
              config.timeout_milliseconds,
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
  }
}

fn udp_address_family(address_family: AddressFamily) -> udp.AddressFamily {
  case address_family {
    Ipv4 -> udp.Ipv4
    Ipv6 -> udp.Ipv6
    DualStack -> udp.Any
  }
}

/// Open a request stream and queue its initial HEADERS frame.
pub fn open_request(
  state: State,
  headers: List(Header),
  allow_qpack_blocking: Bool,
  timeout_milliseconds: Int,
) -> Result(#(State, Int), Error) {
  use state <- result.try(await_request_streams(
    state,
    udp.monotonic_millisecond() + timeout_milliseconds,
  ))
  session.open_request(state.session, headers, allow_qpack_blocking)
  |> result.map(fn(output) {
    let #(next, identifier) = output
    #(State(..state, session: next), identifier)
  })
  |> map_session_result("open_request")
}

/// Return whether the connection actor can open an HTTP request stream now.
///
/// A resumed connection may return `True` during the handshake while its
/// authenticated 0-RTT write keys remain usable. Callers that own an active
/// socket must wait for network events instead of entering the passive pump
/// in `open_request` while this returns `False`.
pub fn request_streams_available(state: State) -> Bool {
  session.request_streams_available(state.session)
}

fn await_request_streams(state: State, deadline: Int) -> Result(State, Error) {
  case
    session.request_streams_available(state.session),
    session.phase(state.session),
    remaining_milliseconds(deadline)
  {
    True, _, _ -> Ok(state)
    False, transport.Closed, _ -> Error(PeerClosed)
    False, _, remaining if remaining <= 0 -> Error(OperationTimeout)
    False, transport.Handshaking, _ -> {
      use state <- result.try(pump_until(state, deadline))
      await_request_streams(state, deadline)
    }
    False, _, _ -> Error(PeerClosed)
  }
}

/// Queue one request-body DATA frame.
pub fn send_data(
  state: State,
  stream_id: Int,
  bytes: BitArray,
) -> Result(State, Error) {
  session.send_data(state.session, stream_id, bytes)
  |> result.map(fn(next) { State(..state, session: next) })
  |> map_session_result("send_data")
}

/// Queue request trailers.
pub fn send_trailers(
  state: State,
  stream_id: Int,
  headers: List(Header),
  allow_qpack_blocking: Bool,
) -> Result(State, Error) {
  session.send_trailers(state.session, stream_id, headers, allow_qpack_blocking)
  |> result.map(fn(next) { State(..state, session: next) })
  |> map_session_result("send_trailers")
}

/// Queue request trailers and the terminal FIN as one state transition.
pub fn finish_with_trailers(
  state: State,
  stream_id: Int,
  headers: List(Header),
  allow_qpack_blocking: Bool,
) -> Result(State, Error) {
  use with_trailers <- result.try(
    session.send_trailers(
      state.session,
      stream_id,
      headers,
      allow_qpack_blocking,
    )
    |> map_session_result("send_trailers"),
  )
  session.finish_stream(with_trailers, stream_id)
  |> result.map(fn(next) { State(..state, session: next) })
  |> map_session_result("finish_trailers")
}

/// Queue a request FIN after HTTP message validation.
pub fn finish_stream(state: State, stream_id: Int) -> Result(State, Error) {
  // A zero-length DATA frame is valid HTTP/3 and makes the terminal FIN
  // observable to peers whose incremental parser otherwise waits for another
  // frame header when FIN arrives in a separate QUIC STREAM frame.
  use with_terminal_data <- result.try(
    session.send_data(state.session, stream_id, <<>>)
    |> map_session_result("finish"),
  )
  session.finish_stream(with_terminal_data, stream_id)
  |> result.map(fn(next) { State(..state, session: next) })
  |> map_session_result("finish")
}

/// Abort both request-stream directions.
pub fn abort_stream(
  state: State,
  stream_id: Int,
  application_error_code: Int,
) -> Result(State, Error) {
  session.abort_stream(state.session, stream_id, application_error_code)
  |> result.map(fn(next) { State(..state, session: next) })
  |> map_session_result("abort")
}

/// Cancel one accepted server push.
pub fn cancel_push(state: State, push_id: Int) -> Result(State, Error) {
  session.cancel_push(state.session, push_id)
  |> result.map(fn(next) { State(..state, session: next) })
  |> map_session_result("cancel_push")
}

/// Return negotiated advanced capabilities.
pub fn datagrams_available(state: State) -> Bool {
  session.datagrams_available(state.session)
}

/// Return whether the peer permits active path migration.
pub fn active_migration_available(state: State) -> Bool {
  session.active_migration_available(state.session)
}

/// Return the largest HTTP Datagram payload for one request stream.
pub fn maximum_http_datagram_size(
  state: State,
  stream_id: Int,
) -> Result(Int, Error) {
  session.maximum_http_datagram_size(state.session, stream_id)
  |> map_session_result("maximum_datagram_size")
}

/// Queue one HTTP Datagram.
pub fn send_http_datagram(
  state: State,
  stream_id: Int,
  payload: BitArray,
) -> Result(State, Error) {
  session.send_http_datagram(state.session, stream_id, payload)
  |> result.map(fn(next) { State(..state, session: next) })
  |> map_session_result("send_datagram")
}

/// Send a request priority update.
pub fn set_request_priority(
  state: State,
  stream_id: Int,
  urgency: Int,
  incremental: Bool,
) -> Result(State, Error) {
  session.set_request_priority(state.session, stream_id, urgency, incremental)
  |> result.map(fn(next) { State(..state, session: next) })
  |> map_session_result("set_priority")
}

/// Queue one transport PING.
pub fn ping(state: State) -> Result(State, Error) {
  session.ping(state.session)
  |> result.map(fn(next) { State(..state, session: next) })
  |> map_session_result("ping")
}

/// Change the live congestion controller.
pub fn set_congestion_algorithm(
  state: State,
  algorithm: transport.CongestionAlgorithm,
) -> Result(State, Error) {
  session.set_congestion_algorithm(state.session, algorithm)
  |> result.map(fn(next) { State(..state, session: next) })
  |> map_session_result("set_congestion_control")
}

/// Return the current non-fragmenting QUIC UDP payload size.
pub fn path_mtu(state: State) -> Int {
  session.path_mtu(state.session)
}

/// Return whether DPLPMTUD has reached this path's current ceiling.
pub fn pmtu_discovery_complete(state: State) -> Bool {
  session.pmtu_discovery_complete(state.session)
}

/// Return whether an active migration candidate is still being validated.
pub fn path_validation_in_progress(state: State) -> Bool {
  session.path_validation_in_progress(state.session)
}

/// Return whether the resumed handshake has installed authenticated 1-RTT.
pub fn handshake_established(state: State) -> Bool {
  session.phase(state.session) == transport.Established
}

/// Return whether the established TLS handshake selected its offered ticket.
pub fn resumed(state: State) -> Bool {
  session.client_resumed(state.session)
}

/// Send and commit at most one exact-size DPLPMTUD probe.
pub fn probe_path_mtu(state: State, now: Int) -> Result(State, Error) {
  case session.prepare_pmtu_probe(state.session, now) {
    Error(error) -> Error(Http3OperationFailed("prepare PMTU probe", error))
    Ok(None) -> Ok(state)
    Ok(Some(prepared)) -> {
      let bytes = session.prepared_bytes(prepared)
      use Nil <- result.try(
        udp.send(state.socket, state.peer, bytes, ecn.NotEct) |> map_udp_send,
      )
      use next <- result.try(
        session.commit_datagram(prepared, ecn.NotEct, now)
        |> result.map_error(fn(error) {
          Http3OperationFailed("commit PMTU probe", error)
        }),
      )
      Ok(
        State(
          ..state,
          session: next,
          packets_sent: state.packets_sent + 1,
          data_sent: state.data_sent + bit_array.byte_size(bytes),
          flushes: state.flushes + 1,
        ),
      )
    }
  }
}

/// Snapshot current path diagnostics.
pub fn path_snapshot(state: State) -> transport.PathSnapshot {
  session.path_snapshot(state.session)
}

/// Snapshot runtime-owned connection counters.
pub fn stats(state: State) -> Stats {
  let transport.ConnectionCounters(acks, retransmissions, coalesced) =
    session.connection_counters(state.session)
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

/// Select a fresh local UDP path and begin QUIC path validation.
pub fn migrate(state: State) -> Result(State, Error) {
  case
    state.previous_socket,
    session.active_migration_available(state.session)
  {
    Some(_), _ | _, False -> Error(MigrationUnavailable)
    None, True -> {
      use challenge <- result.try(
        crypto.secure_random(8) |> result.replace_error(MigrationUnavailable),
      )
      use socket <- result.try(
        open_for_peer(state.peer) |> result.replace_error(MigrationUnavailable),
      )
      case
        session.begin_path_validation(
          state.session,
          challenge,
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
              previous_socket: Some(state.socket),
              session: next,
            ),
          )
      }
    }
  }
}

fn settle_migration(state: State, events: List(session.Event)) -> State {
  case state.previous_socket {
    None -> state
    Some(previous_socket) -> {
      let validated =
        list.any(events, fn(event) {
          event == session.TransportEvent(transport.PathValidated)
        })
      let failed =
        list.any(events, fn(event) {
          event == session.TransportEvent(transport.PathValidationFailed)
        })
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

/// Pull and clear ordered transport and HTTP/3 events.
pub fn take_events(state: State) -> #(State, List(session.Event)) {
  let #(next, events) = session.take_events(state.session)
  #(settle_migration(State(..state, session: next), events), events)
}

/// Advance timers, flush bounded output, and receive at most one datagram.
pub fn pump(state: State, timeout_milliseconds: Int) -> Result(State, Error) {
  case timeout_milliseconds < 0 {
    True -> Error(InvalidInput)
    False -> {
      use state <- result.try(drive(state))
      receive(state, timeout_milliseconds)
    }
  }
}

fn pump_until(state: State, total_deadline: Int) -> Result(State, Error) {
  use state <- result.try(drive(state))
  let now = udp.monotonic_millisecond()
  use protocol_deadline <- result.try(next_deadline(state, now))
  receive(state, wait_milliseconds(total_deadline, protocol_deadline, now))
}

/// Advance timers and flush bounded output without polling the UDP socket.
pub fn drive(state: State) -> Result(State, Error) {
  let now = udp.monotonic_millisecond()
  use state <- result.try(
    session.tick(state.session, now)
    |> result.map(fn(next) { State(..state, session: next) })
    |> map_session_result("tick"),
  )
  flush(state, now, maximum_packets_per_flush)
}

/// Return the earliest protocol deadline for the owning event loop.
pub fn next_deadline(state: State, now: Int) -> Result(Option(Int), Error) {
  session.next_deadline(state.session, now)
  |> map_session_result("next_deadline")
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

/// Consume one active-mode mailbox datagram from either live path.
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

/// Best-effort HTTP/3 close followed by unconditional socket cleanup.
pub fn close(state: State, application_error_code: Int, reason: String) -> Nil {
  let now = udp.monotonic_millisecond()
  case session.close(state.session, application_error_code, reason, now) {
    Error(_) -> Nil
    Ok(next) -> {
      case flush(State(..state, session: next), now, 4) {
        Ok(_) -> Nil
        Error(_) -> Nil
      }
    }
  }
  let _ = udp.close(state.socket)
  case state.previous_socket {
    Some(socket) -> {
      let _ = udp.close(socket)
      Nil
    }
    None -> Nil
  }
  Nil
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
    [address], _ ->
      connect_address(config, address, deadline, confirm_reachability: False)
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
  case connect_address(config, address, deadline, confirm_reachability: True) {
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
    Error(_transfer_error) -> {
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
        Ok(CandidateReady(candidate, decision)) -> {
          select_candidate(candidate, decision, candidates, deadline)
        }
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

// Preserve the most actionable failure when slower candidates time out after
// another address already returned an authenticated TLS or protocol result.
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
    QuicTransportFailed(_, _) | Http3OperationFailed(_, _) | PeerClosed -> 80
    HandshakeTimeout -> 60
    ConnectTimeout -> 50
    DnsTimeout | ResolutionFailed -> 40
    SocketUnavailable -> 30
    TotalTimeout -> 20
    OperationTimeout | MigrationUnavailable | InvalidInput -> 10
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
  confirm_reachability confirm_reachability: Bool,
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
        Ok(state) ->
          case config.resumption_ticket {
            None -> Ok(state)
            Some(ticket) ->
              case session_ticket.early_data_allowed(ticket) {
                False -> Ok(state)
                True if confirm_reachability ->
                  confirm_resumption_candidate(
                    state,
                    int.min(
                      deadline,
                      udp.monotonic_millisecond()
                        + config.handshake_timeout_milliseconds,
                    ),
                  )
                True -> Ok(state)
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

// A 0-RTT session can produce application data before the peer is reachable.
// During a multi-address race, do not let an unreachable first address win
// merely because its ClientHello was queued. A single resolved address skips
// this wait so the owning actor can put application data into a real 0-RTT
// packet before the server completes its side of the handshake.
fn confirm_resumption_candidate(
  state: State,
  deadline: Int,
) -> Result(State, Error) {
  case state.packets_received > 0, remaining_milliseconds(deadline) {
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
  use selected_version <- result.try(initial_connection_version(config))
  establish_version(
    config,
    socket,
    peer,
    int.min(
      deadline,
      udp.monotonic_millisecond() + config.handshake_timeout_milliseconds,
    ),
    selected_version,
    [],
  )
}

fn initial_connection_version(config: Config) -> Result(Version, Error) {
  case config.resumption_ticket {
    None -> Ok(config.quic_version)
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
      application_protocols: [<<"h3">>],
      transport_parameters: client_transport_parameters(
        local_connection_id,
        config.http_datagrams,
        selected_version,
        config.resumption_ticket == None,
        config.idle_timeout_milliseconds,
        config.bidirectional_stream_limit,
        config.unidirectional_stream_limit,
        config.datagram_limit,
      ),
      trust_store: config.trust_store,
      client_credential: None,
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
          session_ticket.early_data_allowed(ticket),
        )
    }
    |> result.replace_error(TlsHandshakeFailed),
  )
  use quic <- result.try(
    driver.start_client_with_token(
      client_transport_config(
        config.http_datagrams,
        selected_version,
        config.idle_timeout_milliseconds,
        config.bidirectional_stream_limit,
        config.unidirectional_stream_limit,
        config.datagram_limit,
      ),
      tls,
      original_destination_connection_id,
      local_connection_id,
      config.address_token,
      now,
    )
    |> result.map_error(fn(error) { QuicTransportFailed("start", error) }),
  )
  case config.resumption_ticket {
    None ->
      complete_handshake(
        config,
        quic,
        socket,
        peer,
        deadline,
        selected_version,
        attempted_versions,
      )
    Some(ticket) ->
      case session_ticket.early_data_allowed(ticket) {
        True -> start_session(config, quic, socket, peer, deadline, False)
        False ->
          complete_handshake(
            config,
            quic,
            socket,
            peer,
            deadline,
            selected_version,
            attempted_versions,
          )
      }
  }
}

fn complete_handshake(
  config: Config,
  quic: driver.State,
  socket: udp.Socket,
  peer: udp.Endpoint,
  deadline: Int,
  selected_version: Version,
  attempted_versions: List(Version),
) -> Result(State, Error) {
  case handshake(quic, socket, peer, deadline, attempted_versions != []) {
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
            socket,
            peer,
            deadline,
            next_version,
            [selected_version, ..attempted_versions],
          )
      }
    Error(error) -> Error(error)
    Ok(quic) -> start_session(config, quic, socket, peer, deadline, True)
  }
}

fn start_session(
  config: Config,
  quic: driver.State,
  socket: udp.Socket,
  peer: udp.Endpoint,
  deadline: Int,
  await_settings: Bool,
) -> Result(State, Error) {
  use http3 <- result.try(
    session.start(
      quic,
      client_http3_config(
        config.http_datagrams,
        config.bidirectional_stream_limit,
        config.frame_limit,
        config.datagram_limit,
        config.qpack_table_limit,
        config.qpack_blocked_stream_limit,
      ),
      config.http_datagrams,
    )
    |> result.map_error(fn(error) { Http3OperationFailed("start", error) }),
  )
  let state = State(socket, peer, http3, None, 0, 0, 0, 0, 0)
  use state <- result.try(case await_settings {
    True -> await_peer_settings(state, deadline)
    False -> Ok(state)
  })
  case config.maximum_pushes {
    0 -> Ok(state)
    maximum ->
      session.permit_pushes(state.session, maximum - 1)
      |> result.map(fn(next) { State(..state, session: next) })
      |> map_session_result("permit_pushes")
  }
}

fn await_peer_settings(state: State, deadline: Int) -> Result(State, Error) {
  case
    session.peer_settings_received(state.session),
    remaining_milliseconds(deadline)
  {
    True, _ -> Ok(state)
    False, remaining if remaining <= 0 -> Error(HandshakeTimeout)
    False, _ -> {
      use state <- result.try(pump_until(state, deadline))
      await_peer_settings(state, deadline)
    }
  }
}

fn handshake(
  state: driver.State,
  socket: udp.Socket,
  peer: udp.Endpoint,
  deadline: Int,
  ignore_version_negotiation: Bool,
) -> Result(driver.State, Error) {
  case driver.phase(state), remaining_milliseconds(deadline) {
    transport.Established, _ -> Ok(state)
    transport.Closed, _ -> Error(PeerClosed)
    _, remaining if remaining <= 0 -> Error(HandshakeTimeout)
    _, _ -> {
      let now = udp.monotonic_millisecond()
      use state <- result.try(
        driver.tick(state, now)
        |> result.map_error(fn(error) { QuicTransportFailed("tick", error) }),
      )
      use state <- result.try(flush_driver(
        state,
        socket,
        peer,
        now,
        maximum_packets_per_flush,
      ))
      let wait_now = udp.monotonic_millisecond()
      use protocol_deadline <- result.try(
        driver.next_deadline(state, wait_now)
        |> result.map_error(fn(error) {
          QuicTransportFailed("next deadline", error)
        }),
      )
      use state <- result.try(receive_driver(
        state,
        socket,
        peer,
        wait_milliseconds(deadline, protocol_deadline, wait_now),
        ignore_version_negotiation,
      ))
      handshake(state, socket, peer, deadline, ignore_version_negotiation)
    }
  }
}

fn flush_driver(
  state: driver.State,
  socket: udp.Socket,
  peer: udp.Endpoint,
  now: Int,
  remaining_packets: Int,
) -> Result(driver.State, Error) {
  case remaining_packets {
    0 -> Ok(state)
    _ ->
      case driver.prepare_datagram(state, maximum_frame_data_bytes, now) {
        Error(driver.ConnectionFailure(transport.PacingLimited(_))) -> Ok(state)
        Error(driver.ConnectionFailure(transport.CongestionLimited)) ->
          Ok(state)
        Error(error) -> Error(QuicTransportFailed("prepare", error))
        Ok(None) -> Ok(state)
        Ok(Some(prepared)) -> {
          use Nil <- result.try(
            udp.send(socket, peer, driver.prepared_bytes(prepared), ecn.NotEct)
            |> map_udp_send,
          )
          use state <- result.try(
            driver.commit_datagram_with_ecn(prepared, ecn.NotEct, now)
            |> result.map_error(fn(error) {
              QuicTransportFailed("commit", error)
            }),
          )
          flush_driver(state, socket, peer, now, remaining_packets - 1)
        }
      }
  }
}

fn receive_driver(
  state: driver.State,
  socket: udp.Socket,
  peer: udp.Endpoint,
  timeout: Int,
  ignore_version_negotiation: Bool,
) -> Result(driver.State, Error) {
  case udp.receive(socket, timeout) {
    Error(udp.Timeout) -> Ok(state)
    Error(_) -> Error(SocketUnavailable)
    Ok(udp.Datagram(received_peer, bytes, marking)) ->
      case same_endpoint(received_peer, peer) {
        False -> Ok(state)
        True ->
          case
            driver.receive_datagram_with_ecn(
              state,
              bytes,
              marking,
              udp.monotonic_millisecond(),
            )
          {
            Ok(state) -> Ok(state)
            Error(driver.VersionNegotiationReceived(versions)) ->
              case ignore_version_negotiation {
                True -> Ok(state)
                False -> Error(VersionNegotiationReceived(versions))
              }
            Error(error) -> discard_or_fail_driver(state, error)
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
        session.prepare_datagram(state.session, maximum_frame_data_bytes, now)
      {
        Error(session.DriverFailure(driver.ConnectionFailure(transport.PacingLimited(
          _,
        )))) -> Ok(state)
        Error(session.DriverFailure(driver.ConnectionFailure(
          transport.CongestionLimited,
        ))) -> Ok(state)
        Error(error) -> Error(Http3OperationFailed("prepare", error))
        Ok(None) -> Ok(state)
        Ok(Some(prepared)) -> {
          use Nil <- result.try(
            udp.send(
              state.socket,
              state.peer,
              session.prepared_bytes(prepared),
              ecn.NotEct,
            )
            |> map_udp_send,
          )
          use next <- result.try(
            session.commit_datagram(prepared, ecn.NotEct, now)
            |> result.map_error(fn(error) {
              Http3OperationFailed("commit", error)
            }),
          )
          let bytes = bit_array.byte_size(session.prepared_bytes(prepared))
          flush(
            State(
              ..state,
              session: next,
              packets_sent: state.packets_sent + 1,
              data_sent: state.data_sent + bytes,
              flushes: state.flushes + 1,
            ),
            now,
            remaining_packets - 1,
          )
        }
      }
  }
}

fn receive(state: State, timeout: Int) -> Result(State, Error) {
  case udp.receive(state.socket, timeout) {
    Error(udp.Timeout) -> Ok(state)
    Error(_) -> Error(SocketUnavailable)
    Ok(datagram) -> process_received_datagram(state, datagram)
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

fn process_received_datagram(
  state: State,
  datagram: udp.Datagram,
) -> Result(State, Error) {
  let udp.Datagram(peer, bytes, marking) = datagram
  case same_endpoint(peer, state.peer) {
    False -> Ok(state)
    True ->
      case
        session.receive_datagram(
          state.session,
          bytes,
          marking,
          udp.monotonic_millisecond(),
        )
      {
        Ok(next) ->
          Ok(
            State(
              ..state,
              session: next,
              packets_received: state.packets_received + 1,
              data_received: state.data_received + bit_array.byte_size(bytes),
            ),
          )
        Error(session.DriverFailure(error)) ->
          case discard_driver_error(error) {
            True -> Ok(state)
            False ->
              Error(Http3OperationFailed(
                "receive",
                session.DriverFailure(error),
              ))
          }
        Error(error) -> Error(Http3OperationFailed("receive", error))
      }
  }
}

fn client_transport_config(
  http_datagrams: Bool,
  selected_version: Version,
  idle_timeout_milliseconds: Int,
  bidirectional_stream_limit: Int,
  unidirectional_stream_limit: Int,
  datagram_limit: Int,
) -> transport.Config {
  let config = transport.default_config(transport.Client)
  let maximum_datagram = int.min(datagram_limit, maximum_udp_payload_size)
  transport.Config(
    ..config,
    version: selected_version,
    idle_timeout_milliseconds: idle_timeout_milliseconds,
    maximum_peer_streams_bidirectional: bidirectional_stream_limit,
    maximum_peer_streams_unidirectional: unidirectional_stream_limit,
    maximum_total_streams: bidirectional_stream_limit
      + unidirectional_stream_limit,
    maximum_udp_payload_size: maximum_udp_payload_size,
    grease_quic_bit: True,
    maximum_datagram_frame_size: case http_datagrams {
      True -> maximum_datagram
      False -> 0
    },
  )
}

fn client_transport_parameters(
  local_connection_id: BitArray,
  http_datagrams: Bool,
  selected_version: Version,
  advertise_compatible_versions: Bool,
  idle_timeout_milliseconds: Int,
  bidirectional_stream_limit: Int,
  unidirectional_stream_limit: Int,
  datagram_limit: Int,
) -> List(transport_parameter.Parameter) {
  let available_versions = case advertise_compatible_versions {
    True -> [version.Version2, version.Version1]
    False -> [selected_version]
  }
  let parameters = [
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
  ]
  case http_datagrams {
    True -> [
      transport_parameter.MaxDatagramFrameSize(int.min(
        datagram_limit,
        maximum_udp_payload_size,
      )),
      ..parameters
    ]
    False -> parameters
  }
}

fn client_http3_config(
  http_datagrams: Bool,
  bidirectional_stream_limit: Int,
  frame_limit: Int,
  datagram_limit: Int,
  qpack_table_limit: Int,
  qpack_blocked_stream_limit: Int,
) -> http3_state.Config {
  let config = http3_state.default_config(http3_state.Client)
  let settings =
    http3_state.Settings(
      ..config.settings,
      qpack_max_table_capacity: qpack_table_limit,
      qpack_blocked_streams: qpack_blocked_stream_limit,
      h3_datagram: http_datagrams,
    )
  http3_state.Config(
    ..config,
    settings: settings,
    preferred_qpack_table_capacity: qpack_table_limit,
    maximum_transactions: bidirectional_stream_limit,
    maximum_datagram_payload_bytes: datagram_limit,
    maximum_frame_payload_bytes: frame_limit,
  )
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

fn map_session_result(
  result: Result(value, session.Error),
  operation: String,
) -> Result(value, Error) {
  result.map_error(result, fn(error) { Http3OperationFailed(operation, error) })
}

fn map_udp_send(result: Result(Nil, udp.Error)) -> Result(Nil, Error) {
  result.replace_error(result, SocketUnavailable)
}

fn same_endpoint(left: udp.Endpoint, right: udp.Endpoint) -> Bool {
  udp.endpoint_parts(left) == udp.endpoint_parts(right)
}

fn remaining_milliseconds(deadline: Int) -> Int {
  deadline - udp.monotonic_millisecond()
}

fn option_error(value: Option(Error), fallback: Error) -> Error {
  case value {
    Some(error) -> error
    None -> fallback
  }
}

fn discard_or_fail_driver(
  state: driver.State,
  error: driver.Error,
) -> Result(driver.State, Error) {
  case discard_driver_error(error) {
    True -> Ok(state)
    False ->
      case error {
        driver.ConnectionFailure(transport.TlsFailure(_)) ->
          Error(TlsHandshakeFailed)
        _ -> Error(QuicTransportFailed("receive", error))
      }
  }
}

fn discard_driver_error(error: driver.Error) -> Bool {
  driver.discardable_receive_error(error)
}

fn validate(config: Config) -> Result(Nil, Error) {
  case
    config.hostname != ""
    && config.port > 0
    && config.port <= 65_535
    && config.dns_timeout_milliseconds > 0
    && config.connect_timeout_milliseconds > 0
    && config.handshake_timeout_milliseconds > 0
    && config.timeout_milliseconds > 0
    && config.idle_timeout_milliseconds > 0
    && config.maximum_pushes >= 0
    && config.maximum_pushes <= 1024
    && config.bidirectional_stream_limit > 0
    && config.unidirectional_stream_limit > 0
    && config.frame_limit > 0
    && config.datagram_limit > 0
    && config.qpack_table_limit > 0
    && config.qpack_blocked_stream_limit > 0
    && {
      config.quic_version == version.Version1
      || config.quic_version == version.Version2
    }
  {
    True -> Ok(Nil)
    False -> Error(InvalidInput)
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

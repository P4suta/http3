//// Synchronous bounded HTTP/3 client over the native QUIC runtime.

import gleam/bit_array
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
import gleam_quic/internal/udp
import gleam_quic/transport_parameter
import gleam_quic/version.{type Version}
import http3/internal/native/connection_state as http3_state
import http3/internal/native/header_semantics
import http3/internal/native/session
import http3/internal/process_label
import http3/internal/qpack/header.{type Header, Header}

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

/// Validated inputs for one native request.
pub type Config {
  Config(
    hostname: String,
    port: Int,
    address_family: AddressFamily,
    dns_timeout_milliseconds: Int,
    connect_timeout_milliseconds: Int,
    handshake_timeout_milliseconds: Int,
    timeout_milliseconds: Int,
    operation_timeout_milliseconds: Int,
    idle_timeout_milliseconds: Int,
    maximum_response_body_bytes: Int,
    trust_store: authentication.TrustStore,
    quic_version: Version,
    keepalive_milliseconds: Int,
  )
}

/// A complete bounded HTTP response.
pub type Response {
  Response(status: Int, headers: List(#(String, String)), body: BitArray)
}

/// Stable failures without leaking protocol-state representations.
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
  Http3ProtocolFailed
  Http3OperationFailed(operation: String, error: session.Error)
  PeerClosed
  StreamReset(Int)
  InvalidHeaderEncoding
  ResponseBodyTooLarge(Int)
  VersionNegotiationReceived(List(Version))
  VersionNegotiationFailed
}

type Collector {
  Collector(
    status: Option(Int),
    headers: List(#(String, String)),
    body: BitArray,
    finished: Bool,
  )
}

type Established {
  Established(socket: udp.Socket, peer: udp.Endpoint, quic: driver.State)
}

type CandidateDecision {
  Select(Subject(Result(Established, Error)))
  Cancel
}

type CandidateMessage {
  CandidateReady(Pid, Subject(CandidateDecision))
  CandidateFailed(Error)
}

/// Run one request on one connection and close its UDP socket before return.
pub fn send(
  config config: Config,
  fields fields: List(#(String, String)),
  body body: BitArray,
) -> Result(Response, Error) {
  case validate(config, body) {
    Error(error) -> Error(error)
    Ok(Nil) -> {
      let started = udp.monotonic_millisecond()
      let deadline = started + config.timeout_milliseconds
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
      use headers <- result.try(encode_headers(fields))
      use established <- result.try(connect_addresses(
        config,
        addresses,
        deadline,
      ))
      let Established(socket, peer, quic) = established
      let outcome =
        request_after_handshake(
          config,
          socket,
          peer,
          headers,
          body,
          deadline,
          quic,
        )
      let closed = udp.close(socket)
      case outcome, closed {
        Ok(response), Ok(Nil) -> Ok(response)
        Ok(_), Error(_) -> Error(SocketUnavailable)
        Error(error), _ -> Error(error)
      }
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

fn connect_addresses(
  config: Config,
  addresses: List(udp.Address),
  deadline: Int,
) -> Result(Established, Error) {
  case addresses, remaining_milliseconds(deadline) {
    _, remaining if remaining <= 0 -> Error(TotalTimeout)
    [], _ -> Error(SocketUnavailable)
    [address], _ -> establish_at_address(config, address, deadline)
    [_, _, ..], _ -> race_addresses(config, addresses, deadline)
  }
}

fn race_addresses(
  config: Config,
  addresses: List(udp.Address),
  deadline: Int,
) -> Result(Established, Error) {
  let results = process.new_subject()
  let owner = process.self()
  let candidates =
    spawn_candidates(config, addresses, deadline, owner, results, 0, [])
  await_candidate(
    results,
    candidates,
    list.length(candidates),
    deadline,
    SocketUnavailable,
  )
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
  case establish_at_address(config, address, deadline) {
    Error(error) -> process.send(results, CandidateFailed(error))
    Ok(established) -> offer_candidate(established, deadline, owner, results)
  }
}

fn offer_candidate(
  established: Established,
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
    Ok(Select(completion)) -> transfer_candidate(established, owner, completion)
    Ok(Cancel) | Error(Nil) -> discard_established(established)
  }
}

fn transfer_candidate(
  established: Established,
  owner: Pid,
  completion: Subject(Result(Established, Error)),
) -> Nil {
  let Established(socket, _, _) = established
  case udp.transfer_owner(socket, owner) {
    Ok(Nil) -> process.send(completion, Ok(established))
    Error(udp.InvalidInput)
    | Error(udp.Timeout)
    | Error(udp.Closed)
    | Error(udp.PermissionDenied)
    | Error(udp.AddressInUse)
    | Error(udp.AddressUnavailable)
    | Error(udp.EcnUnavailable)
    | Error(udp.MessageTooLarge)
    | Error(udp.SocketFailure) -> {
      discard_established(established)
      process.send(completion, Error(SocketUnavailable))
    }
  }
}

fn await_candidate(
  results: Subject(CandidateMessage),
  candidates: List(Pid),
  remaining_candidates: Int,
  deadline: Int,
  last_error: Error,
) -> Result(Established, Error) {
  case remaining_candidates, remaining_milliseconds(deadline) {
    0, _ -> Error(last_error)
    _, remaining if remaining <= 0 -> {
      cancel_candidates(candidates, None)
      Error(TotalTimeout)
    }
    _, remaining ->
      case process.receive(results, within: remaining) {
        Error(Nil) -> {
          cancel_candidates(candidates, None)
          Error(TotalTimeout)
        }
        Ok(CandidateFailed(error)) ->
          await_candidate(
            results,
            candidates,
            remaining_candidates - 1,
            deadline,
            error,
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
) -> Result(Established, Error) {
  let completion = process.new_subject()
  process.send(decision, Select(completion))
  case
    process.receive(
      completion,
      within: int.max(0, remaining_milliseconds(deadline)),
    )
  {
    Ok(Ok(established)) -> {
      cancel_candidates(candidates, Some(candidate))
      Ok(established)
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

fn cancel_candidates(candidates: List(Pid), winner: Option(Pid)) -> Nil {
  list.each(candidates, fn(candidate) {
    case winner {
      Some(selected) if selected == candidate -> Nil
      _ -> process.kill(candidate)
    }
  })
}

fn discard_established(established: Established) -> Nil {
  let Established(socket, _, _) = established
  let _close_result = udp.close(socket)
  Nil
}

fn establish_at_address(
  config: Config,
  address: udp.Address,
  deadline: Int,
) -> Result(Established, Error) {
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
    False -> establish_on_socket(config, socket, peer, deadline)
  }
  case outcome {
    Ok(quic) -> Ok(Established(socket, peer, quic))
    Error(error) -> {
      let _close_result = udp.close(socket)
      Error(error)
    }
  }
}

fn establish_on_socket(
  config: Config,
  socket: udp.Socket,
  peer: udp.Endpoint,
  deadline: Int,
) -> Result(driver.State, Error) {
  let #(handshake_deadline, timeout_error) =
    phase_deadline(
      deadline,
      config.handshake_timeout_milliseconds,
      HandshakeTimeout,
    )
  establish_on_socket_version(
    config,
    socket,
    peer,
    handshake_deadline,
    timeout_error,
    config.quic_version,
    [],
  )
}

fn establish_on_socket_version(
  config: Config,
  socket: udp.Socket,
  peer: udp.Endpoint,
  handshake_deadline: Int,
  timeout_error: Error,
  selected_version: Version,
  attempted_versions: List(Version),
) -> Result(driver.State, Error) {
  use original_destination_connection_id <- result.try(random_connection_id())
  use local_connection_id <- result.try(random_connection_id())
  let transport_config =
    client_transport_config(
      selected_version,
      config.idle_timeout_milliseconds,
      udp.dont_fragment(socket),
    )
  let tls_config =
    engine.ClientConfig(
      version: selected_version,
      hostname: config.hostname,
      application_protocols: [<<"h3">>],
      transport_parameters: client_transport_parameters(
        local_connection_id,
        selected_version,
        config.idle_timeout_milliseconds,
      ),
      trust_store: config.trust_store,
      client_credential: None,
      retried: False,
      version_negotiated: attempted_versions != [],
    )
  use tls <- result.try(
    engine.start_client(tls_config) |> result.replace_error(TlsHandshakeFailed),
  )
  use quic <- result.try(
    driver.start_client(
      transport_config,
      tls,
      original_destination_connection_id,
      local_connection_id,
      udp.monotonic_millisecond(),
    )
    |> result.map_error(fn(error) { QuicTransportFailed("start", error) }),
  )
  case
    handshake(
      quic,
      socket,
      peer,
      handshake_deadline,
      timeout_error,
      attempted_versions != [],
    )
  {
    Error(VersionNegotiationReceived(offered)) ->
      case
        select_compatible_version(selected_version, offered, [
          selected_version,
          ..attempted_versions
        ])
      {
        Error(_) -> Error(VersionNegotiationFailed)
        Ok(next_version) ->
          establish_on_socket_version(
            config,
            socket,
            peer,
            handshake_deadline,
            timeout_error,
            next_version,
            [selected_version, ..attempted_versions],
          )
      }
    Error(error) -> Error(error)
    Ok(quic) -> Ok(quic)
  }
}

fn request_after_handshake(
  config: Config,
  socket: udp.Socket,
  peer: udp.Endpoint,
  headers: List(Header),
  body: BitArray,
  deadline: Int,
  quic: driver.State,
) -> Result(Response, Error) {
  use http3 <- result.try(
    session.start(quic, http3_state.default_config(http3_state.Client), False)
    |> result.map_error(fn(error) { Http3OperationFailed("start", error) }),
  )
  use #(http3, stream_id) <- result.try(
    session.open_request(http3, headers, False)
    |> result.map_error(fn(error) {
      Http3OperationFailed("open_request", error)
    }),
  )
  use http3 <- result.try(case body {
    <<>> -> Ok(http3)
    _ ->
      session.send_data(http3, stream_id, body)
      |> result.map_error(fn(error) { Http3OperationFailed("send_data", error) })
  })
  use http3 <- result.try(
    session.finish_stream(http3, stream_id)
    |> result.map_error(fn(error) { Http3OperationFailed("finish", error) }),
  )
  let #(operation_deadline, timeout_error) =
    phase_deadline(
      deadline,
      config.operation_timeout_milliseconds,
      OperationTimeout,
    )
  use #(http3, response) <- result.try(collect_response(
    http3,
    socket,
    peer,
    stream_id,
    Collector(None, [], <<>>, False),
    config.maximum_response_body_bytes,
    operation_deadline,
    timeout_error,
    config.keepalive_milliseconds,
    next_keepalive(config.keepalive_milliseconds),
  ))
  graceful_close(http3, socket, peer)
  Ok(response)
}

fn handshake(
  state: driver.State,
  socket: udp.Socket,
  peer: udp.Endpoint,
  deadline: Int,
  timeout_error: Error,
  ignore_version_negotiation: Bool,
) -> Result(driver.State, Error) {
  case driver.phase(state), remaining_milliseconds(deadline) {
    transport.Established, _ -> Ok(state)
    transport.Closed, _ -> Error(PeerClosed)
    _, remaining if remaining <= 0 -> Error(timeout_error)
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
        wait_milliseconds(deadline, protocol_deadline, 0, wait_now),
        ignore_version_negotiation,
      ))
      handshake(
        state,
        socket,
        peer,
        deadline,
        timeout_error,
        ignore_version_negotiation,
      )
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
        Ok(Some(prepared)) ->
          send_prepared_handshake(
            state,
            prepared,
            socket,
            peer,
            now,
            remaining_packets,
          )
      }
  }
}

/// Send one prepared handshake datagram and continue the flush.
///
/// The socket sets Don't-Fragment, so a datagram an outgoing device cannot
/// carry whole is refused rather than split. That is a path measurement, not a
/// broken socket: it is dropped uncommitted, its frames stay queued, and the
/// path returns to the 1200-byte floor.
fn send_prepared_handshake(
  state: driver.State,
  prepared: driver.PreparedDatagram,
  socket: udp.Socket,
  peer: udp.Endpoint,
  now: Int,
  remaining_packets: Int,
) -> Result(driver.State, Error) {
  case
    udp.classify_send(udp.send(
      socket,
      peer,
      driver.prepared_bytes(prepared),
      ecn.NotEct,
    ))
  {
    udp.PathTooSmall -> Ok(driver.report_pmtu_black_hole(state))
    udp.SocketLost -> Error(SocketUnavailable)
    udp.Delivered -> {
      use state <- result.try(
        driver.commit_datagram_with_ecn(prepared, ecn.NotEct, now)
        |> result.map_error(fn(error) { QuicTransportFailed("commit", error) }),
      )
      flush_driver(state, socket, peer, now, remaining_packets - 1)
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
    Error(udp.Closed) -> Error(SocketUnavailable)
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

fn collect_response(
  state: session.State,
  socket: udp.Socket,
  peer: udp.Endpoint,
  stream_id: Int,
  collector: Collector,
  body_limit: Int,
  deadline: Int,
  timeout_error: Error,
  keepalive_milliseconds: Int,
  next_keepalive_milliseconds: Int,
) -> Result(#(session.State, Response), Error) {
  let #(state, events) = session.take_events(state)
  use collector <- result.try(apply_events(
    events,
    stream_id,
    collector,
    body_limit,
  ))
  case collector.finished, collector.status, remaining_milliseconds(deadline) {
    True, Some(status), _ ->
      Ok(#(state, Response(status, collector.headers, collector.body)))
    True, None, _ -> Error(Http3ProtocolFailed)
    _, _, remaining if remaining <= 0 -> Error(timeout_error)
    _, _, _ -> {
      let now = udp.monotonic_millisecond()
      use #(state, next_keepalive_milliseconds) <- result.try(maybe_keepalive(
        state,
        keepalive_milliseconds,
        next_keepalive_milliseconds,
        now,
      ))
      use state <- result.try(
        session.tick(state, now)
        |> result.map_error(fn(error) { Http3OperationFailed("tick", error) }),
      )
      let #(state, events) = session.take_events(state)
      use collector <- result.try(apply_events(
        events,
        stream_id,
        collector,
        body_limit,
      ))
      use state <- result.try(flush_session(
        state,
        socket,
        peer,
        now,
        maximum_packets_per_flush,
      ))
      case collector.finished {
        True ->
          collect_response(
            state,
            socket,
            peer,
            stream_id,
            collector,
            body_limit,
            deadline,
            timeout_error,
            keepalive_milliseconds,
            next_keepalive_milliseconds,
          )
        False -> {
          await_more_response(
            state,
            socket,
            peer,
            stream_id,
            collector,
            body_limit,
            deadline,
            timeout_error,
            keepalive_milliseconds,
            next_keepalive_milliseconds,
          )
        }
      }
    }
  }
}

fn await_more_response(
  state: session.State,
  socket: udp.Socket,
  peer: udp.Endpoint,
  stream_id: Int,
  collector: Collector,
  body_limit: Int,
  deadline: Int,
  timeout_error: Error,
  keepalive_milliseconds: Int,
  next_keepalive_milliseconds: Int,
) -> Result(#(session.State, Response), Error) {
  let wait_now = udp.monotonic_millisecond()
  use protocol_deadline <- result.try(
    session.next_deadline(state, wait_now)
    |> result.map_error(fn(error) {
      Http3OperationFailed("next deadline", error)
    }),
  )
  use state <- result.try(receive_session(
    state,
    socket,
    peer,
    wait_milliseconds(
      deadline,
      protocol_deadline,
      next_keepalive_milliseconds,
      wait_now,
    ),
  ))
  collect_response(
    state,
    socket,
    peer,
    stream_id,
    collector,
    body_limit,
    deadline,
    timeout_error,
    keepalive_milliseconds,
    next_keepalive_milliseconds,
  )
}

fn next_keepalive(interval: Int) -> Int {
  case interval {
    0 -> 0
    _ -> udp.monotonic_millisecond() + interval
  }
}

fn wait_milliseconds(
  total_deadline: Int,
  protocol_deadline: Option(Int),
  application_deadline: Int,
  now: Int,
) -> Int {
  let target = case protocol_deadline {
    Some(deadline) if deadline < total_deadline -> deadline
    _ -> total_deadline
  }
  let target = case application_deadline > 0 && application_deadline < target {
    True -> application_deadline
    False -> target
  }
  int.max(0, target - now)
}

fn maybe_keepalive(
  state: session.State,
  interval: Int,
  next: Int,
  now: Int,
) -> Result(#(session.State, Int), Error) {
  case interval > 0 && now >= next {
    False -> Ok(#(state, next))
    True ->
      session.ping(state)
      |> result.map(fn(state) { #(state, now + interval) })
      |> result.map_error(fn(error) { Http3OperationFailed("keepalive", error) })
  }
}

fn flush_session(
  state: session.State,
  socket: udp.Socket,
  peer: udp.Endpoint,
  now: Int,
  remaining_packets: Int,
) -> Result(session.State, Error) {
  case remaining_packets {
    0 -> Ok(state)
    _ ->
      case session.prepare_datagram(state, maximum_frame_data_bytes, now) {
        Error(session.DriverFailure(driver.ConnectionFailure(transport.PacingLimited(
          _,
        )))) -> Ok(state)
        Error(session.DriverFailure(driver.ConnectionFailure(
          transport.CongestionLimited,
        ))) -> Ok(state)
        Error(error) -> Error(Http3OperationFailed("prepare", error))
        Ok(None) -> Ok(state)
        Ok(Some(prepared)) ->
          send_prepared_session(
            state,
            prepared,
            socket,
            peer,
            now,
            remaining_packets,
          )
      }
  }
}

/// Send one prepared HTTP/3 datagram and continue the flush.
///
/// The same path measurement as the handshake flush: a refused datagram is
/// dropped uncommitted, its frames go out again inside the floor.
fn send_prepared_session(
  state: session.State,
  prepared: session.PreparedDatagram,
  socket: udp.Socket,
  peer: udp.Endpoint,
  now: Int,
  remaining_packets: Int,
) -> Result(session.State, Error) {
  case
    udp.classify_send(udp.send(
      socket,
      peer,
      session.prepared_bytes(prepared),
      ecn.NotEct,
    ))
  {
    udp.PathTooSmall -> Ok(session.report_pmtu_black_hole(state))
    udp.SocketLost -> Error(SocketUnavailable)
    udp.Delivered -> {
      use state <- result.try(
        session.commit_datagram(prepared, ecn.NotEct, now)
        |> result.map_error(fn(error) { Http3OperationFailed("commit", error) }),
      )
      flush_session(state, socket, peer, now, remaining_packets - 1)
    }
  }
}

fn receive_session(
  state: session.State,
  socket: udp.Socket,
  peer: udp.Endpoint,
  timeout: Int,
) -> Result(session.State, Error) {
  case udp.receive(socket, timeout) {
    Error(udp.Timeout) -> Ok(state)
    Error(_) -> Error(SocketUnavailable)
    Ok(udp.Datagram(received_peer, bytes, marking)) ->
      case same_endpoint(received_peer, peer) {
        False -> Ok(state)
        True ->
          case
            session.receive_datagram(
              state,
              bytes,
              marking,
              udp.monotonic_millisecond(),
            )
          {
            Ok(state) -> Ok(state)
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
}

fn apply_events(
  events: List(session.Event),
  stream_id: Int,
  collector: Collector,
  body_limit: Int,
) -> Result(Collector, Error) {
  case events {
    [] -> Ok(collector)
    [event, ..rest] -> {
      use collector <- result.try(apply_event(
        event,
        stream_id,
        collector,
        body_limit,
      ))
      apply_events(rest, stream_id, collector, body_limit)
    }
  }
}

fn apply_event(
  event: session.Event,
  stream_id: Int,
  collector: Collector,
  body_limit: Int,
) -> Result(Collector, Error) {
  case event {
    session.Http3Event(http3_state.ResponseHeaders(identifier, validated))
      if identifier == stream_id
    -> {
      let header_semantics.Validated(control, fields, _) = validated
      use status <- result.try(response_status(control))
      use headers <- result.try(decode_headers(fields))
      Ok(Collector(..collector, status: Some(status), headers: headers))
    }
    session.Http3Event(http3_state.Data(identifier, bytes))
      if identifier == stream_id
    -> {
      let size =
        bit_array.byte_size(collector.body) + bit_array.byte_size(bytes)
      case size > body_limit {
        True -> Error(ResponseBodyTooLarge(body_limit))
        False ->
          Ok(Collector(..collector, body: <<collector.body:bits, bytes:bits>>))
      }
    }
    session.Http3Event(http3_state.StreamFinished(identifier))
      if identifier == stream_id
    -> Ok(Collector(..collector, finished: True))
    session.TransportEvent(transport.StreamWasReset(identifier, code))
      if identifier == stream_id
    -> Error(StreamReset(code))
    session.TransportEvent(transport.PeerClosed(_, _)) -> Error(PeerClosed)
    session.TransportEvent(transport.StatelessResetReceived) ->
      Error(PeerClosed)
    _ -> Ok(collector)
  }
}

fn response_status(control: header_semantics.Control) -> Result(Int, Error) {
  case control {
    header_semantics.ResponseControlData(status) -> Ok(status)
    _ -> Error(Http3ProtocolFailed)
  }
}

fn encode_headers(
  fields: List(#(String, String)),
) -> Result(List(Header), Error) {
  list.map(fields, fn(field) {
    let #(name, value) = field
    Header(bit_array.from_string(name), bit_array.from_string(value), False)
  })
  |> Ok
}

fn decode_headers(
  fields: List(Header),
) -> Result(List(#(String, String)), Error) {
  case fields {
    [] -> Ok([])
    [Header(name, value, _), ..rest] -> {
      use name <- result.try(
        bit_array.to_string(name) |> result.replace_error(InvalidHeaderEncoding),
      )
      use value <- result.try(
        bit_array.to_string(value)
        |> result.replace_error(InvalidHeaderEncoding),
      )
      use rest <- result.try(decode_headers(rest))
      Ok([#(name, value), ..rest])
    }
  }
}

fn client_transport_config(
  selected_version: Version,
  idle_timeout_milliseconds: Int,
  dont_fragment: Bool,
) -> transport.Config {
  let config = transport.default_config(transport.Client)
  transport.Config(
    ..config,
    version: selected_version,
    path_dont_fragment: dont_fragment,
    idle_timeout_milliseconds: idle_timeout_milliseconds,
    maximum_udp_payload_size: maximum_udp_payload_size,
    grease_quic_bit: True,
    maximum_datagram_frame_size: 0,
  )
}

fn client_transport_parameters(
  local_connection_id: BitArray,
  selected_version: Version,
  idle_timeout_milliseconds: Int,
) -> List(transport_parameter.Parameter) {
  [
    transport_parameter.GreaseQuicBit,
    transport_parameter.MaxIdleTimeout(idle_timeout_milliseconds),
    transport_parameter.MaxUdpPayloadSize(maximum_udp_payload_size),
    transport_parameter.InitialMaxData(1_048_576),
    transport_parameter.InitialMaxStreamDataBidiLocal(262_144),
    transport_parameter.InitialMaxStreamDataBidiRemote(262_144),
    transport_parameter.InitialMaxStreamDataUni(262_144),
    transport_parameter.InitialMaxStreamsBidi(100),
    transport_parameter.InitialMaxStreamsUni(100),
    transport_parameter.ActiveConnectionIdLimit(4),
    transport_parameter.InitialSourceConnectionId(local_connection_id),
    transport_parameter.VersionInformation(selected_version, [
      version.Version2,
      version.Version1,
    ]),
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

fn graceful_close(
  state: session.State,
  socket: udp.Socket,
  peer: udp.Endpoint,
) -> Nil {
  let now = udp.monotonic_millisecond()
  case session.close(state, 0x100, "request complete", now) {
    // nolint: thrown_away_error -- the socket owner still closes unconditionally.
    Error(_) -> Nil
    Ok(state) -> {
      case flush_session(state, socket, peer, now, 4) {
        Ok(_) -> Nil
        // nolint: thrown_away_error -- best-effort close cannot replace a response.
        Error(_) -> Nil
      }
    }
  }
}

fn discard_or_fail_driver(
  state: driver.State,
  error: driver.Error,
) -> Result(driver.State, Error) {
  case discard_driver_error(error) {
    True -> Ok(state)
    False -> Error(QuicTransportFailed("receive", error))
  }
}

fn discard_driver_error(error: driver.Error) -> Bool {
  driver.discardable_receive_error(error)
}

fn same_endpoint(left: udp.Endpoint, right: udp.Endpoint) -> Bool {
  udp.endpoint_parts(left) == udp.endpoint_parts(right)
}

fn remaining_milliseconds(deadline: Int) -> Int {
  deadline - udp.monotonic_millisecond()
}

fn phase_deadline(
  total_deadline: Int,
  phase_milliseconds: Int,
  phase_error: Error,
) -> #(Int, Error) {
  let phase_deadline = udp.monotonic_millisecond() + phase_milliseconds
  case total_deadline <= phase_deadline {
    True -> #(total_deadline, TotalTimeout)
    False -> #(phase_deadline, phase_error)
  }
}

fn validate(config: Config, body: BitArray) -> Result(Nil, Error) {
  case
    config.hostname != ""
    && config.port > 0
    && config.port <= 65_535
    && config.dns_timeout_milliseconds > 0
    && config.connect_timeout_milliseconds > 0
    && config.handshake_timeout_milliseconds > 0
    && config.timeout_milliseconds > 0
    && config.operation_timeout_milliseconds > 0
    && config.idle_timeout_milliseconds > 0
    && config.maximum_response_body_bytes > 0
    && {
      config.keepalive_milliseconds == 0
      || {
        config.keepalive_milliseconds >= 1000
        && config.keepalive_milliseconds <= 29_000
      }
    }
    && {
      config.quic_version == version.Version1
      || config.quic_version == version.Version2
    }
    && bit_array.bit_size(body) % 8 == 0
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
